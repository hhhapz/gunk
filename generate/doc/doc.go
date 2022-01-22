package doc

import (
	"fmt"
	"go/ast"
	"go/types"
	"strconv"
	"strings"

	"github.com/gunk/gunk/config"
	"github.com/gunk/gunk/loader"
)

type Doc struct {
	pkg *loader.GunkPackage
	cfg config.Generator

	partialEnum *Enum

	services map[string]*Service // service types
	types    map[string]Type     // data types - TODO: figure out the type to use

	inService map[string][]*Endpoint // types used as service params or return type
	inField   map[string]bool        // types defined as used in fields of other types
}

// Generate generates the JSON documentation.
func Generate(pkg *loader.GunkPackage, cfg config.Generator) (p *Package, err error) {
	doc := &Doc{
		pkg:         pkg,
		cfg:         cfg,
		partialEnum: new(Enum),
		services:    make(map[string]*Service),
		types:       make(map[string]Type),
		inService:   make(map[string][]*Endpoint),
		inField:     make(map[string]bool),
	}

	type bailout struct{}
	defer func() {
		if r := recover(); r != nil {
			if _, ok := r.(bailout); ok {
				return
			}
			panic(r)
		}
	}()
	var pkgDesc string
	// collect types and services
	for _, v := range pkg.GunkSyntax {
		if v.Doc.Text() != "" {
			pkgDesc = v.Doc.Text()
		}
		for _, w := range v.Decls {
			ast.Inspect(w, func(n ast.Node) bool {
				switch n := n.(type) {
				default:
					return false
				case *ast.GenDecl, *ast.StructType, *ast.FieldList:
					return true
				// enum def, struct def, iface def
				case *ast.TypeSpec:
					doc.addType(n)
				// enum values
				case *ast.ValueSpec:
					err = doc.addEnum(n)
				}
				if err != nil {
					panic(bailout{})
				}
				return false
			})
		}
	}
	if doc.partialEnum.Name != "" {
		// guaranteed for pkg to not be nil
		qName, _ := doc.qualifiedTypeName(doc.partialEnum.Name, doc.pkg.Types)
		doc.types[qName] = doc.partialEnum
	}
	// cleanup
	for k, v := range doc.types {
		o, ok := v.(*Object)
		if !ok {
			continue
		}
		if doc.inService[k] != nil && !doc.inField[k] {
			// Remove data types that are only part of a service.
			delete(doc.types, k)
			// replace ref types with the object itself
			for _, s := range doc.inService[k] {
				// replace the request / response, if it matches
				if req, ok := s.Request.(*Ref); ok && req.Name == k {
					s.Request = o
				}
				if res, ok := s.Response.(*Ref); ok && res.Name == k {
					s.Response = o
				}
			}
		}
	}
	// create package
	services := make([]*Service, 0, len(doc.services))
	for _, s := range doc.services {
		services = append(services, s)
	}
	return &Package{
		ID:          pkg.Types.Path(),
		Description: pkgDesc,
		Services:    services,
		Types:       doc.types,
	}, nil
}

func (doc *Doc) addType(n *ast.TypeSpec) error {
	switch nn := n.Type.(type) {
	case *ast.StructType:
		return doc.addMesage(n, nn)
	case *ast.InterfaceType:
		return doc.addService(n, nn)
	case *ast.Ident:
		if nn.Name == "int" {
			if e := doc.partialEnum; e != nil {
				// guaranteed for pkg to not be nil
				qName, _ := doc.qualifiedTypeName(e.Name, doc.pkg.Types)
				doc.types[qName] = e
			}
			doc.partialEnum = &Enum{
				Name:        n.Name.Name,
				Description: cleanDescription(n.Name.Name, n.Doc.Text()),
			}
		}
	}
	return nil
}

func (doc *Doc) addMesage(n *ast.TypeSpec, st *ast.StructType) error {
	obj := &Object{
		Name:        n.Name.Name,
		Description: cleanDescription(n.Name.Name, n.Doc.Text()),
	}
	for _, field := range st.Fields.List {
		if len(field.Names) == 0 {
			return fmt.Errorf("field %s has no name", field.Type)
		}
		if len(field.Names) > 1 {
			return fmt.Errorf("field %s has multiple names", field.Names)
		}
		ftype := doc.pkg.TypesInfo.TypeOf(field.Type)
		typ, err := doc.convertType(ftype, false)
		if err != nil {
			return err
		}
		name := field.Names[0].Name
		obj.Fields = append(obj.Fields, &Field{
			Name:        name,
			Description: cleanDescription(name, field.Doc.Text()),
			Type:        typ,
		})
	}
	// guaranteed for pkg to not be nil
	qName, _ := doc.qualifiedTypeName(n.Name.Name, doc.pkg.Types)
	doc.types[qName] = obj
	return nil
}

func (doc *Doc) addService(n *ast.TypeSpec, ifc *ast.InterfaceType) error {
	service := &Service{
		Name:        n.Name.Name,
		Description: cleanDescription(n.Name.Name, n.Doc.Text()),
	}
	for _, v := range ifc.Methods.List {
		if len(v.Names) != 1 {
			return fmt.Errorf("methods must have exactly one name")
		}
		endpoint := &Endpoint{
			Name:        v.Names[0].Name,
			Description: cleanDescription(v.Names[0].Name, v.Doc.Text()),
		}
		for _, tag := range doc.pkg.GunkTags[v] {
			switch tag.Type.String() {
			case "github.com/gunk/opt/http.Match":
				for _, elt := range tag.Expr.(*ast.CompositeLit).Elts {
					kv := elt.(*ast.KeyValueExpr)
					val, _ := strconv.Unquote(kv.Value.(*ast.BasicLit).Value)
					switch name := kv.Key.(*ast.Ident).Name; name {
					case "Method":
						endpoint.Method = val
					case "Path":
						endpoint.Path = val
					case "Body":
						endpoint.BodyField = val
					}
				}
			case "github.com/gunk/opt/doc.Embed":
			}
		}
		sign := doc.pkg.TypesInfo.TypeOf(v.Type).(*types.Signature)
		var err error
		endpoint.Request, endpoint.StreamingRequest, err = doc.convertParam(endpoint, sign.Params())
		if err != nil {
			return fmt.Errorf("%s: %s", v.Names[0].Name, err)
		}
		endpoint.Response, endpoint.StreamingResponse, err = doc.convertParam(endpoint, sign.Results())
		if err != nil {
			return fmt.Errorf("%s: %s", v.Names[0].Name, err)
		}
		service.Endpoints = append(service.Endpoints, endpoint)
	}
	doc.services[n.Name.Name] = service
	return nil
}

func (doc *Doc) convertParam(e *Endpoint, params *types.Tuple) (Type, bool, error) {
	switch params.Len() {
	case 0:
		return nil, false, nil
	case 1:
		// below
	default:
		return nil, false, fmt.Errorf("multiple parameters are not supported")
	}
	param := params.At(0).Type()
	typ, err := doc.convertType(param, true)
	if typ == nil {
		return nil, false, fmt.Errorf("known type for %s", params.At(0).Name())
	}
	if err != nil {
		return nil, false, err
	}
	if _, ok := typ.(*Ref); !ok {
		return nil, false, fmt.Errorf("unsupported parameter type: %v", typ)
	}
	ref := typ.(*Ref)
	doc.inService[ref.Name] = append(doc.inService[ref.Name], e)
	var streaming bool
	if _, ok := param.(*types.Chan); ok {
		streaming = true
	}
	return ref, streaming, nil
}

func (doc *Doc) addEnum(n *ast.ValueSpec) error {
	if doc.partialEnum == nil {
		return fmt.Errorf("type declaration must come before enum values for %s", n.Names[0].Name)
	}
	for _, ident := range n.Names {
		doc.partialEnum.Values = append(doc.partialEnum.Values, &EnumVal{
			Value:       ident.Name,
			Description: cleanDescription(ident.Name, n.Doc.Text()),
		})
	}
	return nil
}

func (doc *Doc) convertType(typ types.Type, inService bool) (Type, error) {
	switch typ := typ.(type) {
	case *types.Chan:
		return doc.convertType(typ.Elem(), inService)
	case *types.Basic:
		switch typ.Kind() {
		case types.String:
			return &Basic{"string", ""}, nil
		case types.Int, types.Int32:
			return &Basic{"integer", ""}, nil
		case types.Uint, types.Uint32:
			return &Basic{"unsigned integer", ""}, nil
		case types.Int64:
			return &Basic{"integer(64)", ""}, nil
		case types.Uint64:
			return &Basic{"unsigned integer(64)", ""}, nil
		case types.Float32:
			return &Basic{"float(32)", ""}, nil
		case types.Float64:
			return &Basic{"float(64)", ""}, nil
		case types.Bool:
			return &Basic{"boolean", ""}, nil
		}
	case *types.Slice:
		if eTyp, ok := typ.Elem().(*types.Basic); ok {
			if eTyp.Kind() == types.Byte {
				return &Basic{"bytes", ""}, nil
			}
		}
		dtyp, err := doc.convertType(typ.Elem(), false)
		if err != nil {
			return nil, err
		}
		if dtyp == nil {
			return nil, nil
		}
		return &Array{dtyp}, nil
	case *types.Map:
		kTyp, err := doc.convertType(typ.Key(), false)
		if err != nil {
			return nil, err
		}
		vTyp, err := doc.convertType(typ.Elem(), false)
		if err != nil {
			return nil, err
		}
		if kTyp == nil || vTyp == nil {
			return nil, nil
		}
		return &Map{kTyp, vTyp}, nil
	case *types.Named:
		switch typ.String() {
		case "time.Time":
			return &Basic{"date time", ""}, nil
		case "time.Duration":
			return &Basic{"duration", ""}, nil
		}
		obj := typ.Obj()
		fullName, err := doc.qualifiedTypeName(obj.Name(), obj.Pkg())
		if err != nil {
			return nil, err
		}
		if !inService {
			doc.inField[fullName] = true
		}
		return &Ref{fullName}, nil
	}
	return nil, nil
}

func (doc *Doc) qualifiedTypeName(typeName string, pkg *types.Package) (string, error) {
	// If pkg is nil, we should format the type for the current package.
	if pkg == nil {
		pkg = doc.pkg.Types
	}
	return pkg.Path() + "." + typeName, nil
}

// cleanDescription removes the leading "XYZ is" and the trailing dot from the
// description.
func cleanDescription(name string, desc string) string {
	// FIXME: Check for Deprecated:
	desc = strings.TrimPrefix(desc, name+" is ")
	desc = strings.TrimPrefix(desc, name+" are ")
	desc = strings.TrimPrefix(desc, name+" ") // Interface methods
	desc = strings.TrimSuffix(desc, ".")
	return desc
}
