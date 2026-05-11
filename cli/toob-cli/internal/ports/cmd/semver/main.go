package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
)

type FieldMeta struct {
	Name string
	Type string
	Tag  string // "required" or "optional"
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <old_ports.go> <new_ports.go>\n", os.Args[0])
		os.Exit(1)
	}

	oldFile, newFile := os.Args[1], os.Args[2]

	oldStructs, oldVersion, err := parseStructs(oldFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse old file: %v\n", err)
		os.Exit(1)
	}

	newStructs, newVersion, err := parseStructs(newFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse new file: %v\n", err)
		os.Exit(1)
	}

	bump := "PATCH"
	var messages []string

	for name, oldFields := range oldStructs {
		newFields, exists := newStructs[name]
		if !exists {
			bump = "MAJOR"
			messages = append(messages, fmt.Sprintf("[MAJOR] Struct %q was removed.", name))
			continue
		}

		// Check for removed or modified fields
		for fieldName, oldField := range oldFields {
			newField, fieldExists := newFields[fieldName]
			if !fieldExists {
				if oldField.Tag == "optional" {
					if bump == "PATCH" {
						bump = "MINOR"
					}
					messages = append(messages, fmt.Sprintf("[MINOR] Optional field %q was removed from struct %q.", fieldName, name))
				} else {
					bump = "MAJOR"
					messages = append(messages, fmt.Sprintf("[MAJOR] Required field %q was removed from struct %q.", fieldName, name))
				}
				continue
			}

			if oldField.Type != newField.Type {
				bump = "MAJOR"
				messages = append(messages, fmt.Sprintf("[MAJOR] Field %q in struct %q changed type from %s to %s.", fieldName, name, oldField.Type, newField.Type))
			}

			if oldField.Tag == "optional" && newField.Tag == "required" {
				bump = "MAJOR"
				messages = append(messages, fmt.Sprintf("[MAJOR] Field %q in struct %q changed from optional to required.", fieldName, name))
			}
		}

		// Check for newly added fields
		for fieldName, newField := range newFields {
			if _, oldExists := oldFields[fieldName]; !oldExists {
				if newField.Tag == "required" {
					bump = "MAJOR"
					messages = append(messages, fmt.Sprintf("[MAJOR] Required field %q was added to struct %q (breaks old clients).", fieldName, name))
				} else {
					if bump == "PATCH" {
						bump = "MINOR"
					}
					messages = append(messages, fmt.Sprintf("[MINOR] Optional field %q was added to struct %q.", fieldName, name))
				}
			}
		}
	}

	for name := range newStructs {
		if _, exists := oldStructs[name]; !exists {
			if bump == "PATCH" {
				bump = "MINOR"
			}
			messages = append(messages, fmt.Sprintf("[MINOR] Struct %q was added.", name))
		}
	}

	if bump == "PATCH" && len(messages) == 0 {
		messages = append(messages, "[PATCH] No structural interface changes detected.")
	}

	if bump == "MAJOR" && newVersion != -1 && oldVersion != -1 {
		if newVersion <= oldVersion {
			fmt.Fprintf(os.Stderr, "[FATAL] BREAKING changes detected, but ProtocolVersion in ports.go was not incremented!\n")
			fmt.Fprintf(os.Stderr, "        Current version: %d. You must increase it to at least %d.\n", newVersion, oldVersion+1)
			
			for _, msg := range messages {
				fmt.Fprintln(os.Stderr, msg)
			}
			
			os.Exit(1)
		}
	}

	// Output messages to stderr for logging
	for _, msg := range messages {
		fmt.Fprintln(os.Stderr, msg)
	}

	// Output the final verdict to stdout
	fmt.Println(bump)
}

func parseStructs(filename string) (map[string]map[string]FieldMeta, int, error) {
	raw, err := os.ReadFile(filename)
	if err != nil || len(bytes.TrimSpace(raw)) == 0 {
		// Empty or missing file (e.g. first-ever release via `touch`)
		return make(map[string]map[string]FieldMeta), -1, nil
	}

	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, filename, nil, 0)
	if err != nil {
		return nil, -1, err
	}

	structs := make(map[string]map[string]FieldMeta)
	protocolVersion := -1

	for _, decl := range node.Decls {
		genDecl, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}

		// Parse Constants (ProtocolVersion)
		if genDecl.Tok == token.CONST {
			for _, spec := range genDecl.Specs {
				valSpec, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, name := range valSpec.Names {
					if name.Name == "ProtocolVersion" && len(valSpec.Values) > i {
						if basicLit, ok := valSpec.Values[i].(*ast.BasicLit); ok {
							fmt.Sscanf(basicLit.Value, "%d", &protocolVersion)
						}
					}
				}
			}
			continue
		}

		if genDecl.Tok != token.TYPE {
			continue
		}

		for _, spec := range genDecl.Specs {
			typeSpec, ok := spec.(*ast.TypeSpec)
			if !ok || !typeSpec.Name.IsExported() {
				continue
			}

			structType, ok := typeSpec.Type.(*ast.StructType)
			if !ok {
				continue
			}

			fields := make(map[string]FieldMeta)
			for _, field := range structType.Fields.List {
				if len(field.Names) == 0 || !field.Names[0].IsExported() {
					continue
				}
				name := field.Names[0].Name
				fieldType := getTypeString(field.Type)
				
				if field.Tag == nil {
					return nil, -1, fmt.Errorf("field %q in struct %q has no struct tag (must have port:\"required\" or port:\"optional\")",
						name, typeSpec.Name.Name)
				}
				tagStr := field.Tag.Value[1 : len(field.Tag.Value)-1]
				tagValue := reflect.StructTag(tagStr).Get("port")
				if tagValue == "" {
					return nil, -1, fmt.Errorf("field %q in struct %q is missing port tag",
						name, typeSpec.Name.Name)
				}
				if tagValue != "required" && tagValue != "optional" {
					return nil, -1, fmt.Errorf("field %q in struct %q has invalid port tag %q (must be \"required\" or \"optional\")",
						name, typeSpec.Name.Name, tagValue)
				}

				fields[name] = FieldMeta{Name: name, Type: fieldType, Tag: tagValue}
			}
			structs[typeSpec.Name.Name] = fields
		}
	}

	return structs, protocolVersion, nil
}

func getTypeString(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return "*" + getTypeString(t.X)
	case *ast.ArrayType:
		return "[]" + getTypeString(t.Elt)
	case *ast.SelectorExpr:
		return getTypeString(t.X) + "." + t.Sel.Name
	case *ast.MapType:
		return "map[" + getTypeString(t.Key) + "]" + getTypeString(t.Value)
	default:
		return fmt.Sprintf("unknown(%T)", t)
	}
}
