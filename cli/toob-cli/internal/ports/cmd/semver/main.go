package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"reflect"
	"strings"
)

type FieldMeta struct {
	Name    string
	Type    string
	Tag     string // "required" or "optional"
	JsonTag string // Wire-format key from `json:"..."` tag
	JsonTagFull string // The complete json tag including options like omitempty
}

type InterfaceInfo struct {
	ProtocolVersion int
	Structs         map[string]map[string]FieldMeta
	Constants       map[string]string // Name -> Type+Value
	TypeAliases     map[string]string // Name -> UnderlyingType
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <old_ports.go> <new_ports.go>\n", os.Args[0])
		os.Exit(1)
	}

	oldFile, newFile := os.Args[1], os.Args[2]

	oldInfo, err := parseInterface(oldFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse old file: %v\n", err)
		os.Exit(1)
	}

	newInfo, err := parseInterface(newFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse new file: %v\n", err)
		os.Exit(1)
	}

	bump := "PATCH"
	var messages []string

	// 1. Check Structs
	for name, oldFields := range oldInfo.Structs {
		newFields, exists := newInfo.Structs[name]
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

			// Wire-format breaking: renaming or removing a JSON key changes the serialized contract
			oldWireName := oldField.JsonTag
			if oldWireName == "" {
				oldWireName = fieldName
			}
			newWireName := newField.JsonTag
			if newWireName == "" {
				newWireName = fieldName
			}
			if oldWireName != newWireName {
				bump = "MAJOR"
				messages = append(messages, fmt.Sprintf("[MAJOR] Field %q in struct %q changed wire-format name from %q to %q.", fieldName, name, oldWireName, newWireName))
			} else if oldField.JsonTagFull != newField.JsonTagFull {
				bump = "MAJOR"
				messages = append(messages, fmt.Sprintf("[MAJOR] Field %q in struct %q changed json serialization options (e.g. omitempty).", fieldName, name))
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

	for name := range newInfo.Structs {
		if _, exists := oldInfo.Structs[name]; !exists {
			if bump == "PATCH" {
				bump = "MINOR"
			}
			messages = append(messages, fmt.Sprintf("[MINOR] Struct %q was added.", name))
		}
	}

	// 2. Check Constants (Enums)
	for name, oldVal := range oldInfo.Constants {
		newVal, exists := newInfo.Constants[name]
		if !exists {
			bump = "MAJOR"
			messages = append(messages, fmt.Sprintf("[MAJOR] Exported constant %q was removed.", name))
			continue
		}
		if oldVal != newVal {
			bump = "MAJOR"
			messages = append(messages, fmt.Sprintf("[MAJOR] Exported constant %q value/type changed from %q to %q.", name, oldVal, newVal))
		}
	}
	for name := range newInfo.Constants {
		if _, exists := oldInfo.Constants[name]; !exists {
			if bump == "PATCH" {
				bump = "MINOR"
			}
			messages = append(messages, fmt.Sprintf("[MINOR] Exported constant %q was added.", name))
		}
	}

	// 3. Check Type Aliases
	for name, oldType := range oldInfo.TypeAliases {
		newType, exists := newInfo.TypeAliases[name]
		if !exists {
			bump = "MAJOR"
			messages = append(messages, fmt.Sprintf("[MAJOR] Exported type alias %q was removed.", name))
			continue
		}
		if oldType != newType {
			bump = "MAJOR"
			messages = append(messages, fmt.Sprintf("[MAJOR] Exported type alias %q underlying type changed from %q to %q.", name, oldType, newType))
		}
	}
	for name := range newInfo.TypeAliases {
		if _, exists := oldInfo.TypeAliases[name]; !exists {
			if bump == "PATCH" {
				bump = "MINOR"
			}
			messages = append(messages, fmt.Sprintf("[MINOR] Exported type alias %q was added.", name))
		}
	}

	if bump == "PATCH" && len(messages) == 0 {
		messages = append(messages, "[PATCH] No structural ABI changes detected.")
	}

	if bump == "MAJOR" && newInfo.ProtocolVersion != -1 && oldInfo.ProtocolVersion != -1 {
		if newInfo.ProtocolVersion <= oldInfo.ProtocolVersion {
			fmt.Fprintf(os.Stderr, "[FATAL] BREAKING changes detected, but ProtocolVersion in ports.go was not incremented!\n")
			fmt.Fprintf(os.Stderr, "        Current version: %d. You must increase it to at least %d.\n", newInfo.ProtocolVersion, oldInfo.ProtocolVersion+1)

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

func parseInterface(filename string) (InterfaceInfo, error) {
	info := InterfaceInfo{
		ProtocolVersion: -1,
		Structs:         make(map[string]map[string]FieldMeta),
		Constants:       make(map[string]string),
		TypeAliases:     make(map[string]string),
	}

	raw, err := os.ReadFile(filename)
	if err != nil || len(bytes.TrimSpace(raw)) == 0 {
		// Empty or missing file
		return info, nil
	}

	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, filename, nil, 0)
	if err != nil {
		return info, err
	}

	for _, decl := range node.Decls {
		genDecl, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}

		// Parse Constants
		if genDecl.Tok == token.CONST {
			for _, spec := range genDecl.Specs {
				valSpec, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, name := range valSpec.Names {
					if !name.IsExported() {
						continue
					}

					if name.Name == "ProtocolVersion" {
						if len(valSpec.Values) > i {
							if basicLit, ok := valSpec.Values[i].(*ast.BasicLit); ok {
								fmt.Sscanf(basicLit.Value, "%d", &info.ProtocolVersion)
							}
						}
						continue
					}

					var valStr string
					if len(valSpec.Values) > i {
						var buf bytes.Buffer
						printer.Fprint(&buf, fset, valSpec.Values[i])
						valStr = buf.String()
					} else {
						valStr = "implicit(iota)"
					}

					typeStr := ""
					if valSpec.Type != nil {
						var buf bytes.Buffer
						printer.Fprint(&buf, fset, valSpec.Type)
						typeStr = buf.String() + " "
					}

					info.Constants[name.Name] = typeStr + valStr
				}
			}
			continue
		}

		// Parse Types
		if genDecl.Tok == token.TYPE {
			for _, spec := range genDecl.Specs {
				typeSpec, ok := spec.(*ast.TypeSpec)
				if !ok || !typeSpec.Name.IsExported() {
					continue
				}

				if structType, ok := typeSpec.Type.(*ast.StructType); ok {
					fields := make(map[string]FieldMeta)
					for _, field := range structType.Fields.List {
						if len(field.Names) == 0 || !field.Names[0].IsExported() {
							continue
						}
						name := field.Names[0].Name
						
						var typeBuf bytes.Buffer
						printer.Fprint(&typeBuf, fset, field.Type)
						fieldType := typeBuf.String()

						if field.Tag == nil {
							return info, fmt.Errorf("field %q in struct %q has no struct tag (must have port:\"required\" or port:\"optional\")",
								name, typeSpec.Name.Name)
						}
						tagStr := field.Tag.Value[1 : len(field.Tag.Value)-1]
						parsedTag := reflect.StructTag(tagStr)
						tagValue := parsedTag.Get("port")
						if tagValue == "" {
							return info, fmt.Errorf("field %q in struct %q is missing port tag",
								name, typeSpec.Name.Name)
						}
						if tagValue != "required" && tagValue != "optional" {
							return info, fmt.Errorf("field %q in struct %q has invalid port tag %q (must be \"required\" or \"optional\")",
								name, typeSpec.Name.Name, tagValue)
						}

						// Extract wire-format JSON key for contract diffing
						jsonTagFull := parsedTag.Get("json")
						jsonTag := jsonTagFull
						if idx := strings.Index(jsonTag, ","); idx != -1 {
							jsonTag = jsonTag[:idx]
						}

						fields[name] = FieldMeta{Name: name, Type: fieldType, Tag: tagValue, JsonTag: jsonTag, JsonTagFull: jsonTagFull}
					}
					info.Structs[typeSpec.Name.Name] = fields
				} else {
					// Type Alias / Basic Type Definition
					var buf bytes.Buffer
					printer.Fprint(&buf, fset, typeSpec.Type)
					info.TypeAliases[typeSpec.Name.Name] = buf.String()
				}
			}
		}
	}

	return info, nil
}
