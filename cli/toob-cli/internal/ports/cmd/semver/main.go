package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

// FieldMeta captures the parsed ABI signature and serialization tags of a contract field.
type FieldMeta struct {
	Name        string
	Type        string
	Tag         string // "required" or "optional"
	JSONTag     string
	JSONTagFull string
	TOMLTag     string
	TOMLTagFull string
}

// InterfaceInfo captures exported contracts parsed from a ports.go file.
type InterfaceInfo struct {
	ProtocolVersion int
	Structs         map[string]map[string]FieldMeta
	Constants       map[string]string
	TypeAliases     map[string]string
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func writef(w io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(w, format, args...)
}

func writeln(w io.Writer, line string) {
	_, _ = fmt.Fprintln(w, line)
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("semver", flag.ContinueOnError)
	fs.SetOutput(stderr)
	initial := fs.Bool("initial", false, "allow missing or empty old_ports.go when establishing an initial contract")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if fs.NArg() != 2 {
		writeln(stderr, "Usage: semver [--initial] <old_ports.go> <new_ports.go>")
		return 1
	}

	oldFile, newFile := fs.Arg(0), fs.Arg(1)

	oldInfo, err := parseInterface(oldFile, *initial)
	if err != nil {
		writef(stderr, "Failed to parse old file %q: %v\n", oldFile, err)
		return 1
	}

	newInfo, err := parseInterface(newFile, false)
	if err != nil {
		writef(stderr, "Failed to parse new file %q: %v\n", newFile, err)
		return 1
	}

	if oldInfo.ProtocolVersion != -1 && newInfo.ProtocolVersion == -1 {
		writeln(stderr, "[FATAL] ProtocolVersion constant was removed from ports.go.")
		return 1
	}

	bump, messages := diffInterfaces(oldInfo, newInfo)

	if bump == "MAJOR" && newInfo.ProtocolVersion != -1 && oldInfo.ProtocolVersion != -1 {
		if newInfo.ProtocolVersion <= oldInfo.ProtocolVersion {
			writeln(stderr, "[FATAL] BREAKING changes detected, but ProtocolVersion in ports.go was not incremented!")
			writef(stderr, "        Current version: %d. You must increase it to at least %d.\n",
				newInfo.ProtocolVersion, oldInfo.ProtocolVersion+1)
			for _, msg := range messages {
				writeln(stderr, msg)
			}
			return 1
		}
	}

	for _, msg := range messages {
		writeln(stderr, msg)
	}
	writeln(stdout, bump)
	return 0
}

func diffInterfaces(oldInfo, newInfo InterfaceInfo) (string, []string) {
	bump := "PATCH"
	var messages []string

	promote := func(level string) {
		switch level {
		case "MAJOR":
			bump = "MAJOR"
		case "MINOR":
			if bump == "PATCH" {
				bump = "MINOR"
			}
		}
	}

	for _, name := range sortedMapKeys(oldInfo.Structs) {
		oldFields := oldInfo.Structs[name]
		newFields, exists := newInfo.Structs[name]
		if !exists {
			promote("MAJOR")
			messages = append(messages, fmt.Sprintf("[MAJOR] Struct %q was removed.", name))
			continue
		}

		for _, fieldName := range sortedMapKeys(oldFields) {
			oldField := oldFields[fieldName]
			newField, fieldExists := newFields[fieldName]
			if !fieldExists {
				promote("MAJOR")
				messages = append(messages, fmt.Sprintf("[MAJOR] Field %q (%s) was removed from struct %q.",
					fieldName, oldField.Tag, name))
				continue
			}

			if oldField.Type != newField.Type {
				promote("MAJOR")
				messages = append(messages, fmt.Sprintf("[MAJOR] Field %q in struct %q changed type from %s to %s.",
					fieldName, name, oldField.Type, newField.Type))
			}

			if oldField.Tag != newField.Tag {
				promote("MAJOR")
				messages = append(messages, fmt.Sprintf("[MAJOR] Field %q in struct %q changed contract requirement from %q to %q.",
					fieldName, name, oldField.Tag, newField.Tag))
			}

			oldJSON := wireOrField(oldField.JSONTag, fieldName)
			newJSON := wireOrField(newField.JSONTag, fieldName)
			if oldJSON != newJSON {
				promote("MAJOR")
				messages = append(messages, fmt.Sprintf("[MAJOR] Field %q in struct %q changed json wire name from %q to %q.",
					fieldName, name, oldJSON, newJSON))
			} else if oldField.JSONTagFull != newField.JSONTagFull {
				promote("MAJOR")
				messages = append(messages, fmt.Sprintf("[MAJOR] Field %q in struct %q changed json serialization options (%q -> %q).",
					fieldName, name, oldField.JSONTagFull, newField.JSONTagFull))
			}

			if oldField.TOMLTag != newField.TOMLTag {
				promote("MAJOR")
				messages = append(messages, fmt.Sprintf("[MAJOR] Field %q in struct %q changed toml key from %q to %q.",
					fieldName, name, oldField.TOMLTag, newField.TOMLTag))
			} else if oldField.TOMLTagFull != newField.TOMLTagFull {
				promote("MAJOR")
				messages = append(messages, fmt.Sprintf("[MAJOR] Field %q in struct %q changed toml serialization options (%q -> %q).",
					fieldName, name, oldField.TOMLTagFull, newField.TOMLTagFull))
			}
		}

		for _, fieldName := range sortedMapKeys(newFields) {
			newField := newFields[fieldName]
			if _, oldExists := oldFields[fieldName]; !oldExists {
				if newField.Tag == "required" {
					promote("MAJOR")
					messages = append(messages, fmt.Sprintf("[MAJOR] Required field %q was added to struct %q (breaks old clients).",
						fieldName, name))
				} else {
					promote("MINOR")
					messages = append(messages, fmt.Sprintf("[MINOR] Optional field %q was added to struct %q.",
						fieldName, name))
				}
			}
		}
	}

	for _, name := range sortedMapKeys(newInfo.Structs) {
		if _, exists := oldInfo.Structs[name]; !exists {
			promote("MINOR")
			messages = append(messages, fmt.Sprintf("[MINOR] Struct %q was added.", name))
		}
	}

	for _, name := range sortedMapKeys(oldInfo.Constants) {
		oldVal := oldInfo.Constants[name]
		newVal, exists := newInfo.Constants[name]
		if !exists {
			promote("MAJOR")
			messages = append(messages, fmt.Sprintf("[MAJOR] Exported constant %q was removed.", name))
			continue
		}
		if oldVal != newVal {
			promote("MAJOR")
			messages = append(messages, fmt.Sprintf("[MAJOR] Exported constant %q value/type changed from %q to %q.",
				name, oldVal, newVal))
		}
	}
	for _, name := range sortedMapKeys(newInfo.Constants) {
		if _, exists := oldInfo.Constants[name]; !exists {
			promote("MINOR")
			messages = append(messages, fmt.Sprintf("[MINOR] Exported constant %q was added.", name))
		}
	}

	for _, name := range sortedMapKeys(oldInfo.TypeAliases) {
		oldType := oldInfo.TypeAliases[name]
		newType, exists := newInfo.TypeAliases[name]
		if !exists {
			promote("MAJOR")
			messages = append(messages, fmt.Sprintf("[MAJOR] Exported type alias %q was removed.", name))
			continue
		}
		if oldType != newType {
			promote("MAJOR")
			messages = append(messages, fmt.Sprintf("[MAJOR] Exported type alias %q underlying type changed from %q to %q.",
				name, oldType, newType))
		}
	}
	for _, name := range sortedMapKeys(newInfo.TypeAliases) {
		if _, exists := oldInfo.TypeAliases[name]; !exists {
			promote("MINOR")
			messages = append(messages, fmt.Sprintf("[MINOR] Exported type alias %q was added.", name))
		}
	}

	if bump == "PATCH" && len(messages) == 0 {
		messages = append(messages, "[PATCH] No structural ABI changes detected.")
	}

	return bump, messages
}

func wireOrField(tagName, fieldName string) string {
	if tagName == "" {
		return fieldName
	}
	return tagName
}

func sortedMapKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func parseInterface(filename string, allowMissingOrEmpty bool) (InterfaceInfo, error) {
	info := InterfaceInfo{
		ProtocolVersion: -1,
		Structs:         make(map[string]map[string]FieldMeta),
		Constants:       make(map[string]string),
		TypeAliases:     make(map[string]string),
	}

	cleanPath := filepath.Clean(filename)
	raw, readErr := os.ReadFile(cleanPath)
	if readErr != nil {
		if os.IsNotExist(readErr) && allowMissingOrEmpty {
			return info, nil
		}
		return info, readErr
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		if allowMissingOrEmpty {
			return info, nil
		}
		return info, fmt.Errorf("contract file %q is empty", filename)
	}

	fset := token.NewFileSet()
	node, parseErr := parser.ParseFile(fset, cleanPath, raw, 0)
	if parseErr != nil {
		return info, parseErr
	}

	for _, decl := range node.Decls {
		genDecl, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}

		switch genDecl.Tok {
		case token.CONST:
			if constErr := parseConstDecl(fset, genDecl, &info); constErr != nil {
				return info, constErr
			}
		case token.TYPE:
			if typeErr := parseTypeDecl(fset, genDecl, &info); typeErr != nil {
				return info, typeErr
			}
		default:
		}
	}

	return info, nil
}

func parseConstDecl(fset *token.FileSet, genDecl *ast.GenDecl, info *InterfaceInfo) error {
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
				if len(valSpec.Values) <= i {
					return errors.New("ProtocolVersion constant is missing a literal value")
				}
				basicLit, isLit := valSpec.Values[i].(*ast.BasicLit)
				if !isLit || basicLit.Kind != token.INT {
					return errors.New("ProtocolVersion must be an integer literal")
				}
				ver, convErr := strconv.Atoi(basicLit.Value)
				if convErr != nil {
					return fmt.Errorf("invalid ProtocolVersion %q: %w", basicLit.Value, convErr)
				}
				info.ProtocolVersion = ver
				continue
			}

			var valStr string
			if len(valSpec.Values) > i {
				rendered, printErr := renderAST(fset, valSpec.Values[i])
				if printErr != nil {
					return printErr
				}
				valStr = rendered
			} else {
				valStr = "implicit(iota)"
			}

			typeStr := ""
			if valSpec.Type != nil {
				renderedType, printErr := renderAST(fset, valSpec.Type)
				if printErr != nil {
					return printErr
				}
				typeStr = renderedType + " "
			}

			info.Constants[name.Name] = typeStr + valStr
		}
	}
	return nil
}

func parseTypeDecl(fset *token.FileSet, genDecl *ast.GenDecl, info *InterfaceInfo) error {
	for _, spec := range genDecl.Specs {
		typeSpec, ok := spec.(*ast.TypeSpec)
		if !ok || !typeSpec.Name.IsExported() {
			continue
		}

		if structType, isStruct := typeSpec.Type.(*ast.StructType); isStruct {
			if parseErr := parseStructFields(fset, typeSpec.Name.Name, structType, info); parseErr != nil {
				return parseErr
			}
			continue
		}

		rendered, printErr := renderAST(fset, typeSpec.Type)
		if printErr != nil {
			return printErr
		}
		info.TypeAliases[typeSpec.Name.Name] = rendered
	}
	return nil
}

func parseStructFields(fset *token.FileSet, structName string, st *ast.StructType, info *InterfaceInfo) error {
	fields := make(map[string]FieldMeta)

	for _, field := range st.Fields.List {
		if len(field.Names) == 0 {
			continue
		}

		for _, ident := range field.Names {
			if !ident.IsExported() {
				continue
			}
			name := ident.Name

			fieldType, printErr := renderFieldType(fset, structName, name, field.Type)
			if printErr != nil {
				return printErr
			}

			if field.Tag == nil {
				return fmt.Errorf("field %q in struct %q has no struct tag (must have port:\"required\" or port:\"optional\")",
					name, structName)
			}
			rawTag := field.Tag.Value
			if len(rawTag) < 2 {
				return fmt.Errorf("field %q in struct %q has malformed struct tag", name, structName)
			}
			parsedTag := reflect.StructTag(rawTag[1 : len(rawTag)-1])

			tagValue := parsedTag.Get("port")
			if tagValue == "" {
				return fmt.Errorf("field %q in struct %q is missing port tag", name, structName)
			}
			if tagValue != "required" && tagValue != "optional" {
				return fmt.Errorf("field %q in struct %q has invalid port tag %q (must be \"required\" or \"optional\")",
					name, structName, tagValue)
			}

			jsonTagFull := parsedTag.Get("json")
			jsonTag, _, _ := strings.Cut(jsonTagFull, ",")

			tomlTagFull := parsedTag.Get("toml")
			tomlTag, _, _ := strings.Cut(tomlTagFull, ",")

			fields[name] = FieldMeta{
				Name:        name,
				Type:        fieldType,
				Tag:         tagValue,
				JSONTag:     jsonTag,
				JSONTagFull: jsonTagFull,
				TOMLTag:     tomlTag,
				TOMLTagFull: tomlTagFull,
			}

			if nestedErr := parseNestedInlineStructs(fset, structName+"."+name, field.Type, info); nestedErr != nil {
				return nestedErr
			}
		}
	}

	info.Structs[structName] = fields
	return nil
}

func renderFieldType(fset *token.FileSet, structName, fieldName string, expr ast.Expr) (string, error) {
	// Normalize anonymous inline structs to a deterministic wrapper signature so
	// optional additions inside an inline struct stay MINOR rather than triggering
	// a spurious type-string mismatch on the enclosing field.
	if hasInlineStruct(expr) {
		return formatWrappedType(fset, structName+"."+fieldName, expr)
	}
	return renderAST(fset, expr)
}

func hasInlineStruct(expr ast.Expr) bool {
	switch node := expr.(type) {
	case *ast.StructType:
		return true
	case *ast.StarExpr:
		return hasInlineStruct(node.X)
	case *ast.ArrayType:
		return hasInlineStruct(node.Elt)
	case *ast.MapType:
		return hasInlineStruct(node.Key) || hasInlineStruct(node.Value)
	default:
		return false
	}
}

func formatWrappedType(fset *token.FileSet, prefix string, expr ast.Expr) (string, error) {
	switch node := expr.(type) {
	case *ast.StructType:
		return "struct<" + prefix + ">", nil
	case *ast.StarExpr:
		inner, err := formatWrappedType(fset, prefix, node.X)
		if err != nil {
			return "", err
		}
		return "*" + inner, nil
	case *ast.ArrayType:
		lenStr := ""
		if node.Len != nil {
			rendered, err := renderAST(fset, node.Len)
			if err != nil {
				return "", err
			}
			lenStr = rendered
		}
		inner, err := formatWrappedType(fset, prefix, node.Elt)
		if err != nil {
			return "", err
		}
		return "[" + lenStr + "]" + inner, nil
	case *ast.MapType:
		keyStr, err := formatWrappedType(fset, prefix+".key", node.Key)
		if err != nil {
			return "", err
		}
		valStr, err := formatWrappedType(fset, prefix+".val", node.Value)
		if err != nil {
			return "", err
		}
		return "map[" + keyStr + "]" + valStr, nil
	default:
		return renderAST(fset, expr)
	}
}

func parseNestedInlineStructs(fset *token.FileSet, prefix string, expr ast.Expr, info *InterfaceInfo) error {
	switch node := expr.(type) {
	case *ast.StructType:
		return parseStructFields(fset, prefix, node, info)
	case *ast.StarExpr:
		return parseNestedInlineStructs(fset, prefix, node.X, info)
	case *ast.ArrayType:
		return parseNestedInlineStructs(fset, prefix, node.Elt, info)
	case *ast.MapType:
		if err := parseNestedInlineStructs(fset, prefix+".key", node.Key, info); err != nil {
			return err
		}
		return parseNestedInlineStructs(fset, prefix+".val", node.Value, info)
	default:
		return nil
	}
}

func renderAST(fset *token.FileSet, node any) (string, error) {
	var buf bytes.Buffer
	if err := printer.Fprint(&buf, fset, node); err != nil {
		return "", err
	}
	return buf.String(), nil
}
