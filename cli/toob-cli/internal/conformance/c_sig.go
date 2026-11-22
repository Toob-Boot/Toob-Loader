package conformance

import (
	"slices"
	"strings"
)

var cTypeSpecifierKeywords = map[string]bool{
	"void": true, "char": true, "short": true, "int": true, "long": true,
	"float": true, "double": true, "signed": true, "unsigned": true,
	"bool": true, "_Bool": true, "_Complex": true, "_Imaginary": true,
}

var cQualifierOrTagKeywords = map[string]bool{
	"const": true, "volatile": true, "restrict": true, "__restrict": true, "__restrict__": true,
	"struct": true, "union": true, "enum": true, "_Atomic": true,
}

var cControlKeywords = map[string]bool{
	"if": true, "for": true, "while": true, "switch": true, "return": true, "sizeof": true,
	"_Static_assert": true, "static_assert": true, "_Alignas": true, "_Alignof": true,
}

func stripAttributeAnnotations(s string) string {
	for {
		idx := strings.Index(s, "__attribute__")
		if idx < 0 {
			return s
		}
		end := idx + len("__attribute__")
		for end < len(s) && (s[end] == ' ' || s[end] == '\t' || s[end] == '\n' || s[end] == '\r') {
			end++
		}
		if end >= len(s) || s[end] != '(' {
			return s[:idx] + " " + s[end:]
		}
		depth := 0
		for end < len(s) {
			if s[end] == '(' {
				depth++
			} else if s[end] == ')' {
				depth--
				if depth == 0 {
					end++
					break
				}
			}
			end++
		}
		s = s[:idx] + " " + s[end:]
	}
}

func preprocessCForSignatures(raw string) string {
	// 1. Splice backslash-newline continuations.
	normalized := strings.ReplaceAll(raw, "\r\n", "\n")
	var spliced strings.Builder
	spliced.Grow(len(normalized))
	for i := 0; i < len(normalized); i++ {
		if normalized[i] == '\\' && i+1 < len(normalized) && normalized[i+1] == '\n' {
			i++
			continue
		}
		spliced.WriteByte(normalized[i])
	}

	// 2. Strip comments and string/character literals.
	noComments := stripCCommentsAndStrings(spliced.String())

	// 3. Remove preprocessor lines (#include, #define, #if, etc.).
	lines := strings.Split(noComments, "\n")
	var out strings.Builder
	out.Grow(len(noComments))
	for _, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			out.WriteByte('\n')
			continue
		}
		out.WriteString(line)
		out.WriteByte('\n')
	}
	return stripAttributeAnnotations(out.String())
}

// extractExportedCFunctionSigs parses non-static top-level C function definitions
// from source files and returns map[fnName]normalizedSignature, handling arbitrary
// return/parameter types (structs, typedefs, pointers, const, arrays, fn pointers).
func extractExportedCFunctionSigs(contents []string) map[string]string {
	funcs := make(map[string]string)

	for _, raw := range contents {
		src := preprocessCForSignatures(raw)
		braceDepth := 0
		declStart := 0
		n := len(src)

		for i := range n {
			ch := src[i]
			switch ch {
			case ';':
				if braceDepth == 0 {
					declStart = i + 1
				}
			case '{':
				if braceDepth == 0 {
					header := strings.TrimSpace(src[declStart:i])
					if fnName, sig, ok := parseFunctionDefinitionHeader(header); ok {
						funcs[fnName] = sig
					}
				}
				braceDepth++
			case '}':
				if braceDepth > 0 {
					braceDepth--
				}
				if braceDepth == 0 {
					declStart = i + 1
				}
			}
		}
	}
	return funcs
}

func parseFunctionDefinitionHeader(header string) (fnName, canonicalSig string, ok bool) {
	if header == "" || strings.Contains(header, "=") {
		return "", "", false
	}
	// Locate the trailing balanced (...) parameter list at the end of header.
	trimmed := strings.TrimSpace(header)
	if !strings.HasSuffix(trimmed, ")") {
		return "", "", false
	}
	depth := 0
	openParen := -1
	for i := len(trimmed) - 1; i >= 0; i-- {
		switch trimmed[i] {
		case ')':
			depth++
		case '(':
			depth--
			if depth == 0 {
				openParen = i
				i = -1
			}
		}
	}
	if openParen <= 0 {
		return "", "", false
	}

	prefix := strings.TrimSpace(trimmed[:openParen])
	paramRaw := strings.TrimSpace(trimmed[openParen+1 : len(trimmed)-1])

	tokens := tokenizeCTypeExpr(prefix)
	if len(tokens) < 2 {
		return "", "", false
	}

	// Exclude static (TU-private) and typedef declarations; strip extern/inline/_Noreturn.
	filtered := make([]string, 0, len(tokens))
	for _, tok := range tokens {
		switch tok {
		case "static", "typedef":
			return "", "", false
		case "extern", "inline", "__inline", "__inline__", "_Noreturn", "__noreturn__":
			continue
		case "__restrict", "__restrict__":
			filtered = append(filtered, "restrict")
		default:
			filtered = append(filtered, tok)
		}
	}
	if len(filtered) < 2 {
		return "", "", false
	}

	nameCandidate := filtered[len(filtered)-1]
	if !isValidCSymbol(nameCandidate) || cControlKeywords[nameCandidate] {
		return "", "", false
	}
	retTokens := filtered[:len(filtered)-1]
	retNorm := formatNormalizedCTokens(retTokens)
	if retNorm == "" {
		return "", "", false
	}

	paramsNorm := normalizeCParamList(paramRaw)
	return nameCandidate, retNorm + "(" + paramsNorm + ")", true
}

func tokenizeCTypeExpr(s string) []string {
	var tokens []string
	i := 0
	for i < len(s) {
		c := s[i]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			i++
			continue
		}
		if c == '*' || c == '(' || c == ')' || c == ',' {
			tokens = append(tokens, string(c))
			i++
			continue
		}
		if c == '[' {
			start := i
			depth := 0
			for i < len(s) {
				if s[i] == '[' {
					depth++
				} else if s[i] == ']' {
					depth--
					if depth == 0 {
						i++
						break
					}
				}
				i++
			}
			tokens = append(tokens, strings.TrimSpace(s[start:i]))
			continue
		}
		if c == '.' && i+2 < len(s) && s[i+1] == '.' && s[i+2] == '.' {
			tokens = append(tokens, "...")
			i += 3
			continue
		}
		start := i
		for i < len(s) {
			ch := s[i]
			if ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' ||
				ch == '*' || ch == '(' || ch == ')' || ch == '[' || ch == ']' || ch == ',' {
				break
			}
			i++
		}
		tokens = append(tokens, s[start:i])
	}
	return tokens
}

func formatNormalizedCTokens(tokens []string) string {
	if len(tokens) == 0 {
		return ""
	}
	var b strings.Builder
	for i, tok := range tokens {
		if i > 0 {
			prev := tokens[i-1]
			needSpace := true
			switch {
			case tok == ")" || tok == "," || strings.HasPrefix(tok, "["):
				needSpace = false
			case prev == "(" || prev == "*":
				if tok == "*" {
					needSpace = false
				}
			}
			if needSpace {
				b.WriteByte(' ')
			}
		}
		b.WriteString(tok)
	}
	return b.String()
}

func splitTopLevelParams(paramList string) []string {
	trimmed := strings.TrimSpace(paramList)
	if trimmed == "" {
		return nil
	}
	var parts []string
	depth := 0
	start := 0
	for i := range len(trimmed) {
		switch trimmed[i] {
		case '(', '[':
			depth++
		case ')', ']':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				parts = append(parts, strings.TrimSpace(trimmed[start:i]))
				start = i + 1
			}
		}
	}
	parts = append(parts, strings.TrimSpace(trimmed[start:]))
	return parts
}

func normalizeCParamList(paramRaw string) string {
	parts := splitTopLevelParams(paramRaw)
	if len(parts) == 0 {
		return "void"
	}
	if len(parts) == 1 && strings.TrimSpace(parts[0]) == "void" {
		return "void"
	}
	norm := make([]string, 0, len(parts))
	for _, p := range parts {
		norm = append(norm, normalizeSingleCParam(p))
	}
	return strings.Join(norm, ", ")
}

func normalizeSingleCParam(param string) string {
	trimmed := strings.TrimSpace(param)
	if trimmed == "" || trimmed == "..." || trimmed == "void" {
		return trimmed
	}

	tokens := tokenizeCTypeExpr(trimmed)
	for i, t := range tokens {
		if t == "__restrict" || t == "__restrict__" {
			tokens[i] = "restrict"
		}
	}

	// Function pointer parameter: e.g. void (*cb)(uint32_t a, uint32_t b)
	if slices.Contains(tokens, "(") {
		return normalizeFunctionPointerParam(tokens)
	}

	// Array parameter decay: e.g. const uint8_t key[32] -> const uint8_t *
	hasArraySuffix := false
	for len(tokens) > 0 && strings.HasPrefix(tokens[len(tokens)-1], "[") {
		hasArraySuffix = true
		tokens = tokens[:len(tokens)-1]
	}

	if len(tokens) > 0 {
		last := tokens[len(tokens)-1]
		if isParamIdentifier(tokens[:len(tokens)-1], last) {
			tokens = tokens[:len(tokens)-1]
		}
	}
	if hasArraySuffix {
		tokens = append(tokens, "*")
	}
	return formatNormalizedCTokens(tokens)
}

func isParamIdentifier(preceding []string, last string) bool {
	if !archSymbolIdentRegex.MatchString(last) || cTypeSpecifierKeywords[last] || cQualifierOrTagKeywords[last] {
		return false
	}
	// There must be at least one base type token or pointer '*' before a parameter identifier.
	for _, tok := range preceding {
		if tok == "*" || (!cQualifierOrTagKeywords[tok]) {
			return true
		}
	}
	return false
}

func normalizeFunctionPointerParam(tokens []string) string {
	// Strip identifier inside (*ident) -> (*) and normalize inner parameter list.
	var out []string
	i := 0
	for i < len(tokens) {
		if tokens[i] == "(" && i+3 < len(tokens) && tokens[i+1] == "*" && tokens[i+3] == ")" &&
			archSymbolIdentRegex.MatchString(tokens[i+2]) && !cQualifierOrTagKeywords[tokens[i+2]] {
			out = append(out, "(", "*", ")")
			i += 4
			continue
		}
		if tokens[i] == "(" {
			depth := 1
			j := i + 1
			for j < len(tokens) && depth > 0 {
				switch tokens[j] {
				case "(":
					depth++
				case ")":
					depth--
				}
				j++
			}
			inner := formatNormalizedCTokens(tokens[i+1 : j-1])
			out = append(out, "("+normalizeCParamList(inner)+")")
			i = j
			continue
		}
		out = append(out, tokens[i])
		i++
	}
	return formatNormalizedCTokens(out)
}
