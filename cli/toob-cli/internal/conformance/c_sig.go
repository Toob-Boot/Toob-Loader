package conformance

import (
	"fmt"
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

type rawCTokKind int

const (
	rawTokIdent rawCTokKind = iota
	rawTokString
	rawTokPunct
	rawTokHash
	rawTokNewline
)

type rawCTok struct {
	kind rawCTokKind
	text string
	line int
}

// tokenizeRawCForAttrScan tokenizes raw C BEFORE attribute stripping, stripping
// comments while retaining preprocessor lines, __attribute__ lists, asm strings,
// and exact 1-based line numbers so forbidden attributes/sections cannot hide.
func tokenizeRawCForAttrScan(raw string) []rawCTok {
	normalized := strings.ReplaceAll(raw, "\r\n", "\n")
	type lc struct {
		ch   byte
		line int
	}
	stream := make([]lc, 0, len(normalized))
	line := 1
	for i := 0; i < len(normalized); i++ {
		c := normalized[i]
		if c == '\\' && i+1 < len(normalized) && normalized[i+1] == '\n' {
			i++
			line++
			continue
		}
		stream = append(stream, lc{ch: c, line: line})
		if c == '\n' {
			line++
		}
	}

	var toks []rawCTok
	n := len(stream)
	atLineStart := true
	for i := 0; i < n; {
		c := stream[i].ch
		ln := stream[i].line
		switch {
		case c == '\n':
			toks = append(toks, rawCTok{kind: rawTokNewline, text: "\n", line: ln})
			atLineStart = true
			i++
		case c == ' ' || c == '\t' || c == '\v' || c == '\f' || c == '\r':
			i++
		case c == '/' && i+1 < n && stream[i+1].ch == '/':
			i += 2
			for i < n && stream[i].ch != '\n' {
				i++
			}
		case c == '/' && i+1 < n && stream[i+1].ch == '*':
			i += 2
			for i < n {
				if stream[i].ch == '*' && i+1 < n && stream[i+1].ch == '/' {
					i += 2
					break
				}
				i++
			}
		case atLineStart && c == '#':
			toks = append(toks, rawCTok{kind: rawTokHash, text: "#", line: ln})
			atLineStart = false
			i++
		case c == '"' || c == '\'':
			atLineStart = false
			quote := c
			i++
			var sb strings.Builder
			for i < n {
				cur := stream[i].ch
				if cur == '\\' && i+1 < n {
					sb.WriteByte(cur)
					sb.WriteByte(stream[i+1].ch)
					i += 2
					continue
				}
				if cur == quote || cur == '\n' {
					if cur == quote {
						i++
					}
					break
				}
				sb.WriteByte(cur)
				i++
			}
			toks = append(toks, rawCTok{kind: rawTokString, text: sb.String(), line: ln})
		case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_':
			atLineStart = false
			var sb strings.Builder
			for i < n {
				ch := stream[i].ch
				if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_' {
					sb.WriteByte(ch)
					i++
					continue
				}
				break
			}
			toks = append(toks, rawCTok{kind: rawTokIdent, text: sb.String(), line: ln})
		default:
			atLineStart = false
			toks = append(toks, rawCTok{kind: rawTokPunct, text: string(c), line: ln})
			i++
		}
	}
	return toks
}

func isForbiddenInitSectionName(sec string) bool {
	lower := strings.ToLower(sec)
	for _, pat := range []string{".init_array", ".preinit_array", ".fini_array", ".ctors", ".dtors"} {
		if strings.Contains(lower, pat) {
			return true
		}
	}
	return false
}

func isOfficialWeakAllowed(toks []rawCTok, weakTokIdx, endDeclSearch int, isIntegration bool) bool {
	// Scan backward to statement/line start for `extern` or protected symbol names,
	// and forward across the declaration for approved symbol names.
	stmtStart := 0
	for k := weakTokIdx - 1; k >= 0; k-- {
		if toks[k].kind == rawTokPunct && (toks[k].text == ";" || toks[k].text == "{" || toks[k].text == "}") {
			stmtStart = k + 1
			break
		}
		if toks[k].kind == rawTokHash {
			stmtStart = k
			break
		}
	}
	// Collect identifiers in this declaration header (before '{' or ';').
	hasExtern := false
	hasBootPrefix := false
	hasApprovedSym := false
	for k := stmtStart; k < len(toks) && k <= endDeclSearch; k++ {
		if toks[k].kind == rawTokPunct && (toks[k].text == ";" || toks[k].text == "{") {
			break
		}
		if toks[k].kind != rawTokIdent {
			continue
		}
		id := toks[k].text
		if id == "extern" {
			hasExtern = true
		}
		if strings.HasPrefix(id, "boot_") {
			hasBootPrefix = true
		}
		switch id {
		case "__stack_chk_guard", "NMI_Handler", "HardFault_Handler", "MemManage_Handler", "BusFault_Handler":
			hasApprovedSym = true
		}
		if isIntegration && (strings.HasPrefix(id, "toob_") || strings.HasPrefix(id, "rtos_") ||
			strings.HasPrefix(id, "TOOB_") && strings.HasSuffix(id, "_WEAK")) {
			hasApprovedSym = true
		}
	}
	if hasBootPrefix {
		return false
	}
	return hasExtern || hasApprovedSym
}

// scanRawCForForbiddenConstructs inspects raw C/H code BEFORE attribute
// stripping to reject constructors, destructors, init/fini arrays, symbol
// aliases, and unauthorized weak linkage (CRIT-72).
func scanRawCForForbiddenConstructs(relPath, raw string, allowOfficialWeak, isIntegration bool) []string {
	toks := tokenizeRawCForAttrScan(raw)
	var issues []string
	inAsmStmt := false

	for i := 0; i < len(toks); i++ {
		tok := toks[i]
		switch tok.kind {
		case rawTokHash:
			if i+1 < len(toks) && toks[i+1].kind == rawTokIdent && toks[i+1].text == "pragma" {
				if i+2 < len(toks) && toks[i+2].kind == rawTokIdent {
					switch toks[i+2].text {
					case "weak", "init", "fini":
						issues = append(issues, fmt.Sprintf("%s:L%d: forbidden '#pragma %s'", relPath, tok.line, toks[i+2].text))
					}
				}
			}
		case rawTokIdent:
			switch tok.text {
			case "asm", "__asm", "__asm__":
				inAsmStmt = true
			case "__weak":
				if !allowOfficialWeak || !isOfficialWeakAllowed(toks, i, min(len(toks)-1, i+24), isIntegration) {
					issues = append(issues, fmt.Sprintf("%s:L%d: forbidden '__weak' symbol qualifier in package", relPath, tok.line))
				}
			case "__attribute__", "__attribute":
				if i+1 >= len(toks) || toks[i+1].kind != rawTokPunct || toks[i+1].text != "(" {
					continue
				}
				depth := 0
				endAttr := i + 1
				for endAttr < len(toks) {
					if toks[endAttr].kind == rawTokPunct {
						if toks[endAttr].text == "(" {
							depth++
						} else if toks[endAttr].text == ")" {
							depth--
							if depth == 0 {
								break
							}
						}
					}
					endAttr++
				}
				for k := i + 2; k < endAttr; k++ {
					if toks[k].kind != rawTokIdent {
						continue
					}
					attr := toks[k].text
					switch attr {
					case "constructor", "__constructor__", "destructor", "__destructor__":
						issues = append(issues, fmt.Sprintf("%s:L%d: forbidden __attribute__((%s))", relPath, toks[k].line, attr))
					case "alias", "__alias__":
						if k+1 < endAttr && toks[k+1].kind == rawTokPunct && toks[k+1].text == "(" {
							issues = append(issues, fmt.Sprintf("%s:L%d: forbidden __attribute__((%s(...)))", relPath, toks[k].line, attr))
						}
					case "section", "__section__":
						if k+2 < endAttr && toks[k+1].kind == rawTokPunct && toks[k+1].text == "(" && toks[k+2].kind == rawTokString {
							if isForbiddenInitSectionName(toks[k+2].text) {
								issues = append(issues, fmt.Sprintf("%s:L%d: forbidden ELF init/fini section %q", relPath, toks[k].line, toks[k+2].text))
							}
						}
					case "weak", "__weak__":
						if !allowOfficialWeak || !isOfficialWeakAllowed(toks, i, min(len(toks)-1, endAttr+24), isIntegration) {
							issues = append(issues, fmt.Sprintf("%s:L%d: forbidden __attribute__((%s)) in package", relPath, toks[k].line, attr))
						}
					}
				}
				i = endAttr
			}
		case rawTokString:
			if inAsmStmt && isForbiddenInitSectionName(tok.text) {
				issues = append(issues, fmt.Sprintf("%s:L%d: forbidden init/fini section in asm directive", relPath, tok.line))
			}
		case rawTokPunct:
			if tok.text == ";" {
				inAsmStmt = false
			}
		case rawTokNewline:
		}
	}
	return issues
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
