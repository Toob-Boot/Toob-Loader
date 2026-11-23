package literallint

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	lintAllowTagRe = regexp.MustCompile(`lint-allow:(.*)$`)
	lintWordRe     = regexp.MustCompile(`[A-Za-z][A-Za-z0-9_/-]{1,}`)
)

var standardAllowedDecimals = map[string]bool{
	"0":    true,
	"1":    true,
	"2":    true,
	"3":    true,
	"4":    true,
	"8":    true,
	"16":   true,
	"32":   true,
	"1000": true,
}

var standardAllowedHex = map[string]bool{
	"0x0":        true,
	"0x00":       true,
	"0x1":        true,
	"0x01":       true,
	"0x3":        true,
	"0x03":       true,
	"0xF":        true,
	"0x0F":       true,
	"0xFF":       true,
	"0xFFF":      true,
	"0xFFFF":     true,
	"0xFFFFFFFF": true,
}

var deepAllowedDecimals = map[string]bool{
	"0": true,
	"1": true,
}

var deepAllowedHex = map[string]bool{
	"0x0":  true,
	"0x00": true,
	"0x1":  true,
	"0x01": true,
}

// RunLint executes the literal-ban lint scan on configured paths, failing fast
// on missing target paths, directory walk errors, or unreadable source files.
func RunLint(cfg LintConfig) (*LintReport, error) {
	if len(cfg.Paths) == 0 {
		return nil, errors.New("literallint: no scan paths configured")
	}
	if len(cfg.Extensions) == 0 {
		cfg.Extensions = []string{".c", ".h"}
	}

	mode := "lexer"
	hasClangQuery := false
	if cfg.DeepMode {
		if _, err := exec.LookPath("clang-query"); err == nil {
			hasClangQuery = true
			mode = "deep (strict lexer + clang-query)"
		} else {
			mode = "deep (strict lexer)"
		}
	}

	report := &LintReport{
		Timestamp:  time.Now().UTC(),
		Paths:      cfg.Paths,
		Mode:       mode,
		Passed:     true,
		Violations: make([]LintViolation, 0),
	}

	for _, root := range cfg.Paths {
		if strings.TrimSpace(root) == "" {
			return nil, errors.New("literallint: empty scan path")
		}
		if _, err := os.Stat(root); err != nil {
			return nil, fmt.Errorf("cannot access scan path %s: %w", root, err)
		}

		err := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.IsDir() {
				name := d.Name()
				if path != root && (name == ".git" || name == "build" || name == "builds" || name == ".toob") {
					return filepath.SkipDir
				}
				return nil
			}

			ext := strings.ToLower(filepath.Ext(path))
			matchedExt := false
			for _, targetExt := range cfg.Extensions {
				if strings.EqualFold(ext, targetExt) {
					matchedExt = true
					break
				}
			}
			if !matchedExt {
				return nil
			}

			violations, lines, suppressed, scanErr := scanFileLexer(path, cfg.DeepMode)
			if scanErr != nil {
				return fmt.Errorf("failed scanning %s: %w", path, scanErr)
			}
			report.Stats.FilesScanned++
			report.Stats.LinesScanned += lines
			report.Stats.Suppressed += suppressed

			if hasClangQuery {
				rawLines, readErr := readPhysicalLines(path)
				if readErr != nil {
					return readErr
				}
				cqViolations := scanFileClangQuery(path, cfg.IncludePaths, rawLines, violations)
				violations = append(violations, cqViolations...)
			}

			report.Violations = append(report.Violations, violations...)
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("error walking path %s: %w", root, err)
		}
	}

	report.Stats.Violations = len(report.Violations)
	if report.Stats.Violations > 0 {
		report.Passed = false
	}

	return report, nil
}

type posChar struct {
	ch   byte
	line int
	col  int
}

// buildLogicalStream performs C17/C23 Translation Phase 2 backslash-newline
// splicing while retaining every logical character's exact 1-based physical
// line and column in the source file.
func buildLogicalStream(data []byte) ([]posChar, []string) {
	normalized := strings.ReplaceAll(string(data), "\r\n", "\n")
	physLines := strings.Split(normalized, "\n")

	out := make([]posChar, 0, len(normalized))
	line := 1
	col := 1
	for i := 0; i < len(normalized); i++ {
		c := normalized[i]
		if c == '\\' && i+1 < len(normalized) && normalized[i+1] == '\n' {
			i++
			line++
			col = 1
			continue
		}
		out = append(out, posChar{ch: c, line: line, col: col})
		if c == '\n' {
			line++
			col = 1
		} else {
			col++
		}
	}
	return out, physLines
}

type cTokenKind int

const (
	tokIdent cTokenKind = iota
	tokNumber
	tokPunct
	tokNewline
)

type cToken struct {
	kind      cTokenKind
	text      string
	line      int
	col       int
	preproc   bool
	fnMacro   bool
	stmtMacro bool
}

func isIdentStart(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || b == '_'
}

func isIdentContinue(b byte) bool {
	return isIdentStart(b) || (b >= '0' && b <= '9')
}

func isDigit(b byte) bool {
	return b >= '0' && b <= '9'
}

func isHexDigit(b byte) bool {
	return isDigit(b) || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

func isStringOrCharPrefix(s []posChar, idx int) (int, byte) {
	rem := len(s) - idx
	if rem >= 3 && s[idx].ch == 'u' && s[idx+1].ch == '8' && (s[idx+2].ch == '"' || s[idx+2].ch == '\'') {
		return 2, s[idx+2].ch
	}
	if rem >= 2 && (s[idx].ch == 'L' || s[idx].ch == 'u' || s[idx].ch == 'U') && (s[idx+1].ch == '"' || s[idx+1].ch == '\'') {
		return 1, s[idx+1].ch
	}
	if rem >= 1 && (s[idx].ch == '"' || s[idx].ch == '\'') {
		return 0, s[idx].ch
	}
	return -1, 0
}

// tokenizeC lexes a Phase-2 logical stream into C17/C23 tokens, accurately
// consuming comments, escaped string/char literals, C23 digit separators,
// hex floats, multi-character integer suffixes, and preprocessor directives.
func tokenizeC(stream []posChar) []cToken {
	var tokens []cToken
	n := len(stream)
	atLineStart := true
	inPreproc := false
	inFnMacro := false

	i := 0
	for i < n {
		c := stream[i].ch

		if c == '\n' {
			tokens = append(tokens, cToken{kind: tokNewline, text: "\n", line: stream[i].line, col: stream[i].col})
			atLineStart = true
			inPreproc = false
			inFnMacro = false
			i++
			continue
		}

		if c == ' ' || c == '\t' || c == '\v' || c == '\f' || c == '\r' {
			i++
			continue
		}

		// Line comment //
		if c == '/' && i+1 < n && stream[i+1].ch == '/' {
			i += 2
			for i < n && stream[i].ch != '\n' {
				i++
			}
			continue
		}

		// Block comment /* ... */
		if c == '/' && i+1 < n && stream[i+1].ch == '*' {
			i += 2
			for i < n {
				if stream[i].ch == '*' && i+1 < n && stream[i+1].ch == '/' {
					i += 2
					break
				}
				i++
			}
			continue
		}

		// Preprocessor directive start (# at start of logical line)
		if atLineStart && c == '#' {
			atLineStart = false
			inPreproc = true
			i++
			// Check if this is a function-like #define NAME(args...) vs object-like #define NAME val.
			for i < n && (stream[i].ch == ' ' || stream[i].ch == '\t') {
				i++
			}
			kwStart := i
			for i < n && isIdentContinue(stream[i].ch) {
				i++
			}
			var kwBuf strings.Builder
			for k := kwStart; k < i; k++ {
				kwBuf.WriteByte(stream[k].ch)
			}
			if kwBuf.String() == "define" {
				for i < n && (stream[i].ch == ' ' || stream[i].ch == '\t') {
					i++
				}
				nameStart := i
				for i < n && isIdentContinue(stream[i].ch) {
					i++
				}
				// In C, a function-like macro has '(' immediately adjacent to the macro identifier with no whitespace!
				if i > nameStart && i < n && stream[i].ch == '(' {
					inFnMacro = true
				}
			}
			continue
		}
		atLineStart = false

		// String or character literal (including L, u, U, u8 prefixes)
		if prefixLen, quote := isStringOrCharPrefix(stream, i); prefixLen >= 0 {
			i += prefixLen + 1 // consume prefix and opening quote
			for i < n {
				cur := stream[i].ch
				if cur == '\\' {
					if i+1 < n && stream[i+1].ch != '\n' {
						i += 2 // consume escape backslash AND escaped char on same logical line
					} else {
						i++
					}
					continue
				}
				if cur == quote || cur == '\n' {
					if cur == quote {
						i++
					}
					break
				}
				i++
			}
			continue
		}

		// C17/C23 preprocessing number (integer, binary, octal, hex, decimal float, hex float, C23 ' separators)
		if isDigit(c) || (c == '.' && i+1 < n && isDigit(stream[i+1].ch)) {
			startLine, startCol := stream[i].line, stream[i].col
			var lit strings.Builder
			for i < n {
				ch := stream[i].ch
				if isIdentContinue(ch) || ch == '.' {
					lit.WriteByte(ch)
					i++
					continue
				}
				// C23 digit separator: '\'' strictly between valid hex/digit characters (not starting a char literal!)
				if ch == '\'' && i+1 < n && isHexDigit(stream[i+1].ch) {
					lit.WriteByte(ch)
					i++
					continue
				}
				// Exponent sign in float/hex-float: e+, e-, E+, E-, p+, p-, P+, P-
				if (ch == '+' || ch == '-') && lit.Len() > 0 {
					prev := lit.String()[lit.Len()-1]
					if prev == 'e' || prev == 'E' || prev == 'p' || prev == 'P' {
						lit.WriteByte(ch)
						i++
						continue
					}
				}
				break
			}
			tokens = append(tokens, cToken{
				kind:    tokNumber,
				text:    lit.String(),
				line:    startLine,
				col:     startCol,
				preproc: inPreproc,
				fnMacro: inFnMacro,
			})
			continue
		}

		// Identifier
		if isIdentStart(c) {
			startLine, startCol := stream[i].line, stream[i].col
			var id strings.Builder
			for i < n && isIdentContinue(stream[i].ch) {
				id.WriteByte(stream[i].ch)
				i++
			}
			tokens = append(tokens, cToken{
				kind:    tokIdent,
				text:    id.String(),
				line:    startLine,
				col:     startCol,
				preproc: inPreproc,
				fnMacro: inFnMacro,
			})
			continue
		}

		// Multi-char shift operators << and >>
		if (c == '<' || c == '>') && i+1 < n && stream[i+1].ch == c {
			op := "<<"
			if c == '>' {
				op = ">>"
			}
			tokens = append(tokens, cToken{
				kind:    tokPunct,
				text:    op,
				line:    stream[i].line,
				col:     stream[i].col,
				preproc: inPreproc,
				fnMacro: inFnMacro,
			})
			i += 2
			continue
		}

		tokens = append(tokens, cToken{
			kind:    tokPunct,
			text:    string(c),
			line:    stream[i].line,
			col:     stream[i].col,
			preproc: inPreproc,
			fnMacro: inFnMacro,
		})
		i++
	}
	return tokens
}

// stripValidCIntegerSuffix strips valid C17/C23 integer suffixes (U, L, LL, UL,
// LU, ULL, LLU, Z, UZ, ZU in valid case forms) and returns (coreDigits, ok).
// Floating-point literals (containing '.', 'p', 'P', or decimal 'e'/'E') return ok=false.
func stripValidCIntegerSuffix(rawNoSep string) (string, bool) {
	if strings.ContainsRune(rawNoSep, '.') || strings.ContainsAny(rawNoSep, "pP") {
		return "", false
	}
	isHex := strings.HasPrefix(rawNoSep, "0x") || strings.HasPrefix(rawNoSep, "0X")
	if !isHex && strings.ContainsAny(rawNoSep, "eEfF") {
		return "", false
	}

	end := len(rawNoSep)
	for end > 0 {
		ch := rawNoSep[end-1]
		if ch == 'u' || ch == 'U' || ch == 'l' || ch == 'L' || ch == 'z' || ch == 'Z' {
			end--
			continue
		}
		break
	}
	core := rawNoSep[:end]
	suffix := rawNoSep[end:]
	if core == "" {
		return "", false
	}
	if !isValidIntegerSuffix(suffix) {
		return "", false
	}
	return core, true
}

func isValidIntegerSuffix(sfx string) bool {
	if sfx == "" {
		return true
	}
	// Reject mixed-case "lL" or "Ll" per MISRA/CERT C.
	if strings.Contains(sfx, "lL") || strings.Contains(sfx, "Ll") {
		return false
	}
	switch strings.ToUpper(sfx) {
	case "U", "L", "LL", "UL", "LU", "ULL", "LLU", "Z", "UZ", "ZU":
		return true
	default:
		return false
	}
}

func isAllowedNumericLiteral(raw string, deep bool) bool {
	clean := strings.ReplaceAll(raw, "'", "")
	core, ok := stripValidCIntegerSuffix(clean)
	if !ok {
		return false
	}

	if strings.HasPrefix(core, "0x") || strings.HasPrefix(core, "0X") {
		hexDigits := strings.ToUpper(core[2:])
		if hexDigits == "" {
			return false
		}
		for i := range len(hexDigits) {
			if !isHexDigit(hexDigits[i]) {
				return false
			}
		}
		canon := "0x" + hexDigits
		if deep {
			return deepAllowedHex[canon]
		}
		return standardAllowedHex[canon]
	}

	if strings.HasPrefix(core, "0b") || strings.HasPrefix(core, "0B") {
		bits := core[2:]
		return bits == "0" || bits == "1"
	}

	for i := range len(core) {
		if !isDigit(core[i]) {
			return false
		}
	}
	if deep {
		return deepAllowedDecimals[core]
	}
	return standardAllowedDecimals[core]
}

func isStmtMacroKeyword(id string) bool {
	switch id {
	case "do", "while", "for", "switch", "return", "goto", "if":
		return true
	default:
		return false
	}
}

func markStatementMacros(tokens []cToken) {
	lineStart := 0
	for i := 0; i <= len(tokens); i++ {
		if i < len(tokens) && tokens[i].kind != tokNewline {
			continue
		}
		if lineStart < i && tokens[lineStart].preproc {
			isStmt := false
			for k := lineStart; k < i; k++ {
				t := tokens[k]
				if (t.kind == tokPunct && (t.text == "{" || t.text == "}" || t.text == ";")) ||
					(t.kind == tokIdent && isStmtMacroKeyword(t.text)) {
					isStmt = true
					break
				}
			}
			if isStmt {
				for k := lineStart; k < i; k++ {
					tokens[k].stmtMacro = true
				}
			}
		}
		lineStart = i + 1
	}
}

func isValidLintAllowComment(commentBody string) bool {
	m := lintAllowTagRe.FindStringSubmatch(commentBody)
	if len(m) < 2 {
		return false
	}
	reason := strings.TrimSpace(m[1])
	return len(reason) >= 4 && lintWordRe.MatchString(reason)
}

// computeCommentLineSuppression extracts genuine C comments containing a valid
// `lint-allow: <reason>` tag (ignoring string/char literals!) and distinguishes
// standalone comment lines (suppressing the next non-empty physical line) from
// inline trailing comments (suppressing only their own line).
func computeCommentLineSuppression(stream []posChar, physLines []string, tokens []cToken) ([]bool, int) {
	hasCodeOnLine := make([]bool, len(physLines)+1)
	for _, t := range tokens {
		if t.kind != tokNewline && t.line >= 1 && t.line < len(hasCodeOnLine) {
			hasCodeOnLine[t.line] = true
		}
	}

	commentAllowLines := make([]bool, len(physLines)+1)
	n := len(stream)
	for i := 0; i < n; {
		c := stream[i].ch
		if c == '/' && i+1 < n && stream[i+1].ch == '/' {
			ln := stream[i].line
			i += 2
			var sb strings.Builder
			for i < n && stream[i].ch != '\n' {
				sb.WriteByte(stream[i].ch)
				i++
			}
			if ln >= 1 && ln < len(commentAllowLines) && isValidLintAllowComment(sb.String()) {
				commentAllowLines[ln] = true
			}
			continue
		}
		if c == '/' && i+1 < n && stream[i+1].ch == '*' {
			startLine := stream[i].line
			i += 2
			var sb strings.Builder
			for i < n {
				if stream[i].ch == '*' && i+1 < n && stream[i+1].ch == '/' {
					i += 2
					break
				}
				sb.WriteByte(stream[i].ch)
				i++
			}
			if startLine >= 1 && startLine < len(commentAllowLines) && isValidLintAllowComment(sb.String()) {
				commentAllowLines[startLine] = true
			}
			continue
		}
		if prefixLen, quote := isStringOrCharPrefix(stream, i); prefixLen >= 0 {
			i += prefixLen + 1
			for i < n {
				cur := stream[i].ch
				if cur == '\\' {
					if i+1 < n && stream[i+1].ch != '\n' {
						i += 2
					} else {
						i++
					}
					continue
				}
				if cur == quote || cur == '\n' {
					if cur == quote {
						i++
					}
					break
				}
				i++
			}
			continue
		}
		i++
	}

	suppressed := make([]bool, len(physLines)+1)
	count := 0
	mark := func(lineNum int) {
		if lineNum >= 1 && lineNum < len(suppressed) && !suppressed[lineNum] {
			suppressed[lineNum] = true
			count++
		}
	}
	for ln := 1; ln <= len(physLines); ln++ {
		if !commentAllowLines[ln] {
			continue
		}
		mark(ln)
		if !hasCodeOnLine[ln] && ln+1 <= len(physLines) && strings.TrimSpace(physLines[ln]) != "" {
			mark(ln + 1)
		}
	}
	return suppressed, count
}

func isByteHexLiteral(raw string) bool {
	clean := strings.ReplaceAll(raw, "'", "")
	core, ok := stripValidCIntegerSuffix(clean)
	if !ok {
		return false
	}
	if !strings.HasPrefix(core, "0x") && !strings.HasPrefix(core, "0X") {
		return false
	}
	digits := core[2:]
	if len(digits) == 0 || len(digits) > 2 {
		return false
	}
	for i := range len(digits) {
		if !isHexDigit(digits[i]) {
			return false
		}
	}
	return true
}

// computeByteArrayInitTokens marks byte-sized hex literal tokens (0x00..0xFF)
// strictly inside `{ 0xAA, 0xBB, ... }` initializer lists (>= 2 byte elements,
// no wider magic constants mixed inside the same brace block).
func computeByteArrayInitTokens(tokens []cToken) []bool {
	exempt := make([]bool, len(tokens))
	type braceState struct {
		elemTokens []int
		byteCount  int
		invalid    bool
	}
	var stack []braceState
	for i, tok := range tokens {
		if tok.kind == tokNewline {
			continue
		}
		if tok.kind == tokPunct && tok.text == "{" {
			stack = append(stack, braceState{})
			continue
		}
		if len(stack) == 0 {
			continue
		}
		top := &stack[len(stack)-1]
		if tok.kind == tokPunct && tok.text == "}" {
			if !top.invalid && top.byteCount >= 2 {
				for _, idx := range top.elemTokens {
					exempt[idx] = true
				}
			}
			stack = stack[:len(stack)-1]
			continue
		}
		if tok.kind == tokPunct && tok.text == "," {
			continue
		}
		if tok.kind == tokNumber && isByteHexLiteral(tok.text) {
			top.elemTokens = append(top.elemTokens, i)
			top.byteCount++
			continue
		}
		top.invalid = true
	}
	return exempt
}

func isValidShiftCountLiteral(raw string) bool {
	clean := strings.ReplaceAll(raw, "'", "")
	core, ok := stripValidCIntegerSuffix(clean)
	if !ok {
		return false
	}
	val, parseErr := strconv.ParseUint(core, 0, 64)
	return parseErr == nil && val <= 63
}

func scanFileLexer(path string, deep bool) ([]LintViolation, int, int, error) {
	// #nosec G304 -- caller validates and walks user-configured source paths intentionally.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, 0, err
	}

	stream, physLines := buildLogicalStream(data)
	tokens := tokenizeC(stream)
	markStatementMacros(tokens)
	suppressedLine, suppressedCount := computeCommentLineSuppression(stream, physLines, tokens)
	byteArrayInit := computeByteArrayInitTokens(tokens)

	var violations []LintViolation
	parenDepth := 0
	braceDepth := 0
	exemptCallDepth := -1

	for idx, tok := range tokens {
		if tok.kind == tokNewline {
			parenDepth = 0
			exemptCallDepth = -1
			continue
		}

		// Track _Static_assert(...) / static_assert(...) / sizeof(...) scopes in standard mode,
		// and function brace nesting depth across lines so #define inside functions is never hidden.
		if !deep && !tok.preproc && tok.kind == tokIdent && (tok.text == "_Static_assert" || tok.text == "static_assert" || tok.text == "sizeof") {
			if idx+1 < len(tokens) && tokens[idx+1].kind == tokPunct && tokens[idx+1].text == "(" && exemptCallDepth < 0 {
				exemptCallDepth = parenDepth
			}
		}
		if tok.kind == tokPunct {
			switch tok.text {
			case "{":
				if !tok.preproc {
					braceDepth++
				}
			case "}":
				if !tok.preproc && braceDepth > 0 {
					braceDepth--
				}
			case "(":
				parenDepth++
			case ")":
				if parenDepth > 0 {
					parenDepth--
				}
				if exemptCallDepth >= 0 && parenDepth <= exemptCallDepth {
					exemptCallDepth = -1
				}
			}
		}

		if tok.kind != tokNumber {
			continue
		}

		// Preprocessor handling:
		// - Statement/control-flow macros and #define inside function bodies are NEVER exempt.
		// - Standard mode skips simple file-scope #define constants and #if/#include.
		// - Deep mode also inspects function-like #define FN(x) ... macro bodies.
		if tok.preproc && !tok.stmtMacro && braceDepth == 0 && (!deep || !tok.fnMacro) {
			continue
		}

		if tok.line >= 1 && tok.line < len(suppressedLine) && suppressedLine[tok.line] {
			continue
		}

		if !deep && exemptCallDepth >= 0 {
			continue
		}

		if !deep && byteArrayInit[idx] {
			continue
		}

		if isAllowedNumericLiteral(tok.text, deep) {
			continue
		}

		// Bounded bit-shift counts (0..63) are permitted in standard mode, flagged in deep mode.
		if !deep && idx > 0 && tokens[idx-1].kind == tokPunct &&
			(tokens[idx-1].text == "<<" || tokens[idx-1].text == ">>") &&
			isValidShiftCountLiteral(tok.text) {
			continue
		}

		physContext := ""
		if tok.line >= 1 && tok.line <= len(physLines) {
			physContext = physLines[tok.line-1]
		}

		violations = append(violations, LintViolation{
			File:    path,
			Line:    tok.line,
			Column:  tok.col,
			Literal: tok.text,
			Context: strings.TrimSpace(physContext),
			Source:  "lexer",
		})
	}

	return violations, len(physLines), suppressedCount, nil
}

func readPhysicalLines(path string) ([]string, error) {
	// #nosec G304 -- caller validates and walks user-configured source paths intentionally.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n"), nil
}

func scanFileClangQuery(path string, includePaths, physLines []string, existing []LintViolation) []LintViolation {
	query := "match integerLiteral(unless(anyOf(equals(0), equals(1), isExpansionInSystemHeader())))"
	args := make([]string, 0, 4+len(includePaths))
	args = append(args, "-c", query, path, "--")
	for _, inc := range includePaths {
		args = append(args, "-I"+inc)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// #nosec G204 -- fixed clang-query binary with explicit non-shell argument vector.
	cmd := exec.CommandContext(ctx, "clang-query", args...)
	out, err := cmd.Output()
	if err != nil {
		return nil
	}

	stream, _ := buildLogicalStream([]byte(strings.Join(physLines, "\n")))
	tokens := tokenizeC(stream)
	suppressed, _ := computeCommentLineSuppression(stream, physLines, tokens)
	seen := make(map[[2]int]bool, len(existing))
	for _, v := range existing {
		seen[[2]int{v.Line, v.Column}] = true
	}

	var violations []LintViolation
	scanner := bufio.NewScanner(bytes.NewReader(out))
	fileLineRe := regexp.MustCompile(regexp.QuoteMeta(path) + `:(\d+):(\d+)`)

	for scanner.Scan() {
		line := scanner.Text()
		matches := fileLineRe.FindStringSubmatch(line)
		if len(matches) != 3 {
			continue
		}
		lineNum, _ := strconv.Atoi(matches[1])
		colNum, _ := strconv.Atoi(matches[2])
		if lineNum >= 1 && lineNum < len(suppressed) && suppressed[lineNum] {
			continue
		}
		key := [2]int{lineNum, colNum}
		if seen[key] {
			continue
		}
		seen[key] = true
		ctxLine := strings.TrimSpace(line)
		if lineNum >= 1 && lineNum <= len(physLines) {
			ctxLine = strings.TrimSpace(physLines[lineNum-1])
		}
		violations = append(violations, LintViolation{
			File:    path,
			Line:    lineNum,
			Column:  colNum,
			Literal: "AST integerLiteral",
			Context: ctxLine,
			Source:  "clang-query",
		})
	}

	return violations
}
