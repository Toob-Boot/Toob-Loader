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
	lintAllowRe = regexp.MustCompile(`lint-allow:\s*\S+`)
	arrayInitRe = regexp.MustCompile(`(0[xX][0-9a-fA-F]{1,2}[uUlL]*\s*,\s*){2,}`)
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
	kind    cTokenKind
	text    string
	line    int
	col     int
	preproc bool
	fnMacro bool
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
					i += 2 // consume escape backslash AND escaped char (handles '\\', '\"', '\'')
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

func computeLineSuppression(physLines []string) ([]bool, int) {
	suppressed := make([]bool, len(physLines)+1) // 1-based line index
	count := 0
	for idx, line := range physLines {
		lineNum := idx + 1
		if lintAllowRe.MatchString(line) || (idx > 0 && lintAllowRe.MatchString(physLines[idx-1])) {
			suppressed[lineNum] = true
			count++
		}
	}
	return suppressed, count
}

func scanFileLexer(path string, deep bool) ([]LintViolation, int, int, error) {
	// #nosec G304 -- caller validates and walks user-configured source paths intentionally.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, 0, err
	}

	stream, physLines := buildLogicalStream(data)
	suppressedLine, suppressedCount := computeLineSuppression(physLines)
	tokens := tokenizeC(stream)

	var violations []LintViolation
	parenDepth := 0
	exemptCallDepth := -1

	for idx, tok := range tokens {
		if tok.kind == tokNewline {
			parenDepth = 0
			exemptCallDepth = -1
			continue
		}

		// Track _Static_assert(...) / static_assert(...) / sizeof(...) scopes in standard mode.
		if !deep && tok.kind == tokIdent && (tok.text == "_Static_assert" || tok.text == "static_assert" || tok.text == "sizeof") {
			if idx+1 < len(tokens) && tokens[idx+1].kind == tokPunct && tokens[idx+1].text == "(" && exemptCallDepth < 0 {
				exemptCallDepth = parenDepth
			}
		}
		if tok.kind == tokPunct {
			switch tok.text {
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
		// - Standard mode skips all # directives.
		// - Deep mode skips object-like #define CONST 0x... (named constants) and #include/#if,
		//   but inspects function-like #define FN(x) ... bodies where executable magic numbers hide!
		if tok.preproc && (!deep || !tok.fnMacro) {
			continue
		}

		if tok.line >= 1 && tok.line < len(suppressedLine) && suppressedLine[tok.line] {
			continue
		}

		if !deep && exemptCallDepth >= 0 {
			continue
		}

		physContext := ""
		if tok.line >= 1 && tok.line <= len(physLines) {
			physContext = physLines[tok.line-1]
		}

		if !deep && arrayInitRe.MatchString(physContext) {
			continue
		}

		if isAllowedNumericLiteral(tok.text, deep) {
			continue
		}

		// Shift-count idiom (e.g. 1U << 30 or val >> 16) is allowed in standard mode, flagged in deep mode.
		if !deep && idx > 0 && tokens[idx-1].kind == tokPunct && (tokens[idx-1].text == "<<" || tokens[idx-1].text == ">>") {
			continue
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

	suppressed, _ := computeLineSuppression(physLines)
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
