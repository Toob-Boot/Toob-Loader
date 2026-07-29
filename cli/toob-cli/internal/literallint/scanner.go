package literallint

import (
	"bufio"
	"bytes"
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
	hexLiteralRe = regexp.MustCompile(`\b0x[0-9a-fA-F]+[ULLull]*\b`)
	decLiteralRe = regexp.MustCompile(`\b[0-9]+[ULLull]*\b`)

	lintAllowRe  = regexp.MustCompile(`lint-allow:\s*(.+)`)
	staticAssert = regexp.MustCompile(`_Static_assert\s*\(`)
	sizeofRe     = regexp.MustCompile(`sizeof\s*\(`)
	arrayInitRe  = regexp.MustCompile(`(0x[0-9a-fA-F]{2},\s*){2,}`)
)

// Allowed trivial or idiom literals
var allowedLiterals = map[string]bool{
	"0":           true,
	"1":           true,
	"2":           true,
	"3":           true,
	"4":           true,
	"8":           true,
	"16":          true,
	"32":          true,
	"0U":          true,
	"1U":          true,
	"2U":          true,
	"3U":          true,
	"4U":          true,
	"8U":          true,
	"16U":         true,
	"32U":         true,
	"0u":          true,
	"1u":          true,
	"2u":          true,
	"3u":          true,
	"4u":          true,
	"8u":          true,
	"16u":         true,
	"32u":         true,
	"0ULL":        true,
	"1ULL":        true,
	"0ull":        true,
	"1ull":        true,
	"1000":        true,
	"1000U":       true,
	"1000u":       true,
	"0x0":         true,
	"0x1":         true,
	"0x0U":        true,
	"0x1U":        true,
	"0x3U":        true,
	"0xFU":        true,
	"0xFFU":       true,
	"0xFFFU":      true,
	"0xFFFFU":     true,
	"0xFFFFFFFFU": true,
	"0x3":         true,
	"0xF":         true,
	"0xFF":        true,
	"0xFFF":       true,
	"0xFFFF":      true,
	"0xFFFFFFFF":  true,

}

// RunLint executes the lint scan on configured paths.
func RunLint(cfg LintConfig) (*LintReport, error) {
	if len(cfg.Extensions) == 0 {
		cfg.Extensions = []string{".c", ".h"}
	}

	report := &LintReport{
		Timestamp:  time.Now().UTC(),
		Paths:      cfg.Paths,
		Mode:       "regex",
		Passed:     true,
		Violations: make([]LintViolation, 0),
	}

	// Determine if clang-query should be run for hybrid mode
	hasClangQuery := false
	if cfg.DeepMode {
		if _, err := exec.LookPath("clang-query"); err == nil {
			hasClangQuery = true
			report.Mode = "hybrid (regex + clang-query)"
		} else {
			report.Mode = "regex (clang-query requested but not found in PATH)"
		}
	}

	for _, root := range cfg.Paths {
		err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}

			ext := strings.ToLower(filepath.Ext(path))
			matchedExt := false
			for _, targetExt := range cfg.Extensions {
				if ext == targetExt {
					matchedExt = true
					break
				}
			}
			if !matchedExt {
				return nil
			}

			report.Stats.FilesScanned++
			violations, lines, suppressed := scanFileRegex(path)
			report.Stats.LinesScanned += lines
			report.Stats.Suppressed += suppressed

			if hasClangQuery {
				cqViolations := scanFileClangQuery(path, cfg.IncludePaths)
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

func scanFileRegex(path string) ([]LintViolation, int, int) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, 0
	}

	lines := strings.Split(string(data), "\n")
	var violations []LintViolation
	suppressedCount := 0
	inBlockComment := false

	for i := 0; i < len(lines); i++ {
		line := lines[i]
		trimmed := strings.TrimSpace(line)

		if lintAllowRe.MatchString(line) || (i > 0 && lintAllowRe.MatchString(lines[i-1])) {
			suppressedCount++
		}

		// Clean line: remove comments (both block comments and line comments) and string literals
		cleanLine, newBlockState := stripStringsAndComments(line, inBlockComment)
		inBlockComment = newBlockState

		cleanTrimmed := strings.TrimSpace(cleanLine)

		// Skip empty lines, pure comment lines, or preprocessor directives
		if cleanTrimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// Skip byte array initializers e.g. 0x0e, 0xe1, 0x72...
		if arrayInitRe.MatchString(cleanLine) {
			continue
		}

		// Skip if explicitly whitelisted
		if lintAllowRe.MatchString(line) || (i > 0 && lintAllowRe.MatchString(lines[i-1])) {
			continue
		}

		// Find all hex and decimal literals in non-comment code
		matches := hexLiteralRe.FindAllStringIndex(cleanLine, -1)
		decMatches := decLiteralRe.FindAllStringIndex(cleanLine, -1)

		allMatches := append(matches, decMatches...)

		for _, m := range allMatches {
			lit := cleanLine[m[0]:m[1]]
			upperLit := strings.ToUpper(lit)

			if allowedLiterals[upperLit] || allowedLiterals[lit] {
				continue
			}

			// Check if literal is a shift position argument e.g. (1U << 30) or (val >> 16)
			if isShiftPosition(cleanLine, m[0], m[1]) {
				continue
			}

			// Check if inside _Static_assert or sizeof
			if staticAssert.MatchString(cleanLine) || sizeofRe.MatchString(cleanLine) {
				continue
			}

			violations = append(violations, LintViolation{
				File:    path,
				Line:    i + 1,
				Column:  m[0] + 1,
				Literal: lit,
				Context: strings.TrimSpace(line),
				Source:  "regex",
			})
		}
	}

	return violations, len(lines), suppressedCount
}

func stripStringsAndComments(line string, inBlock bool) (string, bool) {
	var buf bytes.Buffer
	inString := false
	inChar := false

	chars := []rune(line)
	i := 0
	for i < len(chars) {
		if inBlock {
			if i+1 < len(chars) && chars[i] == '*' && chars[i+1] == '/' {
				inBlock = false
				i += 2
				buf.WriteRune(' ')
				buf.WriteRune(' ')
				continue
			}
			buf.WriteRune(' ')
			i++
			continue
		}

		ch := chars[i]

		// Line comment //
		if !inString && !inChar && i+1 < len(chars) && chars[i] == '/' && chars[i+1] == '/' {
			for j := i; j < len(chars); j++ {
				buf.WriteRune(' ')
			}
			break
		}

		// Block comment /*
		if !inString && !inChar && i+1 < len(chars) && chars[i] == '/' && chars[i+1] == '*' {
			inBlock = true
			buf.WriteRune(' ')
			buf.WriteRune(' ')
			i += 2
			continue
		}

		if ch == '"' && !inChar {
			if inString && i > 0 && chars[i-1] == '\\' {
				// escaped quote
			} else {
				inString = !inString
			}
			buf.WriteRune(' ')
			i++
			continue
		}

		if ch == '\'' && !inString {
			if inChar && i > 0 && chars[i-1] == '\\' {
				// escaped char
			} else {
				inChar = !inChar
			}
			buf.WriteRune(' ')
			i++
			continue
		}

		if inString || inChar {
			buf.WriteRune(' ')
		} else {
			buf.WriteRune(ch)
		}
		i++
	}

	return buf.String(), inBlock
}

func isShiftPosition(line string, start, end int) bool {
	prefix := line[:start]
	trimmedPrefix := strings.TrimSpace(prefix)
	if strings.HasSuffix(trimmedPrefix, "<<") || strings.HasSuffix(trimmedPrefix, ">>") {
		return true
	}
	return false
}

func scanFileClangQuery(path string, includePaths []string) []LintViolation {
	query := "match integerLiteral(unless(isExpansionInSystemHeader()))"
	args := []string{"-c", query, path, "--"}
	for _, inc := range includePaths {
		args = append(args, "-I"+inc)
	}

	cmd := exec.Command("clang-query", args...)
	out, err := cmd.Output()
	if err != nil {
		return nil
	}

	var violations []LintViolation
	scanner := bufio.NewScanner(bytes.NewReader(out))
	fileLineRe := regexp.MustCompile(regexp.QuoteMeta(path) + `:(\d+):(\d+)`)

	for scanner.Scan() {
		line := scanner.Text()
		matches := fileLineRe.FindStringSubmatch(line)
		if len(matches) == 3 {
			lineNum, _ := strconv.Atoi(matches[1])
			colNum, _ := strconv.Atoi(matches[2])
			violations = append(violations, LintViolation{
				File:    path,
				Line:    lineNum,
				Column:  colNum,
				Literal: "AST integerLiteral",
				Context: strings.TrimSpace(line),
				Source:  "clang-query",
			})
		}
	}

	return violations
}
