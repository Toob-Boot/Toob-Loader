package build

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
)

// auditedMacroPrefixes selects the generated macros that must be consumed by C code (HIGH-14).
var auditedMacroPrefixes = []string{"CHIP_", "BOOT_", "TOOB_", "REG_", "ADDR_"}

// auditedSourceExtensions are the (lower-cased) file types scanned for consumers.
var auditedSourceExtensions = map[string]bool{".c": true, ".h": true, ".s": true, ".ld": true, ".inc": true}

// auditableMacros filters defines down to the audited prefixes.
func auditableMacros(defines []string) []string {
	var out []string
	for _, d := range defines {
		for _, p := range auditedMacroPrefixes {
			if strings.HasPrefix(d, p) {
				out = append(out, d)
				break
			}
		}
	}
	return out
}

const maxAuditSourceBytes = 16 << 20 // 16 MiB per scanned source file

// auditMacroUsage fails if any macro is never referenced as a consumer
// identifier in the source trees. The generated output directory is excluded so
// generated headers cannot satisfy their own audit, and #define / #undef LHS
// names are ignored so driver-local or fallback #define directives do not mask
// unconsumed generated macros (HIGH-14).
func auditMacroUsage(macros, sourceDirs []string, outDir string) error {
	pending := make(map[string]struct{}, len(macros))
	for _, m := range macros {
		pending[m] = struct{}{}
	}
	absOut, err := filepath.Abs(outDir)
	if err != nil {
		return fmt.Errorf("macro audit: %w", err)
	}
	var realOut string
	if _, err := os.Lstat(absOut); err == nil {
		realOut, _ = resolveLinkOrPath(absOut)
	}

	visitedDirs := make(map[string]bool)
	dirKey := func(p string) string {
		if runtime.GOOS == "windows" {
			return strings.ToLower(filepath.Clean(p))
		}
		return filepath.Clean(p)
	}

	for _, dir := range sourceDirs {
		if len(pending) == 0 {
			break
		}
		absDir, err := filepath.Abs(dir)
		if err != nil {
			return fmt.Errorf("macro audit: scanning %s: %w", dir, err)
		}
		realDir, err := resolveLinkOrPath(absDir)
		if err != nil {
			return fmt.Errorf("macro audit: scanning %s: %w", dir, err)
		}
		visitedDirs[dirKey(realDir)] = true
		if err := scanAuditTree(absDir, dir, realDir, absOut, realOut, visitedDirs, dirKey, pending); err != nil {
			return fmt.Errorf("macro audit: scanning %s: %w", dir, err)
		}
	}

	if len(pending) == 0 {
		return nil
	}
	return unreferencedMacrosError(pending)
}

func scanAuditTree(
	walkRoot, origRoot, realRoot, absOut, realOut string,
	visitedDirs map[string]bool,
	dirKey func(string) string,
	pending map[string]struct{},
) error {
	return filepath.WalkDir(walkRoot, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		readPath := path
		_, rlErr := os.Readlink(path)
		if d.Type()&fs.ModeSymlink != 0 || rlErr == nil {
			target, err := resolveLinkOrPath(path)
			if err != nil {
				return fmt.Errorf("broken symlink %s: %w", path, err)
			}
			if !isWithinDir(realRoot, target) {
				return fmt.Errorf("symlink %s escapes audited source directory %s", path, origRoot)
			}
			if isWithinDir(absOut, target) || (realOut != "" && isWithinDir(realOut, target)) {
				if d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			info, err := os.Stat(target)
			if err != nil {
				return err
			}
			if info.IsDir() {
				k := dirKey(target)
				if visitedDirs[k] {
					return nil
				}
				visitedDirs[k] = true
				if err := scanAuditTree(target, origRoot, realRoot, absOut, realOut, visitedDirs, dirKey, pending); err != nil {
					return err
				}
				if len(pending) == 0 {
					return fs.SkipAll
				}
				return nil
			}
			readPath = target
		} else if d.IsDir() {
			if isWithinDir(absOut, path) || (realOut != "" && isWithinDir(realOut, path)) {
				return fs.SkipDir
			}
			if path != walkRoot {
				if resolvedDir, rErr := resolveLinkOrPath(path); rErr == nil {
					visitedDirs[dirKey(resolvedDir)] = true
				}
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if !auditedSourceExtensions[ext] {
			return nil
		}
		data, err := readBoundedFile(readPath, maxAuditSourceBytes)
		if err != nil {
			return err
		}
		if err := auditFileUndef(data, readPath); err != nil {
			return err
		}
		forEachConsumerIdentifierExt(data, ext, func(ident []byte) {
			delete(pending, string(ident))
		})
		if len(pending) == 0 {
			return fs.SkipAll
		}
		return nil
	})
}

func unreferencedMacrosError(pending map[string]struct{}) error {
	names := make([]string, 0, len(pending))
	for m := range pending {
		names = append(names, m)
	}
	slices.Sort(names)

	var b strings.Builder
	b.WriteString("\n======================================================================\n")
	b.WriteString("FATAL ERROR: MANIFEST COMPILER FAIL-FAST TRIGGERED!\n")
	b.WriteString("The following macros were generated but NEVER referenced in the C code:\n")
	for _, m := range names {
		fmt.Fprintf(&b, "  - %s\n", m)
	}
	b.WriteString("=\nThis indicates a severe architectural gap! Either:\n")
	b.WriteString("  1. The C code is using a hardcoded fallback and ignoring the manifest.\n")
	b.WriteString("  2. The manifest is generating dead code that should be pruned.\n")
	b.WriteString("  3. You are developing/building locally and the registry sources in the cache (~/.toob/registry) " +
		"are out of sync with your local registry. Ensure TOOB_REGISTRY_DIR points to your local registry directory!\n")
	b.WriteString("Fix the C code to use these macros, or remove them from the generator.\n")
	b.WriteString("======================================================================\n")
	return errors.New(b.String())
}

func spliceLogicalLines(src []byte) []byte {
	src = bytes.TrimPrefix(src, []byte("\xEF\xBB\xBF"))
	if !bytes.Contains(src, []byte("\\")) {
		return src
	}
	out := make([]byte, 0, len(src))
	for i := 0; i < len(src); {
		if src[i] == '\\' {
			if i+1 < len(src) && src[i+1] == '\n' {
				i += 2
				continue
			}
			if i+2 < len(src) && src[i+1] == '\r' && src[i+2] == '\n' {
				i += 3
				continue
			}
		}
		out = append(out, src[i])
		i++
	}
	return out
}

func skipMacroParamList(src []byte, i int) int {
	if i >= len(src) || src[i] != '(' {
		return i
	}
	depth := 0
	for i < len(src) && src[i] != '\n' {
		c := src[i]
		switch {
		case c == '/' && hasPrefixAt(src, i, "/*"):
			end := skipBlockComment(src, i+2)
			if bytes.IndexByte(src[i:end], '\n') >= 0 {
				return end
			}
			i = end
		case c == '/' && hasPrefixAt(src, i, "//"):
			return skipLineComment(src, i+2)
		case c == '"' || c == '\'':
			i = skipQuoted(src, i)
		case c == '(':
			depth++
			i++
		case c == ')':
			depth--
			i++
			if depth <= 0 {
				return i
			}
		default:
			i++
		}
	}
	return i
}

func isZeroIfDirectiveArg(rest []byte) bool {
	// Trim horizontal whitespace and inline comments on the same line.
	var cleaned []byte
	for i := 0; i < len(rest); {
		switch {
		case rest[i] == '\n':
			i = len(rest)
		case rest[i] == '/' && hasPrefixAt(rest, i, "//"):
			i = len(rest)
		case rest[i] == '/' && hasPrefixAt(rest, i, "/*"):
			end := skipBlockComment(rest, i+2)
			if bytes.IndexByte(rest[i:end], '\n') >= 0 {
				i = len(rest)
			} else {
				i = end
			}
		case rest[i] == ' ' || rest[i] == '\t' || rest[i] == '\r' || rest[i] == '(' || rest[i] == ')':
			i++
		default:
			cleaned = append(cleaned, rest[i])
			i++
		}
	}
	return bytes.Equal(cleaned, []byte("0")) ||
		bytes.EqualFold(cleaned, []byte("0u")) ||
		bytes.EqualFold(cleaned, []byte("0ul")) ||
		bytes.EqualFold(cleaned, []byte("0ull"))
}

// forEachConsumerIdentifierExt visits every C identifier token in rawSrc except
// #define / #undef LHS names, #include headers, #if 0 dead blocks, and
// standalone #ifndef X / #define X fallback guards (HIGH-14, MED-44).
func forEachConsumerIdentifierExt(rawSrc []byte, ext string, visit func(ident []byte)) {
	src := spliceLogicalLines(rawSrc)
	isAsm := ext == ".s"

	type condFrame struct {
		parentActive bool
		branchActive bool
		everMatched  bool
	}
	var condStack []condFrame
	isActive := func() bool {
		if len(condStack) == 0 {
			return true
		}
		top := condStack[len(condStack)-1]
		return top.parentActive && top.branchActive
	}

	var pendingIfndef []byte
	flushPendingIfndef := func() {
		if len(pendingIfndef) > 0 {
			visit(pendingIfndef)
			pendingIfndef = nil
		}
	}

	lineStart := true
	sawHash := false
	directive := ""
	skipNextIdent := false
	captureIfndefIdent := false
	inInclude := false

	for i := 0; i < len(src); {
		c := src[i]
		switch {
		case c == '\n':
			lineStart, sawHash, directive, skipNextIdent, captureIfndefIdent, inInclude = true, false, "", false, false, false
			i++
		case c == ' ' || c == '\t' || c == '\r':
			i++
		case isAsm && c == ';':
			i = skipLineComment(src, i+1)
			lineStart, sawHash, directive, skipNextIdent, captureIfndefIdent, inInclude = true, false, "", false, false, false
		case isAsm && c == '@' && (lineStart || (i+1 < len(src) && (src[i+1] == ' ' || src[i+1] == '\t'))):
			i = skipLineComment(src, i+1)
			lineStart, sawHash, directive, skipNextIdent, captureIfndefIdent, inInclude = true, false, "", false, false, false
		case c == '#' && lineStart:
			lineStart = false
			sawHash = true
			i++
		case inInclude && c == '<':
			i++
			for i < len(src) && src[i] != '>' && src[i] != '\n' {
				i++
			}
			if i < len(src) && src[i] == '>' {
				i++
			}
		case isIdentStart(c):
			lineStart = false
			start := i
			for i < len(src) && isIdentPart(src[i]) {
				i++
			}
			tok := src[start:i]
			if sawHash {
				sawHash = false
				directive = string(tok)
				switch directive {
				case "define":
					skipNextIdent = true
					continue
				case "undef":
					flushPendingIfndef()
					skipNextIdent = true
					continue
				case "include":
					flushPendingIfndef()
					inInclude = true
					continue
				case "if":
					flushPendingIfndef()
					parent := isActive()
					branch := parent && !isZeroIfDirectiveArg(src[i:])
					condStack = append(condStack, condFrame{parentActive: parent, branchActive: branch, everMatched: branch})
					continue
				case "ifdef":
					flushPendingIfndef()
					parent := isActive()
					condStack = append(condStack, condFrame{parentActive: parent, branchActive: parent, everMatched: parent})
					continue
				case "ifndef":
					flushPendingIfndef()
					parent := isActive()
					condStack = append(condStack, condFrame{parentActive: parent, branchActive: parent, everMatched: parent})
					if parent {
						captureIfndefIdent = true
					}
					continue
				case "elif":
					flushPendingIfndef()
					if n := len(condStack); n > 0 {
						f := &condStack[n-1]
						if !f.parentActive || f.everMatched {
							f.branchActive = false
						} else {
							branch := !isZeroIfDirectiveArg(src[i:])
							f.branchActive = branch
							if branch {
								f.everMatched = true
							}
						}
					}
					continue
				case "else":
					flushPendingIfndef()
					if n := len(condStack); n > 0 {
						f := &condStack[n-1]
						f.branchActive = f.parentActive && !f.everMatched
						f.everMatched = true
					}
					continue
				case "endif":
					flushPendingIfndef()
					if n := len(condStack); n > 0 {
						condStack = condStack[:n-1]
					}
					continue
				default:
					flushPendingIfndef()
				}
			}
			if captureIfndefIdent {
				captureIfndefIdent = false
				pendingIfndef = tok
				continue
			}
			if skipNextIdent {
				skipNextIdent = false
				if directive == "define" && len(pendingIfndef) > 0 && bytes.Equal(pendingIfndef, tok) {
					// `#ifndef X` immediately followed by `#define X ...` is a fallback
					// guard, not an independent consumer of X.
					pendingIfndef = nil
				} else {
					flushPendingIfndef()
				}
				if i < len(src) && src[i] == '(' {
					i = skipMacroParamList(src, i)
				}
				continue
			}
			if !isActive() {
				continue
			}
			flushPendingIfndef()
			visit(tok)
		case c >= '0' && c <= '9':
			lineStart, sawHash, skipNextIdent, captureIfndefIdent = false, false, false, false
			if isActive() {
				flushPendingIfndef()
			}
			for i < len(src) && isIdentPart(src[i]) {
				i++
			}
		case c == '/' && hasPrefixAt(src, i, "//"):
			i = skipLineComment(src, i+2)
			lineStart, sawHash, directive, skipNextIdent, captureIfndefIdent, inInclude = true, false, "", false, false, false
		case c == '/' && hasPrefixAt(src, i, "/*"):
			end := skipBlockComment(src, i+2)
			if bytes.IndexByte(src[i:end], '\n') >= 0 {
				lineStart, sawHash, directive, skipNextIdent, captureIfndefIdent, inInclude = true, false, "", false, false, false
			}
			i = end
		case c == '"' || c == '\'':
			lineStart, sawHash, skipNextIdent, captureIfndefIdent = false, false, false, false
			if !inInclude && isActive() {
				flushPendingIfndef()
			}
			i = skipQuoted(src, i)
		default:
			lineStart, sawHash, skipNextIdent, captureIfndefIdent = false, false, false, false
			if isActive() {
				flushPendingIfndef()
			}
			i++
		}
	}
	flushPendingIfndef()
}

func hasPrefixAt(src []byte, i int, prefix string) bool {
	return bytes.HasPrefix(src[i:], []byte(prefix))
}

// skipLineComment returns the index after the comment body starting at i. A
// backslash before the line break continues the comment on the next line.
func skipLineComment(src []byte, i int) int {
	for ; i < len(src); i++ {
		if src[i] != '\n' {
			continue
		}
		prev := i - 1
		if prev >= 0 && src[prev] == '\r' {
			prev--
		}
		if prev < 0 || src[prev] != '\\' {
			return i + 1
		}
	}
	return len(src)
}

// skipBlockComment returns the index after the closing delimiter; an
// unterminated comment extends to the end of src.
func skipBlockComment(src []byte, i int) int {
	end := bytes.Index(src[i:], []byte("*/"))
	if end < 0 {
		return len(src)
	}
	return i + end + 2
}

// skipQuoted returns the index after the literal opened by the quote at i, or
// the index of the terminating line break if the literal is not closed.
func skipQuoted(src []byte, i int) int {
	quote := src[i]
	for i++; i < len(src) && src[i] != '\n'; i++ {
		switch src[i] {
		case '\\':
			i++
		case quote:
			return i + 1
		}
	}
	return min(i, len(src))
}

func isIdentStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isIdentPart(c byte) bool { return isIdentStart(c) || (c >= '0' && c <= '9') }

var protectedCoreSecurityMacros = []string{
	"BOOT_SECURE_REQUIRE",
	"BOOT_SECURE_CHECK",
	"BOOT_GLITCH_DELAY",
	"BOOT_PANIC",
	"TOOB_DOUBLE_VERIFY",
	"TOOB_PROFILE_PRODUCTION",
	"TOOB_ALLOW_PUBLIC_JOURNAL_KEY_DEGRADATION",
	"TOOB_ALLOW_DEV_BYPASS",
	"TOOB_MOCK_HW",
	"TOOB_MOCK_EFUSES",
	"TOOB_MOCK_TEST",
	"TOOB_STAGE1_SVN",
	"BOOT_CRYPTO_ARENA_SIZE",
	"TOOB_PQC_ENABLED",
	"TOOB_TRANSPORT_PROVIDER",
	"TOOB_ONEWAY_BACKUP_MODE",
}

func isProtectedSecurityMacro(name string, extraReserved map[string]struct{}) bool {
	if _, ok := extraReserved[name]; ok {
		return true
	}
	if strings.HasPrefix(name, "BOOT_SECURE_") || strings.HasPrefix(name, "BOOT_GLITCH_") || strings.HasPrefix(name, "TOOB_MOCK_") {
		return true
	}
	return slices.Contains(protectedCoreSecurityMacros, name)
}

func isCoreNamespaceMacro(name string) bool {
	return strings.HasPrefix(name, "TOOB_") ||
		strings.HasPrefix(name, "BOOT_") ||
		strings.HasPrefix(name, "CHIP_")
}

func isCoreSourcePath(dirOrFile string) bool {
	slash := filepath.ToSlash(filepath.Clean(dirOrFile))
	return slash == "toobloader/core" ||
		strings.HasSuffix(slash, "/toobloader/core") ||
		strings.Contains(slash, "/toobloader/core/") ||
		slash == "toobloader/stage0" ||
		strings.HasSuffix(slash, "/toobloader/stage0") ||
		strings.Contains(slash, "/toobloader/stage0/")
}

type ppDirectiveKind int

const (
	ppNone ppDirectiveKind = iota
	ppDefine
	ppUndef
	ppIf
	ppIfdef
	ppIfndef
	ppElif
	ppElse
	ppEndif
)

type parsedMacroDirective struct {
	kind   ppDirectiveKind
	name   string
	fnLike bool
	params string
	body   string
	line   int
}

// spliceLogicalLinesWithLines joins backslash-continued lines while mapping
// each logical line back to its starting 1-based physical line number.
func spliceLogicalLinesWithLines(rawSrc []byte) ([]byte, []int) {
	src := bytes.TrimPrefix(rawSrc, []byte("\xEF\xBB\xBF"))
	out := make([]byte, 0, len(src))
	lines := make([]int, 0, bytes.Count(src, []byte{'\n'})+1)
	lines = append(lines, 1)
	physLine := 1
	for i := 0; i < len(src); {
		if src[i] == '\\' {
			if i+1 < len(src) && src[i+1] == '\n' {
				physLine++
				i += 2
				continue
			}
			if i+2 < len(src) && src[i+1] == '\r' && src[i+2] == '\n' {
				physLine++
				i += 3
				continue
			}
		}
		if src[i] == '\n' {
			physLine++
			out = append(out, '\n')
			lines = append(lines, physLine)
			i++
			continue
		}
		out = append(out, src[i])
		i++
	}
	return out, lines
}

func stripCommentsAndNormalize(s []byte) string {
	var out strings.Builder
	inBlock := false
	for i := 0; i < len(s); {
		if inBlock {
			if i+1 < len(s) && s[i] == '*' && s[i+1] == '/' {
				inBlock = false
				i += 2
				out.WriteByte(' ')
				continue
			}
			i++
			continue
		}
		switch {
		case i+1 < len(s) && s[i] == '/' && s[i+1] == '*':
			inBlock = true
			i += 2
		case i+1 < len(s) && s[i] == '/' && s[i+1] == '/':
			return strings.TrimSpace(out.String())
		case s[i] == '"' || s[i] == '\'':
			end := skipQuoted(s, i)
			out.Write(s[i:end])
			i = end
		case s[i] == ' ' || s[i] == '\t' || s[i] == '\r':
			if out.Len() > 0 {
				b := out.String()
				if b[len(b)-1] != ' ' {
					out.WriteByte(' ')
				}
			}
			i++
		default:
			out.WriteByte(s[i])
			i++
		}
	}
	return strings.TrimSpace(out.String())
}

func scanPreprocessorDirectives(rawSrc []byte) []parsedMacroDirective {
	src, lineNums := spliceLogicalLinesWithLines(rawSrc)
	var directives []parsedMacroDirective
	inBlockComment := false
	logicalIdx := 0

	for i := 0; i < len(src); {
		lineStart := i
		nl := bytes.IndexByte(src[i:], '\n')
		var lineBytes []byte
		if nl < 0 {
			lineBytes = src[i:]
			i = len(src)
		} else {
			lineBytes = src[i : i+nl]
			i += nl + 1
		}
		lineNo := 1
		if logicalIdx < len(lineNums) {
			lineNo = lineNums[logicalIdx]
		}
		logicalIdx++

		if len(bytes.TrimSpace(lineBytes)) == 0 {
			continue
		}

		// Strip comments at the start of the line and track block comment state across lines.
		j := 0
		for j < len(lineBytes) {
			if inBlockComment {
				if j+1 < len(lineBytes) && lineBytes[j] == '*' && lineBytes[j+1] == '/' {
					inBlockComment = false
					j += 2
					continue
				}
				j++
				continue
			}
			if lineBytes[j] == ' ' || lineBytes[j] == '\t' || lineBytes[j] == '\r' {
				j++
				continue
			}
			if j+1 < len(lineBytes) && lineBytes[j] == '/' && lineBytes[j+1] == '*' {
				inBlockComment = true
				j += 2
				continue
			}
			break
		}

		// Update trailing block comment state for the rest of the line cleanly.
		updateCommentState := func(b []byte) {
			for k := 0; k < len(b); {
				if inBlockComment {
					if k+1 < len(b) && b[k] == '*' && b[k+1] == '/' {
						inBlockComment = false
						k += 2
						continue
					}
					k++
					continue
				}
				switch {
				case k+1 < len(b) && b[k] == '/' && b[k+1] == '*':
					inBlockComment = true
					k += 2
				case k+1 < len(b) && b[k] == '/' && b[k+1] == '/':
					return
				case b[k] == '"' || b[k] == '\'':
					k = skipQuoted(b, k)
				default:
					k++
				}
			}
		}

		if inBlockComment || j >= len(lineBytes) || lineBytes[j] != '#' {
			updateCommentState(lineBytes[j:])
			_ = lineStart
			continue
		}

		// Parse directive keyword after '#'.
		k := j + 1
		for k < len(lineBytes) && (lineBytes[k] == ' ' || lineBytes[k] == '\t') {
			k++
		}
		kwStart := k
		for k < len(lineBytes) && isIdentPart(lineBytes[k]) {
			k++
		}
		kw := string(lineBytes[kwStart:k])
		for k < len(lineBytes) && (lineBytes[k] == ' ' || lineBytes[k] == '\t') {
			k++
		}

		parseIdent := func(pos int) (string, int) {
			if pos >= len(lineBytes) || !isIdentStart(lineBytes[pos]) {
				return "", pos
			}
			start := pos
			for pos < len(lineBytes) && isIdentPart(lineBytes[pos]) {
				pos++
			}
			return string(lineBytes[start:pos]), pos
		}

		switch kw {
		case "undef":
			name, _ := parseIdent(k)
			directives = append(directives, parsedMacroDirective{kind: ppUndef, name: name, line: lineNo})
		case "define":
			name, pos := parseIdent(k)
			if name != "" {
				var fnLike bool
				var params, body string
				if pos < len(lineBytes) && lineBytes[pos] == '(' {
					fnLike = true
					pEnd := pos + 1
					for pEnd < len(lineBytes) && lineBytes[pEnd] != ')' {
						pEnd++
					}
					if pEnd < len(lineBytes) && lineBytes[pEnd] == ')' {
						params = strings.ReplaceAll(string(lineBytes[pos+1:pEnd]), " ", "")
						pos = pEnd + 1
					}
				}
				body = stripCommentsAndNormalize(lineBytes[pos:])
				directives = append(directives, parsedMacroDirective{
					kind:   ppDefine,
					name:   name,
					fnLike: fnLike,
					params: params,
					body:   body,
					line:   lineNo,
				})
			}
		case "ifndef":
			name, _ := parseIdent(k)
			directives = append(directives, parsedMacroDirective{kind: ppIfndef, name: name, line: lineNo})
		case "ifdef":
			name, _ := parseIdent(k)
			directives = append(directives, parsedMacroDirective{kind: ppIfdef, name: name, line: lineNo})
		case "if":
			directives = append(directives, parsedMacroDirective{kind: ppIf, line: lineNo})
		case "elif":
			directives = append(directives, parsedMacroDirective{kind: ppElif, line: lineNo})
		case "else":
			directives = append(directives, parsedMacroDirective{kind: ppElse, line: lineNo})
		case "endif":
			directives = append(directives, parsedMacroDirective{kind: ppEndif, line: lineNo})
		}
		updateCommentState(lineBytes[k:])
	}
	return directives
}

func auditFileUndef(rawSrc []byte, path string) error {
	for _, d := range scanPreprocessorDirectives(rawSrc) {
		if d.kind == ppUndef {
			return fmt.Errorf("macro audit: %s:%d: forbidden #undef %q", path, d.line, d.name)
		}
	}
	return nil
}

func coreSiblingRoots(coreDir string) []string {
	if strings.TrimSpace(coreDir) == "" {
		return nil
	}
	absCore, err := filepath.Abs(coreDir)
	if err != nil {
		return nil
	}
	coreParent := filepath.Dir(filepath.Clean(absCore)) // <sdk>/toobloader
	if filepath.Base(coreParent) != "toobloader" {
		return []string{filepath.Clean(absCore)}
	}
	sdkRoot := filepath.Dir(coreParent)
	return []string{
		filepath.Join(coreParent, "core"),
		filepath.Join(coreParent, "stage0"),
		filepath.Join(sdkRoot, "common"),
		filepath.Join(sdkRoot, "recovery"),
		filepath.Join(sdkRoot, "sdk"),
	}
}

func isWithinAnyDir(roots []string, path string) bool {
	if len(roots) == 0 {
		return false
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		absPath = filepath.Clean(path)
	}
	realPath, rErr := resolveLinkOrPath(absPath)
	for _, r := range roots {
		if isWithinDir(r, absPath) || (rErr == nil && isWithinDir(r, realPath)) {
			return true
		}
		if rr, err := resolveLinkOrPath(r); err == nil && (isWithinDir(rr, absPath) || (rErr == nil && isWithinDir(rr, realPath))) {
			return true
		}
	}
	return false
}

func isRegistryCatalogRoot(dir string) bool {
	chipsInfo, cErr := os.Stat(filepath.Join(dir, "chips"))
	driversInfo, dErr := os.Stat(filepath.Join(dir, "drivers"))
	return cErr == nil && dErr == nil && chipsInfo.IsDir() && driversInfo.IsDir()
}

func auditComposedSourceMacroHygiene(ctx *Context, generatedMacros []string) error {
	if ctx == nil {
		return nil
	}
	absOut, err := filepath.Abs(ctx.OutDir)
	if err != nil {
		return fmt.Errorf("macro hygiene audit: %w", err)
	}
	var realOut string
	if _, statErr := os.Lstat(absOut); statErr == nil {
		realOut, _ = resolveLinkOrPath(absOut)
	}

	hasExplicitPackages := strings.TrimSpace(ctx.ChipManifestPath) != "" ||
		strings.TrimSpace(ctx.ArchDir) != "" ||
		len(ctx.DriverDirs) > 0 ||
		len(ctx.CryptoDirs) > 0 ||
		len(ctx.RecoveryDriverDirs) > 0 ||
		len(ctx.RecoveryCryptoDirs) > 0

	var absProj, realProj string
	if strings.TrimSpace(ctx.ProjectDir) != "" {
		if ap, pErr := filepath.Abs(ctx.ProjectDir); pErr == nil {
			absProj = ap
			if rp, rErr := resolveLinkOrPath(ap); rErr == nil {
				realProj = rp
			}
		}
	}
	isProjectWorkspaceRoot := func(absDir string) bool {
		if !hasExplicitPackages || absProj == "" {
			return false
		}
		cand := absDir
		if rc, rErr := resolveLinkOrPath(absDir); rErr == nil {
			cand = rc
		}
		targetProj := absProj
		if realProj != "" {
			targetProj = realProj
		}
		if runtime.GOOS == "windows" {
			return strings.EqualFold(filepath.Clean(cand), filepath.Clean(targetProj))
		}
		return filepath.Clean(cand) == filepath.Clean(targetProj)
	}

	firstPartyRoots := coreSiblingRoots(ctx.CoreDir)
	seen := make(map[string]struct{})
	var packageDirs []string
	addPkgDir := func(d string, isSourceRoot bool) {
		if strings.TrimSpace(d) == "" {
			return
		}
		absDir, absErr := filepath.Abs(d)
		if absErr == nil && (isWithinDir(absOut, absDir) || (realOut != "" && isWithinDir(realOut, absDir))) {
			return
		}
		if isCoreSourcePath(d) || isWithinAnyDir(firstPartyRoots, d) {
			return
		}
		if isSourceRoot && (isRegistryCatalogRoot(d) || isProjectWorkspaceRoot(absDir)) {
			return
		}
		keyDir := absDir
		if keyDir == "" {
			keyDir = filepath.Clean(d)
		}
		if rr, rErr := resolveLinkOrPath(keyDir); rErr == nil {
			keyDir = rr
		}
		if runtime.GOOS == "windows" {
			keyDir = strings.ToLower(keyDir)
		}
		if _, exists := seen[keyDir]; exists {
			return
		}
		seen[keyDir] = struct{}{}
		packageDirs = append(packageDirs, d)
	}

	if strings.TrimSpace(ctx.ChipManifestPath) != "" {
		addPkgDir(filepath.Dir(ctx.ChipManifestPath), false)
	}
	addPkgDir(ctx.ArchDir, false)
	for _, d := range ctx.DriverDirs {
		addPkgDir(d, false)
	}
	for _, d := range ctx.CryptoDirs {
		addPkgDir(d, false)
	}
	for _, d := range ctx.RecoveryDriverDirs {
		addPkgDir(d, false)
	}
	for _, d := range ctx.RecoveryCryptoDirs {
		addPkgDir(d, false)
	}
	for _, d := range ctx.SourceDirs {
		addPkgDir(d, true)
	}

	if len(packageDirs) == 0 {
		return nil
	}
	skipRoots := append([]string(nil), firstPartyRoots...)
	skipRoots = append(skipRoots, absOut)
	if realOut != "" {
		skipRoots = append(skipRoots, realOut)
	}
	reserved := make([]string, 0, len(generatedMacros))
	if len(packageDirs) > 1 {
		reserved = append(reserved, generatedMacros...)
	}
	return auditPackageMacrosWithSkip(packageDirs, reserved, skipRoots)
}

type macroDefRecord struct {
	pkgDir string
	file   string
	line   int
	isHdr  bool
	fnLike bool
	params string
	body   string
}

// AuditPackageMacros verifies preprocessor macro hygiene across one or more
// composed package directories (CRIT-72):
//   - forbids all #undef directives,
//   - forbids redefining protected core security macros (or caller-supplied reserved macros),
//   - forbids unguarded #define of TOOB_*/BOOT_*/CHIP_* macros outside header include guards,
//   - forbids colliding header #define identifiers and conflicting #define values across packages.
func AuditPackageMacros(packageDirs, reservedMacros []string) error {
	return auditPackageMacrosWithSkip(packageDirs, reservedMacros, nil)
}

func auditPackageMacrosWithSkip(packageDirs, reservedMacros, skipRoots []string) error {
	extraReserved := make(map[string]struct{}, len(reservedMacros))
	for _, r := range reservedMacros {
		if r != "" {
			extraReserved[r] = struct{}{}
		}
	}

	seenAcrossPkgs := make(map[string]macroDefRecord)

	for _, pkgDir := range packageDirs {
		if strings.TrimSpace(pkgDir) == "" {
			continue
		}
		absPkg, absErr := filepath.Abs(pkgDir)
		if absErr != nil {
			return fmt.Errorf("macro audit: resolve %s: %w", pkgDir, absErr)
		}
		realPkg, realErr := resolveLinkOrPath(absPkg)
		if realErr != nil {
			return fmt.Errorf("macro audit: resolve %s: %w", pkgDir, realErr)
		}
		cleanPkg := filepath.Clean(realPkg)

		var scanDir func(walkRoot string, visited map[string]bool) error
		scanDir = func(walkRoot string, visited map[string]bool) error {
			return filepath.WalkDir(walkRoot, func(path string, d fs.DirEntry, walkErr error) error {
				if walkErr != nil {
					return walkErr
				}
				readPath := path
				_, rlErr := os.Readlink(path)
				if d.Type()&fs.ModeSymlink != 0 || rlErr == nil {
					target, linkErr := resolveLinkOrPath(path)
					if linkErr != nil {
						return fmt.Errorf("broken symlink %s: %w", path, linkErr)
					}
					if !isWithinDir(realPkg, target) {
						return fmt.Errorf("symlink %s escapes audited package directory %s", path, pkgDir)
					}
					info, statErr := os.Stat(target)
					if statErr != nil {
						return statErr
					}
					if info.IsDir() {
						if isWithinAnyDir(skipRoots, target) || filepath.Base(target) == "CMakeFiles" {
							return nil
						}
						if visited[target] {
							return nil
						}
						visited[target] = true
						return scanDir(target, visited)
					}
					readPath = target
				} else if d.IsDir() {
					if isWithinAnyDir(skipRoots, path) || d.Name() == "CMakeFiles" {
						return fs.SkipDir
					}
					return nil
				}

				ext := strings.ToLower(filepath.Ext(path))
				if !auditedSourceExtensions[ext] {
					return nil
				}
				if isCoreSourcePath(readPath) || isWithinAnyDir(skipRoots, readPath) {
					return nil
				}
				data, readErr := readBoundedFile(readPath, maxAuditSourceBytes)
				if readErr != nil {
					return readErr
				}
				return auditSingleFileMacros(readPath, ext, cleanPkg, data, extraReserved, seenAcrossPkgs)
			})
		}

		visited := map[string]bool{cleanPkg: true}
		if walkErr := scanDir(absPkg, visited); walkErr != nil {
			return walkErr
		}
	}
	return nil
}

type ppFrame struct {
	ifndefName string
	inElse     bool
}

func hasEnclosingIfndef(stack []ppFrame, name string) bool {
	for i := len(stack) - 1; i >= 0; i-- {
		if !stack[i].inElse && stack[i].ifndefName == name {
			return true
		}
	}
	return false
}

func auditSingleFileMacros(
	path, ext, cleanPkg string,
	data []byte,
	extraReserved map[string]struct{},
	seenAcrossPkgs map[string]macroDefRecord,
) error {
	directives := scanPreprocessorDirectives(data)
	var stack []ppFrame
	isHdr := ext == ".h" || ext == ".inc"

	for idx, d := range directives {
		switch d.kind {
		case ppNone:
			continue
		case ppUndef:
			return fmt.Errorf("macro audit: %s:%d: forbidden #undef %q", path, d.line, d.name)
		case ppIfndef:
			stack = append(stack, ppFrame{ifndefName: d.name})
		case ppIfdef, ppIf:
			stack = append(stack, ppFrame{})
		case ppElif, ppElse:
			if len(stack) > 0 {
				stack[len(stack)-1].inElse = true
				stack[len(stack)-1].ifndefName = ""
			}
		case ppEndif:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		case ppDefine:
			if isProtectedSecurityMacro(d.name, extraReserved) {
				return fmt.Errorf("macro audit: %s:%d: forbidden redefinition of core security macro %q", path, d.line, d.name)
			}

			isIncludeGuard := isHdr && idx > 0 && directives[idx-1].kind == ppIfndef &&
				directives[idx-1].name == d.name && !d.fnLike && d.body == "" &&
				(strings.HasSuffix(d.name, "_H") || strings.HasSuffix(d.name, "_H_") || strings.HasSuffix(d.name, "_INC"))

			if isCoreNamespaceMacro(d.name) && !isIncludeGuard && !hasEnclosingIfndef(stack, d.name) {
				return fmt.Errorf("macro audit: %s:%d: unguarded redefinition of core namespace macro %q (must use #ifndef fallback guard or omit)",
					path, d.line, d.name)
			}

			if isIncludeGuard {
				continue
			}

			prev, exists := seenAcrossPkgs[d.name]
			if !exists {
				seenAcrossPkgs[d.name] = macroDefRecord{
					pkgDir: cleanPkg,
					file:   path,
					line:   d.line,
					isHdr:  isHdr,
					fnLike: d.fnLike,
					params: d.params,
					body:   d.body,
				}
				continue
			}

			if prev.pkgDir == cleanPkg {
				continue
			}

			if prev.isHdr || isHdr {
				return fmt.Errorf("macro audit: %s:%d: colliding header #define %q also defined at %s:%d across composed packages",
					path, d.line, d.name, prev.file, prev.line)
			}
			if prev.fnLike != d.fnLike || prev.params != d.params || prev.body != d.body {
				return fmt.Errorf("macro audit: %s:%d: conflicting #define %q across composed packages (previous at %s:%d)",
					path, d.line, d.name, prev.file, prev.line)
			}
		}
	}
	return nil
}
