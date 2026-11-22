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
