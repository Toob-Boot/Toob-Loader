package build

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
)

var (
	packageNamePattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	packageScopePattern = regexp.MustCompile(`^@[A-Za-z0-9][A-Za-z0-9._-]*$`)

	// reservedCWords blocks C11/C23 keywords, preprocessor operators, and NULL
	// from being accepted as HAL function/symbol identifiers or driver_config
	// constant names (prevents e.g. "read_pubkey": "NULL" bypassing required checks).
	reservedCWords = map[string]bool{
		"NULL": true, "defined": true, "_Pragma": true,
		"asm": true, "__asm": true, "__asm__": true,
		"typeof": true, "typeof_unqual": true, "__typeof__": true,
		"alignas": true, "alignof": true, "auto": true, "bool": true,
		"break": true, "case": true, "char": true, "const": true,
		"constexpr": true, "continue": true, "default": true, "do": true,
		"double": true, "else": true, "enum": true, "extern": true,
		"false": true, "float": true, "for": true, "goto": true,
		"if": true, "inline": true, "int": true, "long": true,
		"nullptr": true, "register": true, "restrict": true, "return": true,
		"short": true, "signed": true, "sizeof": true, "static": true,
		"static_assert": true, "struct": true, "switch": true, "thread_local": true,
		"true": true, "typedef": true, "union": true, "unsigned": true,
		"void": true, "volatile": true, "while": true,
		"_Alignas": true, "_Alignof": true, "_Atomic": true, "_BitInt": true,
		"_Bool": true, "_Complex": true, "_Decimal128": true, "_Decimal32": true,
		"_Decimal64": true, "_Generic": true, "_Imaginary": true, "_Noreturn": true,
		"_Static_assert": true, "_Thread_local": true,
	}
)

func isCSymbol(s string) bool {
	return isCIdentifier(s) && !reservedCWords[s] && !strings.HasPrefix(s, "__builtin_")
}

// isWindowsReservedDeviceStem reports whether name (ignoring any extension and
// trailing dots/spaces stripped by Win32) collides with a DOS device name.
func isWindowsReservedDeviceStem(name string) bool {
	trimmed := strings.TrimRight(name, ". ")
	stem, _, _ := strings.Cut(trimmed, ".")
	switch strings.ToUpper(stem) {
	case "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$",
		"COM0", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
		"LPT0", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9":
		return true
	default:
		return false
	}
}

// ValidateName rejects identifiers that are unsafe to use as a path segment
// or to embed in generated build files: separators, traversal, whitespace,
// quotes, trailing dots, Windows device names, and shell/CMake/C metacharacters.
func ValidateName(kind, name string) error {
	if !packageNamePattern.MatchString(name) {
		return fmt.Errorf("invalid %s name %q: must start with a letter or digit and contain only "+
			"letters, digits, '.', '_' and '-'", kind, name)
	}
	if strings.HasSuffix(name, ".") {
		return fmt.Errorf("invalid %s name %q: must not end with '.'", kind, name)
	}
	if isWindowsReservedDeviceStem(name) {
		return fmt.Errorf("invalid %s name %q: reserved device name is not permitted", kind, name)
	}
	return nil
}

// ValidatePackageRef validates an unscoped ("esp_efuse") or scoped
// ("@partner/atecc608", "@community/usb_jtag") registry package identifier.
func ValidatePackageRef(kind, ref string) error {
	if strings.HasPrefix(ref, "@") {
		scope, pkg, ok := strings.Cut(ref, "/")
		if !ok || strings.Contains(pkg, "/") {
			return fmt.Errorf("invalid scoped %s reference %q: expected @scope/name", kind, ref)
		}
		if !packageScopePattern.MatchString(scope) {
			return fmt.Errorf("invalid %s scope %q in %q: must match @<letters/digits/._->", kind, scope, ref)
		}
		if err := ValidateName(kind+" scope", scope[1:]); err != nil {
			return fmt.Errorf("invalid %s scope %q in %q: %w", kind, scope, ref, err)
		}
		return ValidateName(kind, pkg)
	}
	return ValidateName(kind, ref)
}

// ValidateCompilerFlag rejects compiler/assembler/linker flags that could
// inject CMake list separators (';'), variable expansions ('$'), quotes,
// whitespace/newlines, shell metacharacters, or path traversal ('..') (HIGH-87).
func ValidateCompilerFlag(kind, flag string) error {
	if flag == "" {
		return fmt.Errorf("%s entry must not be empty", kind)
	}
	if flag[0] != '-' {
		return fmt.Errorf("invalid %s %q: compiler flag must start with '-'", kind, flag)
	}
	if strings.Contains(flag, "..") {
		return fmt.Errorf("invalid %s %q: '..' is not permitted in compiler flags", kind, flag)
	}
	for i := range len(flag) {
		c := flag[i]
		if c <= 0x20 || c > 0x7E {
			return fmt.Errorf("invalid %s %q: contains whitespace or control byte 0x%02X", kind, flag, c)
		}
		switch c {
		case ';', '$', '"', '\'', '`', '\\', '|', '&', '<', '>', '(', ')', '{', '}', '!':
			return fmt.Errorf("invalid %s %q: contains forbidden metacharacter %q", kind, flag, c)
		}
	}
	return nil
}

// ValidateCompilerFlags validates optional C, ASM, and LD flag slices on a manifest.
func ValidateCompilerFlags(kind string, cf *CompilerFlags) error {
	if cf == nil {
		return nil
	}
	for _, f := range cf.CFlags {
		if err := ValidateCompilerFlag(kind+".c_flags", f); err != nil {
			return err
		}
	}
	for _, f := range cf.AsmFlags {
		if err := ValidateCompilerFlag(kind+".asm_flags", f); err != nil {
			return err
		}
	}
	for _, f := range cf.LDFlags {
		if err := ValidateCompilerFlag(kind+".ld_flags", f); err != nil {
			return err
		}
	}
	return nil
}

// validateDisplayText rejects text that would corrupt the generated C output
// when printed inside a block comment: non-printable characters and comment
// delimiters.
func validateDisplayText(field, text string) error {
	for i := range len(text) {
		if c := text[i]; c < 0x20 || c > 0x7E {
			return fmt.Errorf("%s contains the non-printable or non-ASCII byte 0x%02X at offset %d", field, c, i)
		}
	}
	if strings.Contains(text, "/*") || strings.Contains(text, "*/") {
		return fmt.Errorf("%s %q must not contain comment delimiters", field, text)
	}
	return nil
}

// validateSafeText rejects Unicode control characters (including NUL, CR, LF, TAB)
// while permitting printable UTF-8 text such as '§' in provenance references.
func validateSafeText(field, text string) error {
	for i, r := range text {
		if unicode.IsControl(r) || r == unicode.ReplacementChar {
			return fmt.Errorf("%s contains invalid or control character U+%04X at byte offset %d", field, r, i)
		}
	}
	return nil
}

// validateRelPath validates a '/'-separated relative path segment by segment.
func validateRelPath(kind, rel string) error {
	if rel == "" {
		return fmt.Errorf("%s path must not be empty", kind)
	}
	if strings.Contains(rel, `\`) {
		return fmt.Errorf("invalid %s path %q: backslashes are not permitted", kind, rel)
	}
	for _, seg := range strings.Split(rel, "/") {
		if err := ValidateName(kind, seg); err != nil {
			return fmt.Errorf("%w (in %q)", err, rel)
		}
	}
	return nil
}

// validatePackageOrRelPath accepts either a scoped package ref (@scope/name)
// or a '/'-separated relative package path.
func validatePackageOrRelPath(kind, ref string) error {
	if strings.HasPrefix(ref, "@") {
		return ValidatePackageRef(kind, ref)
	}
	return validateRelPath(kind, ref)
}

// validateHeaderPath validates a relative C header include path (e.g. "foo.h"
// or "drivers/slot/tc_slot/tc_slot.h"), blocking path traversal, absolute/UNC
// paths, backslashes, quotes, comment delimiters, and non-.h files.
func validateHeaderPath(h string) error {
	if err := validateRelPath("header", h); err != nil {
		return err
	}
	if !strings.HasSuffix(h, ".h") {
		return fmt.Errorf("header %q must end with '.h'", h)
	}
	return nil
}

func isWithinDir(base, candidate string) bool {
	rel, err := filepath.Rel(base, candidate)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

func normalizeReadlinkTarget(target string) string {
	switch {
	case len(target) >= 8 && strings.EqualFold(target[:8], `\??\UNC\`):
		return `\\` + target[8:]
	case len(target) >= 8 && strings.EqualFold(target[:8], `\\?\UNC\`):
		return `\\` + target[8:]
	case strings.HasPrefix(target, `\??\`):
		return target[4:]
	case strings.HasPrefix(target, `\\?\`):
		return target[4:]
	default:
		return target
	}
}

func splitPathFromRoot(absPath string) (string, []string) {
	cleaned := filepath.Clean(absPath)
	vol := filepath.VolumeName(cleaned)
	if len(vol) == 2 && vol[1] == ':' {
		vol = strings.ToUpper(vol[:1]) + ":"
	}
	rest := cleaned[len(filepath.VolumeName(cleaned)):]
	rest = strings.TrimLeft(rest, `/\`)
	root := vol + string(filepath.Separator)
	if rest == "" {
		return root, nil
	}
	norm := strings.ReplaceAll(rest, `\`, "/")
	raw := strings.Split(norm, "/")
	segs := make([]string, 0, len(raw))
	for _, s := range raw {
		if s != "" && s != "." {
			segs = append(segs, s)
		}
	}
	return root, segs
}

// resolveLinkOrPath expands symbolic links and Windows NTFS junctions segment
// by segment so chained symlink -> junction escapes cannot bypass EvalSymlinks.
func resolveLinkOrPath(path string) (string, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	cur, pending := splitPathFromRoot(absPath)
	const maxHops = 40
	hops := 0

	for len(pending) > 0 {
		seg := pending[0]
		pending = pending[1:]
		if seg == "" || seg == "." {
			continue
		}
		if seg == ".." {
			cur = filepath.Dir(cur)
			continue
		}
		next := filepath.Join(cur, seg)
		fi, err := os.Lstat(next)
		if err != nil {
			return "", err
		}

		var target string
		isLink := false
		if fi.Mode()&fs.ModeSymlink != 0 {
			target, err = os.Readlink(next)
			if err != nil {
				return "", err
			}
			isLink = true
		} else if !fi.Mode().IsRegular() {
			if jt, rlErr := os.Readlink(next); rlErr == nil {
				target = jt
				isLink = true
			}
		}

		if isLink {
			hops++
			if hops > maxHops {
				return "", fmt.Errorf("too many link indirections at %s", path)
			}
			target = normalizeReadlinkTarget(target)
			if filepath.IsAbs(target) || filepath.VolumeName(target) != "" {
				newRoot, targetSegs := splitPathFromRoot(target)
				cur = newRoot
				pending = append(targetSegs, pending...)
			} else {
				relNorm := strings.ReplaceAll(target, `\`, "/")
				relParts := strings.Split(relNorm, "/")
				merged := make([]string, 0, len(relParts)+len(pending))
				for _, p := range relParts {
					if p != "" && p != "." {
						merged = append(merged, p)
					}
				}
				pending = append(merged, pending...)
			}
			continue
		}

		cur = next
	}

	if _, err := os.Lstat(cur); err != nil {
		return "", err
	}
	return cur, nil
}

// containPath joins rel onto base and rejects absolute paths, drive/stream colons,
// reserved device names, traversal outside base, and symlinks/junctions escaping base.
func containPath(base, rel string) (string, error) {
	if rel == "" {
		return "", errors.New("path must not be empty")
	}
	if strings.ContainsRune(rel, 0) || strings.Contains(rel, ":") {
		return "", fmt.Errorf("path %q contains forbidden characters", rel)
	}
	if filepath.IsAbs(rel) || filepath.VolumeName(rel) != "" || strings.HasPrefix(rel, "/") || strings.HasPrefix(rel, `\`) {
		return "", fmt.Errorf("path %q must be relative", rel)
	}
	cleanBase := filepath.Clean(base)
	joined := filepath.Join(cleanBase, rel)
	if !isWithinDir(cleanBase, joined) {
		return "", fmt.Errorf("path %q escapes %s", rel, base)
	}

	if _, err := os.Lstat(cleanBase); err != nil {
		return "", fmt.Errorf("cannot access base directory %s: %w", base, err)
	}
	realBase, err := resolveLinkOrPath(cleanBase)
	if err != nil {
		return "", fmt.Errorf("cannot resolve base directory %s: %w", base, err)
	}

	cur := realBase
	missingAncestor := false
	norm := strings.ReplaceAll(rel, `\`, "/")
	for _, part := range strings.Split(norm, "/") {
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			cur = filepath.Dir(cur)
			if !isWithinDir(realBase, cur) {
				return "", fmt.Errorf("path %q escapes %s", rel, base)
			}
			continue
		}
		if strings.HasSuffix(part, ".") || strings.HasSuffix(part, " ") || isWindowsReservedDeviceStem(part) {
			return "", fmt.Errorf("path %q contains forbidden segment %q", rel, part)
		}
		next := filepath.Join(cur, part)
		if missingAncestor {
			cur = next
			if !isWithinDir(realBase, cur) {
				return "", fmt.Errorf("path %q escapes %s", rel, base)
			}
			continue
		}
		if _, err := os.Lstat(next); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				missingAncestor = true
				cur = next
				if !isWithinDir(realBase, cur) {
					return "", fmt.Errorf("path %q escapes %s", rel, base)
				}
				continue
			}
			return "", fmt.Errorf("path %q: %w", rel, err)
		}
		resolvedNext, err := resolveLinkOrPath(next)
		if err != nil {
			return "", fmt.Errorf("path %q traverses broken symlink: %w", rel, err)
		}
		if !isWithinDir(realBase, resolvedNext) {
			return "", fmt.Errorf("path %q escapes %s via symlink", rel, base)
		}
		cur = resolvedNext
	}
	return cur, nil
}
