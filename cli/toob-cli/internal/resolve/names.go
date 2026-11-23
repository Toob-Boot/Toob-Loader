// Package resolve turns device.toml, the chip package and the registry index
// into a fully resolved, validated BuildPlan. Every declared package must
// resolve; nothing is skipped silently.
package resolve

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/toob-boot/toob/internal/archiveutil"
	manifestpkg "github.com/toob-boot/toob/internal/manifest"
)

const (
	maxManifestBytes = 4 << 20 // 4 MiB upper bound on manifest files
	maxJSONDepth     = 32
)

var (
	cIdentifierPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

	// reservedCWords mirrors toob-go-lib/build/names.go so resolve and build.Load
	// enforce identical C11/C23 keyword and preprocessor operator rejections.
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
	return cIdentifierPattern.MatchString(s) && !reservedCWords[s] && !strings.HasPrefix(s, "__builtin_")
}

// validateRelName validates a '/'-separated registry name segment by segment,
// delegating individual token validation to manifestpkg.ValidateName.
func validateRelName(kind, name string) error {
	if name == "" {
		return fmt.Errorf("%s name must not be empty", kind)
	}
	if strings.Contains(name, `\`) {
		return fmt.Errorf("invalid %s name %q: backslashes are not permitted", kind, name)
	}
	for _, segment := range strings.Split(name, "/") {
		if err := manifestpkg.ValidateName(kind, segment); err != nil {
			return fmt.Errorf("%w (in %q)", err, name)
		}
	}
	return nil
}

// validateHeaderRel validates a relative C header path declared in a package manifest.
func validateHeaderRel(h string) error {
	if err := validateRelName("header", h); err != nil {
		return err
	}
	if !strings.HasSuffix(h, ".h") {
		return fmt.Errorf("header %q must end with '.h'", h)
	}
	return nil
}

// validatePackageOrRelName accepts either a scoped package identifier
// (@scope/pkg) or a '/'-separated relative package path/name.
func validatePackageOrRelName(kind, ref string) error {
	if strings.HasPrefix(ref, "@") {
		return manifestpkg.ValidatePackageRef(kind, ref)
	}
	return validateRelName(kind, ref)
}

// Contain joins rel onto base and rejects empty paths, control/NUL bytes,
// drive/ADS colons, Windows reserved device stems, trailing dots/spaces, lexical
// '..' traversal outside base, and symlink/junction escapes on disk via os.Root.
func Contain(base, rel string) (string, error) {
	joined, relOS, err := archiveutil.SafeRelPath(base, rel)
	if err != nil {
		return "", fmt.Errorf("path %q escapes %s: %w", rel, base, err)
	}

	cleanBase := preserveExtendedUNCPrefix(filepath.Clean(base), base)
	if _, statErr := os.Lstat(cleanBase); statErr != nil {
		if errors.Is(statErr, fs.ErrNotExist) {
			return joined, nil
		}
		return "", fmt.Errorf("cannot stat base directory %s: %w", base, statErr)
	}

	root, openErr := os.OpenRoot(cleanBase)
	if openErr != nil {
		return "", fmt.Errorf("cannot open base directory %s: %w", base, openErr)
	}
	defer func() { _ = root.Close() }()

	// Validate intermediate anchors before '..' collapses them so a symlink like
	// "a/../b" where "a" escapes root cannot cancel out before os.Root inspects it.
	norm := strings.ReplaceAll(rel, `\`, "/")
	var built []string
	for _, part := range strings.Split(norm, "/") {
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			if len(built) > 0 {
				if statErr := checkRootPathContained(root, strings.Join(built, string(os.PathSeparator)), rel, base); statErr != nil {
					return "", statErr
				}
				built = built[:len(built)-1]
			}
			continue
		}
		built = append(built, part)
		if statErr := checkRootPathContained(root, strings.Join(built, string(os.PathSeparator)), rel, base); statErr != nil {
			return "", statErr
		}
	}

	if statErr := checkRootPathContained(root, relOS, rel, base); statErr != nil {
		return "", statErr
	}
	return joined, nil
}

func checkRootPathContained(root *os.Root, relOS, rawRel, base string) error {
	if relOS == "" || relOS == "." {
		return nil
	}
	if _, err := root.Stat(relOS); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("path %q escapes %s via symlink: %w", rawRel, base, err)
	}
	return nil
}

func preserveExtendedUNCPrefix(cleaned, orig string) string {
	// Retain Windows NT \??\UNC\ prefix when callers explicitly supply it.
	if strings.HasPrefix(orig, `\??\UNC\`) && !strings.HasPrefix(cleaned, `\??\UNC\`) {
		trimmed := strings.TrimPrefix(cleaned, `\`)
		return `\??\UNC\` + strings.TrimPrefix(trimmed, `??\UNC\`)
	}
	return cleaned
}

func readBoundedManifest(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if info.Size() > maxManifestBytes {
		return nil, fmt.Errorf("%s exceeds maximum manifest size (%d > %d bytes)", path, info.Size(), maxManifestBytes)
	}
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	data, readErr := io.ReadAll(io.LimitReader(f, maxManifestBytes+1))
	closeErr := f.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if int64(len(data)) > maxManifestBytes {
		return nil, fmt.Errorf("%s exceeds maximum manifest size (%d bytes)", path, maxManifestBytes)
	}
	return data, nil
}

func decodeStrictManifestJSON(path string, dst any) error {
	return decodeJSONFile(path, dst, true)
}

func decodeJSONFile(path string, dst any, strict bool) error {
	data, err := readBoundedManifest(path)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", path, err)
	}
	if err := validateJSONStructure(data); err != nil {
		return fmt.Errorf("failed to parse %s: %w", path, err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if strict {
		dec.DisallowUnknownFields()
	}
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("failed to parse %s: %w", path, err)
	}
	if tok, err := dec.Token(); !errors.Is(err, io.EOF) {
		if err != nil {
			return fmt.Errorf("failed to parse %s: %w", path, err)
		}
		return fmt.Errorf("failed to parse %s: unexpected trailing JSON token %v", path, tok)
	}
	return nil
}

func validateJSONStructure(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := walkJSONValue(dec, 0); err != nil {
		return err
	}
	if tok, err := dec.Token(); !errors.Is(err, io.EOF) {
		if err != nil {
			return err
		}
		return fmt.Errorf("unexpected trailing JSON token %v", tok)
	}
	return nil
}

func walkJSONValue(dec *json.Decoder, depth int) error {
	if depth > maxJSONDepth {
		return fmt.Errorf("JSON nesting exceeds maximum depth of %d", maxJSONDepth)
	}
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		// Reject case-colliding keys as well (CWE-436): encoding/json matches
		// struct fields case-insensitively when no exact match exists.
		seen := make(map[string]string)
		for dec.More() {
			kTok, err := dec.Token()
			if err != nil {
				return err
			}
			key, ok := kTok.(string)
			if !ok {
				return fmt.Errorf("expected string object key, got %T", kTok)
			}
			folded := strings.ToLower(key)
			if prev, dup := seen[folded]; dup {
				return fmt.Errorf("duplicate JSON key %q (conflicts with %q)", key, prev)
			}
			seen[folded] = key
			if err := walkJSONValue(dec, depth+1); err != nil {
				return err
			}
		}
		_, err := dec.Token()
		return err
	case '[':
		for dec.More() {
			if err := walkJSONValue(dec, depth+1); err != nil {
				return err
			}
		}
		_, err := dec.Token()
		return err
	default:
		return fmt.Errorf("unexpected delimiter %q", delim)
	}
}
