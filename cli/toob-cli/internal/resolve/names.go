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
// so that neither separators nor traversal can leave the registry root.
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

func isWithinDir(base, candidate string) bool {
	rel, err := filepath.Rel(base, candidate)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

func resolveLinkOrPath(path string) (string, error) {
	cur := path
	for range 40 {
		fi, err := os.Lstat(cur)
		if err != nil {
			return "", err
		}
		if fi.Mode()&fs.ModeSymlink != 0 {
			return filepath.EvalSymlinks(cur)
		}
		if target, rlErr := os.Readlink(cur); rlErr == nil {
			target = strings.TrimPrefix(target, `\??\`)
			target = strings.TrimPrefix(target, `\\?\`)
			if !filepath.IsAbs(target) {
				target = filepath.Join(filepath.Dir(cur), target)
			}
			cur = filepath.Clean(target)
			continue
		}
		return filepath.EvalSymlinks(cur)
	}
	return "", fmt.Errorf("too many link indirections at %s", path)
}

// Contain joins rel onto base and rejects absolute paths, drive/stream colons,
// lexical traversal outside base, and symbolic links (or junctions) escaping base on disk.
func Contain(base, rel string) (string, error) {
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
	joined := filepath.Join(base, rel)
	if !isWithinDir(cleanBase, joined) {
		return "", fmt.Errorf("path %q escapes %s", rel, base)
	}

	if _, err := os.Lstat(cleanBase); err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return "", fmt.Errorf("cannot stat base directory %s: %w", base, err)
		}
		return joined, nil
	}

	realBase, err := resolveLinkOrPath(cleanBase)
	if err != nil {
		return "", fmt.Errorf("cannot resolve base directory %s: %w", base, err)
	}
	cur := realBase
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
		next := filepath.Join(cur, part)
		if _, err := os.Lstat(next); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				cur = next
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
	return joined, nil
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
	// #nosec G304 -- path is resolved via Contain() and verified as a bounded regular file above.
	f, err := os.Open(path)
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
		seen := make(map[string]struct{})
		for dec.More() {
			kTok, err := dec.Token()
			if err != nil {
				return err
			}
			key, ok := kTok.(string)
			if !ok {
				return fmt.Errorf("expected string object key, got %T", kTok)
			}
			if _, dup := seen[key]; dup {
				return fmt.Errorf("duplicate JSON key %q", key)
			}
			seen[key] = struct{}{}
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
