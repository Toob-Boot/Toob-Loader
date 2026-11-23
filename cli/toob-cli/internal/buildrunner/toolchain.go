package buildrunner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/toob-boot/toob/internal/resolve"
	"github.com/toob-boot/toob/internal/toolchain"
)

const maxCompilerVersionBytes = 64 * 1024

// ResolvedToolchain holds the verified toolchain binary directory, C compiler
// executable path, and cryptographic digest for lockfile recording.
type ResolvedToolchain struct {
	BinDir         string
	CMakePathArg   string
	CompilerBinary string
	DigestSHA256   string
}

// ProvisionToolchain resolves, provisions (unless overridden or locked), and
// verifies the target compiler toolchain against MinCompiler and ExpectedVersion.
func ProvisionToolchain(ctx context.Context, plan *resolve.Plan, regDir, toolchainPathOverride string, locked bool) (*ResolvedToolchain, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if plan == nil {
		return nil, errors.New("provision toolchain: resolved plan is nil")
	}

	override := strings.TrimSpace(toolchainPathOverride)
	if locked && override != "" {
		return nil, errors.New("--toolchain-path cannot be combined with --locked builds")
	}

	tc := plan.Toolchain
	var binDir string

	switch {
	case override != "":
		resolved, err := resolveOverrideToolchainBinDir(override, tc)
		if err != nil {
			return nil, err
		}
		binDir = resolved
	case strings.TrimSpace(tc.Name) != "":
		binDir = toolchain.FindCachedToolchainBinDir(tc.Name, tc.Prefix, tc.CompilerBinary, tc.ExpectedVersion, tc.UpstreamVersion)
		if binDir == "" {
			ensured, err := toolchain.EnsureToolchain(ctx, tc.Name, tc.Prefix, tc.CompilerBinary, tc.ExpectedVersion, regDir)
			if err != nil {
				return nil, fmt.Errorf("ensure toolchain %s: %w", tc.Name, err)
			}
			binDir = ensured
		}
	default:
		// Host/native builds without a registry toolchain name probe system PATH.
		ccPath, err := lookupHostCompiler(tc)
		if err != nil {
			return nil, err
		}
		binDir = filepath.Dir(ccPath)
	}

	ccPath, err := findCompilerExecutable(binDir, tc)
	if err != nil {
		return nil, err
	}

	if verErr := VerifyCompilerVersion(ctx, ccPath, tc); verErr != nil {
		return nil, verErr
	}

	digest, err := fileSHA256Hex(ccPath)
	if err != nil {
		return nil, fmt.Errorf("hash compiler binary %s: %w", ccPath, err)
	}

	cmakeRoot := binDir
	if strings.EqualFold(filepath.Base(binDir), "bin") {
		cmakeRoot = filepath.Dir(binDir)
	}
	cmakeArg := filepath.ToSlash(cmakeRoot)
	if err := ValidateCMakeArgPath(cmakeArg, "toolchain path"); err != nil {
		return nil, err
	}

	return &ResolvedToolchain{
		BinDir:         binDir,
		CMakePathArg:   cmakeArg,
		CompilerBinary: ccPath,
		DigestSHA256:   "sha256:" + digest,
	}, nil
}

// VerifyCompilerVersion executes "<cc> --version", verifies MinCompiler lower
// bounds via resolve.CheckMinCompiler, and enforces exact bounded vendor
// release token matches (or xPack revision pins) when ExpectedVersion is set.
func VerifyCompilerVersion(ctx context.Context, ccPath string, tc resolve.Toolchain) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if strings.TrimSpace(ccPath) == "" {
		return errors.New("compiler executable path is empty")
	}
	if !isRegularFile(ccPath) {
		return fmt.Errorf("compiler executable not found: %s", ccPath)
	}

	if strings.TrimSpace(tc.MinCompiler) == "" && strings.TrimSpace(tc.ExpectedVersion) == "" {
		return nil
	}

	out, err := runBoundedCommand(ctx, ccPath, "--version")
	if err != nil {
		return fmt.Errorf("query compiler version via %s --version: %w", ccPath, err)
	}

	if strings.TrimSpace(tc.MinCompiler) != "" {
		baseVer := ExtractCompilerBaseVersion(out)
		if baseVer == "" {
			if dumpOut, dumpErr := runBoundedCommand(ctx, ccPath, "-dumpfullversion", "-dumpversion"); dumpErr == nil {
				baseVer = ExtractCompilerBaseVersion(dumpOut)
			}
		}
		if baseVer == "" {
			return fmt.Errorf("unable to extract compiler SemVer from %s --version output", filepath.Base(ccPath))
		}
		if err := resolve.CheckMinCompiler(tc.Name, baseVer, tc.MinCompiler); err != nil {
			return err
		}
	}

	if expected := strings.TrimSpace(tc.ExpectedVersion); expected != "" {
		if !matchesExpectedCompilerVersion(out, ccPath, expected) {
			firstLine, _, _ := strings.Cut(strings.TrimSpace(out), "\n")
			return fmt.Errorf("compiler version mismatch for %s: expected pinned release token %q in %q", tc.Name, expected, SanitizeTerminalOutput(firstLine))
		}
	}

	return nil
}

// ExtractCompilerBaseVersion extracts the base X.Y[.Z] SemVer token from the
// first line of --version output, stripping parenthesized vendor build metadata
// so vendor timestamps do not shadow the base compiler version.
func ExtractCompilerBaseVersion(versionOutput string) string {
	firstLine, _, _ := strings.Cut(strings.TrimSpace(versionOutput), "\n")
	stripped := stripParenthesizedSegments(firstLine)
	if v, err := resolve.ExtractCompilerSemver(stripped); err == nil {
		return v.String()
	}
	if v, err := resolve.ExtractCompilerSemver(firstLine); err == nil {
		return v.String()
	}
	return ""
}

// ValidateCMakeArgPath validates that a path passed to CMake -D arguments does
// not contain characters that corrupt CMake list expansion or command parsing.
func ValidateCMakeArgPath(path, label string) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("%s must not be empty", label)
	}
	if strings.ContainsRune(path, ';') {
		return fmt.Errorf("%s %q contains invalid ';' character", label, path)
	}
	if strings.ContainsAny(path, "\r\n\x00") {
		return fmt.Errorf("%s %q contains control characters", label, path)
	}
	return nil
}

// ClassifyBuildError maps raw CMake/Ninja failure output into concise actionable
// diagnostics after sanitizing terminal control sequences.
func ClassifyBuildError(rawOutput string) string {
	clean := SanitizeTerminalOutput(rawOutput)
	lower := strings.ToLower(clean)

	switch {
	case strings.Contains(lower, "could not find cmake") || strings.Contains(lower, "cmake: command not found"):
		return "CMake executable not found in PATH or Visual Studio Build Tools"
	case strings.Contains(lower, "cmake_make_program") && strings.Contains(lower, "ninja"):
		return "Ninja build tool not found in PATH or Visual Studio Build Tools"
	case strings.Contains(lower, "region `flash' overflowed") || strings.Contains(lower, "region 'flash' overflowed"):
		return "Firmware section overflowed target flash linker region; check partition budget and optimization flags"
	case strings.Contains(lower, "region `iram' overflowed") || strings.Contains(lower, "region `dram' overflowed"):
		return "Firmware section overflowed target SRAM region; inspect static allocations"
	case strings.Contains(lower, "unknown type name") || strings.Contains(lower, "implicit declaration of function"):
		return "C compilation error in firmware or HAL sources (see sanitized compiler diagnostics)"
	default:
		lines := strings.Split(strings.TrimSpace(clean), "\n")
		const maxTailLines = 12
		if len(lines) > maxTailLines {
			lines = lines[len(lines)-maxTailLines:]
		}
		return strings.Join(lines, "\n")
	}
}

func resolveOverrideToolchainBinDir(override string, tc resolve.Toolchain) (string, error) {
	absPath, err := filepath.Abs(override)
	if err != nil {
		return "", fmt.Errorf("resolve --toolchain-path %q: %w", override, err)
	}
	info, err := os.Stat(absPath)
	if err != nil {
		return "", fmt.Errorf("--toolchain-path %s does not exist: %w", absPath, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("--toolchain-path %s must be a directory", absPath)
	}

	if cc, findErr := findCompilerExecutable(absPath, tc); findErr == nil && cc != "" {
		return absPath, nil
	}
	binSub := filepath.Join(absPath, "bin")
	if cc, findErr := findCompilerExecutable(binSub, tc); findErr == nil && cc != "" {
		return binSub, nil
	}
	return "", fmt.Errorf("--toolchain-path %s does not contain expected compiler binary for %s", absPath, tc.Name)
}

func lookupHostCompiler(tc resolve.Toolchain) (string, error) {
	for _, name := range compilerCandidateNames(tc) {
		if path, err := exec.LookPath(name); err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("compiler binary for toolchain %q not found in PATH", tc.Name)
}

func findCompilerExecutable(dir string, tc resolve.Toolchain) (string, error) {
	if strings.TrimSpace(dir) == "" {
		return "", errors.New("toolchain bin directory is empty")
	}
	for _, name := range compilerCandidateNames(tc) {
		candidate := filepath.Join(dir, name)
		if isRegularFile(candidate) {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("compiler executable not found in %s (expected %v)", dir, compilerCandidateNames(tc))
}

func compilerCandidateNames(tc resolve.Toolchain) []string {
	var raw []string
	if bin := strings.TrimSpace(tc.CompilerBinary); bin != "" {
		raw = append(raw, bin)
	}
	if prefix := strings.TrimSpace(tc.Prefix); prefix != "" {
		raw = append(raw, prefix+"gcc", prefix+"clang")
	}
	if len(raw) == 0 {
		raw = append(raw, "gcc", "clang", "cc")
	}

	var names []string
	for _, item := range raw {
		if runtime.GOOS == "windows" && !strings.HasSuffix(strings.ToLower(item), ".exe") {
			names = append(names, item+".exe")
		}
		names = append(names, item)
	}
	return names
}

func runBoundedCommand(ctx context.Context, exe string, args ...string) (string, error) {
	// #nosec G204 -- exe is resolved from validated toolchain dir or LookPath, args are fixed compiler flags.
	cmd := exec.CommandContext(ctx, exe, args...)
	var out bytes.Buffer
	limited := &limitedWriter{w: &out, remaining: maxCompilerVersionBytes}
	cmd.Stdout = limited
	cmd.Stderr = limited
	if err := cmd.Run(); err != nil {
		return "", err
	}
	return out.String(), nil
}

type limitedWriter struct {
	w         io.Writer
	remaining int
}

func (lw *limitedWriter) Write(p []byte) (int, error) {
	if lw.remaining <= 0 {
		return len(p), nil
	}
	chunk := p
	if len(chunk) > lw.remaining {
		chunk = chunk[:lw.remaining]
	}
	if _, err := lw.w.Write(chunk); err != nil {
		return 0, err
	}
	lw.remaining -= len(chunk)
	return len(p), nil
}

func stripParenthesizedSegments(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	depth := 0
	for i := range len(s) {
		switch s[i] {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		default:
			if depth == 0 {
				b.WriteByte(s[i])
			}
		}
	}
	return b.String()
}

func containsBoundedVersionToken(output, expected string) bool {
	haystack := strings.ToLower(output)
	needle := strings.ToLower(strings.TrimSpace(expected))
	if needle == "" {
		return false
	}

	searchStart := 0
	for {
		idx := strings.Index(haystack[searchStart:], needle)
		if idx < 0 {
			return false
		}
		absIdx := searchStart + idx
		endIdx := absIdx + len(needle)

		leftOK := absIdx == 0 || !isVersionTokenChar(haystack[absIdx-1])
		rightOK := endIdx == len(haystack) || !isVersionTokenChar(haystack[endIdx])
		if leftOK && rightOK {
			return true
		}
		searchStart = absIdx + 1
	}
}

func isVersionTokenChar(ch byte) bool {
	return (ch >= 'a' && ch <= 'z') ||
		(ch >= '0' && ch <= '9') ||
		ch == '.' || ch == '_' || ch == '-' || ch == '+'
}

func matchesExpectedCompilerVersion(out, ccPath, expected string) bool {
	if containsBoundedVersionToken(out, expected) {
		return true
	}
	baseSemVer, ok := splitXPackRevisionPin(expected)
	if !ok {
		return false
	}
	firstLine, _, _ := strings.Cut(strings.TrimSpace(out), "\n")
	if !strings.Contains(strings.ToLower(firstLine), "xpack") {
		return false
	}
	if ExtractCompilerBaseVersion(firstLine) != baseSemVer || !containsBoundedVersionToken(firstLine, baseSemVer) {
		return false
	}
	return !pathHasConflictingXPackPin(ccPath, expected)
}

func splitXPackRevisionPin(pin string) (string, bool) {
	trimmed := strings.TrimSpace(pin)
	baseSemVer, rev, hasDash := strings.Cut(trimmed, "-")
	if !hasDash || !isDottedDigits(baseSemVer, 3) || !isDottedDigits(rev, 2) {
		return "", false
	}
	return baseSemVer, true
}

func isDottedDigits(val string, partCount int) bool {
	parts := strings.Split(val, ".")
	if len(parts) != partCount {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		for i := range len(part) {
			if part[i] < '0' || part[i] > '9' {
				return false
			}
		}
	}
	return true
}

func pathHasConflictingXPackPin(ccPath, expected string) bool {
	if strings.TrimSpace(ccPath) == "" {
		return false
	}
	dir := filepath.Dir(filepath.Clean(ccPath))
	for range 4 {
		seg := filepath.Base(dir)
		if seg == "" || seg == "." || seg == "/" || seg == "\\" {
			break
		}
		if pin, ok := extractSegmentXPackPin(seg); ok && !strings.EqualFold(pin, expected) {
			return true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return false
}

func extractSegmentXPackPin(seg string) (string, bool) {
	if _, ok := splitXPackRevisionPin(seg); ok {
		return seg, true
	}
	lastDash := strings.LastIndexByte(seg, '-')
	if lastDash <= 0 {
		return "", false
	}
	prevDash := strings.LastIndexByte(seg[:lastDash], '-')
	if prevDash < 0 {
		return "", false
	}
	candidate := seg[prevDash+1:]
	if _, ok := splitXPackRevisionPin(candidate); !ok {
		return "", false
	}
	return candidate, true
}

func fileSHA256Hex(path string) (string, error) {
	f, err := os.Open(path) // #nosec G304 -- validated regular file inside toolchain/project directory.
	if err != nil {
		return "", err
	}
	defer func() {
		_ = f.Close()
	}()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
