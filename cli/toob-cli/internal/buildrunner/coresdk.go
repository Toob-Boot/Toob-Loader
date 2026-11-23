package buildrunner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/toob-boot/toob/internal/apiclient"
	"github.com/toob-boot/toob/internal/archiveutil"
	"github.com/toob-boot/toob/internal/filelock"
	"github.com/toob-boot/toob/internal/lockfile"
	"github.com/toob-boot/toob/internal/manifest"
	"github.com/toob-boot/toob/internal/paths"
	"github.com/toob-boot/toob/internal/registry"
	"github.com/toob-boot/toob/internal/toolchain"
)

const (
	coreSDKDownloadTimeout  = 120 * time.Second
	maxCoreSDKArchiveBytes  = 512 * 1024 * 1024
	emptySHA256Hex          = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	coreSDKVersionStampFile = ".toob_core_version"
	coreSDKDigestStampFile  = ".toob_core_sha256"
	devMonorepoWalkLimit    = 6
)

// CoreSDKOptions configures Core SDK resolution, verification, and caching.
type CoreSDKOptions struct {
	ProjectRoot    string
	Version        string
	RegistryURL    string
	Index          *registry.Index
	Lock           *lockfile.Lockfile
	ExpectedSHA256 string
	CompilerDirEnv string
	DevMode        bool
	Locked         bool
}

// SelectCoreSDKVersion resolves the Core SDK version pin matching device.toml,
// toob.lock, and the registry index before invoking resolve.Resolve.
func SelectCoreSDKVersion(dt *manifest.DeviceToml, lf *lockfile.Lockfile, idx *registry.Index, locked bool) (string, error) {
	if locked {
		if lf == nil || strings.TrimSpace(lf.Environment.CoreSDK) == "" {
			return "", errors.New("--locked requires environment.core_sdk in toob.lock")
		}
		if dt != nil {
			devVer := strings.TrimSpace(dt.Build.CoreSDK)
			if devVer != "" && devVer != "latest" && devVer != "toob-boot" &&
				NormalizeCoreSDKVersion(devVer) != NormalizeCoreSDKVersion(lf.Environment.CoreSDK) {
				return "", fmt.Errorf("device.toml core_sdk %q conflicts with toob.lock %q under --locked", devVer, lf.Environment.CoreSDK)
			}
		}
		return strings.TrimSpace(lf.Environment.CoreSDK), nil
	}

	raw := ""
	if dt != nil {
		raw = strings.TrimSpace(dt.Build.CoreSDK)
	}
	if raw == "" && lf != nil {
		raw = strings.TrimSpace(lf.Environment.CoreSDK)
	}
	if raw == "" {
		raw = "latest"
	}

	if raw == "latest" || raw == "toob-boot" {
		if best := latestCoreSDKVersion(idx); best != "" {
			return best, nil
		}
		if lf != nil && strings.TrimSpace(lf.Environment.CoreSDK) != "" {
			return strings.TrimSpace(lf.Environment.CoreSDK), nil
		}
		return "", errors.New("unable to resolve latest core SDK version from registry index")
	}

	return raw, nil
}

// NormalizeCoreSDKVersion normalizes tags like "core/v0.0.1" or "v0.0.1" to "0.0.1".
func NormalizeCoreSDKVersion(raw string) string {
	v := strings.TrimSpace(raw)
	v = strings.TrimPrefix(v, "core/")
	v = strings.TrimPrefix(v, "v")
	return v
}

// EnsureCoreSDK locates, downloads if needed, verifies SHA-256, and returns
// the local Core SDK directory path and verified lowercase hex digest.
func EnsureCoreSDK(ctx context.Context, opts CoreSDKOptions) (string, string, error) {
	if err := ctx.Err(); err != nil {
		return "", "", err
	}

	compilerDir := strings.TrimSpace(opts.CompilerDirEnv)
	if compilerDir == "" {
		compilerDir = strings.TrimSpace(os.Getenv("TOOB_COMPILER_DIR"))
	}

	expectedSHA, err := resolveExpectedCoreSDKSHA(opts)
	if err != nil {
		return "", "", err
	}

	if compilerDir != "" {
		return validateOverrideCoreSDKDir(compilerDir, opts.Version, expectedSHA, opts)
	}

	if opts.DevMode || paths.IsDevMode() {
		if monoCore := findMonorepoCoreDir(opts.ProjectRoot); monoCore != "" {
			return monoCore, "", nil
		}
	}

	rawVer := strings.TrimSpace(opts.Version)
	if rawVer == "" {
		return "", "", errors.New("core SDK version is required (or pass --dev inside the Toob-Loader monorepo)")
	}

	normVer := NormalizeCoreSDKVersion(rawVer)
	if normVer == "" || strings.ContainsAny(normVer, `/\`) || normVer == "." || normVer == ".." {
		return "", "", fmt.Errorf("invalid core SDK version %q", opts.Version)
	}

	toobHome, err := paths.ToobHome()
	if err != nil {
		return "", "", fmt.Errorf("resolve TOOB_HOME: %w", err)
	}

	coreRoot := filepath.Join(toobHome, "core")
	if mkErr := os.MkdirAll(coreRoot, 0o700); mkErr != nil {
		return "", "", fmt.Errorf("create core SDK root %s: %w", coreRoot, mkErr)
	}

	sdkDir, err := archiveutil.SafeJoin(coreRoot, normVer)
	if err != nil {
		return "", "", fmt.Errorf("resolve core SDK cache path: %w", err)
	}

	unlock, err := filelock.Lock(ctx, sdkDir+".lock")
	if err != nil {
		return "", "", fmt.Errorf("lock core SDK cache: %w", err)
	}
	defer func() {
		_ = unlock()
	}()

	if isRegularFile(filepath.Join(sdkDir, "CMakeLists.txt")) {
		verifiedSHA, cacheErr := verifyCachedCoreSDK(sdkDir, expectedSHA, opts)
		if cacheErr != nil {
			return "", "", cacheErr
		}
		return sdkDir, verifiedSHA, nil
	}

	if !opts.DevMode && expectedSHA == "" {
		return "", "", fmt.Errorf("no expected SHA-256 digest for core SDK %q (required outside --dev)", rawVer)
	}

	regURL := strings.TrimSpace(opts.RegistryURL)
	if regURL == "" {
		regURL = apiclient.DefaultBaseURL
	}

	actualSHA, err := downloadAndExtractCoreSDK(ctx, regURL, normVer, expectedSHA, coreRoot, sdkDir, opts.DevMode)
	if err != nil {
		return "", "", err
	}
	return sdkDir, actualSHA, nil
}

func validateOverrideCoreSDKDir(compilerDir, version, expectedSHA string, opts CoreSDKOptions) (string, string, error) {
	absDir, err := filepath.Abs(compilerDir)
	if err != nil {
		return "", "", fmt.Errorf("resolve TOOB_COMPILER_DIR %q: %w", compilerDir, err)
	}
	if !isRegularFile(filepath.Join(absDir, "CMakeLists.txt")) {
		return "", "", fmt.Errorf("TOOB_COMPILER_DIR %s does not contain CMakeLists.txt", absDir)
	}

	if version != "" && !isSymbolicDevVersion(version) {
		if data, readErr := readFileInDir(absDir, coreSDKVersionStampFile); readErr == nil {
			foundVer := strings.TrimSpace(string(data))
			if foundVer != "" && NormalizeCoreSDKVersion(foundVer) != NormalizeCoreSDKVersion(version) {
				return "", "", fmt.Errorf("TOOB_COMPILER_DIR version %q does not match required core SDK %q", foundVer, version)
			}
		}
	}

	if !opts.DevMode {
		if expectedSHA == "" {
			return "", "", fmt.Errorf("core SDK digest required outside --dev when using TOOB_COMPILER_DIR %s", absDir)
		}
		cachedSHA, err := readCoreSDKDigestStamp(absDir)
		if err != nil {
			return "", "", fmt.Errorf("TOOB_COMPILER_DIR %s cannot verify integrity: %w", absDir, err)
		}
		if !strings.EqualFold(cachedSHA, expectedSHA) {
			return "", "", fmt.Errorf("TOOB_COMPILER_DIR %s SHA-256 %s mismatches expected %s", absDir, cachedSHA, expectedSHA)
		}
		return absDir, cachedSHA, nil
	}

	cachedSHA, _ := readCoreSDKDigestStamp(absDir)
	return absDir, cachedSHA, nil
}

func verifyCachedCoreSDK(sdkDir, expectedSHA string, opts CoreSDKOptions) (string, error) {
	cachedSHA, stampErr := readCoreSDKDigestStamp(sdkDir)
	if stampErr != nil {
		if opts.DevMode && expectedSHA == "" {
			return "", nil
		}
		return "", fmt.Errorf("cached core SDK %s missing verified SHA-256 stamp (remove directory to re-download): %w", sdkDir, stampErr)
	}

	if expectedSHA != "" && !strings.EqualFold(cachedSHA, expectedSHA) {
		return "", fmt.Errorf("cached core SDK %s SHA-256 mismatch: expected %s, got %s (remove directory to re-download)", sdkDir, expectedSHA, cachedSHA)
	}
	return cachedSHA, nil
}

func downloadAndExtractCoreSDK(ctx context.Context, regURL, normVer, expectedSHA, coreRoot, sdkDir string, devMode bool) (string, error) {
	client := apiclient.NewForBaseURL(regURL, coreSDKDownloadTimeout)
	rc, err := client.DownloadRelease(ctx, "core", normVer, "core-source.tar.gz")
	if err != nil {
		return "", fmt.Errorf("download core SDK %s from %s: %w", normVer, regURL, err)
	}
	defer func() {
		_ = rc.Close()
	}()

	tmpFile, err := os.CreateTemp(coreRoot, ".core-sdk-*.tar.gz")
	if err != nil {
		return "", fmt.Errorf("create temp archive for core SDK: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer func() {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
	}()

	hasher := sha256.New()
	limited := io.LimitReader(rc, maxCoreSDKArchiveBytes+1)
	written, err := io.Copy(io.MultiWriter(tmpFile, hasher), limited)
	if err != nil {
		return "", fmt.Errorf("stream core SDK archive: %w", err)
	}
	if written > maxCoreSDKArchiveBytes {
		return "", fmt.Errorf("core SDK archive exceeds %d byte limit", maxCoreSDKArchiveBytes)
	}

	actualSHA := hex.EncodeToString(hasher.Sum(nil))
	if actualSHA == emptySHA256Hex || written == 0 {
		return "", errors.New("downloaded core SDK archive is empty")
	}
	if expectedSHA != "" && !strings.EqualFold(actualSHA, expectedSHA) {
		return "", fmt.Errorf("core SDK %s SHA-256 mismatch: expected %s, got %s", normVer, expectedSHA, actualSHA)
	}
	if expectedSHA == "" && !devMode {
		return "", fmt.Errorf("refusing unverified core SDK %s download outside --dev", normVer)
	}

	if _, seekErr := tmpFile.Seek(0, io.SeekStart); seekErr != nil {
		return "", fmt.Errorf("rewind core SDK archive: %w", seekErr)
	}

	stageDir, err := os.MkdirTemp(coreRoot, ".core-sdk-stage-*")
	if err != nil {
		return "", fmt.Errorf("create staging dir for core SDK: %w", err)
	}
	cleanupStage := true
	defer func() {
		if cleanupStage {
			_ = os.RemoveAll(stageDir)
		}
	}()

	if extractErr := registry.ExtractTarball(tmpFile, stageDir); extractErr != nil {
		return "", fmt.Errorf("extract core SDK archive: %w", extractErr)
	}
	_ = tmpFile.Close()

	if !isRegularFile(filepath.Join(stageDir, "CMakeLists.txt")) {
		return "", fmt.Errorf("extracted core SDK %s missing CMakeLists.txt", normVer)
	}

	if writeErr := os.WriteFile(filepath.Join(stageDir, coreSDKVersionStampFile), []byte(normVer+"\n"), 0o600); writeErr != nil {
		return "", fmt.Errorf("write core SDK version stamp: %w", writeErr)
	}
	if writeErr := os.WriteFile(filepath.Join(stageDir, coreSDKDigestStampFile), []byte(actualSHA+"\n"), 0o600); writeErr != nil {
		return "", fmt.Errorf("write core SDK digest stamp: %w", writeErr)
	}

	if renameErr := toolchain.RetryWindowsLocks(func() error {
		return os.Rename(stageDir, sdkDir)
	}); renameErr != nil {
		return "", fmt.Errorf("install core SDK to %s: %w", sdkDir, renameErr)
	}
	cleanupStage = false
	return actualSHA, nil
}

func resolveExpectedCoreSDKSHA(opts CoreSDKOptions) (string, error) {
	explicit := strings.TrimSpace(opts.ExpectedSHA256)
	if explicit == "" {
		explicit = strings.TrimSpace(os.Getenv("TOOB_CORE_SDK_SHA256"))
	}

	indexSHA := lookupCoreSDKIndexSHA(opts.Index, opts.Version)

	lockSHA := ""
	if opts.Lock != nil {
		lockSHA = strings.TrimSpace(opts.Lock.Environment.CoreSDKSHA256)
	}

	if opts.Locked {
		if !opts.DevMode && lockSHA == "" {
			return "", errors.New("--locked requires environment.core_sdk_sha256 in toob.lock")
		}
		if lockSHA != "" && indexSHA != "" && !strings.EqualFold(lockSHA, indexSHA) {
			return "", fmt.Errorf("toob.lock environment.core_sdk_sha256 (%s) conflicts with registry index (%s)", lockSHA, indexSHA)
		}
	}

	candidates := []struct {
		source string
		val    string
	}{
		{"explicit digest", explicit},
		{"toob.lock environment.core_sdk_sha256", lockSHA},
		{"registry index ecosystem.core_sdk_sha256", indexSHA},
	}

	chosen := ""
	for _, cand := range candidates {
		if cand.val == "" {
			continue
		}
		if !isValidSHA256Hex(cand.val) {
			return "", fmt.Errorf("invalid SHA-256 digest in %s: %q", cand.source, cand.val)
		}
		norm := strings.ToLower(cand.val)
		if chosen == "" {
			chosen = norm
		}
	}
	return chosen, nil
}

func lookupCoreSDKIndexSHA(idx *registry.Index, version string) string {
	if idx == nil || idx.Ecosystem == nil || len(idx.Ecosystem.CoreSDKSha256) == 0 || strings.TrimSpace(version) == "" {
		return ""
	}
	raw := strings.TrimSpace(version)
	norm := NormalizeCoreSDKVersion(raw)
	keys := []string{
		raw,
		strings.TrimPrefix(raw, "core/"),
		"core/" + strings.TrimPrefix(raw, "core/"),
		norm,
		"v" + norm,
		"core/v" + norm,
	}
	for _, k := range keys {
		if v := strings.TrimSpace(idx.Ecosystem.CoreSDKSha256[k]); v != "" {
			return v
		}
	}
	return ""
}

func readCoreSDKDigestStamp(dir string) (string, error) {
	data, err := readFileInDir(dir, coreSDKDigestStampFile)
	if err != nil {
		return "", err
	}
	digest := strings.ToLower(strings.TrimSpace(string(data)))
	if !isValidSHA256Hex(digest) {
		return "", fmt.Errorf("invalid SHA-256 stamp %q", digest)
	}
	return digest, nil
}

func readFileInDir(dir, name string) ([]byte, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = root.Close()
	}()
	return root.ReadFile(name)
}

func isValidSHA256Hex(s string) bool {
	if len(s) != 64 || strings.EqualFold(s, emptySHA256Hex) {
		return false
	}
	decoded, err := hex.DecodeString(s)
	return err == nil && len(decoded) == 32
}

func isSymbolicDevVersion(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "main", "dev", "latest", "toob-boot":
		return true
	default:
		return false
	}
}

func findMonorepoCoreDir(startDir string) string {
	if strings.TrimSpace(startDir) == "" {
		return ""
	}
	cur, err := filepath.Abs(startDir)
	if err != nil {
		return ""
	}
	for range devMonorepoWalkLimit {
		if isRegularFile(filepath.Join(cur, "CMakeLists.txt")) &&
			isRegularFile(filepath.Join(cur, "toobloader", "core", "hal_contract.json")) {
			return cur
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			break
		}
		cur = parent
	}
	return ""
}

func latestCoreSDKVersion(idx *registry.Index) string {
	if idx == nil || idx.Ecosystem == nil || len(idx.Ecosystem.CoreSDK) == 0 {
		return ""
	}
	best := ""
	for _, cand := range idx.Ecosystem.CoreSDK {
		if cand == "" {
			continue
		}
		if best == "" || compareSemverLike(cand, best) > 0 {
			best = cand
		}
	}
	return best
}

func compareSemverLike(a, b string) int {
	pa := parseSemverParts(a)
	pb := parseSemverParts(b)
	for i := range 3 {
		if pa[i] != pb[i] {
			if pa[i] > pb[i] {
				return 1
			}
			return -1
		}
	}
	return strings.Compare(NormalizeCoreSDKVersion(a), NormalizeCoreSDKVersion(b))
}

func parseSemverParts(raw string) [3]int {
	s := NormalizeCoreSDKVersion(raw)
	if idx := strings.IndexAny(s, "-+"); idx >= 0 {
		s = s[:idx]
	}
	parts := strings.Split(s, ".")
	var out [3]int
	for i := 0; i < 3 && i < len(parts); i++ {
		if n, err := strconv.Atoi(parts[i]); err == nil {
			out[i] = n
		}
	}
	return out
}
