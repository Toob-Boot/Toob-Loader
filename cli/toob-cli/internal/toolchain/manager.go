// BOUNDARY TYPES: RegistryToolchain is mirrored in internal/ports/ports.go.
package toolchain

import (
	"archive/tar"
	"archive/zip"
	"cmp"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/ulikunitz/xz"

	"github.com/toob-boot/toob/internal/archiveutil"
	"github.com/toob-boot/toob/internal/filelock"
	"github.com/toob-boot/toob/internal/httputil"
	"github.com/toob-boot/toob/internal/paths"
	"github.com/toob-boot/toob/internal/ui"
)

const (
	maxToolchainArchiveBytes int64 = 2 << 30 // 2 GiB compressed archive download cap
	emptyFileSHA256                = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	lockWaitTimeout                = 30 * time.Minute
)

var (
	tcSingleTokenPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]*$`)
	tcSlugPattern        = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._+-]*$`)
	tcScopedRefPattern   = regexp.MustCompile(`^@[a-z0-9][a-z0-9_-]*/[a-z0-9][a-z0-9._+-]*$`)
)

func validateToken(label, val string) error {
	if val == "" {
		return fmt.Errorf("%s must not be empty", label)
	}
	if strings.Contains(val, "..") || !tcSingleTokenPattern.MatchString(val) {
		return fmt.Errorf("unsafe %s %q", label, val)
	}
	return nil
}

func validateToolchainSlug(val string) error {
	if val == "" || strings.Contains(val, "..") || !tcSlugPattern.MatchString(val) {
		return fmt.Errorf("unsafe toolchain slug %q", val)
	}
	return nil
}

func validateToolchainRef(label, val string) error {
	if val == "" {
		return fmt.Errorf("%s must not be empty", label)
	}
	if strings.Contains(val, "..") {
		return fmt.Errorf("unsafe %s %q", label, val)
	}
	if strings.HasPrefix(val, "@") {
		if !tcScopedRefPattern.MatchString(val) {
			return fmt.Errorf("unsafe scoped %s %q", label, val)
		}
		return nil
	}
	return validateToken(label, val)
}

// ToolchainSlug converts an unscoped or @scope/name toolchain package identifier
// into a collision-free single-segment filesystem directory name.
func ToolchainSlug(tcRef string) (string, error) {
	if err := validateToolchainRef("toolchain name", tcRef); err != nil {
		return "", err
	}
	if strings.HasPrefix(tcRef, "@") {
		scope, pkg, _ := strings.Cut(tcRef[1:], "/")
		return "_" + scope + "__" + pkg, nil
	}
	return tcRef, nil
}

// ToolchainDir resolves <toobHome>/toolchains/<goos>_<goarch>/<tcSlug>/<version>.
func ToolchainDir(toobHome, goos, goarch, tcRef, version string) (string, error) {
	if err := validateToken("host OS", goos); err != nil {
		return "", err
	}
	if err := validateToken("host arch", goarch); err != nil {
		return "", err
	}
	slug, err := ToolchainSlug(tcRef)
	if err != nil {
		return "", err
	}
	if err := validateToken("toolchain version", version); err != nil {
		return "", err
	}
	base := filepath.Join(toobHome, "toolchains")
	rel := filepath.ToSlash(filepath.Join(goos+"_"+goarch, slug, version))
	return archiveutil.SafeJoin(base, rel)
}

// RegistryToolchain defines the toolchain metadata and download URLs in registry.json.
type RegistryToolchain struct {
	Version         string            `json:"version"`
	UpstreamVersion string            `json:"upstream_version"`
	CompilerBinary  string            `json:"compiler_binary,omitempty"`
	URLs            map[string]string `json:"urls"`
	Sha256          map[string]string `json:"sha256"`
}

// RegistryConfig represents the toolchains section of registry.json.
type RegistryConfig struct {
	FormatVersion int                          `json:"format_version"`
	Toolchains    map[string]RegistryToolchain `json:"toolchains"`
}

func resolveToolchainEntry(refOrPrefix string, reg *RegistryConfig) (string, RegistryToolchain, bool) {
	if reg == nil || len(reg.Toolchains) == 0 {
		return "", RegistryToolchain{}, false
	}
	if info, ok := reg.Toolchains[refOrPrefix]; ok {
		return refOrPrefix, info, true
	}
	trimmed := strings.TrimSuffix(refOrPrefix, "-")
	if trimmed != "" {
		if info, ok := reg.Toolchains[trimmed]; ok {
			return trimmed, info, true
		}
	}
	return "", RegistryToolchain{}, false
}

// GetExpectedVersion returns the version specified in registry.json for a toolchain name or prefix.
func GetExpectedVersion(prefixOrRef, regDir string) string {
	data, err := os.ReadFile(filepath.Join(regDir, "registry.json"))
	if err != nil {
		return ""
	}
	var reg RegistryConfig
	if err := json.Unmarshal(data, &reg); err != nil {
		return ""
	}
	if _, tcInfo, ok := resolveToolchainEntry(prefixOrRef, &reg); ok {
		return tcInfo.Version
	}
	return ""
}

// FindCachedBinDir locates a cached toolchain's /bin directory for the current host OS/arch.
func FindCachedBinDir(prefixOrRef, expectedVersion, upstreamVersion string) string {
	tcName := strings.TrimSuffix(prefixOrRef, "-")
	if strings.HasPrefix(prefixOrRef, "@") {
		tcName = prefixOrRef
	}
	prefix := prefixOrRef
	if strings.HasPrefix(prefixOrRef, "@") {
		prefix = ""
	}
	return FindCachedToolchainBinDir(tcName, prefix, "", expectedVersion, upstreamVersion)
}

// FindCachedToolchainBinDir locates a cached toolchain's /bin directory under
// <ToobHome>/toolchains/<goos>_<goarch>/<tcSlug>/<version>.
func FindCachedToolchainBinDir(tcName, prefix, compilerBinary, expectedVersion, upstreamVersion string) string {
	if tcName == "" {
		tcName = strings.TrimSuffix(prefix, "-")
	}
	if validateToolchainRef("toolchain name", tcName) != nil {
		return ""
	}
	homeDir, err := paths.ToobHome()
	if err != nil {
		return ""
	}

	for _, cand := range []string{expectedVersion, upstreamVersion} {
		if cand == "" {
			continue
		}
		tcRoot, dirErr := ToolchainDir(homeDir, runtime.GOOS, runtime.GOARCH, tcName, cand)
		if dirErr != nil {
			continue
		}
		if bin := FindBinDirWithBinary(tcRoot, prefix, compilerBinary); bin != "" {
			return bin
		}
	}
	return ""
}

// EnsureAvailable provisions the toolchain identified by prefixOrRef on demand.
func EnsureAvailable(prefixOrRef, expectedVersion, regDir string) (string, error) {
	tcName := strings.TrimSuffix(prefixOrRef, "-")
	prefix := prefixOrRef
	if strings.HasPrefix(prefixOrRef, "@") {
		tcName = prefixOrRef
		prefix = ""
	}
	return EnsureToolchain(context.Background(), tcName, prefix, "", expectedVersion, regDir)
}

// EnsureToolchain checks if the toolchain exists under <ToobHome>/toolchains/<goos>_<goarch>/<tcSlug>/<version>,
// downloading, verifying, and extracting it under an advisory file lock if missing.
func EnsureToolchain(ctx context.Context, tcName, prefix, compilerBinary, expectedVersion, regDir string) (string, error) {
	lookupKey := cmp.Or(strings.TrimSpace(tcName), strings.TrimSuffix(strings.TrimSpace(prefix), "-"))
	if err := validateToolchainRef("toolchain name", lookupKey); err != nil {
		return "", err
	}
	if expectedVersion != "" {
		if err := validateToken("expected toolchain version", expectedVersion); err != nil {
			return "", err
		}
	}

	regJSON := filepath.Join(regDir, "registry.json")
	data, err := os.ReadFile(regJSON)
	if err != nil {
		return "", fmt.Errorf("could not read registry.json: %w", err)
	}

	var reg RegistryConfig
	if err = json.Unmarshal(data, &reg); err != nil {
		return "", fmt.Errorf("failed to parse registry.json: %w", err)
	}

	resolvedName, tcInfo, ok := resolveToolchainEntry(lookupKey, &reg)
	if !ok && prefix != "" {
		resolvedName, tcInfo, ok = resolveToolchainEntry(prefix, &reg)
	}
	if !ok {
		return "", fmt.Errorf("toolchain '%s' is not defined in the registry. Auto-provisioning failed", lookupKey)
	}

	if tcInfo.Version != "" {
		if verErr := validateToken("registry toolchain version", tcInfo.Version); verErr != nil {
			return "", verErr
		}
	}
	if tcInfo.UpstreamVersion != "" {
		if upErr := validateToken("registry toolchain upstream_version", tcInfo.UpstreamVersion); upErr != nil {
			return "", upErr
		}
	}

	if expectedVersion != "" && expectedVersion != tcInfo.Version && expectedVersion != tcInfo.UpstreamVersion {
		return "", fmt.Errorf("locked toolchain '%s' version %q does not match registry version %q (upstream %q)",
			resolvedName, expectedVersion, tcInfo.Version, tcInfo.UpstreamVersion)
	}

	probeBin := cmp.Or(strings.TrimSpace(compilerBinary), strings.TrimSpace(tcInfo.CompilerBinary))
	effectivePrefix := prefix
	if strings.HasPrefix(prefix, "@") || prefix == resolvedName {
		if probeBin != "" {
			effectivePrefix = ""
		}
	}

	homeDir, err := paths.ToobHome()
	if err != nil {
		return "", err
	}

	cacheVer := cmp.Or(expectedVersion, tcInfo.Version, tcInfo.UpstreamVersion)
	if cacheVer == "" {
		return "", fmt.Errorf("registry toolchain '%s' declares no version", resolvedName)
	}
	tcRoot, err := ToolchainDir(homeDir, runtime.GOOS, runtime.GOARCH, resolvedName, cacheVer)
	if err != nil {
		return "", err
	}

	if tcPath := FindBinDirWithBinary(tcRoot, effectivePrefix, probeBin); tcPath != "" {
		return tcPath, nil
	}
	if expectedVersion == tcInfo.Version && tcInfo.UpstreamVersion != "" && tcInfo.UpstreamVersion != cacheVer {
		if altRoot, altErr := ToolchainDir(homeDir, runtime.GOOS, runtime.GOARCH, resolvedName, tcInfo.UpstreamVersion); altErr == nil {
			if tcPath := FindBinDirWithBinary(altRoot, effectivePrefix, probeBin); tcPath != "" {
				return tcPath, nil
			}
		}
	}

	lockCtx, cancel := context.WithTimeout(ctx, lockWaitTimeout)
	defer cancel()

	unlock, err := filelock.Lock(lockCtx, tcRoot+".lock")
	if err != nil {
		return "", fmt.Errorf("acquiring toolchain provisioning lock for %s: %w", resolvedName, err)
	}
	defer func() { _ = unlock() }()

	if tcPath := FindBinDirWithBinary(tcRoot, effectivePrefix, probeBin); tcPath != "" {
		return tcPath, nil
	}

	_ = RetryWindowsLocks(func() error { return os.RemoveAll(tcRoot) })

	ui.Muted("Toolchain '%s' (v%s) not found locally.", resolvedName, cacheVer)
	ui.Step("Looking up auto-provisioning URL in registry...")

	osArch := runtime.GOOS + "_" + runtime.GOARCH
	downloadURL, ok := tcInfo.URLs[osArch]
	if !ok || strings.TrimSpace(downloadURL) == "" {
		return "", fmt.Errorf("no download URL provided for toolchain '%s' on OS/Arch: %s", resolvedName, osArch)
	}

	ui.Info("Found toolchain v%s for %s", cmp.Or(tcInfo.Version, cacheVer), osArch)

	expectedSha256, ok := tcInfo.Sha256[osArch]
	cleanSha, shaErr := validateToolchainSHA256(resolvedName, osArch, expectedSha256)
	if !ok || shaErr != nil {
		if shaErr != nil {
			return "", shaErr
		}
		return "", fmt.Errorf("registry has no sha256 for toolchain '%s' on %s: refusing to install it unverified", resolvedName, osArch)
	}

	tcSlug, err := ToolchainSlug(resolvedName)
	if err != nil {
		return "", err
	}
	if err := downloadAndExtract(lockCtx, downloadURL, tcRoot, tcSlug, cleanSha, cacheVer); err != nil {
		return "", fmt.Errorf("failed to download and extract toolchain: %w", err)
	}

	tcPath := FindBinDirWithBinary(tcRoot, effectivePrefix, probeBin)
	if tcPath == "" {
		return "", fmt.Errorf("auto-provisioning completed but /bin directory with compiler (prefix=%q, binary=%q) was not found inside %s",
			effectivePrefix, probeBin, tcRoot)
	}

	ui.Success("Successfully installed toolchain to %s", tcPath)
	return tcPath, nil
}

func validateToolchainSHA256(tcName, osArch, raw string) (string, error) {
	clean := strings.ToLower(strings.TrimSpace(raw))
	if clean == "" {
		return "", fmt.Errorf("registry has no sha256 for toolchain '%s' on %s: refusing to install it unverified", tcName, osArch)
	}
	decoded, err := hex.DecodeString(clean)
	if err != nil || len(decoded) != sha256.Size {
		return "", fmt.Errorf("registry has invalid sha256 %q for toolchain '%s' on %s", raw, tcName, osArch)
	}
	if clean == emptyFileSHA256 {
		return "", fmt.Errorf("registry sha256 for toolchain '%s' on %s is the empty-file placeholder digest; refusing download", tcName, osArch)
	}
	return clean, nil
}

// RetryWindowsLocks wraps an operation with exponential backoff to bypass temporary NTFS locks.
func RetryWindowsLocks(op func() error) error {
	var err error
	delays := []time.Duration{
		10 * time.Millisecond,
		50 * time.Millisecond,
		100 * time.Millisecond,
		500 * time.Millisecond,
		1000 * time.Millisecond,
		2000 * time.Millisecond,
	}
	for i, d := range delays {
		err = op()
		if err == nil {
			return nil
		}
		if i == 3 {
			ui.Warn("Waiting for background file lock release (Windows Defender/IDE)...")
		}
		time.Sleep(d)
	}
	return err
}

func newDownloadClient() (*http.Client, error) {
	tr, err := httputil.BuildTransport()
	if err != nil {
		return nil, err
	}
	tr.ResponseHeaderTimeout = 30 * time.Second
	return &http.Client{
		Transport:     tr,
		CheckRedirect: httputil.SafeCheckRedirect,
	}, nil
}

func clampProgressInt(v int64) int {
	if v < 0 {
		return 0
	}
	if v > int64(math.MaxInt32) {
		return math.MaxInt32
	}
	return int(v)
}

func downloadToPartFile(ctx context.Context, client *http.Client, rawURL, partPath, expectedSha256 string) error {
	for resetAttempt := range 2 {
		var startBytes int64
		if stat, statErr := os.Stat(partPath); statErr == nil {
			startBytes = stat.Size()
		}
		if startBytes >= maxToolchainArchiveBytes {
			_ = os.Remove(partPath)
			startBytes = 0
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			return err
		}
		if startBytes > 0 {
			req.Header.Set("Range", fmt.Sprintf("bytes=%d-", startBytes))
			ui.Step("Resuming download %s from byte %d...", rawURL, startBytes)
		} else {
			ui.Step("Downloading %s", rawURL)
		}

		resp, err := client.Do(req)
		if err != nil {
			return err
		}

		status := resp.StatusCode
		if status == http.StatusRequestedRangeNotSatisfiable {
			_ = resp.Body.Close()
			if actual, hErr := hashFile(partPath); hErr == nil && strings.EqualFold(actual, expectedSha256) {
				return nil
			}
			_ = os.Remove(partPath)
			if resetAttempt == 0 {
				continue
			}
			return errors.New("server returned HTTP 416 and cached partial archive checksum did not match")
		}

		if status != http.StatusPartialContent && status != http.StatusOK {
			_ = resp.Body.Close()
			if status >= 400 && status < 500 && status != http.StatusTooManyRequests {
				_ = os.Remove(partPath)
			}
			return fmt.Errorf("server returned HTTP %d", status)
		}

		var out *os.File
		if status == http.StatusPartialContent && startBytes > 0 {
			out, err = os.OpenFile(partPath, os.O_WRONLY|os.O_APPEND, 0o600)
		} else {
			out, err = os.OpenFile(partPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
			startBytes = 0
		}
		if err != nil {
			_ = resp.Body.Close()
			return err
		}

		totalHint := startBytes
		if resp.ContentLength > 0 {
			totalHint += resp.ContentLength
		}
		spinner := ui.NewSpinner("Downloading Toolchain")
		spinner.SetProgress(clampProgressInt(startBytes), clampProgressInt(totalHint))
		spinner.Start()

		remaining := maxToolchainArchiveBytes - startBytes
		written, copyErr := io.Copy(io.MultiWriter(out, spinner), io.LimitReader(resp.Body, remaining+1))
		spinner.Stop()
		_ = resp.Body.Close()
		closeErr := out.Close()

		if copyErr != nil {
			// Keep valid partial bytes on transient stream interruption so next invocation can resume.
			return copyErr
		}
		if closeErr != nil {
			_ = os.Remove(partPath)
			return fmt.Errorf("failed flushing downloaded toolchain archive: %w", closeErr)
		}
		if written > remaining {
			_ = os.Remove(partPath)
			return fmt.Errorf("toolchain archive exceeds maximum allowed download size (%d bytes)", maxToolchainArchiveBytes)
		}

		actualSha256, err := hashFile(partPath)
		if err != nil {
			_ = os.Remove(partPath)
			return fmt.Errorf("failed hashing the downloaded archive: %w", err)
		}
		if !strings.EqualFold(actualSha256, expectedSha256) {
			_ = os.Remove(partPath)
			if startBytes > 0 && resetAttempt == 0 {
				ui.Warn("Resumed toolchain archive checksum mismatched; retrying full download from byte 0...")
				continue
			}
			return fmt.Errorf("SHA256 mismatch!\nExpected: %s\nGot:      %s", expectedSha256, actualSha256)
		}
		return nil
	}

	return errors.New("toolchain download failed after retry")
}

func downloadAndExtract(ctx context.Context, rawURL, destDir, tcSlug, expectedSha256, cacheVer string) error {
	if _, err := httputil.ValidateHTTPSOrLoopbackURL(rawURL); err != nil {
		return fmt.Errorf("refusing to download toolchain from unsafe URL %q: %w", rawURL, err)
	}
	if len(expectedSha256) < 12 {
		return errors.New("refusing to install a toolchain without a valid SHA256 checksum")
	}
	if err := validateToolchainSlug(tcSlug); err != nil {
		return err
	}
	if err := validateToken("toolchain cache version", cacheVer); err != nil {
		return err
	}

	client, err := newDownloadClient()
	if err != nil {
		return err
	}

	homeDir, err := paths.ToobHome()
	if err != nil {
		return err
	}
	cacheDir := filepath.Join(homeDir, "cache", "downloads")
	if err = os.MkdirAll(cacheDir, 0o700); err != nil {
		return fmt.Errorf("failed creating download cache directory: %w", err)
	}

	partName := fmt.Sprintf("%s-%s-%s.part", tcSlug, cacheVer, expectedSha256[:12])
	partPath, err := archiveutil.SafeJoin(cacheDir, partName)
	if err != nil {
		return err
	}

	if err := downloadToPartFile(ctx, client, rawURL, partPath, expectedSha256); err != nil {
		return err
	}
	ui.Success("Checksum verified.")

	tmpDestDir := fmt.Sprintf("%s.tmp.%d", destDir, os.Getpid())
	_ = RetryWindowsLocks(func() error { return os.RemoveAll(tmpDestDir) })
	if err := os.MkdirAll(tmpDestDir, 0o750); err != nil {
		_ = os.Remove(partPath)
		return err
	}

	if extractErr := extractArchive(rawURL, partPath, tmpDestDir); extractErr != nil {
		_ = os.Remove(partPath)
		_ = RetryWindowsLocks(func() error { return os.RemoveAll(tmpDestDir) })
		return extractErr
	}

	if _, err := os.Stat("/.dockerenv"); errors.Is(err, fs.ErrNotExist) && os.Getenv("TOOB_DISABLE_CAS") == "" {
		if err := postProcessCAS(tmpDestDir); err != nil {
			_ = os.Remove(partPath)
			_ = RetryWindowsLocks(func() error { return os.RemoveAll(tmpDestDir) })
			return fmt.Errorf("CAS processing failed: %w", err)
		}
	} else {
		ui.Muted("Bypassing CAS deduplication (Docker Environment / Disabled).")
	}

	_ = RetryWindowsLocks(func() error { return os.RemoveAll(destDir) })
	if err := os.MkdirAll(filepath.Dir(destDir), 0o750); err != nil {
		_ = os.Remove(partPath)
		_ = RetryWindowsLocks(func() error { return os.RemoveAll(tmpDestDir) })
		return err
	}
	if err := RetryWindowsLocks(func() error { return os.Rename(tmpDestDir, destDir) }); err != nil {
		if !strings.Contains(err.Error(), "cross-device link") {
			_ = os.Remove(partPath)
			return fmt.Errorf("failed to finalize installation: %w", err)
		}
		if copyErr := copyTree(tmpDestDir, destDir); copyErr != nil {
			_ = os.Remove(partPath)
			return fmt.Errorf("failed to finalize installation (cross-device fallback failed): %w", copyErr)
		}
		_ = RetryWindowsLocks(func() error { return os.RemoveAll(tmpDestDir) })
	}

	_ = os.Remove(partPath)
	return nil
}

func postProcessCAS(extractedDir string) error {
	homeDir, err := paths.ToobHome()
	if err != nil {
		return err
	}
	casDir := filepath.Join(homeDir, "store", "cas")
	if err = os.MkdirAll(casDir, 0o700); err != nil {
		return fmt.Errorf("failed creating CAS directory: %w", err)
	}

	extRoot, err := os.OpenRoot(extractedDir)
	if err != nil {
		return err
	}
	defer func() { _ = extRoot.Close() }()

	casRoot, err := os.OpenRoot(casDir)
	if err != nil {
		return err
	}
	defer func() { _ = casRoot.Close() }()

	return filepath.WalkDir(extractedDir, func(walkPath string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}

		rel, err := filepath.Rel(extractedDir, walkPath)
		if err != nil {
			return err
		}

		origStat, err := extRoot.Lstat(rel)
		if err != nil {
			return err
		}
		if !origStat.Mode().IsRegular() {
			return nil
		}
		origMode := origStat.Mode()
		origSize := origStat.Size()

		f, err := extRoot.Open(rel)
		if err != nil {
			return err
		}
		hasher := sha256.New()
		hashedBytes, copyErr := io.Copy(hasher, f)
		closeErr := f.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		if hashedBytes != origSize {
			return fmt.Errorf("concurrent modification detected while hashing %s", rel)
		}

		hashStr := hex.EncodeToString(hasher.Sum(nil))
		casPath := filepath.Join(casDir, hashStr)

		casStat, statErr := casRoot.Stat(hashStr)
		if statErr != nil && !errors.Is(statErr, fs.ErrNotExist) {
			return statErr
		}

		if errors.Is(statErr, fs.ErrNotExist) || casStat.Size() != origSize {
			if statErr == nil && casStat.Size() != origSize {
				_ = casRoot.Chmod(hashStr, 0o600)
				_ = casRoot.Remove(hashStr)
			}
			tmpName := fmt.Sprintf("%s.tmp.%d", hashStr, os.Getpid())
			tmpCasPath := filepath.Join(casDir, tmpName)

			if err := streamCopyInRoots(extRoot, rel, casRoot, tmpName, origMode, origSize); err != nil {
				_ = casRoot.Remove(tmpName)
				return err
			}

			var roMode fs.FileMode = 0o444
			if origMode&0o111 != 0 {
				roMode = 0o555
			}
			if err := casRoot.Chmod(tmpName, roMode); err != nil && runtime.GOOS != "windows" {
				_ = casRoot.Remove(tmpName)
				return err
			}

			if err := RetryWindowsLocks(func() error { return os.Rename(tmpCasPath, casPath) }); err != nil {
				_ = casRoot.Remove(tmpName)
				if verifyStat, vErr := casRoot.Stat(hashStr); vErr != nil || verifyStat.Size() != origSize {
					return fmt.Errorf("failed committing %s to CAS: %w", hashStr, err)
				}
			}
		}

		if err := extRoot.Remove(rel); err != nil {
			return err
		}

		targetPath := filepath.Join(extractedDir, rel)
		if err := os.Link(casPath, targetPath); err != nil {
			if err := streamCopyInRoots(casRoot, hashStr, extRoot, rel, origMode, origSize); err != nil {
				return err
			}
		}
		return nil
	})
}

func streamCopyInRoots(srcRoot *os.Root, srcRel string, dstRoot *os.Root, dstRel string, mode fs.FileMode, expectedSize int64) error {
	srcFile, err := srcRoot.Open(srcRel)
	if err != nil {
		return err
	}
	dstFile, err := dstRoot.OpenFile(dstRel, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, archiveutil.EntryMode(mode))
	if err != nil {
		_ = srcFile.Close()
		return err
	}
	written, copyErr := io.Copy(dstFile, srcFile)
	srcCloseErr := srcFile.Close()
	dstCloseErr := dstFile.Close()
	if copyErr != nil {
		return copyErr
	}
	if srcCloseErr != nil {
		return srcCloseErr
	}
	if dstCloseErr != nil {
		return dstCloseErr
	}
	if expectedSize >= 0 && written != expectedSize {
		return fmt.Errorf("short copy for %s: wrote %d of %d bytes", dstRel, written, expectedSize)
	}
	return nil
}

func hashFile(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	hasher := sha256.New()
	_, copyErr := io.Copy(hasher, f)
	closeErr := f.Close()
	if copyErr != nil {
		return "", copyErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func archivePathSuffix(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return strings.ToLower(rawURL)
	}
	return strings.ToLower(u.Path)
}

func extractArchive(rawURL, archivePath, destDir string) error {
	urlPath := archivePathSuffix(rawURL)
	switch {
	case strings.HasSuffix(urlPath, ".zip"):
		return extractZip(archivePath, destDir)

	case strings.HasSuffix(urlPath, ".tar.gz"), strings.HasSuffix(urlPath, ".tgz"), strings.HasSuffix(urlPath, ".tar.xz"):
		f, err := os.Open(archivePath)
		if err != nil {
			return err
		}
		var extractErr error
		if strings.HasSuffix(urlPath, ".tar.xz") {
			extractErr = extractTarXz(f, destDir)
		} else {
			extractErr = extractTarGz(f, destDir)
		}
		closeErr := f.Close()
		if extractErr != nil {
			return extractErr
		}
		return closeErr

	default:
		return fmt.Errorf("unsupported archive format for URL path %q", urlPath)
	}
}

type pendingSymlink struct {
	relOS      string
	fullTarget string
	entryName  string
	linkname   string
}

func extractZip(zipPath, destDir string) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer func() { _ = r.Close() }()

	if mkdirErr := os.MkdirAll(destDir, 0o750); mkdirErr != nil {
		return mkdirErr
	}
	root, err := os.OpenRoot(destDir)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()

	spinner := ui.NewSpinner("Unzipping Toolchain")
	spinner.SetProgress(0, len(r.File))
	spinner.Start()
	defer spinner.Stop()

	budget := archiveutil.NewBudgetWithEntries(archiveutil.DefaultSizeLimit, archiveutil.ToolchainMaxEntries)
	tracker := archiveutil.NewPathTracker()
	linkMap := make(map[string]string)
	var symlinks []pendingSymlink

	for _, f := range r.File {
		spinner.AddProgress(1)
		if takeErr := budget.TakeEntry(); takeErr != nil {
			return takeErr
		}

		fpath, relOS, err := archiveutil.SafeRelPath(destDir, f.Name)
		if err != nil {
			return err
		}
		if relOS == "." {
			continue
		}
		if recErr := tracker.Record(relOS); recErr != nil {
			return recErr
		}

		if f.Mode()&fs.ModeSymlink != 0 {
			linkname, lErr := readZipSymlinkTarget(f, budget)
			if lErr != nil {
				return lErr
			}
			if linkErr := archiveutil.ValidateLinkSyntax(fpath, linkname); linkErr != nil {
				return linkErr
			}
			linkMap[archiveutil.CanonicalLinkKey(relOS)] = linkname
			symlinks = append(symlinks, pendingSymlink{
				relOS:      relOS,
				fullTarget: fpath,
				entryName:  f.Name,
				linkname:   linkname,
			})
			continue
		}

		resolvedRelOS, err := archiveutil.ResolveArchiveRelPath(destDir, relOS, linkMap)
		if err != nil {
			return err
		}

		if f.FileInfo().IsDir() {
			if err := archiveutil.RootMkdirAll(root, resolvedRelOS); err != nil {
				return err
			}
			continue
		}

		if err := archiveutil.RootMkdirAll(root, filepath.Dir(resolvedRelOS)); err != nil {
			return err
		}
		if err := writeZipEntryRoot(root, f, resolvedRelOS, budget); err != nil {
			return fmt.Errorf("failed extracting %q: %w", f.Name, err)
		}
	}

	if err := archiveutil.ValidateSymlinkGraph(destDir, linkMap); err != nil {
		return err
	}
	return materializeSymlinksTopologically(root, destDir, symlinks, linkMap)
}

func readZipSymlinkTarget(f *zip.File, budget *archiveutil.Budget) (string, error) {
	rc, err := f.Open()
	if err != nil {
		return "", err
	}
	var sb strings.Builder
	_, copyErr := budget.Copy(&sb, io.LimitReader(rc, 4096))
	closeErr := rc.Close()
	if copyErr != nil {
		return "", copyErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	return sb.String(), nil
}

func writeZipEntryRoot(root *os.Root, f *zip.File, relOS string, budget *archiveutil.Budget) error {
	rc, err := f.Open()
	if err != nil {
		return err
	}

	outFile, err := root.OpenFile(relOS, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, archiveutil.EntryMode(f.Mode()))
	if err != nil {
		_ = rc.Close()
		return err
	}

	_, copyErr := budget.Copy(outFile, rc)
	rcCloseErr := rc.Close()
	outCloseErr := outFile.Close()
	if copyErr != nil {
		return copyErr
	}
	if rcCloseErr != nil {
		return rcCloseErr
	}
	return outCloseErr
}

func extractTarGz(r io.Reader, destDir string) error {
	gzr, err := gzip.NewReader(r)
	if err != nil {
		return err
	}

	tr := tar.NewReader(gzr)
	if err := extractTar(tr, destDir); err != nil {
		_ = gzr.Close()
		return err
	}
	if err := archiveutil.DrainStreamTrailer(gzr, 1<<20); err != nil {
		_ = gzr.Close()
		return fmt.Errorf("gzip trailer integrity failure: %w", err)
	}
	return gzr.Close()
}

func extractTarXz(r io.Reader, destDir string) error {
	xzr, err := xz.NewReader(r)
	if err != nil {
		return err
	}

	tr := tar.NewReader(xzr)
	if err := extractTar(tr, destDir); err != nil {
		return err
	}
	if err := archiveutil.DrainStreamTrailer(xzr, 1<<20); err != nil {
		return fmt.Errorf("xz trailer integrity failure: %w", err)
	}
	return nil
}

func extractTar(tr *tar.Reader, destDir string) error {
	if err := os.MkdirAll(destDir, 0o750); err != nil {
		return err
	}
	root, err := os.OpenRoot(destDir)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()

	spinner := ui.NewSpinner("Unpacking Toolchain")
	spinner.Start()
	defer spinner.Stop()

	budget := archiveutil.NewBudgetWithEntries(archiveutil.DefaultSizeLimit, archiveutil.ToolchainMaxEntries)
	tracker := archiveutil.NewPathTracker()
	linkMap := make(map[string]string)
	var symlinks []pendingSymlink

	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}

		if header.Typeflag == tar.TypeXGlobalHeader || header.Typeflag == tar.TypeXHeader {
			continue
		}

		if takeErr := budget.TakeEntry(); takeErr != nil {
			return takeErr
		}

		cleanName := strings.TrimPrefix(filepath.ToSlash(header.Name), "./")
		cleanName = strings.TrimSuffix(cleanName, "/")
		if cleanName == "" || cleanName == "." {
			if header.Typeflag == tar.TypeDir {
				continue
			}
			return fmt.Errorf("%w: invalid root entry %q", archiveutil.ErrUnsafePath, header.Name)
		}

		target, relOS, err := archiveutil.SafeRelPath(destDir, cleanName)
		if err != nil {
			return err
		}
		if relOS == "." {
			if header.Typeflag == tar.TypeDir {
				continue
			}
			return fmt.Errorf("%w: entry %q resolves to destination root", archiveutil.ErrUnsafePath, header.Name)
		}
		if err := tracker.Record(relOS); err != nil {
			return err
		}

		switch header.Typeflag {
		case tar.TypeDir:
			resolvedRelOS, rErr := archiveutil.ResolveArchiveRelPath(destDir, relOS, linkMap)
			if rErr != nil {
				return rErr
			}
			if err := archiveutil.RootMkdirAll(root, resolvedRelOS); err != nil {
				return err
			}

		case tar.TypeReg, '\x00':
			resolvedRelOS, rErr := archiveutil.ResolveArchiveRelPath(destDir, relOS, linkMap)
			if rErr != nil {
				return rErr
			}
			if err := archiveutil.RootMkdirAll(root, filepath.Dir(resolvedRelOS)); err != nil {
				return err
			}
			if err := writeTarFileRoot(root, tr, resolvedRelOS, header, budget); err != nil {
				return fmt.Errorf("failed extracting %q: %w", header.Name, err)
			}

		case tar.TypeSymlink:
			if err := archiveutil.ValidateLinkSyntax(target, header.Linkname); err != nil {
				return err
			}
			linkMap[archiveutil.CanonicalLinkKey(relOS)] = header.Linkname
			symlinks = append(symlinks, pendingSymlink{
				relOS:      relOS,
				fullTarget: target,
				entryName:  header.Name,
				linkname:   header.Linkname,
			})

		case tar.TypeLink:
			_, srcRelOS, err := archiveutil.SafeRelPath(destDir, header.Linkname)
			if err != nil || srcRelOS == "." {
				return fmt.Errorf("hard link %q: %w", header.Name, archiveutil.ErrUnsafePath)
			}
			if _, isSym := linkMap[archiveutil.CanonicalLinkKey(srcRelOS)]; isSym {
				return fmt.Errorf("hard link %q targets symlink %q: %w", header.Name, header.Linkname, archiveutil.ErrUnsafePath)
			}
			resolvedSrcRelOS, sErr := archiveutil.ResolveArchiveRelPath(destDir, srcRelOS, linkMap)
			if sErr != nil {
				return sErr
			}
			resolvedDstRelOS, dErr := archiveutil.ResolveArchiveRelPath(destDir, relOS, linkMap)
			if dErr != nil {
				return dErr
			}
			srcInfo, statErr := root.Lstat(resolvedSrcRelOS)
			if statErr != nil {
				return fmt.Errorf("hard link %q target %q missing: %w", header.Name, header.Linkname, archiveutil.ErrUnsafePath)
			}
			if srcInfo.Mode()&fs.ModeSymlink != 0 || !srcInfo.Mode().IsRegular() {
				return fmt.Errorf("hard link %q targets non-regular file %q: %w", header.Name, header.Linkname, archiveutil.ErrUnsafePath)
			}
			if err := archiveutil.RootMkdirAll(root, filepath.Dir(resolvedDstRelOS)); err != nil {
				return err
			}
			_ = root.Remove(resolvedDstRelOS)
			sourceHost := filepath.Join(destDir, resolvedSrcRelOS)
			dstHost := filepath.Join(destDir, resolvedDstRelOS)
			if err := os.Link(sourceHost, dstHost); err != nil {
				return fmt.Errorf("failed linking %q -> %q: %w", header.Name, header.Linkname, err)
			}

		default:
			return fmt.Errorf("unsupported archive entry type %q for %q", string(header.Typeflag), header.Name)
		}
	}

	if err := archiveutil.ValidateSymlinkGraph(destDir, linkMap); err != nil {
		return err
	}
	return materializeSymlinksTopologically(root, destDir, symlinks, linkMap)
}

func writeTarFileRoot(root *os.Root, tr *tar.Reader, relOS string, header *tar.Header, budget *archiveutil.Budget) error {
	f, err := root.OpenFile(relOS, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, archiveutil.EntryMode(header.FileInfo().Mode()))
	if err != nil {
		return err
	}
	if _, err := budget.Copy(f, tr); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func materializeSymlinksTopologically(root *os.Root, destDir string, symlinks []pendingSymlink, linkMap map[string]string) error {
	if len(symlinks) == 0 {
		return nil
	}

	byKey := make(map[string]pendingSymlink, len(symlinks))
	orderKeys := make([]string, 0, len(symlinks))
	for _, s := range symlinks {
		k := archiveutil.CanonicalLinkKey(s.relOS)
		if _, exists := byKey[k]; !exists {
			orderKeys = append(orderKeys, k)
		}
		byKey[k] = s
	}

	state := make(map[string]uint8, len(byKey)) // 0 = pending, 1 = visiting, 2 = materialized

	var materializeKey func(k string) error
	materializeKey = func(k string) error {
		switch state[k] {
		case 2:
			return nil
		case 1:
			return fmt.Errorf("%w: symlink cycle at %q", archiveutil.ErrUnsafePath, k)
		}
		s, ok := byKey[k]
		if !ok {
			return nil
		}
		state[k] = 1

		// Ensure any symlink components along the parent directory or target path are materialized first.
		parentSlash := path.Dir(filepath.ToSlash(s.relOS))
		for _, dep := range referencedSymlinkKeys(parentSlash, s.linkname, linkMap) {
			if dep != k {
				if err := materializeKey(dep); err != nil {
					return err
				}
			}
		}

		resolvedRelOS, err := archiveutil.ResolveArchiveRelPath(destDir, s.relOS, nil)
		if err != nil {
			resolvedRelOS = s.relOS
		}
		if err := archiveutil.RootMkdirAll(root, filepath.Dir(resolvedRelOS)); err != nil {
			return err
		}
		fullTarget := filepath.Join(destDir, resolvedRelOS)
		if err := createSymlinkOrWindowsCopy(root, destDir, resolvedRelOS, fullTarget, s.entryName, s.linkname); err != nil {
			return err
		}

		state[k] = 2
		return nil
	}

	for _, k := range orderKeys {
		if err := materializeKey(k); err != nil {
			return err
		}
	}
	return nil
}

func referencedSymlinkKeys(parentSlash, linkname string, linkMap map[string]string) []string {
	var deps []string
	cur := "."
	if parentSlash != "" && parentSlash != "." {
		for _, seg := range strings.Split(parentSlash, "/") {
			if seg == "" || seg == "." {
				continue
			}
			if cur == "." {
				cur = seg
			} else {
				cur = cur + "/" + seg
			}
			key := strings.ToLower(cur)
			if _, ok := linkMap[key]; ok {
				deps = append(deps, key)
			}
		}
	}

	norm := strings.ReplaceAll(linkname, `\`, "/")
	for _, seg := range strings.Split(norm, "/") {
		if seg == "" || seg == "." {
			continue
		}
		if seg == ".." {
			cur = path.Dir(cur)
			if cur == "" {
				cur = "."
			}
			continue
		}
		if cur == "." {
			cur = seg
		} else {
			cur = cur + "/" + seg
		}
		key := strings.ToLower(cur)
		if _, ok := linkMap[key]; ok {
			deps = append(deps, key)
		}
	}
	return deps
}

func createSymlinkOrWindowsCopy(root *os.Root, destDir, relOS, fullTarget, entryName, linkname string) error {
	_ = root.Remove(relOS)
	if err := os.Symlink(linkname, fullTarget); err != nil {
		if runtime.GOOS == "windows" {
			candHost := filepath.Clean(filepath.Join(filepath.Dir(fullTarget), filepath.FromSlash(linkname)))
			candRel, relErr := filepath.Rel(filepath.Clean(destDir), candHost)
			if relErr != nil || candRel == ".." || strings.HasPrefix(candRel, ".."+string(filepath.Separator)) {
				return fmt.Errorf("%w: symlink %q -> %q escapes destination", archiveutil.ErrUnsafePath, entryName, linkname)
			}
			st, statErr := root.Stat(candRel)
			if statErr != nil {
				return fmt.Errorf("failed materializing Windows symlink %q -> %q (enable Windows Developer Mode or verify archive target): %w",
					entryName, linkname, statErr)
			}
			if st.Mode().IsRegular() {
				return streamCopyInRoots(root, candRel, root, relOS, st.Mode(), st.Size())
			}
			if st.IsDir() {
				return copySubtreeInRoot(root, destDir, candRel, relOS)
			}
			return fmt.Errorf("unsupported symlink target mode for %q -> %q on Windows", entryName, linkname)
		}
		return fmt.Errorf("failed creating symlink %q -> %q: %w", entryName, linkname, err)
	}
	return nil
}

func copySubtreeInRoot(root *os.Root, destDir, srcRel, dstRel string) error {
	srcAbs := filepath.Join(destDir, srcRel)
	return filepath.WalkDir(srcAbs, func(walkPath string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		sub, err := filepath.Rel(srcAbs, walkPath)
		if err != nil {
			return err
		}
		targetRel := dstRel
		if sub != "." {
			targetRel = filepath.Join(dstRel, sub)
		}
		if d.IsDir() {
			return archiveutil.RootMkdirAll(root, targetRel)
		}
		srcEntryRel := srcRel
		if sub != "." {
			srcEntryRel = filepath.Join(srcRel, sub)
		}
		st, err := root.Stat(srcEntryRel)
		if err != nil {
			return err
		}
		if !st.Mode().IsRegular() {
			return nil
		}
		if err := archiveutil.RootMkdirAll(root, filepath.Dir(targetRel)); err != nil {
			return err
		}
		return streamCopyInRoots(root, srcEntryRel, root, targetRel, st.Mode(), st.Size())
	})
}

func isRegularFileFollowingSymlink(filePath string) bool {
	st, err := os.Stat(filePath)
	return err == nil && st.Mode().IsRegular()
}

func binaryCandidates(base string) []string {
	if runtime.GOOS == "windows" && !strings.HasSuffix(strings.ToLower(base), ".exe") {
		return []string{base + ".exe", base}
	}
	return []string{base}
}

func binDirContainsCompiler(binDir, prefix, compilerBinary string) bool {
	if compilerBinary != "" {
		for _, cand := range binaryCandidates(compilerBinary) {
			if isRegularFileFollowingSymlink(filepath.Join(binDir, cand)) {
				return true
			}
		}
		return false
	}

	if prefix != "" {
		for _, tool := range []string{prefix + "gcc", prefix + "clang", prefix + "cc"} {
			for _, cand := range binaryCandidates(tool) {
				if isRegularFileFollowingSymlink(filepath.Join(binDir, cand)) {
					return true
				}
			}
		}
		entries, err := os.ReadDir(binDir)
		if err != nil {
			return false
		}
		for _, e := range entries {
			if !e.IsDir() && strings.HasPrefix(e.Name(), prefix) {
				if isRegularFileFollowingSymlink(filepath.Join(binDir, e.Name())) {
					return true
				}
			}
		}
		return false
	}

	// Prefix-less toolchains (such as Clang/LLVM).
	for _, tool := range []string{"clang", "clang++", "gcc", "cc"} {
		for _, cand := range binaryCandidates(tool) {
			if isRegularFileFollowingSymlink(filepath.Join(binDir, cand)) {
				return true
			}
		}
	}
	return false
}

// FindBinDir recursively searches root for a "bin" directory containing executables matching prefix.
func FindBinDir(root, prefix string) string {
	return FindBinDirWithBinary(root, prefix, "")
}

// FindBinDirWithBinary searches root for the shallowest "bin" directory containing a valid
// regular compiler executable (resolved via os.Stat so dangling symlinks never match).
func FindBinDirWithBinary(root, prefix, compilerBinary string) string {
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		root = resolved
	}
	if st, err := os.Stat(root); err != nil || !st.IsDir() {
		return ""
	}

	type binCandidate struct {
		path  string
		depth int
	}
	var candidates []binCandidate

	_ = filepath.WalkDir(root, func(walkPath string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			if d != nil && d.IsDir() && walkPath != root {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() && d.Name() == "bin" {
			rel, relErr := filepath.Rel(root, walkPath)
			depth := 1
			if relErr == nil {
				depth = strings.Count(filepath.ToSlash(rel), "/") + 1
			}
			candidates = append(candidates, binCandidate{path: walkPath, depth: depth})
			return filepath.SkipDir
		}
		return nil
	})

	slices.SortStableFunc(candidates, func(a, b binCandidate) int {
		if c := cmp.Compare(a.depth, b.depth); c != 0 {
			return c
		}
		return cmp.Compare(a.path, b.path)
	})

	for _, c := range candidates {
		if binDirContainsCompiler(c.path, prefix, compilerBinary) {
			return c.path
		}
	}
	return ""
}

// CleanToolchainsAndCAS removes <ToobHome>/toolchains, <ToobHome>/store/cas (clearing
// read-only 0o444/0o555 blob permissions first), <ToobHome>/cache/downloads, and
// <ToobHome>/.trash, returning the total physical bytes reclaimed.
func CleanToolchainsAndCAS() (int64, error) {
	homeDir, err := paths.ToobHome()
	if err != nil {
		return 0, err
	}

	targets := []string{
		filepath.Join(homeDir, "toolchains"),
		filepath.Join(homeDir, "store", "cas"),
		filepath.Join(homeDir, "cache", "downloads"),
		filepath.Join(homeDir, ".trash"),
	}

	var seenFiles []fs.FileInfo
	var reclaimed int64

	for _, dir := range targets {
		unlockDirForRemoval(dir, &seenFiles, &reclaimed)
	}

	for _, dir := range targets {
		if _, statErr := os.Lstat(dir); errors.Is(statErr, fs.ErrNotExist) {
			continue
		}
		if err := RetryWindowsLocks(func() error { return os.RemoveAll(dir) }); err != nil {
			return reclaimed, fmt.Errorf("failed removing %s: %w", dir, err)
		}
	}

	return reclaimed, nil
}

func unlockDirForRemoval(dir string, seenFiles *[]fs.FileInfo, reclaimed *int64) {
	rootInfo, err := os.Lstat(dir)
	if err != nil || !rootInfo.IsDir() {
		return
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return
	}
	defer func() { _ = root.Close() }()
	unlockRootEntries(root, seenFiles, reclaimed)
}

func unlockRootEntries(root *os.Root, seenFiles *[]fs.FileInfo, reclaimed *int64) {
	_ = root.Chmod(".", 0o700)
	dirFile, err := root.Open(".")
	if err != nil {
		return
	}
	entries, readErr := dirFile.ReadDir(-1)
	_ = dirFile.Close()
	if readErr != nil {
		return
	}

	for _, entry := range entries {
		name := entry.Name()
		info, statErr := root.Lstat(name)
		if statErr != nil || info.Mode()&fs.ModeSymlink != 0 {
			continue
		}
		if info.IsDir() {
			_ = root.Chmod(name, 0o700)
			subRoot, subErr := root.OpenRoot(name)
			if subErr != nil {
				continue
			}
			unlockRootEntries(subRoot, seenFiles, reclaimed)
			_ = subRoot.Close()
			continue
		}
		if info.Mode().IsRegular() {
			alreadyCounted := false
			for _, prev := range *seenFiles {
				if os.SameFile(prev, info) {
					alreadyCounted = true
					break
				}
			}
			if !alreadyCounted {
				*seenFiles = append(*seenFiles, info)
				*reclaimed += info.Size()
			}
			_ = root.Chmod(name, 0o600)
		}
	}
}

func copyTree(src, dst string) error {
	if err := os.MkdirAll(dst, 0o750); err != nil {
		return err
	}
	srcRoot, err := os.OpenRoot(src)
	if err != nil {
		return err
	}
	defer func() { _ = srcRoot.Close() }()

	dstRoot, err := os.OpenRoot(dst)
	if err != nil {
		return err
	}
	defer func() { _ = dstRoot.Close() }()

	var symlinks []pendingSymlink
	linkMap := make(map[string]string)

	if err := filepath.WalkDir(src, func(walkPath string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(src, walkPath)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}

		if d.Type()&fs.ModeSymlink != 0 {
			linkTarget, rlErr := os.Readlink(walkPath)
			if rlErr != nil {
				return rlErr
			}
			fullDst := filepath.Join(dst, rel)
			if linkErr := archiveutil.ValidateLinkSyntax(fullDst, linkTarget); linkErr != nil {
				return linkErr
			}
			linkMap[archiveutil.CanonicalLinkKey(rel)] = linkTarget
			symlinks = append(symlinks, pendingSymlink{
				relOS:      rel,
				fullTarget: fullDst,
				entryName:  rel,
				linkname:   linkTarget,
			})
			return nil
		}

		if d.IsDir() {
			return archiveutil.RootMkdirAll(dstRoot, rel)
		}

		if mkdirErr := archiveutil.RootMkdirAll(dstRoot, filepath.Dir(rel)); mkdirErr != nil {
			return mkdirErr
		}
		sInfo, err := srcRoot.Lstat(rel)
		if err != nil {
			return err
		}
		if !sInfo.Mode().IsRegular() {
			return fmt.Errorf("unsupported non-regular file %q in toolchain tree", rel)
		}
		return streamCopyInRoots(srcRoot, rel, dstRoot, rel, sInfo.Mode(), sInfo.Size())
	}); err != nil {
		return err
	}

	if err := archiveutil.ValidateSymlinkGraph(dst, linkMap); err != nil {
		return err
	}
	return materializeSymlinksTopologically(dstRoot, dst, symlinks, linkMap)
}
