// BOUNDARY TYPES: RegistryToolchain is mirrored in internal/ports/ports.go.
// If you modify these structs, you MUST update ports.go and assertions.go.
package toolchain

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/toob-boot/toob/internal/archiveutil"
	"github.com/toob-boot/toob/internal/paths"
	"github.com/toob-boot/toob/internal/ui"
	"github.com/ulikunitz/xz"
)

// RegistryToolchain defines the toolchain URLs from registry.json
type RegistryToolchain struct {
	Version         string            `json:"version"`
	UpstreamVersion string            `json:"upstream_version"`
	URLs            map[string]string `json:"urls"`
	Sha256          map[string]string `json:"sha256"`
}

// RegistryConfig represents the root of registry.json
type RegistryConfig struct {
	FormatVersion int                          `json:"format_version"`
	Toolchains    map[string]RegistryToolchain `json:"toolchains"`
}

// GetExpectedVersion returns the version specified in registry.json for a toolchain.
// Reads and parses registry.json from disk. Prefer GetExpectedVersionFromIndex when
// the Index is already loaded.
func GetExpectedVersion(prefix string, regDir string) string {
	tcName := strings.TrimSuffix(prefix, "-")
	data, err := os.ReadFile(filepath.Join(regDir, "registry.json"))
	if err != nil {
		return ""
	}
	var reg RegistryConfig
	if err := json.Unmarshal(data, &reg); err != nil {
		return ""
	}
	if tcInfo, ok := reg.Toolchains[tcName]; ok {
		return tcInfo.Version
	}
	return ""
}

// GetExpectedVersionFromConfig returns the expected version from an already-parsed config.
// Avoids redundant disk reads when the config is already loaded.
func GetExpectedVersionFromConfig(prefix string, reg *RegistryConfig) string {
	tcName := strings.TrimSuffix(prefix, "-")
	if tcInfo, ok := reg.Toolchains[tcName]; ok {
		return tcInfo.Version
	}
	return ""
}

// GetExpectedSha256FromConfig returns the expected sha256 from an already-parsed config.
func GetExpectedSha256FromConfig(prefix string, reg *RegistryConfig) string {
	tcName := strings.TrimSuffix(prefix, "-")
	if tcInfo, ok := reg.Toolchains[tcName]; ok {
		osArch := fmt.Sprintf("%s_%s", runtime.GOOS, runtime.GOARCH)
		return tcInfo.Sha256[osArch]
	}
	return ""
}

// EnsureAvailable checks if the toolchain exists, and if not, downloads and extracts it.
// Returns the absolute path to the toolchain's /bin directory.
func EnsureAvailable(prefix string, expectedVersion string, regDir string) (string, error) {
	tcName := strings.TrimSuffix(prefix, "-")

	// Read registry immediately to get UpstreamVersion for cache paths
	regJSON := filepath.Join(regDir, "registry.json")
	data, err := os.ReadFile(regJSON)
	if err != nil {
		return "", fmt.Errorf("could not read registry.json: %w", err)
	}

	var reg RegistryConfig
	if err := json.Unmarshal(data, &reg); err != nil {
		return "", fmt.Errorf("failed to parse registry.json: %w", err)
	}

	tcInfo, ok := reg.Toolchains[tcName]
	if !ok {
		return "", fmt.Errorf("toolchain '%s' is not defined in the registry. Auto-provisioning failed", tcName)
	}

	homeDir, err := paths.ToobHome()
	if err != nil {
		return "", err
	}
	localDir := filepath.Join(homeDir, "toolchains")

	cacheVer := tcInfo.UpstreamVersion
	if cacheVer == "" {
		cacheVer = expectedVersion
	}
	if cacheVer == "" {
		cacheVer = "latest"
	}
	tcRoot := filepath.Join(localDir, tcName, cacheVer)
	lockDir := tcRoot + ".lock.d"

	// 1. Cache Check (Gap 1.1 Versioning)
	if tcPath := FindBinDir(tcRoot, prefix); tcPath != "" {
		return tcPath, nil
	}

	// Acquire global provisioning lock
	if err := os.MkdirAll(filepath.Dir(lockDir), 0755); err != nil {
		return "", fmt.Errorf("failed to create toolchain directory: %w", err)
	}

	for {
		err := os.Mkdir(lockDir, 0755)
		if err == nil {
			defer os.RemoveAll(lockDir)
			break
		}

		if stat, err := os.Stat(lockDir); err == nil {
			if time.Since(stat.ModTime()) > 15*time.Minute {
				ui.Warn("Toolchain lock for %s is older than 15 minutes. Assuming stale and removing...", tcName)
				os.RemoveAll(lockDir)
				continue
			}
		}

		ui.Warn("Waiting for another process to finish provisioning %s...", tcName)
		time.Sleep(3 * time.Second)
	}

	// Double-check after acquiring the lock
	if tcPath := FindBinDir(tcRoot, prefix); tcPath != "" {
		return tcPath, nil
	}

	// Ensure a clean slate for extraction if it's corrupted.
	_ = RetryWindowsLocks(func() error { return os.RemoveAll(tcRoot) })

	// 2. Not found or corrupted, we must auto-provision it.
	ui.Muted("Toolchain '%s' (v%s) not found locally.", tcName, cacheVer)
	ui.Step("Looking up auto-provisioning URL in registry...")

	osArch := fmt.Sprintf("%s_%s", runtime.GOOS, runtime.GOARCH)
	downloadURL, ok := tcInfo.URLs[osArch]
	if !ok {
		return "", fmt.Errorf("no download URL provided for OS/Arch: %s", osArch)
	}

	ui.Info("Found toolchain v%s for %s", tcInfo.Version, osArch)

	// A missing entry used to yield an empty string, and the download then skipped verification
	// entirely. The registry is the only thing standing between a compromised mirror and a compiler
	// that runs on the developer's machine, so a gap in it is a hard error and not a silent
	// downgrade.
	expectedSha256, ok := tcInfo.Sha256[osArch]
	if !ok || strings.TrimSpace(expectedSha256) == "" {
		return "", fmt.Errorf("registry has no sha256 for toolchain '%s' on %s: refusing to install it unverified", tcName, osArch)
	}

	if err := downloadAndExtract(downloadURL, tcRoot, expectedSha256, expectedVersion); err != nil {
		return "", fmt.Errorf("failed to download and extract toolchain: %w", err)
	}

	// 3. Find the actual /bin directory recursively
	tcPath := FindBinDir(tcRoot, prefix)
	if tcPath == "" {
		return "", fmt.Errorf("auto-provisioning completed but /bin directory with executables prefixed '%s' not found inside %s", prefix, tcRoot)
	}

	ui.Success("Successfully installed toolchain to %s", tcPath)
	return tcPath, nil
}

// RetryWindowsLocks wraps an operation with exponential backoff to bypass temporary NTFS locks (e.g. from Defender)
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

// downloadClient fetches toolchain archives.
//
// It deliberately has no overall timeout — a toolchain is hundreds of megabytes and a slow link is
// not an error — but it bounds every phase that can hang without transferring anything, and it
// refuses to be redirected off HTTPS. http.DefaultClient, which this used before, has none of that.
var downloadClient = &http.Client{
	Transport: &http.Transport{
		DialContext:           (&net.Dialer{Timeout: 15 * time.Second}).DialContext,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		Proxy:                 http.ProxyFromEnvironment,
	},
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return fmt.Errorf("stopped after 10 redirects")
		}
		if req.URL.Scheme != "https" {
			return fmt.Errorf("refusing redirect to non-HTTPS URL %s", req.URL.Redacted())
		}
		return nil
	},
}

func downloadAndExtract(url, destDir, expectedSha256, expectedVersion string) error {
	// The archive is executed as a compiler on the developer's machine, so neither of these is
	// optional. The checksum was skipped whenever the registry had no entry for this platform.
	if !strings.HasPrefix(url, "https://") {
		return fmt.Errorf("refusing to download a toolchain over a non-HTTPS URL: %s", url)
	}
	if expectedSha256 == "" {
		return fmt.Errorf("refusing to install a toolchain without an expected SHA256 checksum")
	}

	// Setup download cache directory
	homeDir, _ := paths.ToobHome()
	cacheDir := filepath.Join(homeDir, "cache", "downloads")
	os.MkdirAll(cacheDir, 0755)

	tcName := filepath.Base(filepath.Dir(destDir))
	archivePath := filepath.Join(cacheDir, fmt.Sprintf("%s-%s.archive", tcName, expectedVersion))

	var startBytes int64 = 0
	if stat, err := os.Stat(archivePath); err == nil {
		startBytes = stat.Size()
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}

	if startBytes > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", startBytes))
		ui.Step("Resuming download %s from byte %d...", url, startBytes)
	} else {
		ui.Step("Downloading %s", url)
	}

	resp, err := downloadClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case 416:
		// Requested Range Not Satisfiable - we probably downloaded the whole file already!
		ui.Muted("Download already complete.")
	case 206, 200:
		var out *os.File
		if resp.StatusCode == 206 {
			// Resuming
			out, err = os.OpenFile(archivePath, os.O_WRONLY|os.O_APPEND, 0644)
		} else {
			// Server didn't support range or we started from 0
			out, err = os.Create(archivePath)
			startBytes = 0 // Reset
		}
		if err != nil {
			return err
		}

		spinner := ui.NewSpinner("Downloading Toolchain")
		spinner.SetProgress(int(startBytes), int(resp.ContentLength+startBytes))
		spinner.Start()

		if _, err := io.Copy(io.MultiWriter(out, spinner), resp.Body); err != nil {
			out.Close()
			spinner.Stop()
			return err
		}
		spinner.Stop()
		out.Close()
	default:
		return fmt.Errorf("server returned %d", resp.StatusCode)
	}

	// Verify SHA256 of the FULL file before anything is unpacked.
	actualSha256, err := hashFile(archivePath)
	if err != nil {
		os.Remove(archivePath)
		return fmt.Errorf("failed hashing the downloaded archive: %w", err)
	}
	if actualSha256 != expectedSha256 {
		// Corrupt! Delete it and fail.
		os.Remove(archivePath)
		return fmt.Errorf("SHA256 mismatch!\nExpected: %s\nGot:      %s", expectedSha256, actualSha256)
	}
	ui.Success("Checksum verified.")

	tmpDestDir := fmt.Sprintf("%s.tmp.%d", destDir, os.Getpid())
	_ = RetryWindowsLocks(func() error { return os.RemoveAll(tmpDestDir) })
	if err := os.MkdirAll(tmpDestDir, 0755); err != nil {
		return err
	}

	// Extraction runs in-process. It used to shell out to tar and unzip first and fall back to
	// these only when the external tool failed, which meant the path guards below applied to the
	// exceptional case and the normal case relied on the defaults of two programs that are not
	// installed everywhere, differ between platforms and are not covered by any test here.
	extractErr := extractArchive(url, archivePath, tmpDestDir)

	if extractErr != nil {
		os.Remove(archivePath) // Gap 4: Wipe broken archive from cache to avoid endless loops
		RetryWindowsLocks(func() error { return os.RemoveAll(tmpDestDir) })
		return extractErr
	}

	// Post-process extracted files to push them into CAS (Bypass in Docker)
	if _, err := os.Stat("/.dockerenv"); os.IsNotExist(err) && os.Getenv("TOOB_DISABLE_CAS") == "" {
		if err := postProcessCAS(tmpDestDir); err != nil {
			RetryWindowsLocks(func() error { return os.RemoveAll(tmpDestDir) })
			return fmt.Errorf("CAS processing failed: %w", err)
		}
	} else {
		ui.Muted("Bypassing CAS deduplication (Docker Environment / Disabled).")
	}

	// Atomic commit
	_ = RetryWindowsLocks(func() error { return os.RemoveAll(destDir) })
	if err := RetryWindowsLocks(func() error { return os.Rename(tmpDestDir, destDir) }); err != nil {
		if strings.Contains(err.Error(), "cross-device link") {
			// Fallback to recursive copy for cross-volume mounts (e.g. Docker/Windows)
			if copyErr := copyTree(tmpDestDir, destDir); copyErr != nil {
				return fmt.Errorf("failed to finalize installation (cross-device fallback failed): %w", copyErr)
			}
			RetryWindowsLocks(func() error { return os.RemoveAll(tmpDestDir) })
		} else {
			return fmt.Errorf("failed to finalize installation: %w", err)
		}
	}

	os.Remove(archivePath) // Gap 3: Free up disk space after successful installation
	return nil
}

func postProcessCAS(extractedDir string) error {
	homeDir, _ := paths.ToobHome()
	casDir := filepath.Join(homeDir, "store", "cas")
	os.MkdirAll(casDir, 0755)

	return filepath.WalkDir(extractedDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}

		// Hash file
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		hasher := sha256.New()
		io.Copy(hasher, f)
		f.Close()

		hashStr := hex.EncodeToString(hasher.Sum(nil))
		casPath := filepath.Join(casDir, hashStr)

		origStat, err := os.Stat(path)
		if err != nil {
			return err
		}
		origMode := origStat.Mode()

		// Check if it's already in CAS
		if _, err := os.Stat(casPath); os.IsNotExist(err) {
			// Move into CAS
			tmpCas := fmt.Sprintf("%s.tmp.%d", casPath, os.Getpid())
			if err := RetryWindowsLocks(func() error { return os.Rename(path, tmpCas) }); err != nil {
				// If rename fails (e.g. cross volume), copy it using O(1) memory streaming to prevent OOM
				srcFile, _ := os.Open(path)
				dstFile, _ := os.OpenFile(tmpCas, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, origMode)
				io.Copy(dstFile, srcFile)
				srcFile.Close()
				dstFile.Close()
				os.Remove(path) // Remove original
			}

			// Gap 1: Protect CAS store from accidental user modifications
			var roMode fs.FileMode = 0444
			if origMode&0111 != 0 {
				roMode = 0555 // Preserve executable bit for read-only
			}
			os.Chmod(tmpCas, roMode)
			if err := RetryWindowsLocks(func() error { return os.Rename(tmpCas, casPath) }); err != nil {
				// We lost the race condition (another process created casPath in the exact same millisecond).
				// Since the file is mathematically identical (SHA256), we just drop our temp file and use theirs!
				os.Remove(tmpCas)
			}
		} else {
			// Already in CAS, just remove the extracted file so we can hardlink it
			os.Remove(path)
		}

		// Now create a hardlink from CAS to the original path
		if err := os.Link(casPath, path); err != nil {
			// If hardlink fails (e.g. cross-device), copy from CAS using O(1) memory streaming to prevent OOM
			srcFile, _ := os.Open(casPath)
			dstFile, _ := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, origMode)
			io.Copy(dstFile, srcFile)
			srcFile.Close()
			dstFile.Close()
		}

		return nil
	})
}

// hashFile returns the hex SHA-256 of a file. The read error is not discarded: a truncated read
// would produce the hash of a prefix, and while that still fails the comparison, it would fail it
// with a misleading "checksum mismatch" instead of the actual I/O problem.
func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// extractArchive unpacks an archive according to the extension of the URL it came from.
func extractArchive(url, archivePath, destDir string) error {
	switch {
	case strings.HasSuffix(url, ".zip"):
		return extractZip(archivePath, destDir)

	case strings.HasSuffix(url, ".tar.gz"), strings.HasSuffix(url, ".tar.xz"):
		f, err := os.Open(archivePath)
		if err != nil {
			return err
		}
		defer f.Close()

		if strings.HasSuffix(url, ".tar.gz") {
			return extractTarGz(f, destDir)
		}
		return extractTarXz(f, destDir)

	default:
		return fmt.Errorf("unsupported archive format for url: %s", url)
	}
}

func extractZip(zipPath, destDir string) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer r.Close()

	spinner := ui.NewSpinner("Unzipping Toolchain")
	spinner.SetProgress(0, len(r.File))
	spinner.Start()
	defer spinner.Stop()

	budget := archiveutil.NewBudget(archiveutil.DefaultSizeLimit)

	for _, f := range r.File {
		spinner.AddProgress(1)

		fpath, err := archiveutil.SafeJoin(destDir, f.Name)
		if err != nil {
			return err
		}

		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(fpath, archiveutil.DirMode); err != nil {
				return err
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(fpath), archiveutil.DirMode); err != nil {
			return err
		}

		if err := writeZipEntry(f, fpath, budget); err != nil {
			return fmt.Errorf("failed extracting %q: %w", f.Name, err)
		}
	}
	return nil
}

func writeZipEntry(f *zip.File, fpath string, budget *archiveutil.Budget) error {
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()

	outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, archiveutil.EntryMode(f.Mode()))
	if err != nil {
		return err
	}

	if _, err := budget.Copy(outFile, rc); err != nil {
		outFile.Close()
		return err
	}
	return outFile.Close()
}

func extractTarGz(r io.Reader, destDir string) error {
	gzr, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	return extractTar(tr, destDir)
}

func extractTarXz(r io.Reader, destDir string) error {
	xzr, err := xz.NewReader(r)
	if err != nil {
		return err
	}

	tr := tar.NewReader(xzr)
	return extractTar(tr, destDir)
}

func extractTar(tr *tar.Reader, destDir string) error {
	spinner := ui.NewSpinner("Unpacking Toolchain")
	// Since TAR length is unknown beforehand, we just use it as a spinner without progress bar
	spinner.Start()
	defer spinner.Stop()

	budget := archiveutil.NewBudget(archiveutil.DefaultSizeLimit)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		// Extended headers carry metadata for the following entry and are consumed by the reader.
		if header.Typeflag == tar.TypeXGlobalHeader || header.Typeflag == tar.TypeXHeader {
			continue
		}

		target, err := archiveutil.SafeJoin(destDir, header.Name)
		if err != nil {
			return err
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, archiveutil.DirMode); err != nil {
				return err
			}

		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), archiveutil.DirMode); err != nil {
				return err
			}
			if err := writeTarFile(tr, target, header, budget); err != nil {
				return fmt.Errorf("failed extracting %q: %w", header.Name, err)
			}

		case tar.TypeSymlink:
			if err := writeSymlink(destDir, target, header); err != nil {
				return err
			}

		case tar.TypeLink:
			// A hard link names another entry of the same archive, so its source is resolved and
			// checked exactly like an entry path.
			source, err := archiveutil.SafeJoin(destDir, header.Linkname)
			if err != nil {
				return fmt.Errorf("hard link %q: %w", header.Name, err)
			}
			if err := os.MkdirAll(filepath.Dir(target), archiveutil.DirMode); err != nil {
				return err
			}
			_ = os.Remove(target)
			if err := os.Link(source, target); err != nil {
				return fmt.Errorf("failed linking %q -> %q: %w", header.Name, header.Linkname, err)
			}

		default:
			// Character devices, block devices and FIFOs have no place in a toolchain archive.
			// Skipping them silently used to leave an installation that looked complete.
			return fmt.Errorf("unsupported archive entry type %q for %q", string(header.Typeflag), header.Name)
		}
	}
	return nil
}

func writeTarFile(tr *tar.Reader, target string, header *tar.Header, budget *archiveutil.Budget) error {
	// O_TRUNC matters when extracting over an existing tree: without it a shorter file leaves the
	// tail of its predecessor in place. The zip path always had it, this one did not.
	f, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, archiveutil.EntryMode(header.FileInfo().Mode()))
	if err != nil {
		return err
	}
	if _, err := budget.Copy(f, tr); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// writeSymlink creates a link only after checking where it points.
//
// The path check on the entry itself is lexical and cannot see through links: an archive that first
// creates "evil -> /etc" and then writes "evil/passwd" passes it twice and still lands outside the
// destination, because the operating system resolves the link on the second write.
func writeSymlink(destDir, target string, header *tar.Header) error {
	if err := archiveutil.SafeLinkTarget(destDir, target, header.Linkname); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(target), archiveutil.DirMode); err != nil {
		return err
	}
	_ = os.Remove(target)

	if err := os.Symlink(header.Linkname, target); err != nil {
		// Windows only creates symlinks with Developer Mode or elevation. That is an environment
		// limitation rather than a broken archive, so it is reported and skipped instead of
		// aborting a provisioning run that would otherwise succeed. Everywhere else a failure here
		// means the installation is incomplete, and a toolchain missing "gcc -> gcc-13" fails much
		// later with a far more confusing message.
		if runtime.GOOS == "windows" {
			ui.Warn("Skipping symlink %s -> %s (Windows requires Developer Mode): %v", header.Name, header.Linkname, err)
			return nil
		}
		return fmt.Errorf("failed creating symlink %q -> %q: %w", header.Name, header.Linkname, err)
	}
	return nil
}

// FindBinDir recursively searches for a directory named "bin" containing any executables starting with the given prefix.
// This is completely compiler-agnostic (it doesn't care if it's gcc, clang, ld, etc.)
func FindBinDir(root string, prefix string) string {
	var binDir string

	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if binDir != "" {
			return filepath.SkipDir // Abort further traversal once found
		}
		if info.IsDir() && info.Name() == "bin" {
			// Check if this bin directory contains any files starting with the prefix
			entries, err := os.ReadDir(path)
			if err == nil {
				for _, e := range entries {
					if !e.IsDir() && strings.HasPrefix(e.Name(), prefix) {
						binDir = path
						return filepath.SkipDir // Found it!
					}
				}
			}
			return filepath.SkipDir // Skip traversing inside bin if it didn't match
		}
		return nil
	})
	return binDir
}

// copyTree recursively copies src to dst. Used as fallback for EXDEV errors.
// Uses hard-links where possible for instant, zero-disk-cost copies.
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, path)
		target := filepath.Join(dst, rel)

		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}

		// Hard-link first (instant, shares inode), byte-copy fallback
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		if err := os.Link(path, target); err == nil {
			return nil
		}

		sInfo, err := d.Info()
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, sInfo.Mode())
	})
}
