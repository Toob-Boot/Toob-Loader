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
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/toob-boot/toob/internal/paths"
	"github.com/toob-boot/toob/internal/ui"
	"github.com/ulikunitz/xz"
)

// RegistryToolchain defines the toolchain URLs from registry.json
type RegistryToolchain struct {
	Version string            `json:"version"`
	URLs    map[string]string `json:"urls"`
	Sha256  map[string]string `json:"sha256"`
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

	homeDir, err := paths.ToobHome()
	if err != nil {
		return "", err
	}
	localDir := filepath.Join(homeDir, "toolchains")

	if expectedVersion == "" {
		expectedVersion = "latest"
	}
	tcRoot := filepath.Join(localDir, tcName, expectedVersion)

	// 1. Cache Check (Gap 1.1 Versioning)
	if tcPath := FindBinDir(tcRoot, prefix); tcPath != "" {
		return tcPath, nil
	}

	// Ensure a clean slate for extraction if it's corrupted.
	_ = RetryWindowsLocks(func() error { return os.RemoveAll(tcRoot) })

	// 2. Not found or corrupted, we must auto-provision it.
	ui.Muted("Toolchain '%s' (v%s) not found locally.", tcName, expectedVersion)
	ui.Step("Looking up auto-provisioning URL in registry...")

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

	osArch := fmt.Sprintf("%s_%s", runtime.GOOS, runtime.GOARCH)
	downloadURL, ok := tcInfo.URLs[osArch]
	if !ok {
		return "", fmt.Errorf("no download URL provided for OS/Arch: %s", osArch)
	}

	ui.Info("Found toolchain v%s for %s", tcInfo.Version, osArch)

	expectedSha256 := tcInfo.Sha256[osArch]

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

func downloadAndExtract(url, destDir, expectedSha256, expectedVersion string) error {
	// Setup download cache directory
	homeDir, _ := paths.ToobHome()
	cacheDir := filepath.Join(homeDir, "cache", "downloads")
	os.MkdirAll(cacheDir, 0755)

	tcName := filepath.Base(filepath.Dir(destDir))
	archivePath := filepath.Join(cacheDir, fmt.Sprintf("%s-%s.archive", tcName, expectedVersion))
	lockPath := archivePath + ".lock"

	// Wait for exclusive download lock to prevent concurrent HTTP Range appending corruption
	for {
		lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
		if err == nil {
			lockFile.Close()
			defer os.Remove(lockPath)
			break
		}
		ui.Warn("Waiting for another process to finish downloading %s...", tcName)
		time.Sleep(2 * time.Second)
	}

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

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 416 {
		// Requested Range Not Satisfiable - we probably downloaded the whole file already!
		ui.Muted("Download already complete.")
	} else if resp.StatusCode == 206 || resp.StatusCode == 200 {
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
	} else {
		return fmt.Errorf("server returned %d", resp.StatusCode)
	}

	// Verify SHA256 of the FULL file
	if expectedSha256 != "" {
		hasher := sha256.New()
		f, err := os.Open(archivePath)
		if err != nil {
			return err
		}
		io.Copy(hasher, f)
		f.Close()

		actualSha256 := hex.EncodeToString(hasher.Sum(nil))
		if actualSha256 != expectedSha256 {
			// Corrupt! Delete it and fail.
			os.Remove(archivePath)
			return fmt.Errorf("SHA256 mismatch!\nExpected: %s\nGot:      %s", expectedSha256, actualSha256)
		}
		ui.Success("Checksum verified.")
	}

	tmpDestDir := fmt.Sprintf("%s.tmp.%d", destDir, os.Getpid())
	_ = RetryWindowsLocks(func() error { return os.RemoveAll(tmpDestDir) })
	if err := os.MkdirAll(tmpDestDir, 0755); err != nil {
		return err
	}

	var extractErr error
	if strings.HasSuffix(url, ".zip") {
		extractErr = extractZipFast(archivePath, tmpDestDir)
		if extractErr != nil {
			ui.Warn("Fast native zip failed. Falling back to Go extraction...")
			extractErr = extractZip(archivePath, tmpDestDir)
		}
	} else if strings.HasSuffix(url, ".tar.gz") || strings.HasSuffix(url, ".tar.xz") {
		extractErr = extractTarFast(archivePath, tmpDestDir)
		if extractErr != nil {
			ui.Warn("Fast native tar failed. Falling back to Go extraction...")
			f, _ := os.Open(archivePath)
			if strings.HasSuffix(url, ".tar.gz") {
				extractErr = extractTarGz(f, tmpDestDir)
			} else {
				extractErr = extractTarXz(f, tmpDestDir)
			}
			f.Close()
		}
	} else {
		extractErr = fmt.Errorf("unsupported archive format for url: %s", url)
	}

	if extractErr != nil {
		os.Remove(archivePath) // Gap 4: Wipe broken archive from cache to avoid endless loops
		RetryWindowsLocks(func() error { return os.RemoveAll(tmpDestDir) })
		return extractErr
	}

	// Post-process extracted files to push them into CAS
	if err := postProcessCAS(tmpDestDir); err != nil {
		RetryWindowsLocks(func() error { return os.RemoveAll(tmpDestDir) })
		return fmt.Errorf("CAS processing failed: %w", err)
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

func extractTarFast(archivePath, destDir string) error {
	cmd := exec.Command("tar", "-xf", archivePath, "-C", destDir)
	return cmd.Run()
}

func extractZipFast(archivePath, destDir string) error {
	cmd := exec.Command("unzip", "-q", archivePath, "-d", destDir)
	return cmd.Run()
}

func extractZip(zipPath, destDir string) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer r.Close()

	totalFiles := len(r.File)

	spinner := ui.NewSpinner("Unzipping Toolchain")
	spinner.SetProgress(0, totalFiles)
	spinner.Start()
	defer spinner.Stop()

	for _, f := range r.File {
		spinner.AddProgress(1)

		fpath := filepath.Join(destDir, f.Name)
		if !strings.HasPrefix(fpath, filepath.Clean(destDir)+string(os.PathSeparator)) {
			return fmt.Errorf("illegal file path: %s", fpath)
		}

		if f.FileInfo().IsDir() {
			os.MkdirAll(fpath, os.ModePerm)
			continue
		}

		if err = os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
			return err
		}

		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return err
		}

		rc, err := f.Open()
		if err != nil {
			outFile.Close()
			return err
		}

		_, err = io.Copy(outFile, rc)
		outFile.Close()
		rc.Close()

		if err != nil {
			return err
		}
	}
	return nil
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

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		target := filepath.Join(destDir, header.Name)

		// Prevention of Zip-Slip / Path Traversal for TAR archives
		if !strings.HasPrefix(target, filepath.Clean(destDir)+string(os.PathSeparator)) {
			return fmt.Errorf("illegal file path (zip slip vulnerability): %s", target)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_RDWR, os.FileMode(header.Mode))
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return err
			}
			f.Close()
		case tar.TypeSymlink:
			os.Symlink(header.Linkname, target)
		}
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
