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

	"github.com/schollz/progressbar/v3"
	"github.com/toob-boot/toob/internal/paths"
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



// GetExpectedVersion returns the version specified in registry.json for a toolchain
func GetExpectedVersion(prefix string) string {
	tcName := strings.TrimSuffix(prefix, "-")
	regDir, err := paths.RegistryDir()
	if err != nil {
		return ""
	}
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

// GetExpectedSha256 returns the sha256 specified in registry.json for a toolchain
func GetExpectedSha256(prefix string) string {
	tcName := strings.TrimSuffix(prefix, "-")
	regDir, err := paths.RegistryDir()
	if err != nil {
		return ""
	}
	data, err := os.ReadFile(filepath.Join(regDir, "registry.json"))
	if err != nil {
		return ""
	}
	var reg RegistryConfig
	if err := json.Unmarshal(data, &reg); err != nil {
		return ""
	}
	if tcInfo, ok := reg.Toolchains[tcName]; ok {
		osArch := fmt.Sprintf("%s_%s", runtime.GOOS, runtime.GOARCH)
		return tcInfo.Sha256[osArch]
	}
	return ""
}

// EnsureAvailable checks if the toolchain exists, and if not, downloads and extracts it.
// Returns the absolute path to the toolchain's /bin directory.
func EnsureAvailable(prefix string, expectedVersion string) (string, error) {
	tcName := strings.TrimSuffix(prefix, "-")

	// 1. Cache Invalidation Check
	// If a folder exists, verify its .toob_version matches expectedVersion.
	// If not, we wipe it and re-download.
	homeDir, err := paths.ToobHome()
	if err != nil {
		return "", err
	}
	localDir := filepath.Join(homeDir, "toolchains")
	tcRoot := filepath.Join(localDir, tcName)
	var tcPath string
	if expectedVersion != "" {
		versionFile := filepath.Join(tcRoot, ".toob_version")
		cachedVersionBytes, err := os.ReadFile(versionFile)
		if err == nil {
			cachedVersion := strings.TrimSpace(string(cachedVersionBytes))
			if cachedVersion == expectedVersion {
				tcPath = findBinDir(tcRoot, prefix)
				if tcPath != "" {
					return tcPath, nil
				}
			} else {
				fmt.Printf("[toob] Auto-provisioned toolchain cache is outdated (v%s). Upgrading to v%s...\n", cachedVersion, expectedVersion)
			}
		}
	}
	
	// Ensure a clean slate for extraction if it's outdated or corrupted.
	_ = os.RemoveAll(tcRoot)

	// 2. Not found or outdated, we must auto-provision it.
	fmt.Printf("[toob] Toolchain '%s' not found locally or outdated.\n", tcName)
	fmt.Printf("[toob] Looking up auto-provisioning URL in registry...\n")

	regDir, err := paths.RegistryDir()
	if err != nil {
		return "", fmt.Errorf("failed to locate registry: %w", err)
	}

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

	fmt.Printf("[toob] Found toolchain v%s for %s\n", tcInfo.Version, osArch)

	expectedSha256 := tcInfo.Sha256[osArch]

	if err := downloadAndExtract(downloadURL, filepath.Join(localDir, tcName), expectedSha256, expectedVersion); err != nil {
		return "", fmt.Errorf("failed to download and extract toolchain: %w", err)
	}

	// 3. Find the actual /bin directory recursively
	tcPath = findBinDir(filepath.Join(localDir, tcName), prefix)
	if tcPath == "" {
		return "", fmt.Errorf("auto-provisioning completed but /bin directory with %sgcc not found inside %s", prefix, filepath.Join(localDir, tcName))
	}

	fmt.Printf("[toob] Successfully installed toolchain to %s\n", tcPath)
	return tcPath, nil
}

func downloadAndExtract(url, destDir, expectedSha256, expectedVersion string) error {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}

	fmt.Printf("[toob] Downloading %s\n", url)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("server returned %d", resp.StatusCode)
	}

	bar := progressbar.NewOptions64(
		resp.ContentLength,
		progressbar.OptionSetDescription("Downloading"),
		progressbar.OptionSetWriter(os.Stderr),
		progressbar.OptionShowBytes(true),
		progressbar.OptionSetWidth(30),
		progressbar.OptionThrottle(150*time.Millisecond),
		progressbar.OptionShowCount(),
		progressbar.OptionOnCompletion(func() {
			fmt.Fprint(os.Stderr, "\n")
		}),
		progressbar.OptionSpinnerType(14),
		progressbar.OptionFullWidth(),
	)
	
	tmpFile, err := os.CreateTemp("", "toob-toolchain-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	if _, err := io.Copy(io.MultiWriter(tmpFile, bar), resp.Body); err != nil {
		return err
	}

	// Check SHA256 if expected
	if expectedSha256 != "" {
		tmpFile.Seek(0, 0)
		hasher := sha256.New()
		if _, err := io.Copy(hasher, tmpFile); err != nil {
			return fmt.Errorf("failed to compute hash: %w", err)
		}
		actualSha256 := hex.EncodeToString(hasher.Sum(nil))
		if actualSha256 != expectedSha256 {
			return fmt.Errorf("SHA256 mismatch!\nExpected: %s\nGot:      %s", expectedSha256, actualSha256)
		}
		fmt.Printf("[toob] Checksum verified.\n")
	}

	// Seek back to start for extraction
	tmpFile.Seek(0, 0)

	tmpDestDir := destDir + ".tmp"
	_ = os.RemoveAll(tmpDestDir)
	if err := os.MkdirAll(tmpDestDir, 0755); err != nil {
		return err
	}

	var extractErr error
	if strings.HasSuffix(url, ".zip") {
		extractErr = extractZipFast(tmpFile.Name(), tmpDestDir)
		if extractErr != nil {
			fmt.Printf("\n[toob] Fast native zip failed. Falling back to Go extraction...\n")
			tmpFile.Seek(0, 0)
			extractErr = extractZip(tmpFile.Name(), tmpDestDir)
		}
	} else if strings.HasSuffix(url, ".tar.gz") || strings.HasSuffix(url, ".tar.xz") {
		extractErr = extractTarFast(tmpFile.Name(), tmpDestDir)
		if extractErr != nil {
			fmt.Printf("\n[toob] Fast native tar failed. Falling back to Go extraction...\n")
			tmpFile.Seek(0, 0)
			if strings.HasSuffix(url, ".tar.gz") {
				extractErr = extractTarGz(tmpFile, tmpDestDir)
			} else {
				extractErr = extractTarXz(tmpFile, tmpDestDir)
			}
		}
	} else {
		extractErr = fmt.Errorf("unsupported archive format for url: %s", url)
	}

	if extractErr != nil {
		os.RemoveAll(tmpDestDir)
		return extractErr
	}

	// Atomic commit
	_ = os.RemoveAll(destDir)
	if err := os.Rename(tmpDestDir, destDir); err != nil {
		if strings.Contains(err.Error(), "cross-device link") {
			// Fallback to recursive copy for cross-volume mounts (e.g. Docker/Windows)
			if copyErr := copyTree(tmpDestDir, destDir); copyErr != nil {
				return fmt.Errorf("failed to finalize installation (cross-device fallback failed): %w", copyErr)
			}
			os.RemoveAll(tmpDestDir)
		} else {
			return fmt.Errorf("failed to finalize installation: %w", err)
		}
	}

	if expectedVersion != "" {
		_ = os.WriteFile(filepath.Join(destDir, ".toob_version"), []byte(expectedVersion), 0o644)
	}

	return nil
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
	bar := progressbar.NewOptions(totalFiles,
		progressbar.OptionSetDescription("Unzipping"),
		progressbar.OptionSetWriter(os.Stderr),
		progressbar.OptionSetWidth(30),
		progressbar.OptionThrottle(150*time.Millisecond),
		progressbar.OptionShowCount(),
		progressbar.OptionOnCompletion(func() {
			fmt.Fprint(os.Stderr, "\n")
		}),
		progressbar.OptionSpinnerType(14),
		progressbar.OptionFullWidth(),
	)

	for _, f := range r.File {
		bar.Add(1)

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
	bar := progressbar.NewOptions(-1,
		progressbar.OptionSetDescription("Unpacking"),
		progressbar.OptionSetWriter(os.Stderr),
		progressbar.OptionSetWidth(30),
		progressbar.OptionThrottle(150*time.Millisecond),
		progressbar.OptionShowCount(),
		progressbar.OptionOnCompletion(func() {
			fmt.Fprint(os.Stderr, "\n")
		}),
		progressbar.OptionSpinnerType(14),
		progressbar.OptionFullWidth(),
	)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		bar.Add(1)

		target := filepath.Join(destDir, header.Name)

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

// findBinDir recursively searches for a directory named "bin" containing the prefixed gcc
func findBinDir(root string, prefix string) string {
	var binDir string
	expectedExe := prefix + "gcc"
	if runtime.GOOS == "windows" {
		expectedExe += ".exe"
	}

	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if binDir != "" {
			return filepath.SkipDir // Abort further traversal once found
		}
		if info.IsDir() && info.Name() == "bin" {
			// Check if this bin directory contains the compiler
			if stat, err := os.Stat(filepath.Join(path, expectedExe)); err == nil && !stat.IsDir() {
				binDir = path
			}
			return filepath.SkipDir // Skip traversing inside bin
		}
		return nil
	})
	return binDir
}

// copyTree recursively copies src to dst. Used as fallback for EXDEV errors.
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
