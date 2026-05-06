package toolchain

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
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
}

// RegistryConfig represents the root of registry.json
type RegistryConfig struct {
	Toolchains map[string]RegistryToolchain `json:"toolchains"`
}



// EnsureAvailable checks if the toolchain exists, and if not, downloads and extracts it.
// Returns the absolute path to the toolchain's /bin directory.
func EnsureAvailable(prefix string) (string, error) {
	tcName := strings.TrimSuffix(prefix, "-")

	// 1. Check if already installed
	homeDir, err := paths.ToobHome()
	if err != nil {
		return "", err
	}

	localDir := filepath.Join(homeDir, "toolchains")
	tcPath := filepath.Join(localDir, tcName, "bin")
	if _, err := os.Stat(tcPath); err == nil {
		return tcPath, nil
	}

	// 1b. Check if already installed but wrapped in a top-level folder
	entries, err := os.ReadDir(filepath.Join(localDir, tcName))
	if err == nil && len(entries) == 1 && entries[0].IsDir() && entries[0].Name() != "bin" {
		wrappedPath := filepath.Join(localDir, tcName, entries[0].Name(), "bin")
		if _, err := os.Stat(wrappedPath); err == nil {
			return wrappedPath, nil
		}
	}

	// 2. Not found, we must auto-provision it.
	fmt.Printf("[toob] Toolchain '%s' not found locally.\n", tcName)
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

	if err := downloadAndExtract(downloadURL, filepath.Join(localDir, tcName)); err != nil {
		return "", fmt.Errorf("failed to download and extract toolchain: %w", err)
	}

	// After extraction, check if bin exists. Often archives have a top-level wrapper folder.
	// We might need to handle wrapper folders (e.g. `riscv32-esp-elf/riscv32-esp-elf/bin`).
	entries, err = os.ReadDir(filepath.Join(localDir, tcName))
	if err == nil && len(entries) == 1 && entries[0].IsDir() && entries[0].Name() != "bin" {
		// Unwrap the top level folder
		tcPath = filepath.Join(localDir, tcName, entries[0].Name(), "bin")
	}

	if _, err := os.Stat(tcPath); err != nil {
		return "", fmt.Errorf("auto-provisioning completed but /bin directory not found at %s", tcPath)
	}

	fmt.Printf("[toob] Successfully installed toolchain to %s\n", tcPath)
	return tcPath, nil
}

func downloadAndExtract(url, destDir string) error {
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

	// Seek back to start for extraction
	tmpFile.Seek(0, 0)

	if err := os.MkdirAll(destDir, 0755); err != nil {
		return err
	}

	if strings.HasSuffix(url, ".zip") {
		return extractZip(tmpFile.Name(), destDir)
	} else if strings.HasSuffix(url, ".tar.gz") {
		return extractTarGz(tmpFile, destDir)
	} else if strings.HasSuffix(url, ".tar.xz") {
		return extractTarXz(tmpFile, destDir)
	}

	return fmt.Errorf("unsupported archive format for url: %s", url)
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
