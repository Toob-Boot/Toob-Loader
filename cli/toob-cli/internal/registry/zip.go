package registry

import (
	"archive/zip"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// downloadAndExtractZip downloads a ZIP archive to a temp file and extracts it to targetDir.
// Streams directly to disk to avoid holding the full archive in RAM.
// Automatically strips the root folder (e.g. 'Toob-Registry-main/') from zip entries.
func downloadAndExtractZip(url string, targetDir string) error {
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to download %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("bad status %d from %s", resp.StatusCode, url)
	}

	// Stream to temp file instead of buffering entire archive in RAM
	tmpFile, err := os.CreateTemp("", "toob-registry-*.zip")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	if _, err := io.Copy(tmpFile, resp.Body); err != nil {
		return fmt.Errorf("failed to download archive: %w", err)
	}
	tmpFile.Close()

	zipReader, err := zip.OpenReader(tmpFile.Name())
	if err != nil {
		return err
	}
	defer zipReader.Close()

	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		return err
	}

	for _, f := range zipReader.File {
		// Strip the top-level directory
		parts := strings.SplitN(filepath.ToSlash(f.Name), "/", 2)
		if len(parts) < 2 || parts[1] == "" {
			continue
		}

		relPath := filepath.FromSlash(parts[1])
		destPath := filepath.Join(targetDir, relPath)

		// Zip-Slip protection
		cleanDest := filepath.Clean(destPath)
		cleanTarget := filepath.Clean(targetDir) + string(os.PathSeparator)
		if !strings.HasPrefix(cleanDest, cleanTarget) {
			return fmt.Errorf("illegal path (zip-slip): %s", destPath)
		}

		if f.FileInfo().IsDir() {
			os.MkdirAll(destPath, 0o755)
			continue
		}

		if err := extractFile(f, destPath); err != nil {
			return err
		}
	}

	return nil
}

func extractFile(f *zip.File, destPath string) error {
	if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
		return err
	}

	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()

	destFile, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, rc)
	return err
}
