package registry

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// downloadAndExtractTarball downloads a .tar.gz from a URL and extracts it into targetDir.
// It skips the root folder of the archive if it exists.
func downloadAndExtractTarball(url string, targetDir string) error {
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to download %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("bad status %d from %s", resp.StatusCode, url)
	}

	gzr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)

	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		return err
	}

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		if header == nil {
			continue
		}

		// Strip the top-level directory (like the ZIP extractor did)
		parts := strings.SplitN(filepath.ToSlash(header.Name), "/", 2)
		if len(parts) < 2 || parts[1] == "" {
			continue
		}

		relPath := filepath.FromSlash(parts[1])
		destPath := filepath.Join(targetDir, relPath)

		// Zip-Slip protection
		cleanDest := filepath.Clean(destPath)
		cleanTarget := filepath.Clean(targetDir) + string(os.PathSeparator)
		if !strings.HasPrefix(cleanDest, cleanTarget) {
			return fmt.Errorf("illegal path (tar-slip): %s", destPath)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(destPath, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
				return err
			}
			outFile, err := os.OpenFile(destPath, os.O_CREATE|os.O_RDWR, os.FileMode(header.Mode))
			if err != nil {
				return err
			}
			if _, err := io.Copy(outFile, tr); err != nil {
				outFile.Close()
				return err
			}
			outFile.Close()
		}
	}

	return nil
}
