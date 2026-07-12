package registry

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// defaultIgnorePatterns are always excluded from tarballs, regardless of ignore files.
var defaultIgnorePatterns = []string{
	".git",
	".git/",
	"build",
	"build/",
	".toob",
	".toob/",
	"credentials.json",
	".DS_Store",
	"*.swp",
	"*.swo",
	"*~",
}

// CreateTarball creates a gzip-compressed tarball of srcDir and writes it to w.
// It respects ignore rules in the following priority:
//  1. .toobignore (if present in srcDir)
//  2. .gitignore (if present in srcDir, and no .toobignore)
//  3. Hardcoded defaults (always applied)
func CreateTarball(srcDir string, w io.Writer) error {
	absDir, err := filepath.Abs(srcDir)
	if err != nil {
		return fmt.Errorf("failed to resolve source directory: %w", err)
	}

	info, err := os.Stat(absDir)
	if err != nil {
		return fmt.Errorf("source directory does not exist: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("source path is not a directory: %s", absDir)
	}

	ignorePatterns := loadIgnorePatterns(absDir)

	gzw := gzip.NewWriter(w)
	defer gzw.Close()

	tw := tar.NewWriter(gzw)
	defer tw.Close()

	return filepath.Walk(absDir, func(path string, fi os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		relPath, err := filepath.Rel(absDir, path)
		if err != nil {
			return err
		}

		// Skip the root directory itself
		if relPath == "." {
			return nil
		}

		// Normalize to forward slashes for matching and tar headers
		normalizedRel := filepath.ToSlash(relPath)

		if shouldIgnore(normalizedRel, fi.IsDir(), ignorePatterns) {
			if fi.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		// Only include regular files and directories
		if !fi.Mode().IsRegular() && !fi.IsDir() {
			return nil
		}

		header, err := tar.FileInfoHeader(fi, "")
		if err != nil {
			return fmt.Errorf("failed to create tar header for %s: %w", relPath, err)
		}
		header.Name = normalizedRel

		if err := tw.WriteHeader(header); err != nil {
			return fmt.Errorf("failed to write tar header for %s: %w", relPath, err)
		}

		if fi.IsDir() {
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("failed to open %s: %w", path, err)
		}
		defer f.Close()

		if _, err := io.Copy(tw, f); err != nil {
			return fmt.Errorf("failed to write %s to tarball: %w", relPath, err)
		}

		return nil
	})
}

// loadIgnorePatterns reads the applicable ignore file and merges with defaults.
func loadIgnorePatterns(dir string) []string {
	patterns := make([]string, len(defaultIgnorePatterns))
	copy(patterns, defaultIgnorePatterns)

	// Priority 1: .toobignore
	toobIgnore := filepath.Join(dir, ".toobignore")
	if filePatterns, err := readIgnoreFile(toobIgnore); err == nil {
		return append(patterns, filePatterns...)
	}

	// Priority 2: .gitignore fallback
	gitIgnore := filepath.Join(dir, ".gitignore")
	if filePatterns, err := readIgnoreFile(gitIgnore); err == nil {
		return append(patterns, filePatterns...)
	}

	return patterns
}

// readIgnoreFile parses a gitignore-style file and returns the non-empty, non-comment lines.
func readIgnoreFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var patterns []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		patterns = append(patterns, line)
	}
	return patterns, scanner.Err()
}

// shouldIgnore checks if a relative path matches any of the ignore patterns.
func shouldIgnore(relPath string, isDir bool, patterns []string) bool {
	// Check each path component against directory patterns
	parts := strings.Split(relPath, "/")

	for _, pattern := range patterns {
		// Directory-specific pattern (ending with /)
		if before, ok := strings.CutSuffix(pattern, "/"); ok {
			dirPattern := before
			if isDir && matchComponent(filepath.Base(relPath), dirPattern) {
				return true
			}
			for _, part := range parts {
				if matchComponent(part, dirPattern) {
					return true
				}
			}
			continue
		}

		// Exact filename or basename match
		baseName := filepath.Base(relPath)
		if matchComponent(baseName, pattern) {
			return true
		}

		// Full path match
		if matchComponent(relPath, pattern) {
			return true
		}
	}

	return false
}

// matchComponent performs a simplified glob match supporting * wildcards.
func matchComponent(name, pattern string) bool {
	matched, _ := filepath.Match(pattern, name)
	return matched
}

// downloadAndExtractTarball downloads a .tar.gz from a URL and extracts it into targetDir.
// The caller must provide a properly configured *http.Client that respects enterprise
// transport settings (CA certificates via TOOB_CA_CERT, proxy via HTTP_PROXY, timeouts).
func downloadAndExtractTarball(client *http.Client, url string, targetDir string) error {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request for %s: %w", url, err)
	}
	req.Header.Set("User-Agent", "Toob-CLI")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to download %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status %d from %s", resp.StatusCode, url)
	}

	return ExtractTarball(resp.Body, targetDir)
}

// ExtractTarball decompresses a gzipped tar stream into targetDir,
// stripping the top-level directory from archive paths.
func ExtractTarball(r io.Reader, targetDir string) error {
	gzr, err := gzip.NewReader(r)
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

		// Strip the top-level directory
		parts := strings.SplitN(filepath.ToSlash(header.Name), "/", 2)
		if len(parts) < 2 || parts[1] == "" {
			continue
		}

		relPath := filepath.FromSlash(parts[1])
		destPath := filepath.Join(targetDir, relPath)

		// Tar-Slip protection
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
