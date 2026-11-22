package registry

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/toob-boot/toob/internal/archiveutil"
)

// nonNegatableSecurityPatterns can never be re-included via '!' rules in .gitignore/.toobignore.
var nonNegatableSecurityPatterns = []string{
	".git",
	".git/",
	".toob",
	".toob/",
	"credentials.json",
	".env",
	".env.*",
	"*.pem",
	"*.key",
	".toob_pkg_meta.json",
}

// defaultIgnorePatterns are excluded by default unless explicitly negated in .gitignore/.toobignore.
var defaultIgnorePatterns = []string{
	"build/",
	"builds/",
	"conformance_report.json",
	"conformance_report.md",
	".DS_Store",
	"*.swp",
	"*.swo",
	"*~",
}

// canonicalRootManifests identifies genuine root-level package manifests across all 8 categories
// plus the Core SDK root CMakeLists.txt, used to safely unwrap GitHub-style single-top-dir archives.
var canonicalRootManifests = []string{
	"CMakeLists.txt",
	"chip_manifest.json",
	"driver_manifest.json",
	"crypto_manifest.json",
	"arch_manifest.json",
	"toolchain_manifest.json",
	"integration_manifest.json",
	"soc_manifest.json",
	"port_manifest.json",
}

// CreateTarball creates a deterministic gzip-compressed tarball of srcDir and writes it to w.
// It unions security defaults with .gitignore and .toobignore, normalizes tar and gzip headers
// for reproducible SHA-256 digests, and rejects symlinks and NTFS directory junctions.
func CreateTarball(srcDir string, w io.Writer) error {
	absDir, err := filepath.Abs(srcDir)
	if err != nil {
		return fmt.Errorf("failed to resolve source directory: %w", err)
	}

	info, err := os.Lstat(absDir)
	if err != nil {
		return fmt.Errorf("source directory does not exist: %w", err)
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("refusing to package symlinked root directory: %s", absDir)
	}
	if _, rlErr := os.Readlink(absDir); rlErr == nil {
		return fmt.Errorf("refusing to package junction root directory: %s", absDir)
	}
	if !info.IsDir() {
		return fmt.Errorf("source path is not a directory: %s", absDir)
	}

	realBase, err := filepath.EvalSymlinks(absDir)
	if err != nil {
		return fmt.Errorf("failed to canonicalize source directory %s: %w", absDir, err)
	}

	ignorePatterns, hasNegation, err := loadIgnorePatterns(absDir)
	if err != nil {
		return err
	}

	srcRoot, err := os.OpenRoot(absDir)
	if err != nil {
		return fmt.Errorf("failed to open source root %s: %w", absDir, err)
	}
	defer func() { _ = srcRoot.Close() }()

	gzw := gzip.NewWriter(w)
	gzw.ModTime = time.Time{}
	gzw.Name = ""
	gzw.Comment = ""
	gzw.OS = 255

	tw := tar.NewWriter(gzw)
	epoch := time.Unix(0, 0).UTC()

	walkErr := filepath.WalkDir(absDir, func(walkPath string, d fs.DirEntry, walkInErr error) error {
		if walkInErr != nil {
			return walkInErr
		}

		relPath, err := filepath.Rel(absDir, walkPath)
		if err != nil {
			return err
		}
		if relPath == "." {
			return nil
		}

		normalizedRel := filepath.ToSlash(relPath)
		isLink := d.Type()&fs.ModeSymlink != 0
		if !isLink {
			if _, rlErr := os.Readlink(walkPath); rlErr == nil {
				isLink = true
			}
		}

		if matchesAnyPattern(normalizedRel, d.IsDir(), nonNegatableSecurityPatterns) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		if shouldIgnore(normalizedRel, d.IsDir(), ignorePatterns) {
			if d.IsDir() && !hasNegation {
				return filepath.SkipDir
			}
			return nil
		}

		if isLink {
			return fmt.Errorf("refusing to package symlink or directory junction %q in %s", normalizedRel, absDir)
		}

		if _, joinErr := archiveutil.SafeJoin(absDir, normalizedRel); joinErr != nil {
			return joinErr
		}

		resolvedPath, err := filepath.EvalSymlinks(walkPath)
		if err != nil {
			return fmt.Errorf("failed to verify containment of %s: %w", normalizedRel, err)
		}
		relReal, err := filepath.Rel(realBase, resolvedPath)
		if err != nil || relReal == ".." || strings.HasPrefix(relReal, ".."+string(filepath.Separator)) || filepath.IsAbs(relReal) {
			return fmt.Errorf("path %q escapes package root %s", normalizedRel, absDir)
		}

		fi, err := srcRoot.Lstat(relPath)
		if err != nil {
			return fmt.Errorf("failed to stat %s: %w", normalizedRel, err)
		}
		if !fi.Mode().IsRegular() && !fi.IsDir() {
			return fmt.Errorf("unsupported file type for %q in package directory", normalizedRel)
		}

		header, err := tar.FileInfoHeader(fi, "")
		if err != nil {
			return fmt.Errorf("failed to create tar header for %s: %w", normalizedRel, err)
		}
		header.Name = normalizedRel
		switch {
		case fi.IsDir():
			if !strings.HasSuffix(header.Name, "/") {
				header.Name += "/"
			}
			header.Mode = 0o755
		case fi.Mode()&0o111 != 0:
			header.Mode = 0o755
		default:
			header.Mode = 0o644
		}
		header.ModTime = epoch
		header.AccessTime = time.Time{}
		header.ChangeTime = time.Time{}
		header.Uid = 0
		header.Gid = 0
		header.Uname = ""
		header.Gname = ""

		if err = tw.WriteHeader(header); err != nil {
			return fmt.Errorf("failed to write tar header for %s: %w", normalizedRel, err)
		}
		if fi.IsDir() {
			return nil
		}

		f, err := srcRoot.Open(relPath)
		if err != nil {
			return fmt.Errorf("failed to open %s: %w", normalizedRel, err)
		}
		_, copyErr := io.Copy(tw, f)
		closeErr := f.Close()
		if copyErr != nil {
			return fmt.Errorf("failed to write %s to tarball: %w", normalizedRel, copyErr)
		}
		if closeErr != nil {
			return fmt.Errorf("failed closing %s: %w", normalizedRel, closeErr)
		}
		return nil
	})
	if walkErr != nil {
		_ = tw.Close()
		_ = gzw.Close()
		return walkErr
	}

	if err := tw.Close(); err != nil {
		_ = gzw.Close()
		return fmt.Errorf("failed finalizing tar stream: %w", err)
	}
	if err := gzw.Close(); err != nil {
		return fmt.Errorf("failed finalizing gzip stream: %w", err)
	}
	return nil
}

func loadIgnorePatterns(dir string) ([]string, bool, error) {
	patterns := make([]string, 0, len(defaultIgnorePatterns)+16)
	patterns = append(patterns, defaultIgnorePatterns...)

	for _, name := range []string{".gitignore", ".toobignore"} {
		filePatterns, err := readIgnoreFile(filepath.Join(dir, name))
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return nil, false, fmt.Errorf("failed reading %s: %w", name, err)
		}
		patterns = append(patterns, filePatterns...)
	}

	hasNegation := false
	for _, p := range patterns {
		if strings.HasPrefix(p, "!") {
			hasNegation = true
			break
		}
	}
	return patterns, hasNegation, nil
}

func readIgnoreFile(filePath string) ([]string, error) {
	info, err := os.Lstat(filePath)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", filePath)
	}
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}

	var patterns []string
	reader := bufio.NewReader(f)
	for {
		line, readErr := reader.ReadString('\n')
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			_ = f.Close()
			return nil, readErr
		}
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			patterns = append(patterns, trimmed)
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	return patterns, nil
}

func matchesAnyPattern(relPath string, isDir bool, patterns []string) bool {
	for _, pat := range patterns {
		if matchGitignoreRule(relPath, isDir, pat) {
			return true
		}
	}
	return false
}

// shouldIgnore evaluates gitignore-style patterns sequentially using slash-normalized
// path.Match rules, supporting leading '/root' anchors, '**' globs, trailing '/', and '!' negation.
func shouldIgnore(relPath string, isDir bool, patterns []string) bool {
	if matchesAnyPattern(relPath, isDir, nonNegatableSecurityPatterns) {
		return true
	}
	ignored := false
	for _, raw := range patterns {
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		negated := false
		pat := raw
		if after, ok := strings.CutPrefix(pat, "!"); ok {
			negated = true
			pat = after
		}
		if pat == "" {
			continue
		}
		if matchGitignoreRule(relPath, isDir, pat) {
			ignored = !negated
		}
	}
	return ignored
}

func matchGitignoreRule(relPath string, isDir bool, rawPat string) bool {
	pat := strings.ReplaceAll(rawPat, `\`, "/")
	dirOnly := false
	if before, ok := strings.CutSuffix(pat, "/"); ok {
		dirOnly = true
		pat = before
	}
	anchored := false
	if after, ok := strings.CutPrefix(pat, "/"); ok {
		anchored = true
		pat = after
	}
	if pat == "" {
		return false
	}

	pathParts := strings.Split(strings.Trim(relPath, "/"), "/")
	patParts := strings.Split(pat, "/")
	hasSlash := len(patParts) > 1

	if anchored || hasSlash {
		// Match against the root-anchored path, or any parent directory prefix when dirOnly (or directory rule) covers descendants.
		for prefixLen := 1; prefixLen <= len(pathParts); prefixLen++ {
			targetIsDir := prefixLen < len(pathParts) || isDir
			if dirOnly && !targetIsDir {
				continue
			}
			if matchSegments(patParts, pathParts[:prefixLen]) {
				return true
			}
		}
		return false
	}

	// Unanchored single-segment pattern (may still contain '*' or '**'): match any component or directory ancestor.
	for idx, comp := range pathParts {
		compIsDir := idx < len(pathParts)-1 || isDir
		if dirOnly && !compIsDir {
			continue
		}
		if matchSingleGlob(pat, comp) {
			return true
		}
	}
	return false
}

func matchSegments(patParts, pathParts []string) bool {
	if len(patParts) == 0 {
		return len(pathParts) == 0
	}
	if patParts[0] == "**" {
		if matchSegments(patParts[1:], pathParts) {
			return true
		}
		if len(pathParts) > 0 {
			return matchSegments(patParts, pathParts[1:])
		}
		return false
	}
	if len(pathParts) == 0 {
		return false
	}
	if !matchSingleGlob(patParts[0], pathParts[0]) {
		return false
	}
	return matchSegments(patParts[1:], pathParts[1:])
}

func matchSingleGlob(pattern, name string) bool {
	if pattern == "**" {
		return true
	}
	cleanPat := strings.ReplaceAll(pattern, "**", "*")
	matched, err := path.Match(cleanPat, name)
	return err == nil && matched
}

// ExtractTarball decompresses a gzipped package tar stream into targetDir using
// *os.Root containment, rejecting case-colliding entries, verifying the gzip CRC
// trailer, and unwrapping GitHub-style single-top-dir archives only when safe.
func ExtractTarball(r io.Reader, targetDir string) error {
	gzr, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}

	if err = os.MkdirAll(targetDir, 0o750); err != nil {
		_ = gzr.Close()
		return err
	}

	root, err := os.OpenRoot(targetDir)
	if err != nil {
		_ = gzr.Close()
		return fmt.Errorf("failed opening extraction root %s: %w", targetDir, err)
	}

	tr := tar.NewReader(gzr)
	budget := archiveutil.NewBudgetWithEntries(archiveutil.PackageSizeLimit, archiveutil.PackageMaxEntries)
	tracker := archiveutil.NewPathTracker()
	regularFiles := 0

	for {
		header, nextErr := tr.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			_ = root.Close()
			_ = gzr.Close()
			return nextErr
		}
		if header == nil || header.Typeflag == tar.TypeXGlobalHeader || header.Typeflag == tar.TypeXHeader {
			continue
		}

		if err := budget.TakeEntry(); err != nil {
			_ = root.Close()
			_ = gzr.Close()
			return err
		}

		cleanName := strings.TrimPrefix(filepath.ToSlash(header.Name), "./")
		cleanName = strings.TrimSuffix(cleanName, "/")
		if cleanName == "" || cleanName == "." {
			continue
		}

		_, relOS, err := archiveutil.SafeRelPath(targetDir, cleanName)
		if err != nil {
			_ = root.Close()
			_ = gzr.Close()
			return err
		}
		if relOS == "." {
			continue
		}
		if err := tracker.Record(relOS); err != nil {
			_ = root.Close()
			_ = gzr.Close()
			return err
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := archiveutil.RootMkdirAll(root, relOS); err != nil {
				_ = root.Close()
				_ = gzr.Close()
				return err
			}
		case tar.TypeReg, '\x00':
			if err := archiveutil.RootMkdirAll(root, filepath.Dir(relOS)); err != nil {
				_ = root.Close()
				_ = gzr.Close()
				return err
			}
			if err := writeTarEntryRoot(root, tr, relOS, header, budget); err != nil {
				_ = root.Close()
				_ = gzr.Close()
				return fmt.Errorf("failed extracting %q: %w", header.Name, err)
			}
			regularFiles++
		default:
			_ = root.Close()
			_ = gzr.Close()
			return fmt.Errorf("unsupported archive entry type %q for %q", string(header.Typeflag), header.Name)
		}
	}

	if err := root.Close(); err != nil {
		_ = gzr.Close()
		return err
	}

	if err := archiveutil.DrainStreamTrailer(gzr, 1<<20); err != nil {
		_ = gzr.Close()
		return fmt.Errorf("gzip stream integrity error: %w", err)
	}
	if err := gzr.Close(); err != nil {
		return fmt.Errorf("failed closing gzip stream: %w", err)
	}

	if regularFiles == 0 {
		return errors.New("archive contained no regular files")
	}

	return unwrapSingleTopDirIfNeeded(targetDir)
}

func writeTarEntryRoot(root *os.Root, tr *tar.Reader, relOS string, header *tar.Header, budget *archiveutil.Budget) error {
	outFile, err := root.OpenFile(relOS, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, archiveutil.EntryMode(header.FileInfo().Mode()))
	if err != nil {
		return err
	}
	if _, err := budget.Copy(outFile, tr); err != nil {
		_ = outFile.Close()
		return err
	}
	return outFile.Close()
}

func unwrapSingleTopDirIfNeeded(targetDir string) error {
	topEntries, err := os.ReadDir(targetDir)
	if err != nil {
		return err
	}
	if len(topEntries) != 1 || !topEntries[0].IsDir() {
		return nil
	}
	topName := topEntries[0].Name()
	wrapperDir := filepath.Join(targetDir, topName)
	if !shouldUnwrapTopDir(wrapperDir) {
		return nil
	}

	tmpWrapper := filepath.Join(targetDir, fmt.Sprintf(".toob-unwrap-%d", os.Getpid()))
	if renameErr := os.Rename(wrapperDir, tmpWrapper); renameErr != nil {
		return renameErr
	}
	children, err := os.ReadDir(tmpWrapper)
	if err != nil {
		return err
	}
	for _, child := range children {
		src := filepath.Join(tmpWrapper, child.Name())
		dst := filepath.Join(targetDir, child.Name())
		if err := os.Rename(src, dst); err != nil {
			return err
		}
	}
	return os.Remove(tmpWrapper)
}

func shouldUnwrapTopDir(wrapperDir string) bool {
	for _, marker := range canonicalRootManifests {
		if st, err := os.Stat(filepath.Join(wrapperDir, marker)); err == nil && st.Mode().IsRegular() {
			return true
		}
	}
	return false
}
