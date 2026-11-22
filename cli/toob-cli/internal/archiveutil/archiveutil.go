// Package archiveutil holds the safety rules every archive extractor in the CLI has to follow.
//
// Extraction turns attacker-influenced names into paths and writes them with the user's
// privileges, so a mistake here is arbitrary file write. All extractors combine *os.Root
// handle-scoped containment with multi-hop symlink graph verification and byte/entry budgets.
package archiveutil

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
)

var (
	// ErrUnsafePath marks an entry that would be written outside the destination directory
	// or uses a reserved/colliding host path representation.
	ErrUnsafePath = errors.New("archive: entry would escape the destination directory")
	// ErrTooLarge marks an extraction that exceeded its byte or entry-count budget.
	ErrTooLarge = errors.New("archive: extracted content exceeds the size limit")
)

const (
	// DefaultSizeLimit bounds one toolchain extraction (8 GiB).
	DefaultSizeLimit int64 = 8 << 30
	// PackageSizeLimit bounds one source/SDK package extraction (64 MiB).
	PackageSizeLimit int64 = 64 << 20

	// ToolchainMaxEntries caps total tar/zip entries in a toolchain archive.
	ToolchainMaxEntries = 200_000
	// PackageMaxEntries caps total tar entries in a registry package archive.
	PackageMaxEntries = 4_096

	// DirMode is the permission an extracted directory gets.
	DirMode fs.FileMode = 0o755

	maxSymlinkHops = 40
)

// SafeJoin resolves an archive entry name against destDir and rejects NUL/control bytes,
// drive/UNC/ADS colons, rooted paths, Windows reserved device names, trailing dots/spaces,
// and lexical '..' escapes outside destDir.
func SafeJoin(destDir, name string) (string, error) {
	if strings.TrimSpace(name) == "" {
		return "", fmt.Errorf("%w: empty entry name", ErrUnsafePath)
	}
	if err := validatePathSyntax(name); err != nil {
		return "", err
	}
	if isRooted(name) {
		return "", fmt.Errorf("%w: %q is an absolute path", ErrUnsafePath, name)
	}

	clean := filepath.Clean(destDir)
	target := filepath.Join(clean, filepath.FromSlash(name))

	if err := containedIn(clean, target); err != nil {
		return "", fmt.Errorf("%w: %q", ErrUnsafePath, name)
	}
	return target, nil
}

// SafeRelPath validates name via SafeJoin and returns both the joined host path
// and the clean relative path beneath destDir suitable for *os.Root operations.
func SafeRelPath(destDir, name string) (string, string, error) {
	target, err := SafeJoin(destDir, name)
	if err != nil {
		return "", "", err
	}
	clean := filepath.Clean(destDir)
	rel, err := filepath.Rel(clean, target)
	if err != nil {
		return "", "", fmt.Errorf("%w: %q: %w", ErrUnsafePath, name, err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", "", fmt.Errorf("%w: %q", ErrUnsafePath, name)
	}
	return target, rel, nil
}

func validatePathSyntax(raw string) error {
	for _, r := range raw {
		if r == 0 {
			return fmt.Errorf("%w: entry name contains a NUL byte", ErrUnsafePath)
		}
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%w: %q contains a control character", ErrUnsafePath, raw)
		}
	}
	if strings.Contains(raw, ":") {
		return fmt.Errorf("%w: %q contains forbidden ':' character", ErrUnsafePath, raw)
	}

	norm := strings.ReplaceAll(raw, `\`, "/")
	for _, seg := range strings.Split(norm, "/") {
		if seg == "" || seg == "." || seg == ".." {
			continue
		}
		if strings.HasSuffix(seg, ".") || strings.HasSuffix(seg, " ") {
			return fmt.Errorf("%w: segment %q in %q has trailing dot or space", ErrUnsafePath, seg, raw)
		}
		if isWindowsReservedSegment(seg) {
			return fmt.Errorf("%w: segment %q in %q is a Windows reserved device name", ErrUnsafePath, seg, raw)
		}
	}
	return nil
}

func isWindowsReservedSegment(seg string) bool {
	stem, _, _ := strings.Cut(seg, ".")
	stem = strings.TrimRight(stem, " .")
	upper := strings.ToUpper(stem)
	switch upper {
	case "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$":
		return true
	}
	if len(upper) == 4 && (strings.HasPrefix(upper, "COM") || strings.HasPrefix(upper, "LPT")) {
		d := upper[3]
		return d >= '0' && d <= '9'
	}
	return false
}

// CanonicalLinkKey normalizes a relative path into its lowercase forward-slash key
// so case-insensitive filesystems (NTFS, APFS) cannot bypass link-map lookups.
func CanonicalLinkKey(relPath string) string {
	clean := strings.TrimPrefix(filepath.ToSlash(filepath.Clean(relPath)), "./")
	return strings.ToLower(clean)
}

// PathTracker detects case-colliding archive paths (such as "Dir/a" and "dir/b"
// or "File.c" and "file.c") across all platforms.
type PathTracker struct {
	seenCasing map[string]string
}

// NewPathTracker returns an initialized PathTracker.
func NewPathTracker() *PathTracker {
	return &PathTracker{seenCasing: make(map[string]string)}
}

// Record registers relPath (and all of its parent directory prefixes) and fails
// with ErrUnsafePath if any path component collides with an earlier entry of different case.
func (pt *PathTracker) Record(relPath string) error {
	if pt == nil {
		return nil
	}
	slash := strings.Trim(strings.TrimPrefix(filepath.ToSlash(filepath.Clean(relPath)), "./"), "/")
	if slash == "" || slash == "." {
		return nil
	}
	parts := strings.Split(slash, "/")
	var prefix string
	for _, p := range parts {
		if prefix == "" {
			prefix = p
		} else {
			prefix = prefix + "/" + p
		}
		folded := strings.ToLower(prefix)
		if prev, ok := pt.seenCasing[folded]; ok && prev != prefix {
			return fmt.Errorf("%w: case-colliding archive paths %q and %q", ErrUnsafePath, prev, prefix)
		}
		pt.seenCasing[folded] = prefix
	}
	return nil
}

type diskLinkEntry struct {
	target string
	isLink bool
}

type linkResolver struct {
	cleanDest   string
	foldedLinks map[string]string
	diskCache   map[string]diskLinkEntry
	memo        map[string]string
	visitState  map[string]uint8 // 0 = unvisited, 1 = visiting, 2 = resolved
}

func newLinkResolver(cleanDest string, linkMap map[string]string) (*linkResolver, error) {
	folded := make(map[string]string, len(linkMap))
	seenOrig := make(map[string]string, len(linkMap))
	for rawKey, target := range linkMap {
		cleanSlash := strings.Trim(strings.TrimPrefix(filepath.ToSlash(filepath.Clean(rawKey)), "./"), "/")
		key := strings.ToLower(cleanSlash)
		if prevOrig, exists := seenOrig[key]; exists && prevOrig != cleanSlash {
			return nil, fmt.Errorf("%w: case-colliding symlink entries %q and %q", ErrUnsafePath, prevOrig, cleanSlash)
		}
		seenOrig[key] = cleanSlash
		folded[key] = target
	}
	return &linkResolver{
		cleanDest:   cleanDest,
		foldedLinks: folded,
		diskCache:   make(map[string]diskLinkEntry),
		memo:        make(map[string]string, len(folded)),
		visitState:  make(map[string]uint8, len(folded)),
	}, nil
}

func (lr *linkResolver) lookup(relSlash string) (string, bool, error) {
	key := strings.ToLower(strings.Trim(relSlash, "/"))
	if lr.foldedLinks != nil {
		if target, ok := lr.foldedLinks[key]; ok {
			return target, true, nil
		}
	}
	if cached, ok := lr.diskCache[key]; ok {
		return cached.target, cached.isLink, nil
	}

	diskPath := filepath.Join(lr.cleanDest, filepath.FromSlash(relSlash))
	fi, err := os.Lstat(diskPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			lr.diskCache[key] = diskLinkEntry{}
			return "", false, nil
		}
		return "", false, err
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		target, rlErr := os.Readlink(diskPath)
		if rlErr != nil {
			return "", false, rlErr
		}
		cleaned := cleanWindowsReparsePrefix(target)
		lr.diskCache[key] = diskLinkEntry{target: cleaned, isLink: true}
		return cleaned, true, nil
	}
	if target, rlErr := os.Readlink(diskPath); rlErr == nil {
		cleaned := cleanWindowsReparsePrefix(target)
		lr.diskCache[key] = diskLinkEntry{target: cleaned, isLink: true}
		return cleaned, true, nil
	}
	lr.diskCache[key] = diskLinkEntry{}
	return "", false, nil
}

func (lr *linkResolver) resolveSymlinkNode(linkRelSlash, subTarget string, hops int) (string, error) {
	key := strings.ToLower(strings.Trim(linkRelSlash, "/"))
	switch lr.visitState[key] {
	case 2:
		return lr.memo[key], nil
	case 1:
		return "", fmt.Errorf("%w: symlink cycle involving %q", ErrUnsafePath, linkRelSlash)
	}
	if hops > maxSymlinkHops {
		return "", fmt.Errorf("%w: too many symlink indirections", ErrUnsafePath)
	}
	if err := validateLinkSyntax(linkRelSlash, subTarget); err != nil {
		return "", err
	}

	lr.visitState[key] = 1
	parentSlash := path.Dir(linkRelSlash)
	if parentSlash == "" {
		parentSlash = "."
	}
	resolved, err := lr.resolveSegments(parentSlash, subTarget, hops)
	if err != nil {
		lr.visitState[key] = 0
		return "", err
	}
	lr.visitState[key] = 2
	lr.memo[key] = resolved
	return resolved, nil
}

func (lr *linkResolver) resolveSegments(startRel, rawTarget string, hops int) (string, error) {
	cur := startRel
	if cur == "" {
		cur = "."
	}
	norm := strings.ReplaceAll(rawTarget, `\`, "/")
	for _, seg := range strings.Split(norm, "/") {
		if seg == "" || seg == "." {
			continue
		}
		if seg == ".." {
			if cur == "." || cur == "" {
				return "", ErrUnsafePath
			}
			parent := path.Dir(cur)
			if parent == "" {
				parent = "."
			}
			cur = parent
			continue
		}

		next := seg
		if cur != "." {
			next = cur + "/" + seg
		}

		subTarget, isLink, err := lr.lookup(next)
		if err != nil {
			return "", err
		}
		if isLink {
			resolved, rErr := lr.resolveSymlinkNode(next, subTarget, hops+1)
			if rErr != nil {
				return "", rErr
			}
			cur = resolved
			continue
		}
		cur = next
	}
	return cur, nil
}

func (lr *linkResolver) validateOne(linkPath, linkname string) error {
	if err := validateLinkSyntax(linkPath, linkname); err != nil {
		return err
	}
	cleanLink := filepath.Clean(linkPath)
	if cleanLink == lr.cleanDest {
		return fmt.Errorf("%w: link %q targets destination root", ErrUnsafePath, linkPath)
	}
	if err := containedIn(lr.cleanDest, cleanLink); err != nil {
		return fmt.Errorf("%w: link path %q lies outside destination", ErrUnsafePath, linkPath)
	}

	linkDirRelOS, err := filepath.Rel(lr.cleanDest, filepath.Dir(cleanLink))
	if err != nil {
		return fmt.Errorf("%w: link %q: %w", ErrUnsafePath, linkPath, err)
	}
	linkDirRel := filepath.ToSlash(linkDirRelOS)

	startRel := "."
	if linkDirRel != "." && linkDirRel != "" {
		startRel, err = lr.resolveSegments(".", linkDirRel, 0)
		if err != nil {
			return fmt.Errorf("%w: link parent of %q escapes via symlink: %w", ErrUnsafePath, linkPath, err)
		}
	}

	if _, err := lr.resolveSegments(startRel, linkname, 0); err != nil {
		return fmt.Errorf("%w: link %q points outside the destination via %q: %w", ErrUnsafePath, linkPath, linkname, err)
	}
	return nil
}

// SafeLinkTarget validates where a symlink entry points, resolving every path
// component against existing symlinks/junctions on disk inside destDir so
// multi-hop symlink chains cannot escape destDir.
func SafeLinkTarget(destDir, linkPath, linkname string) error {
	return SafeLinkTargetWithLinks(destDir, linkPath, linkname, nil)
}

// SafeLinkTargetWithLinks validates linkname against both on-disk symlinks under
// destDir and an in-memory map of archive symlinks (matched case-insensitively).
func SafeLinkTargetWithLinks(destDir, linkPath, linkname string, linkMap map[string]string) error {
	lr, err := newLinkResolver(filepath.Clean(destDir), linkMap)
	if err != nil {
		return err
	}
	return lr.validateOne(linkPath, linkname)
}

// ValidateSymlinkGraph validates an entire archive's symlink graph in linear O(S)
// time using memoized target resolution and case-insensitive link keys.
func ValidateSymlinkGraph(destDir string, links map[string]string) error {
	if len(links) == 0 {
		return nil
	}
	cleanDest := filepath.Clean(destDir)
	lr, err := newLinkResolver(cleanDest, links)
	if err != nil {
		return err
	}
	for rawRel, target := range links {
		cleanSlash := strings.Trim(strings.TrimPrefix(filepath.ToSlash(filepath.Clean(rawRel)), "./"), "/")
		linkPath := filepath.Join(cleanDest, filepath.FromSlash(cleanSlash))
		if err := lr.validateOne(linkPath, target); err != nil {
			return err
		}
	}
	return nil
}

// ResolveArchiveRelPath resolves any parent symlinks recorded in links for relOS,
// ensuring that extracting a directory or regular file beneath a queued intra-archive
// symlink cannot escape destDir and resolves to its canonical relative OS path.
func ResolveArchiveRelPath(destDir, relOS string, links map[string]string) (string, error) {
	cleanSlash := strings.Trim(strings.TrimPrefix(filepath.ToSlash(filepath.Clean(relOS)), "./"), "/")
	if cleanSlash == "" || cleanSlash == "." {
		return ".", nil
	}
	lr, err := newLinkResolver(filepath.Clean(destDir), links)
	if err != nil {
		return "", err
	}
	parentSlash := path.Dir(cleanSlash)
	base := path.Base(cleanSlash)
	resolvedParent := "."
	if parentSlash != "." && parentSlash != "" {
		resolvedParent, err = lr.resolveSegments(".", parentSlash, 0)
		if err != nil {
			return "", fmt.Errorf("%w: parent of %q escapes via symlink: %w", ErrUnsafePath, relOS, err)
		}
	}
	if resolvedParent == "." {
		return filepath.FromSlash(base), nil
	}
	return filepath.FromSlash(resolvedParent + "/" + base), nil
}

// RecordAndValidateSymlink adds relLinkOS -> linkname to linkMap (using canonical
// lowercase keys) and verifies that the resulting symlink graph stays contained.
func RecordAndValidateSymlink(destDir, relLinkOS, linkname string, linkMap map[string]string) error {
	cleanDest := filepath.Clean(destDir)
	linkPath := filepath.Join(cleanDest, relLinkOS)
	if err := SafeLinkTargetWithLinks(cleanDest, linkPath, linkname, linkMap); err != nil {
		return err
	}
	if linkMap == nil {
		return nil
	}
	key := CanonicalLinkKey(relLinkOS)
	prev, hadPrev := linkMap[key]
	linkMap[key] = linkname

	if err := ValidateSymlinkGraph(cleanDest, linkMap); err != nil {
		if hadPrev {
			linkMap[key] = prev
		} else {
			delete(linkMap, key)
		}
		return err
	}
	return nil
}

// ValidateLinkSyntax checks that linkname is non-empty, relative, and free of NUL,
// control characters, drive/ADS colons, trailing dots/spaces, and reserved stems.
func ValidateLinkSyntax(linkPath, linkname string) error {
	return validateLinkSyntax(linkPath, linkname)
}

func validateLinkSyntax(linkPath, linkname string) error {
	if strings.TrimSpace(linkname) == "" {
		return fmt.Errorf("%w: link %q has an empty target", ErrUnsafePath, linkPath)
	}
	if err := validatePathSyntax(linkname); err != nil {
		return err
	}
	if isRooted(linkname) {
		return fmt.Errorf("%w: link %q points at the absolute path %q", ErrUnsafePath, linkPath, linkname)
	}
	return nil
}

func cleanWindowsReparsePrefix(target string) string {
	upper := strings.ToUpper(target)
	if strings.HasPrefix(upper, `\??\UNC\`) {
		return `\\` + target[len(`\??\UNC\`):]
	}
	if strings.HasPrefix(upper, `\\?\UNC\`) {
		return `\\` + target[len(`\\?\UNC\`):]
	}
	target = strings.TrimPrefix(target, `\??\`)
	target = strings.TrimPrefix(target, `\\?\`)
	return target
}

func isRooted(name string) bool {
	return filepath.IsAbs(name) ||
		filepath.VolumeName(name) != "" ||
		strings.HasPrefix(name, "/") ||
		strings.HasPrefix(name, `\`)
}

// containedIn reports whether target lies within root.
func containedIn(root, target string) error {
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return ErrUnsafePath
	}
	return nil
}

// RootMkdirAll creates relDir and its parents inside root (*os.Root).
func RootMkdirAll(root *os.Root, relDir string) error {
	if relDir == "" || relDir == "." {
		return nil
	}
	return root.MkdirAll(relDir, DirMode)
}

// DrainStreamTrailer reads up to maxPad trailing bytes from r to ensure stream
// readers (gzip.Reader, xz.Reader) reach io.EOF and verify their integrity trailers.
func DrainStreamTrailer(r io.Reader, maxPad int64) error {
	if maxPad < 0 {
		return fmt.Errorf("archive: negative trailer padding limit %d", maxPad)
	}
	n, err := io.Copy(io.Discard, io.LimitReader(r, maxPad+1))
	if err != nil {
		return err
	}
	if n > maxPad {
		return fmt.Errorf("%w: stream trailer exceeds %d byte padding limit", ErrTooLarge, maxPad)
	}
	return nil
}

// Budget caps how many bytes and entries a single extraction may create on disk.
type Budget struct {
	remaining  int64
	entries    int
	maxEntries int
}

// NewBudget constructs an extraction budget with ToolchainMaxEntries.
func NewBudget(limit int64) *Budget {
	return NewBudgetWithEntries(limit, ToolchainMaxEntries)
}

// NewBudgetWithEntries constructs an extraction budget with explicit byte and entry caps.
func NewBudgetWithEntries(limit int64, maxEntries int) *Budget {
	if limit <= 0 {
		limit = DefaultSizeLimit
	}
	if maxEntries <= 0 {
		maxEntries = ToolchainMaxEntries
	}
	return &Budget{remaining: limit, maxEntries: maxEntries}
}

// TakeEntry accounts for one archive header entry and fails once maxEntries is exceeded.
func (b *Budget) TakeEntry() error {
	if b.entries >= b.maxEntries {
		return fmt.Errorf("%w: archive exceeds maximum entry limit (%d)", ErrTooLarge, b.maxEntries)
	}
	b.entries++
	return nil
}

// Copy writes src to dst and fails once the extraction as a whole exceeds its byte limit.
func (b *Budget) Copy(dst io.Writer, src io.Reader) (int64, error) {
	n, err := io.Copy(dst, io.LimitReader(src, b.remaining+1))
	if err != nil {
		return n, err
	}
	if n > b.remaining {
		return n, ErrTooLarge
	}
	b.remaining -= n
	return n, nil
}

// EntryMode returns the sanitized file mode (dropping setuid/setgid/sticky and group/other write).
func EntryMode(m fs.FileMode) fs.FileMode {
	return m.Perm() &^ 0o022
}
