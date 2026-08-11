// Package archiveutil holds the safety rules every archive extractor in the CLI has to follow.
//
// Extraction turns attacker-influenced names into paths and writes them with the user's
// privileges, so a mistake here is arbitrary file write. The rules live in one place because the
// two extractors that existed before disagreed about what "inside the destination" means, and one
// of them created symlinks without ever looking at where they pointed.
package archiveutil

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

var (
	// ErrUnsafePath marks an entry that would be written outside the destination directory.
	ErrUnsafePath = errors.New("archive: entry would escape the destination directory")
	// ErrTooLarge marks an extraction that exceeded its size budget.
	ErrTooLarge = errors.New("archive: extracted content exceeds the size limit")
)

// SafeJoin resolves an archive entry name against destDir and rejects anything that would land
// outside it.
//
// The check is lexical. That is sufficient only as long as no link inside the tree points out of
// it, which is what SafeLinkTarget enforces — the operating system resolves symlinks, and
// filepath.Join does not.
func SafeJoin(destDir, name string) (string, error) {
	if strings.TrimSpace(name) == "" {
		return "", fmt.Errorf("%w: empty entry name", ErrUnsafePath)
	}
	if strings.ContainsRune(name, 0) {
		return "", fmt.Errorf("%w: entry name contains a NUL byte", ErrUnsafePath)
	}
	// An absolute path or a volume name makes filepath.Join drop destDir on at least one platform,
	// so it is rejected before the join rather than after it.
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

// SafeLinkTarget validates where a link entry points.
//
// Without it a lexical path check is not enough: an entry "evil -> /etc" followed by an entry
// "evil/passwd" passes SafeJoin twice and still writes outside the destination, because the second
// write follows the link the first one created. Requiring every link inside the tree to resolve
// inside the tree closes that by induction — no path in the extracted tree can then leave it.
func SafeLinkTarget(destDir, linkPath, linkname string) error {
	if strings.TrimSpace(linkname) == "" {
		return fmt.Errorf("%w: link %q has an empty target", ErrUnsafePath, linkPath)
	}
	if strings.ContainsRune(linkname, 0) {
		return fmt.Errorf("%w: link target contains a NUL byte", ErrUnsafePath)
	}
	if isRooted(linkname) {
		return fmt.Errorf("%w: link %q points at the absolute path %q", ErrUnsafePath, linkPath, linkname)
	}

	clean := filepath.Clean(destDir)
	resolved := filepath.Join(filepath.Dir(linkPath), filepath.FromSlash(linkname))

	if err := containedIn(clean, resolved); err != nil {
		return fmt.Errorf("%w: link %q points outside the destination via %q", ErrUnsafePath, linkPath, linkname)
	}
	return nil
}

func isRooted(name string) bool {
	return filepath.IsAbs(name) ||
		filepath.VolumeName(name) != "" ||
		strings.HasPrefix(name, "/") ||
		strings.HasPrefix(name, `\`)
}

// containedIn reports whether target lies within root.
//
// The comparison is on the relative path rather than a string prefix: a prefix test on ".." alone
// also rejects a legitimate entry named "..config", and a prefix test on the directory string
// accepts a sibling directory whose name merely starts with the destination's.
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

// DefaultSizeLimit bounds one extraction. A compiler toolchain is large but bounded; an archive
// that expands past this is either corrupt or a decompression bomb.
const DefaultSizeLimit int64 = 8 << 30 // 8 GiB

// Budget caps how many bytes a single extraction may write to disk.
type Budget struct {
	remaining int64
}

func NewBudget(limit int64) *Budget {
	if limit <= 0 {
		limit = DefaultSizeLimit
	}
	return &Budget{remaining: limit}
}

// Copy writes src to dst and fails once the extraction as a whole exceeds its limit. The limit is
// enforced on what is written, not on what the archive header claims, because the header is part
// of the archive.
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

// EntryMode is the permission an extracted file gets.
//
// Only the permission bits of the archive entry survive, minus write access for group and other.
// Setuid, setgid and the sticky bit are dropped: nothing a toolchain archive contains needs them,
// and honouring them lets an archive plant a privileged binary.
func EntryMode(m fs.FileMode) fs.FileMode {
	return m.Perm() &^ 0o022
}

// DirMode is the permission an extracted directory gets. Archive-supplied directory modes are
// ignored; 0777 directories were what the previous extractor created.
const DirMode fs.FileMode = 0o755
