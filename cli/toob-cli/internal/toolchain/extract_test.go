package toolchain

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/toob-boot/toob/internal/archiveutil"
)

// tarEntry is one record of a synthetic archive.
type tarEntry struct {
	name     string
	typeflag byte
	linkname string
	body     string
	mode     int64
}

func buildTarGz(t *testing.T, entries ...tarEntry) *bytes.Reader {
	t.Helper()

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

	for _, e := range entries {
		mode := e.mode
		if mode == 0 {
			mode = 0o644
		}
		hdr := &tar.Header{
			Name:     e.name,
			Typeflag: e.typeflag,
			Linkname: e.linkname,
			Mode:     mode,
			Size:     int64(len(e.body)),
		}
		if e.typeflag == tar.TypeDir {
			hdr.Mode = 0o755
			hdr.Size = 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("failed writing header for %q: %v", e.name, err)
		}
		if e.body != "" {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatalf("failed writing body for %q: %v", e.name, err)
			}
		}
	}

	if err := tw.Close(); err != nil {
		t.Fatalf("failed closing tar writer: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("failed closing gzip writer: %v", err)
	}
	return bytes.NewReader(buf.Bytes())
}

// TestExtractTar_RejectsPathTraversal covers the escape the path guard already caught.
func TestExtractTar_RejectsPathTraversal(t *testing.T) {
	dest := t.TempDir()
	outside := filepath.Join(dest, "..", "escaped.txt")

	err := extractTarGz(buildTarGz(t,
		tarEntry{name: "bin/", typeflag: tar.TypeDir},
		tarEntry{name: "../escaped.txt", typeflag: tar.TypeReg, body: "pwned"},
	), dest)

	if !errors.Is(err, archiveutil.ErrUnsafePath) {
		t.Fatalf("expected ErrUnsafePath, got %v", err)
	}
	if _, statErr := os.Stat(outside); statErr == nil {
		t.Fatal("the archive wrote outside the destination directory")
	}
}

// TestExtractTar_RejectsSymlinkEscape is the vulnerability the path guard could not catch, because
// filepath.Join is lexical and the operating system is not: the first entry creates a link out of
// the tree, the second writes through it. Both entries pass a path check on their own.
// It runs on every platform: the entry is refused before any link is created, so it needs no
// symlink privilege.
func TestExtractTar_RejectsSymlinkEscape(t *testing.T) {
	parent := t.TempDir()
	dest := filepath.Join(parent, "toolchain")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatalf("failed preparing the destination: %v", err)
	}

	victim := filepath.Join(parent, "victim")
	if err := os.MkdirAll(victim, 0o755); err != nil {
		t.Fatalf("failed preparing the victim directory: %v", err)
	}

	err := extractTarGz(buildTarGz(t,
		tarEntry{name: "escape", typeflag: tar.TypeSymlink, linkname: "../victim"},
		tarEntry{name: "escape/owned.txt", typeflag: tar.TypeReg, body: "pwned"},
	), dest)

	if !errors.Is(err, archiveutil.ErrUnsafePath) {
		t.Fatalf("expected the escaping symlink to be refused, got %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(victim, "owned.txt")); statErr == nil {
		t.Fatal("the archive wrote through a symlink into a directory outside the destination")
	}
}

func TestExtractTar_RejectsAbsoluteSymlink(t *testing.T) {
	dest := t.TempDir()

	err := extractTarGz(buildTarGz(t,
		tarEntry{name: "bin/sh", typeflag: tar.TypeSymlink, linkname: "/bin/sh"},
	), dest)

	if !errors.Is(err, archiveutil.ErrUnsafePath) {
		t.Fatalf("expected an absolute symlink target to be refused, got %v", err)
	}
}

// TestExtractTar_KeepsLegitimateSymlinks: a compiler toolchain ships them, so refusing every link
// would be the wrong fix.
func TestExtractTar_KeepsLegitimateSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs Developer Mode on Windows")
	}

	dest := t.TempDir()

	if err := extractTarGz(buildTarGz(t,
		tarEntry{name: "bin/", typeflag: tar.TypeDir},
		tarEntry{name: "bin/gcc-13", typeflag: tar.TypeReg, body: "#!/bin/sh\n", mode: 0o755},
		tarEntry{name: "bin/gcc", typeflag: tar.TypeSymlink, linkname: "gcc-13"},
	), dest); err != nil {
		t.Fatalf("a toolchain with an ordinary symlink failed to extract: %v", err)
	}

	resolved, err := filepath.EvalSymlinks(filepath.Join(dest, "bin", "gcc"))
	if err != nil {
		t.Fatalf("the symlink was not created: %v", err)
	}
	if resolved != filepath.Join(dest, "bin", "gcc-13") {
		t.Errorf("symlink resolves to %q, expected the sibling binary", resolved)
	}
}

// TestExtractTar_TruncatesExistingFiles: without O_TRUNC a shorter file left the tail of its
// predecessor behind, producing a binary that is neither the old one nor the new one.
func TestExtractTar_TruncatesExistingFiles(t *testing.T) {
	dest := t.TempDir()

	stale := filepath.Join(dest, "bin", "cc")
	if err := os.MkdirAll(filepath.Dir(stale), 0o755); err != nil {
		t.Fatalf("failed preparing the destination: %v", err)
	}
	if err := os.WriteFile(stale, []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAA"), 0o644); err != nil {
		t.Fatalf("failed writing the stale file: %v", err)
	}

	if err := extractTarGz(buildTarGz(t,
		tarEntry{name: "bin/cc", typeflag: tar.TypeReg, body: "new"},
	), dest); err != nil {
		t.Fatalf("extraction failed: %v", err)
	}

	got, err := os.ReadFile(stale)
	if err != nil {
		t.Fatalf("failed reading the extracted file: %v", err)
	}
	if string(got) != "new" {
		t.Fatalf("the previous content was not truncated: %q", got)
	}
}

// TestExtractTar_RejectsUnsupportedEntryTypes: silently skipping them produced an installation that
// looked complete and failed much later.
func TestExtractTar_RejectsUnsupportedEntryTypes(t *testing.T) {
	dest := t.TempDir()

	err := extractTarGz(buildTarGz(t,
		tarEntry{name: "dev/null", typeflag: tar.TypeChar},
	), dest)

	if err == nil {
		t.Fatal("a character device entry was accepted")
	}
}
