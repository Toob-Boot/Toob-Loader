package toolchain

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/toob-boot/toob/internal/archiveutil"
)

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

// TestExtractTar_RejectsThreeEntrySymlinkChainEscape (CRIT-45):
// Entry 1 creates an intra-tree symlink back to destDir, Entry 2 traverses through it
// and climbs above destDir while looking lexically contained under filepath.Join,
// and Entry 3 attempts to write a file outside destDir.
func TestExtractTar_RejectsThreeEntrySymlinkChainEscape(t *testing.T) {
	parent := t.TempDir()
	dest := filepath.Join(parent, "d", "e", "s", "t", "toolchain")
	victim := filepath.Join(parent, "victim")
	for _, dir := range []string{dest, victim} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	err := extractTarGz(buildTarGz(t,
		tarEntry{name: "d1/d2/d3/d4/d5/d6/up", typeflag: tar.TypeSymlink, linkname: "../../../../../.."},
		tarEntry{name: "d1/escape", typeflag: tar.TypeSymlink, linkname: "d2/d3/d4/d5/d6/up/../../../../../victim"},
		tarEntry{name: "d1/escape/owned.txt", typeflag: tar.TypeReg, body: "pwned"},
	), dest)

	if !errors.Is(err, archiveutil.ErrUnsafePath) {
		t.Fatalf("expected ErrUnsafePath on 3-entry symlink-chain escape, got %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(victim, "owned.txt")); statErr == nil {
		t.Fatal("3-entry symlink chain wrote outside destination directory")
	}
}

// TestExtractTar_RejectsHardlinkToSymlinkEscape (CRIT-45):
// Entry 1 creates a valid intra-tree relative symlink d1/d2/up -> ../.., and Entry 2
// attempts to hardlink 'up' at the root to d1/d2/up so '../..' escapes two levels above destDir.
func TestExtractTar_RejectsHardlinkToSymlinkEscape(t *testing.T) {
	parent := t.TempDir()
	dest := filepath.Join(parent, "nested", "toolchain")
	victim := filepath.Join(parent, "victim")
	for _, dir := range []string{dest, victim} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	err := extractTarGz(buildTarGz(t,
		tarEntry{name: "d1/d2/up", typeflag: tar.TypeSymlink, linkname: "../.."},
		tarEntry{name: "up", typeflag: tar.TypeLink, linkname: "d1/d2/up"},
		tarEntry{name: "up/victim/owned.txt", typeflag: tar.TypeReg, body: "pwned"},
	), dest)

	if !errors.Is(err, archiveutil.ErrUnsafePath) {
		t.Fatalf("expected ErrUnsafePath on TypeLink targeting TypeSymlink, got %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(victim, "owned.txt")); statErr == nil {
		t.Fatal("hardlink-to-symlink escape wrote outside destination directory")
	}
}

func TestExtractTar_AllowsHardlinkToRegularFile(t *testing.T) {
	dest := t.TempDir()

	if err := extractTarGz(buildTarGz(t,
		tarEntry{name: "bin/", typeflag: tar.TypeDir},
		tarEntry{name: "bin/gcc-13", typeflag: tar.TypeReg, body: "binary", mode: 0o755},
		tarEntry{name: "bin/cc", typeflag: tar.TypeLink, linkname: "bin/gcc-13"},
	), dest); err != nil {
		t.Fatalf("legitimate hardlink to regular file failed: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dest, "bin", "cc"))
	if err != nil || string(got) != "binary" {
		t.Fatalf("got %q, err %v", string(got), err)
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

func TestExtractTar_RejectsUnsupportedEntryTypes(t *testing.T) {
	dest := t.TempDir()

	err := extractTarGz(buildTarGz(t,
		tarEntry{name: "dev/null", typeflag: tar.TypeChar},
	), dest)

	if err == nil {
		t.Fatal("a character device entry was accepted")
	}
}

func TestEnsureAvailable_RejectsTraversalInputs(t *testing.T) {
	regDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(regDir, "registry.json"), []byte(`{"format_version":1,"toolchains":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureAvailable("../evil-", "1.0.0", regDir); err == nil {
		t.Fatal("expected traversal prefix rejection")
	}
	if _, err := EnsureAvailable("riscv32-esp-elf-", "../../../../evil", regDir); err == nil {
		t.Fatal("expected traversal expectedVersion rejection")
	}
}

func TestToolchainSlugDir_FindBinDir_PresignedDownloadAndCleanCAS(t *testing.T) {
	slug, err := ToolchainSlug("@espressif/riscv32-esp-elf")
	if err != nil || slug != "_espressif__riscv32-esp-elf" {
		t.Fatalf("ToolchainSlug = %q, %v", slug, err)
	}

	toobHome := filepath.Join(t.TempDir(), ".toob")
	t.Setenv("TOOB_HOME", toobHome)

	tcDir, err := ToolchainDir(toobHome, "linux", "amd64", "@espressif/riscv32-esp-elf", "14.2.0")
	if err != nil {
		t.Fatalf("ToolchainDir failed: %v", err)
	}
	wantSuffix := filepath.Join("toolchains", "linux_amd64", "_espressif__riscv32-esp-elf", "14.2.0")
	if !strings.HasSuffix(tcDir, wantSuffix) {
		t.Fatalf("ToolchainDir = %q, want suffix %q", tcDir, wantSuffix)
	}

	// Build a .tgz archive where forward-referenced symlink "llvm/bin/cc -> clang" appears BEFORE "llvm/bin/clang"!
	binName := "clang"
	aliasName := "cc"
	if runtime.GOOS == "windows" {
		binName = "clang.exe"
		aliasName = "cc.exe"
	}
	archiveReader := buildTarGz(t,
		tarEntry{name: "llvm/bin/", typeflag: tar.TypeDir},
		tarEntry{name: "llvm/bin/" + aliasName, typeflag: tar.TypeSymlink, linkname: binName},
		tarEntry{name: "llvm/bin/" + binName, typeflag: tar.TypeReg, body: "fake-clang-binary", mode: 0o755},
	)
	archiveBytes := make([]byte, archiveReader.Len())
	if _, err = archiveReader.Read(archiveBytes); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(archiveBytes)
	archiveSHA := hex.EncodeToString(sum[:])

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/llvm-18.tgz" {
			_, _ = w.Write(archiveBytes)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)

	osArch := runtime.GOOS + "_" + runtime.GOARCH
	regDir := t.TempDir()
	regJSON := `{
		"format_version": 1,
		"toolchains": {
			"@llvm/clang": {
				"version": "18.1.8",
				"compiler_binary": "` + binName + `",
				"urls": { "` + osArch + `": "` + srv.URL + `/llvm-18.tgz?X-Amz-Signature=presigned123" },
				"sha256": { "` + osArch + `": "` + archiveSHA + `" }
			}
		}
	}`
	if err = os.WriteFile(filepath.Join(regDir, "registry.json"), []byte(regJSON), 0o600); err != nil {
		t.Fatal(err)
	}

	gotBin, err := EnsureToolchain(t.Context(), "@llvm/clang", "", "", "18.1.8", regDir)
	if err != nil {
		t.Fatalf("EnsureToolchain(@llvm/clang) failed: %v", err)
	}
	if _, err = os.Stat(filepath.Join(gotBin, aliasName)); err != nil {
		t.Fatalf("expected forward-referenced symlink/copy %s materialized in %s: %v", aliasName, gotBin, err)
	}
	if cached := FindCachedToolchainBinDir("@llvm/clang", "", binName, "18.1.8", ""); cached != gotBin {
		t.Fatalf("FindCachedToolchainBinDir = %q, want %q", cached, gotBin)
	}

	// CleanToolchainsAndCAS must unlock 0o444/0o555 CAS blobs and remove toolchains + CAS cleanly.
	reclaimed, err := CleanToolchainsAndCAS()
	if err != nil {
		t.Fatalf("CleanToolchainsAndCAS failed: %v", err)
	}
	if reclaimed <= 0 {
		t.Fatalf("expected positive reclaimed bytes, got %d", reclaimed)
	}
	if _, err := os.Stat(filepath.Join(toobHome, "store", "cas")); !os.IsNotExist(err) {
		t.Fatalf("expected store/cas removed, stat err = %v", err)
	}
}
