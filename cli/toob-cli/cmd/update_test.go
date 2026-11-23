package cmd

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"

	"github.com/toob-boot/toob/internal/httputil"
)

func TestUpdateDevBuildRequiresExplicitVersion(t *testing.T) {
	orig := Version
	Version = "dev"
	defer func() { Version = orig }()

	root := NewRootCmd()
	root.SetArgs([]string{"update", "--check"})
	err := root.Execute()
	if err == nil {
		t.Fatalf("expected error running update without --version on dev build")
	}
	if !strings.Contains(err.Error(), "dev") {
		t.Fatalf("unexpected error message: %v", err)
	}

	// Verify --insecure flag was completely removed.
	badRoot := NewRootCmd()
	badRoot.SetArgs([]string{"update", "--insecure"})
	if badErr := badRoot.Execute(); badErr == nil {
		t.Fatalf("expected unknown flag error for removed --insecure flag")
	}
}

func TestExtractVerifiedBinaryFailClosedOnUnknownFormats(t *testing.T) {
	payload := []byte("ELF-FAKE-RAW-BINARY")
	if _, err := extractVerifiedBinary("https://example.com/toob-linux-amd64", payload); err == nil {
		t.Fatalf("expected fail-closed error for unknown binary extension")
	}
	if _, err := extractVerifiedBinary("https://example.com/toob.exe", payload); err == nil {
		t.Fatalf("expected fail-closed error for raw .exe extension")
	}

	targetName := "toob"
	if runtime.GOOS == "windows" {
		targetName = "toob.exe"
	}

	// Build valid tar.gz containing a symlink (ignored) and a regular binary entry.
	var tarBuf bytes.Buffer
	gzw := gzip.NewWriter(&tarBuf)
	tw := tar.NewWriter(gzw)
	if err := tw.WriteHeader(&tar.Header{
		Name:     targetName,
		Typeflag: tar.TypeSymlink,
		Linkname: "/etc/passwd",
		Mode:     0o777,
	}); err != nil {
		t.Fatalf("write symlink header: %v", err)
	}
	if err := tw.WriteHeader(&tar.Header{
		Name:     "bin/" + targetName,
		Typeflag: tar.TypeReg,
		Size:     int64(len(payload)),
		Mode:     0o755,
	}); err != nil {
		t.Fatalf("write reg header: %v", err)
	}
	if _, err := tw.Write(payload); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	_ = tw.Close()
	_ = gzw.Close()

	got, err := extractVerifiedBinary("https://example.com/toob.tar.gz", tarBuf.Bytes())
	if err != nil {
		t.Fatalf("extractVerifiedBinary(.tar.gz) failed: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("extracted tar.gz payload mismatch")
	}

	// Build valid zip archive.
	var zipBuf bytes.Buffer
	zw := zip.NewWriter(&zipBuf)
	zf, err := zw.Create(targetName)
	if err != nil {
		t.Fatalf("create zip entry: %v", err)
	}
	if _, writeErr := zf.Write(payload); writeErr != nil {
		t.Fatalf("write zip entry: %v", writeErr)
	}
	_ = zw.Close()

	gotZip, err := extractVerifiedBinary("https://example.com/toob.zip", zipBuf.Bytes())
	if err != nil {
		t.Fatalf("extractVerifiedBinary(.zip) failed: %v", err)
	}
	if !bytes.Equal(gotZip, payload) {
		t.Fatalf("extracted zip payload mismatch")
	}
}

func TestFetchUpdateAssetHandles410Gone(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Toob-Warning", "recalled security advisory TOOB-2026-01")
		w.WriteHeader(http.StatusGone)
		_, _ = w.Write([]byte("release yanked due to vulnerability"))
	}))
	defer srv.Close()

	client, err := httputil.NewClient(defaultCmdTimeout)
	if err != nil {
		t.Fatalf("httputil.NewClient failed: %v", err)
	}

	_, fetchErr := fetchUpdateAsset(t.Context(), client, srv.URL+"/release.tar.gz", 1024)
	if fetchErr == nil {
		t.Fatalf("expected error on HTTP 410 Gone")
	}
	if !strings.Contains(fetchErr.Error(), "410 Gone") {
		t.Fatalf("expected 410 Gone in error message, got: %v", fetchErr)
	}
}
