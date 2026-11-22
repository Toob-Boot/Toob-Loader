package registry

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/toob-boot/toob/internal/updater"
)

func TestCreateAndExtractTarball_FlatAndWrappedParity(t *testing.T) {
	src := t.TempDir()
	files := map[string]string{
		"driver_manifest.json": `{"name":"esp_wdt","trait":"wdt"}`,
		"wdt.c":                "int x = 1;\n",
		"include/wdt.h":        "#pragma once\n",
		"builds/out.bin":       "must-be-ignored",
		".env":                 "SECRET=1",
		"signing.key":          "PRIVATE",
		"cert.pem":             "CERT",
		".gitignore":           "ignored_git.txt\n",
		".toobignore":          "ignored_toob.txt\n",
		"ignored_git.txt":      "skip1",
		"ignored_toob.txt":     "skip2",
	}
	for rel, content := range files {
		full := filepath.Join(src, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	var tarBuf bytes.Buffer
	if err := CreateTarball(src, &tarBuf); err != nil {
		t.Fatalf("CreateTarball failed: %v", err)
	}

	dstFlat := t.TempDir()
	if err := ExtractTarball(bytes.NewReader(tarBuf.Bytes()), dstFlat); err != nil {
		t.Fatalf("ExtractTarball (flat) failed: %v", err)
	}

	for _, want := range []string{"driver_manifest.json", "wdt.c", "include/wdt.h"} {
		if _, err := os.Stat(filepath.Join(dstFlat, filepath.FromSlash(want))); err != nil {
			t.Errorf("expected extracted file %q missing: %v", want, err)
		}
	}
	for _, forbidden := range []string{"builds/out.bin", ".env", "signing.key", "cert.pem", "ignored_git.txt", "ignored_toob.txt"} {
		if _, err := os.Stat(filepath.Join(dstFlat, filepath.FromSlash(forbidden))); err == nil {
			t.Errorf("ignored/sensitive file %q leaked into tarball", forbidden)
		}
	}

	// Single-top-dir-wrapped archive (GitHub release tarball style).
	var wrappedBuf bytes.Buffer
	gzw := gzip.NewWriter(&wrappedBuf)
	tw := tar.NewWriter(gzw)
	for _, entry := range []struct{ name, body string }{
		{"Toob-Loader-v0.0.1/CMakeLists.txt", "cmake_minimum_required(VERSION 3.20)\n"},
		{"Toob-Loader-v0.0.1/toobloader/core/boot_main.c", "void boot(void) {}\n"},
	} {
		hdr := &tar.Header{Name: entry.name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(entry.body))}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(entry.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzw.Close(); err != nil {
		t.Fatal(err)
	}

	dstWrapped := t.TempDir()
	if err := ExtractTarball(bytes.NewReader(wrappedBuf.Bytes()), dstWrapped); err != nil {
		t.Fatalf("ExtractTarball (wrapped) failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dstWrapped, "CMakeLists.txt")); err != nil {
		t.Fatalf("expected unwrapped CMakeLists.txt at root: %v", err)
	}

	// Flat archive with only include/esp_soc.h must NOT strip 'include/'.
	var socBuf bytes.Buffer
	gzw2 := gzip.NewWriter(&socBuf)
	tw2 := tar.NewWriter(gzw2)
	hdr := &tar.Header{Name: "include/esp_soc.h", Typeflag: tar.TypeReg, Mode: 0o644, Size: 13}
	if err := tw2.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := tw2.Write([]byte("#pragma once\n")); err != nil {
		t.Fatal(err)
	}
	_ = tw2.Close()
	_ = gzw2.Close()

	dstSoc := t.TempDir()
	if err := ExtractTarball(bytes.NewReader(socBuf.Bytes()), dstSoc); err != nil {
		t.Fatalf("ExtractTarball (soc include) failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dstSoc, "include", "esp_soc.h")); err != nil {
		t.Fatalf("standard subdir 'include/' was erroneously stripped: %v", err)
	}
}

func TestCreateTarball_RejectsJunctionAndSymlink(t *testing.T) {
	src := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("host-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "driver_manifest.json"), []byte(`{"name":"x"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	linkPath := filepath.Join(src, "junction_out")
	created := false
	if err := os.Symlink(outside, linkPath); err == nil {
		created = true
	} else if runtime.GOOS == "windows" {
		if out, jErr := exec.Command("cmd", "/c", "mklink", "/J", linkPath, outside).CombinedOutput(); jErr == nil {
			created = true
		} else {
			t.Skipf("cannot create symlink or junction: %v / %s", jErr, string(out))
		}
	}
	if !created {
		t.Skip("symlink creation unavailable")
	}

	var buf bytes.Buffer
	if err := CreateTarball(src, &buf); err == nil {
		t.Fatal("CreateTarball must reject unignored symlinks and Windows NTFS directory junctions")
	}
}

func TestClassifyTier_BlocksSpoofing(t *testing.T) {
	if got := ClassifyTier("@untrusted/evil", "toob-core-team", "official", false); got != "community" {
		t.Fatalf("@untrusted/evil spoofed tier %q, want community", got)
	}
	if got := ClassifyTier("unscoped_pkg", "", "", false); got != "community" {
		t.Fatalf("empty author defaulted to %q, want community", got)
	}
	if got := ClassifyTier("@toob/esp_efuse", "", "", false); got != "official" {
		t.Fatalf("@toob/ package classified as %q, want official", got)
	}
	if got := ClassifyTier("@partner/atecc608", "", "", false); got != "partner" {
		t.Fatalf("@partner/ package classified as %q, want partner", got)
	}
}

func TestCacheFetchPackage_EnforcesSHA256AndContainment(t *testing.T) {
	pkgSrc := t.TempDir()
	if err := os.WriteFile(filepath.Join(pkgSrc, "driver_manifest.json"), []byte(`{"name":"drv","trait":"wdt"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	var tarBuf bytes.Buffer
	if err := CreateTarball(pkgSrc, &tarBuf); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(tarBuf.Bytes())
	goodSHA := hex.EncodeToString(sum[:])

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/package/drv/1.0.0/download" {
			_, _ = w.Write(tarBuf.Bytes())
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("TOOB_REGISTRY_URL", srv.URL)
	t.Setenv("TOOB_DEV", "")
	t.Setenv("TOOB_REGISTRY_DIR", "")

	c := &Cache{rootDir: filepath.Join(home, "reg"), dir: filepath.Join(home, "reg", "versions", "1")}

	// 1. Path traversal rejected before network or disk write.
	if err := c.fetchPackage("drv", "1.0.0", "../../../outside", goodSHA); err == nil {
		t.Fatal("expected path traversal in info.Path to fail")
	}

	// 2. Empty SHA-256 rejected in non-dev mode.
	if err := c.fetchPackage("drv", "1.0.0", "drivers/wdt/drv", ""); err == nil || !strings.Contains(err.Error(), "no sha256") {
		t.Fatalf("expected missing sha256 error, got %v", err)
	}

	// 3. Mismatched SHA-256 rejected before extraction.
	badSHA := strings.Repeat("a", 64)
	if err := c.fetchPackage("drv", "1.0.0", "drivers/wdt/drv", badSHA); err == nil || !strings.Contains(err.Error(), "SHA256 mismatch") {
		t.Fatalf("expected SHA256 mismatch error, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(c.dir, "drivers", "wdt", "drv")); err == nil {
		t.Fatal("mismatched tarball must not create cached package directory")
	}

	// 4. Matching SHA-256 extracts and commits atomically.
	if err := c.fetchPackage("drv", "1.0.0", "drivers/wdt/drv", goodSHA); err != nil {
		t.Fatalf("valid fetchPackage failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(c.dir, "drivers", "wdt", "drv", "driver_manifest.json")); err != nil {
		t.Fatalf("expected driver_manifest.json in committed cache dir: %v", err)
	}
}

func TestSelectVersion_RejectsTraversalUnsignedAndUnpinnedHead(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	origKey := updater.ToobMasterPublicKeyHex
	updater.ToobMasterPublicKeyHex = hex.EncodeToString(pub)
	t.Cleanup(func() {
		updater.ToobMasterPublicKeyHex = origKey
	})

	indexBody := []byte(`{"format_version":1,"registry_version":"v9.9.9","chips":{},"archs":{},"toolchains":{},"integrations":{}}`)
	indexDigest := sha256.Sum256(indexBody)
	indexSig := "vault:v1:" + base64.StdEncoding.EncodeToString(ed25519.Sign(priv, indexDigest[:]))

	sendSig := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/registry/index":
			if sendSig {
				w.Header().Set("X-Registry-Signature", indexSig)
			}
			_, _ = w.Write(indexBody)
		case "/api/v1/registry/revision":
			_, _ = w.Write([]byte(`{"revision":99,"format_version":1,"commit_sha":"abcd","created_at":"2026-01-01T00:00:00Z"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	home := t.TempDir()
	t.Setenv("TOOB_HOME", filepath.Join(home, ".toob"))
	t.Setenv("TOOB_REGISTRY_URL", srv.URL)
	t.Setenv("TOOB_REGISTRY_DIR", "")
	t.Setenv("TOOB_DEV", "")

	c := &Cache{rootDir: filepath.Join(home, "reg"), dir: filepath.Join(home, "reg")}
	if err := c.SelectVersion("../../evil", true); err == nil {
		t.Fatal("expected SelectVersion traversal rejection")
	}

	// Unsigned index response in non-dev mode must fail closed.
	if err := c.SelectVersion("42", true); err == nil || !strings.Contains(err.Error(), "missing X-Registry-Signature") {
		t.Fatalf("expected missing X-Registry-Signature rejection, got %v", err)
	}

	// Signed index response whose revision does not match requested rev 42 must still be rejected.
	sendSig = true
	if err := c.SelectVersion("42", true); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("expected SelectVersion to reject unpinned head mismatch for rev 42, got %v", err)
	}
}

func TestCreateTarball_DeterministicDigestIgnoreRulesAndUnwrapSafety(t *testing.T) {
	makeTree := func(t *testing.T, mtime time.Time) string {
		t.Helper()
		dir := t.TempDir()
		files := map[string]string{
			"driver_manifest.json":    `{"name":"drv","trait":"wdt"}`,
			"src/wdt.c":               "int wdt_init(void) { return 0; }\n",
			"root_only.tmp":           "ignore at root",
			"sub/root_only.tmp":       "keep in subdir",
			"deep/a/b/gen.log":        "ignore via **",
			"deep/a/b/keep.log":       "re-included via !",
			"conformance_report.json": `{"passed":true}`,
			"conformance_report.md":   "# Report\n",
			".env":                    "SECRET=never-reinclude",
			".toobignore":             "/root_only.tmp\n**/*.log\n!deep/a/b/keep.log\n!.env\n",
		}
		for rel, body := range files {
			p := filepath.Join(dir, filepath.FromSlash(rel))
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
			_ = os.Chtimes(p, mtime, mtime)
		}
		return dir
	}

	dir1 := makeTree(t, time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC))
	dir2 := makeTree(t, time.Date(2026, 6, 7, 8, 9, 10, 0, time.UTC))

	var buf1, buf2 bytes.Buffer
	if err := CreateTarball(dir1, &buf1); err != nil {
		t.Fatalf("CreateTarball(dir1) failed: %v", err)
	}
	if err := CreateTarball(dir2, &buf2); err != nil {
		t.Fatalf("CreateTarball(dir2) failed: %v", err)
	}
	if !bytes.Equal(buf1.Bytes(), buf2.Bytes()) {
		t.Fatal("CreateTarball output is not byte-for-byte deterministic across differing mtimes")
	}

	extracted := t.TempDir()
	if err := ExtractTarball(bytes.NewReader(buf1.Bytes()), extracted); err != nil {
		t.Fatalf("ExtractTarball failed: %v", err)
	}
	for _, want := range []string{"driver_manifest.json", "src/wdt.c", "sub/root_only.tmp", "deep/a/b/keep.log"} {
		if _, err := os.Stat(filepath.Join(extracted, filepath.FromSlash(want))); err != nil {
			t.Errorf("expected %q to be included: %v", want, err)
		}
	}
	for _, forbidden := range []string{"root_only.tmp", "deep/a/b/gen.log", "conformance_report.json", "conformance_report.md", ".env"} {
		if _, err := os.Stat(filepath.Join(extracted, filepath.FromSlash(forbidden))); err == nil {
			t.Errorf("forbidden/ignored file %q leaked into tarball", forbidden)
		}
	}

	// Single top directory WITHOUT a canonical root manifest (e.g. soc/esp containing esp/bootrom_image.json)
	// MUST NOT be unwrapped!
	var socTar bytes.Buffer
	gzw := gzip.NewWriter(&socTar)
	tw := tar.NewWriter(gzw)
	body := `{"rom":"esp32c6"}`
	if err := tw.WriteHeader(&tar.Header{Name: "esp/bootrom_image.json", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	_ = tw.Close()
	_ = gzw.Close()

	dstEsp := t.TempDir()
	if err := ExtractTarball(bytes.NewReader(socTar.Bytes()), dstEsp); err != nil {
		t.Fatalf("ExtractTarball(esp/bootrom_image.json) failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dstEsp, "esp", "bootrom_image.json")); err != nil {
		t.Fatalf("non-wrapper top directory 'esp/' was erroneously stripped: %v", err)
	}
}

func TestRegistrySplit_MetaInvalidationSoCDriverRemoteAndVerifyHead(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	origKey := updater.ToobMasterPublicKeyHex
	updater.ToobMasterPublicKeyHex = hex.EncodeToString(pub)
	t.Cleanup(func() {
		updater.ToobMasterPublicKeyHex = origKey
	})

	makePkgTar := func(t *testing.T, files map[string]string) ([]byte, string) {
		t.Helper()
		src := t.TempDir()
		for rel, content := range files {
			full := filepath.Join(src, filepath.FromSlash(rel))
			if mkErr := os.MkdirAll(filepath.Dir(full), 0o755); mkErr != nil {
				t.Fatal(mkErr)
			}
			if wErr := os.WriteFile(full, []byte(content), 0o644); wErr != nil {
				t.Fatal(wErr)
			}
		}
		var b bytes.Buffer
		if tarErr := CreateTarball(src, &b); tarErr != nil {
			t.Fatal(tarErr)
		}
		sum := sha256.Sum256(b.Bytes())
		return b.Bytes(), hex.EncodeToString(sum[:])
	}

	drvTarV1, drvSHAV1 := makePkgTar(t, map[string]string{"driver_manifest.json": `{"name":"esp_wdt","version":"1.0.0"}`, "v.txt": "v1"})
	drvTarV2, drvSHAV2 := makePkgTar(t, map[string]string{"driver_manifest.json": `{"name":"esp_wdt","version":"1.0.0"}`, "v.txt": "v2"})
	socTar, socSHA := makePkgTar(t, map[string]string{"soc_manifest.json": `{"name":"esp"}`, "include/esp_soc.h": "#pragma once\n"})

	activeDrvTar := drvTarV1
	idxObj := Index{
		FormatVersion:   1,
		RegistryVersion: "7",
		Drivers: map[string]DriverInfo{
			"esp_wdt": {Name: "esp_wdt", Version: "1.0.0", Path: "driver/wdt/esp_wdt", SHA256: drvSHAV1},
		},
		SoCs: map[string]SoCInfo{
			"esp": {Name: "esp", Version: "1.0.0", Path: "soc/esp", SHA256: socSHA},
		},
	}
	indexBytes, err := json.Marshal(idxObj)
	if err != nil {
		t.Fatal(err)
	}
	indexSum := sha256.Sum256(indexBytes)
	indexSig := "vault:v3:" + base64.StdEncoding.EncodeToString(ed25519.Sign(priv, indexSum[:]))
	commitHex := hex.EncodeToString(indexSum[:])
	revSig := "vault:v3:" + base64.StdEncoding.EncodeToString(ed25519.Sign(priv, indexSum[:]))

	customSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/registry/revision":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"revision":       7,
				"format_version": 1,
				"commit_sha":     commitHex,
				"signature":      revSig,
				"created_at":     "2026-01-01T00:00:00Z",
			})
		case "/api/v1/registry/index":
			w.Header().Set("X-Registry-Signature", indexSig)
			_, _ = w.Write(indexBytes)
		case "/api/v1/package/esp_wdt/1.0.0/download":
			_, _ = w.Write(activeDrvTar)
		case "/api/v1/package/esp/1.0.0/download":
			_, _ = w.Write(socTar)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(customSrv.Close)

	home := t.TempDir()
	t.Setenv("TOOB_HOME", filepath.Join(home, ".toob"))
	// Point default env at an unreachable URL so we prove OpenForProject + c.remote honors device.toml!
	t.Setenv("TOOB_REGISTRY_URL", "http://127.0.0.1:1")
	t.Setenv("TOOB_REGISTRY_DIR", "")
	t.Setenv("TOOB_DEV", "")

	projDir := t.TempDir()
	if err = os.WriteFile(filepath.Join(projDir, "device.toml"), []byte("[build]\nregistry = \""+customSrv.URL+"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	c, err := OpenForProject(projDir, false)
	if err != nil {
		t.Fatalf("OpenForProject failed: %v", err)
	}
	if c.Remote() != customSrv.URL {
		t.Fatalf("Cache.Remote() = %q, want %q", c.Remote(), customSrv.URL)
	}

	// VerifyHead must succeed against the signed revision + matching local registry.json.
	if err = c.VerifyHead(); err != nil {
		t.Fatalf("VerifyHead failed: %v", err)
	}

	// GetDriver supports both "driver/..." and "drivers/..." prefixes.
	if _, err = c.GetDriver("drivers/wdt/esp_wdt"); err != nil {
		t.Fatalf("GetDriver(drivers/...) failed: %v", err)
	}
	drvDir, err := c.DriverSourcePath("driver/wdt/esp_wdt")
	if err != nil {
		t.Fatalf("DriverSourcePath failed: %v", err)
	}
	gotV, err := os.ReadFile(filepath.Join(drvDir, "v.txt"))
	if err != nil || string(gotV) != "v1" {
		t.Fatalf("got driver v.txt = %q, %v", string(gotV), err)
	}

	// Rolling update at same path with new SHA256 must invalidate .toob_pkg_meta.json and re-fetch!
	activeDrvTar = drvTarV2
	if err = c.fetchPackage("esp_wdt", "1.0.0", "driver/wdt/esp_wdt", drvSHAV2); err != nil {
		t.Fatalf("re-fetching updated SHA at same path failed: %v", err)
	}
	gotV2, err := os.ReadFile(filepath.Join(drvDir, "v.txt"))
	if err != nil || string(gotV2) != "v2" {
		t.Fatalf("stale package cache survived SHA change: got %q, %v", string(gotV2), err)
	}

	// ResolveSoCInclude resolves "soc/esp/include" -> pkgRoot, includeDir, "esp".
	pkgRoot, incDir, socName, err := c.ResolveSoCInclude("soc/esp/include")
	if err != nil {
		t.Fatalf("ResolveSoCInclude failed: %v", err)
	}
	if socName != "esp" || incDir != filepath.Join(pkgRoot, "include") {
		t.Fatalf("ResolveSoCInclude = (%q, %q, %q)", pkgRoot, incDir, socName)
	}

	// Tampering with local registry.json must fail VerifyHead!
	if err := os.WriteFile(filepath.Join(c.Dir(), "registry.json"), []byte(`{"tampered":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := c.VerifyHead(); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("expected VerifyHead to detect local registry.json tampering, got %v", err)
	}
}
