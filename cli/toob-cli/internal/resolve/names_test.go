package resolve

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	manifestpkg "github.com/toob-boot/toob/internal/manifest"
)

func TestValidateRelName(t *testing.T) {
	valid := []string{"uart", "uart/esp_uart_v1", "core/v1.2.3", "a-b.c_d"}
	for _, name := range valid {
		requireNoErr(t, validateRelName("driver", name))
	}
	invalid := []string{"", "/abs", "a//b", "a/", "../x", "a/../b", "a/./b", "a b", "a;b", `a\b`, "a$b", `a"b`}
	for _, name := range invalid {
		if err := validateRelName("driver", name); err == nil {
			t.Errorf("validateRelName(%q) accepted an invalid name", name)
		}
	}
}

func TestContain(t *testing.T) {
	base := filepath.Join(t.TempDir(), "pkg")
	valid := map[string]string{
		"a/b":     filepath.Join(base, "a", "b"),
		"./a":     filepath.Join(base, "a"),
		"a/../b":  filepath.Join(base, "b"),
		"inc/..a": filepath.Join(base, "inc", "..a"),
	}
	for rel, want := range valid {
		got, err := Contain(base, rel)
		requireNoErr(t, err)
		if got != want {
			t.Errorf("Contain(%q) = %q, want %q", rel, got, want)
		}
	}

	invalid := []string{"", "/abs", `\abs`, "..", "../x", "a/../../x", "../pkg2/x"}
	for _, rel := range invalid {
		if _, err := Contain(base, rel); err == nil {
			t.Errorf("Contain(%q) accepted an escaping path", rel)
		}
	}
}

func TestContainAll(t *testing.T) {
	base := t.TempDir()
	got, err := containAll(base, []string{"a", "b/c"})
	requireNoErr(t, err)
	if len(got) != 2 || got[1] != filepath.Join(base, "b", "c") {
		t.Fatalf("unexpected result %v", got)
	}
	if _, badErr := containAll(base, []string{"a", "../b"}); badErr == nil {
		t.Fatal("containAll accepted an escaping entry")
	}
	empty, err := containAll(base, nil)
	requireNoErr(t, err)
	if empty == nil || len(empty) != 0 {
		t.Fatalf("expected an empty, non-nil slice, got %#v", empty)
	}
}

func TestFirstNonEmpty(t *testing.T) {
	if got := firstNonEmpty("", "b", "c"); got != "b" {
		t.Errorf("got %q, want b", got)
	}
	if got := firstNonEmpty("", ""); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestDecodeManifestJSON_StrictAndRegistryParity(t *testing.T) {
	tmp := t.TempDir()
	badChip := filepath.Join(tmp, "chip_manifest.json")
	if err := os.WriteFile(badChip, []byte(`{"arch":"riscv32","compiler_prefix":"riscv32-","version":"1.0.0","unknown_field":true}`), 0o644); err != nil {
		t.Fatal(err)
	}
	var cm manifestpkg.ChipManifest
	requireErr(t, decodeStrictManifestJSON(badChip, &cm), "unknown field")

	badDrv := filepath.Join(tmp, "driver_manifest.json")
	if err := os.WriteFile(badDrv, []byte(`{"name":"foo","bogus_key":1}`), 0o644); err != nil {
		t.Fatal(err)
	}
	var dm manifestpkg.DriverManifest
	requireErr(t, decodeStrictManifestJSON(badDrv, &dm), "unknown field")

	regRoot := filepath.Join("..", "..", "..", "..", "toob-infra", "registry", "packages")
	if st, err := os.Stat(regRoot); err == nil && st.IsDir() {
		var checked int
		err := filepath.WalkDir(regRoot, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil || d.IsDir() {
				return walkErr
			}
			switch d.Name() {
			case "chip_manifest.json":
				var c manifestpkg.ChipManifest
				if err := decodeStrictManifestJSON(path, &c); err != nil {
					t.Errorf("strict decode failed on real chip manifest %s: %v", path, err)
				}
				checked++
			case "driver_manifest.json":
				var drv manifestpkg.DriverManifest
				if err := decodeStrictManifestJSON(path, &drv); err != nil {
					t.Errorf("strict decode failed on real driver manifest %s: %v", path, err)
				}
				checked++
			}
			return nil
		})
		requireNoErr(t, err)
		if checked == 0 {
			t.Fatal("expected at least one real manifest in toob-infra/registry/packages")
		}
	}
}

func TestContainWindowsHardeningAndCWE436(t *testing.T) {
	base := t.TempDir()
	badPaths := []string{
		"CON", "PRN.c", "AUX.h", "NUL", "COM1", "LPT9.txt",
		"foo.", "foo ", "dir /bar", "sub\\..\\..\\out",
	}
	for _, bad := range badPaths {
		if _, err := Contain(base, bad); err == nil {
			t.Errorf("Contain(%q) expected error for unsafe path", bad)
		}
	}
	if got := preserveExtendedUNCPrefix(`\??\UNC\server\share\dir`, `\??\UNC\server\share\dir`); got != `\??\UNC\server\share\dir` {
		t.Errorf("preserveExtendedUNCPrefix altered UNC path: %q", got)
	}

	dupPath := filepath.Join(t.TempDir(), "case_dup.json")
	if err := os.WriteFile(dupPath, []byte(`{"version":"1.0.0","VERSION":"2.0.0"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var out map[string]string
	requireErr(t, decodeJSONFile(dupPath, &out, false), "duplicate JSON key")
}
