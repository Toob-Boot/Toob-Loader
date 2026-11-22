package regcheck_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/toob-boot/toob/internal/lockfile"
	"github.com/toob-boot/toob/internal/regcheck"
)

func TestCheckAsync_NumericRevisionComparisonPersistedChipWarningsAndCISkip(t *testing.T) {
	var upstreamRev int64 = 42
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/registry/revision":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"revision":       upstreamRev,
				"format_version": 1,
				"commit_sha":     "abcd",
				"created_at":     "2026-01-01T00:00:00Z",
			})
		case "/api/v1/resolve/chip":
			if r.URL.Query().Get("name") == "removed_chip" {
				http.Error(w, `{"code":"not_found","detail":"removed"}`, http.StatusNotFound)
				return
			}
			_, _ = w.Write([]byte(`{"name":"esp32c6","version":"1.3.2","path":"chips/esp32c6"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	toobHome := filepath.Join(t.TempDir(), ".toob")
	projDir := t.TempDir()
	t.Setenv("TOOB_HOME", toobHome)
	t.Setenv("TOOB_REGISTRY_URL", srv.URL)
	t.Setenv("TOOB_DEV", "")
	t.Setenv("TOOB_REGISTRY_DIR", "")
	t.Setenv("CI", "")
	t.Setenv("TOOB_NO_UPDATE_CHECK", "")

	if err := os.WriteFile(filepath.Join(projDir, "device.toml"), []byte("name = \"demo\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(projDir)

	// 1. Legacy lockfile with Version="v1.2.2" AND Commit="42" must NOT false-positive against upstream rev 42!
	lf := &lockfile.Lockfile{
		Chips: []lockfile.ChipEntry{{Name: "esp32c6", Version: "1.3.2", Arch: "riscv32"}},
	}
	lf.Registry.Version = "v1.2.2"
	lf.Registry.Commit = "42"
	if err := lf.Save(filepath.Join(projDir, "toob.lock")); err != nil {
		t.Fatal(err)
	}

	if res := <-regcheck.CheckAsync(); res != nil {
		t.Fatalf("expected nil Result when numeric Commit=42 matches upstream Revision=42, got %+v", res)
	}

	// 2. Clear cache and advance upstream to rev 43 with a missing chip: must report Outdated + ChipWarnings,
	//    and persist ChipWarnings into registry_check.json so subsequent cache hits still show them!
	_ = os.Remove(filepath.Join(toobHome, "registry_check.json"))
	upstreamRev = 43

	v2 := lockfile.NewV2()
	v2.Registry = lockfile.RegistryLock{URL: srv.URL, Revision: "42"}
	v2.Targets["esp32c6"] = lockfile.TargetLock{Chip: "esp32c6@1.3.2"}
	v2.Targets["removed_chip"] = lockfile.TargetLock{Chip: "removed_chip@1.0.0"}
	if err := v2.Save(filepath.Join(projDir, "toob.lock")); err != nil {
		t.Fatal(err)
	}

	res1 := <-regcheck.CheckAsync()
	if res1 == nil || !res1.Outdated || res1.CurrentVersion != "42" || res1.LatestVersion != "43" {
		t.Fatalf("expected Outdated 42->43, got %+v", res1)
	}
	if !slices.Equal(res1.ChipWarnings, []string{"removed_chip"}) {
		t.Fatalf("expected ChipWarnings=[removed_chip], got %v", res1.ChipWarnings)
	}

	// Second call hits registry_check.json cache and must STILL return ChipWarnings!
	res2 := <-regcheck.CheckAsync()
	if res2 == nil || !slices.Equal(res2.ChipWarnings, []string{"removed_chip"}) {
		t.Fatalf("expected cached CheckAsync to preserve ChipWarnings, got %+v", res2)
	}

	// 3. CI=1 skips CheckAsync immediately.
	t.Setenv("CI", "1")
	if resCI := <-regcheck.CheckAsync(); resCI != nil {
		t.Fatalf("expected nil Result when CI=1, got %+v", resCI)
	}
}
