package paths_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/toob-boot/toob/internal/paths"
)

func TestToobHomeAndRegistryDirOverrides(t *testing.T) {
	customHome := filepath.Join(t.TempDir(), "rel", "..", "toob_home")
	t.Setenv("TOOB_HOME", customHome)

	gotHome, err := paths.ToobHome()
	if err != nil {
		t.Fatalf("ToobHome failed: %v", err)
	}
	wantHome, _ := filepath.Abs(customHome)
	if gotHome != wantHome {
		t.Fatalf("ToobHome = %q, want %q", gotHome, wantHome)
	}

	relReg := filepath.Join(t.TempDir(), "sub", "..", "local_reg")
	t.Setenv("TOOB_REGISTRY_DIR", relReg)
	gotReg, err := paths.RegistryDir()
	if err != nil {
		t.Fatalf("RegistryDir failed: %v", err)
	}
	wantReg, _ := filepath.Abs(relReg)
	if gotReg != wantReg {
		t.Fatalf("RegistryDir = %q, want %q", gotReg, wantReg)
	}

	t.Setenv("TOOB_DEV", "TrUe")
	if !paths.IsDevMode() {
		t.Fatal("expected case-insensitive TOOB_DEV=TrUe to enable IsDevMode()")
	}
	t.Setenv("TOOB_DEV", "0")
	if paths.IsDevMode() {
		t.Fatal("expected TOOB_DEV=0 to disable IsDevMode()")
	}
}

func TestFindProjectRootStrict_AndFromManifest(t *testing.T) {
	parent := t.TempDir()
	childProj := filepath.Join(parent, "app_project")
	if err := os.MkdirAll(childProj, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(childProj, "device.toml"), []byte("name = \"app\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Directory named device.toml in parent must NOT count as a project root!
	if err := os.MkdirAll(filepath.Join(parent, "device.toml"), 0o755); err != nil {
		t.Fatal(err)
	}

	// FindProjectRootStrict must NOT descend into childProj when run from parent.
	if _, err := paths.FindProjectRootStrict(parent); err == nil {
		t.Fatal("FindProjectRootStrict descended into child directory or accepted directory named device.toml")
	}

	// Upward walk from nested dir inside childProj must find childProj.
	nested := filepath.Join(childProj, "src", "hal")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	gotStrict, err := paths.FindProjectRootStrict(nested)
	if err != nil || gotStrict != childProj {
		t.Fatalf("FindProjectRootStrict(%q) = %q, %v; want %q", nested, gotStrict, err, childProj)
	}

	// Multi-manifest workspace: boards/revA/device.toml sharing root toob.lock.
	wsRoot := t.TempDir()
	if wErr := os.WriteFile(filepath.Join(wsRoot, "toob.lock"), []byte("format_version = 2\n"), 0o644); wErr != nil {
		t.Fatal(wErr)
	}
	boardDir := filepath.Join(wsRoot, "boards", "revA")
	if mErr := os.MkdirAll(boardDir, 0o755); mErr != nil {
		t.Fatal(mErr)
	}
	manifestFile := filepath.Join(boardDir, "device.toml")
	if wErr := os.WriteFile(manifestFile, []byte("name = \"revA\"\n"), 0o644); wErr != nil {
		t.Fatal(wErr)
	}

	gotWS, err := paths.FindProjectRootFromManifest(manifestFile)
	if err != nil || gotWS != wsRoot {
		t.Fatalf("FindProjectRootFromManifest = %q, %v; want workspace root %q", gotWS, err, wsRoot)
	}

	// Standalone manifest with no toob.lock anywhere upward falls back to manifest directory.
	standaloneDir := filepath.Join(t.TempDir(), "standalone")
	if mErr := os.MkdirAll(standaloneDir, 0o755); mErr != nil {
		t.Fatal(mErr)
	}
	standaloneManifest := filepath.Join(standaloneDir, "device.toml")
	if wErr := os.WriteFile(standaloneManifest, []byte("name = \"solo\"\n"), 0o644); wErr != nil {
		t.Fatal(wErr)
	}
	gotSolo, err := paths.FindProjectRootFromManifest(standaloneManifest)
	if err != nil || gotSolo != standaloneDir {
		t.Fatalf("FindProjectRootFromManifest(standalone) = %q, %v; want %q", gotSolo, err, standaloneDir)
	}
}
