package resolve

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/toob-boot/toob/internal/ports"
	"github.com/toob-boot/toob/internal/registry"
)

func TestResolveChipRegistry(t *testing.T) {
	fx := newFixture(t)
	chip := fx.chip()

	if chip.Local || chip.Dir != fx.registryChipDir() {
		t.Fatalf("expected the registry chip, got %+v", chip)
	}
	if chip.Name != testChip || chip.Arch != "riscv" || chip.Prefix != testToolchain+"-" || chip.Version != "2.0.0" {
		t.Fatalf("unexpected chip %+v", chip)
	}
	if chip.HardwarePath != filepath.Join(chip.Dir, hardwareFile) || chip.ManifestPath != filepath.Join(chip.Dir, chipManifestFile) {
		t.Fatalf("unexpected paths %q, %q", chip.HardwarePath, chip.ManifestPath)
	}
}

func TestResolveChipDefaultVersion(t *testing.T) {
	fx := newFixture(t)
	fx.setSpec(func(s *ports.ChipManifest) { s.Version = "" })
	if got := fx.chip().Version; got != defaultChipVer {
		t.Fatalf("Version = %q, want %q", got, defaultChipVer)
	}
}

func TestResolveChipLocalOverride(t *testing.T) {
	fx := newFixture(t)
	local := fx.spec
	local.Sources = &ports.ChipSources{Drivers: []string{"drivers/local/drv/x.c"}}
	local.Recovery = nil
	fx.writeChip(fx.localChipDir(), local)
	fx.index.Chips[testChip] = registry.ChipInfo{
		Sources:  &registry.ChipSources{Drivers: []string{"drivers/reg/drv/y.c"}},
		Recovery: &registry.ChipRecovery{Console: "idx/console", Flash: "idx/flash"},
	}

	chip := fx.chip()
	if !chip.Local || chip.Dir != fx.localChipDir() {
		t.Fatalf("expected the local chip, got %+v", chip)
	}
	if fx.reg.called("chips:") {
		t.Fatal("the registry was queried although the project overrides the chip")
	}
	if len(chip.driverFiles) != 1 || chip.driverFiles[0] != "drivers/local/drv/x.c" {
		t.Fatalf("driver files %v must come from the local manifest, not the index", chip.driverFiles)
	}
	if chip.recovery != nil {
		t.Fatalf("recovery %+v must come from the local manifest, not the index", chip.recovery)
	}
}

func TestResolveChipIndexEntries(t *testing.T) {
	fx := newFixture(t)
	fx.index.Chips[testChip] = registry.ChipInfo{
		Sources: &registry.ChipSources{Drivers: []string{"drivers/reg/drv/y.c"}},
		Recovery: &registry.ChipRecovery{
			Console: "idx/console", Flash: "idx/flash", WDT: "w", Clock: "c", RTC: "r",
			Crypto:  &registry.RecoveryCrypto{Backend: "rom", Hash: "h"},
			Sources: []string{"s.c"}, Includes: []string{"i"},
		},
	}
	chip := fx.chip()

	if len(chip.driverFiles) != 1 || chip.driverFiles[0] != "drivers/reg/drv/y.c" {
		t.Fatalf("driver files %v must come from the index", chip.driverFiles)
	}
	want := ports.ChipRecovery{
		Console: "idx/console", Flash: "idx/flash", WDT: "w", Clock: "c", RTC: "r",
		Crypto:  &ports.RecoveryCrypto{Backend: "rom", Hash: "h"},
		Sources: []string{"s.c"}, Includes: []string{"i"},
	}
	got := chip.recovery
	if got == nil || got.Console != want.Console || got.Flash != want.Flash || got.WDT != want.WDT ||
		got.Clock != want.Clock || got.RTC != want.RTC || got.Crypto == nil || *got.Crypto != *want.Crypto ||
		len(got.Sources) != 1 || len(got.Includes) != 1 {
		t.Fatalf("recovery = %+v, want %+v", got, want)
	}
}

func TestResolveChipIndexFallsBackToManifest(t *testing.T) {
	fx := newFixture(t)
	fx.index.Chips[testChip] = registry.ChipInfo{}
	chip := fx.chip()

	if len(chip.driverFiles) != 3 {
		t.Fatalf("driver files %v must fall back to the manifest", chip.driverFiles)
	}
	if chip.recovery == nil || chip.recovery.Console != "uart/esp_uart_v1" {
		t.Fatalf("recovery %+v must fall back to the manifest", chip.recovery)
	}
}

func TestResolveChipErrors(t *testing.T) {
	tests := []struct {
		name  string
		setup func(fx *fixture)
		want  string
	}{
		{"empty chip", func(fx *fixture) { fx.dev.Device.Chip = "" }, "must define [device]"},
		{"traversal in chip", func(fx *fixture) { fx.dev.Device.Chip = "../x" }, "invalid chip name"},
		{"registry failure", func(fx *fixture) { fx.reg.fail["chips:"+testChip] = true }, "failed to resolve chip"},
		{"registry chip without hardware.json", func(fx *fixture) {
			if err := os.Remove(filepath.Join(fx.registryChipDir(), hardwareFile)); err != nil {
				fx.t.Fatal(err)
			}
		}, "is incomplete"},
		{"local chip without files", func(fx *fixture) {
			if err := os.MkdirAll(fx.localChipDir(), 0o755); err != nil {
				fx.t.Fatal(err)
			}
		}, "is incomplete"},
		{"local chip path is a file", func(fx *fixture) { fx.touch(fx.localChipDir()) }, "not a directory"},
		{"missing arch", func(fx *fixture) { fx.setSpec(func(s *ports.ChipManifest) { s.Arch = "" }) }, "'arch'"},
		{"missing prefix", func(fx *fixture) { fx.setSpec(func(s *ports.ChipManifest) { s.CompilerPrefix = "" }) }, "'compiler_prefix'"},
		{"unsafe arch", func(fx *fixture) { fx.setSpec(func(s *ports.ChipManifest) { s.Arch = "a b" }) }, "invalid arch name"},
		{"unsafe prefix", func(fx *fixture) { fx.setSpec(func(s *ports.ChipManifest) { s.CompilerPrefix = "a;b-" }) }, "invalid compiler prefix name"},
		{"malformed manifest", func(fx *fixture) {
			if err := os.WriteFile(filepath.Join(fx.registryChipDir(), chipManifestFile), []byte("{"), 0o644); err != nil {
				fx.t.Fatal(err)
			}
		}, "failed to parse"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fx := newFixture(t)
			tc.setup(fx)
			_, err := resolveChip(fx.input())
			requireErr(t, err, tc.want)
		})
	}
}

func TestResolveArch(t *testing.T) {
	t.Run("registry", func(t *testing.T) {
		fx := newFixture(t)
		arch, err := resolveArch(fx.input(), fx.chip())
		requireNoErr(t, err)
		if arch.Name != "riscv" || arch.Dir != filepath.Join(fx.reg.base, "arch", "riscv") {
			t.Fatalf("unexpected arch %+v", arch)
		}
	})

	t.Run("local override", func(t *testing.T) {
		fx := newFixture(t)
		local := filepath.Join(fx.root, localHalDir, "arch", "riscv")
		if err := os.MkdirAll(local, 0o755); err != nil {
			t.Fatal(err)
		}
		arch, err := resolveArch(fx.input(), fx.chip())
		requireNoErr(t, err)
		if arch.Dir != local || fx.reg.called("arch:") {
			t.Fatalf("expected the local arch without a registry call, got %+v", arch)
		}
	})

	t.Run("registry failure", func(t *testing.T) {
		fx := newFixture(t)
		fx.reg.fail["arch:riscv"] = true
		_, err := resolveArch(fx.input(), fx.chip())
		requireErr(t, err, "failed to resolve architecture")
	})
}

func TestIsDir(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "f")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}

	if ok, err := isDir(dir); !ok || err != nil {
		t.Errorf("directory: got %v, %v", ok, err)
	}
	if ok, err := isDir(filepath.Join(dir, "missing")); ok || err != nil {
		t.Errorf("missing path: got %v, %v", ok, err)
	}
	if _, err := isDir(file); err == nil {
		t.Error("a file was accepted as directory")
	}
}
