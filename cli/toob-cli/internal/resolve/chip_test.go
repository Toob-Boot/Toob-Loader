package resolve

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	manifestpkg "github.com/toob-boot/toob/internal/manifest"
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

func TestResolveChipRequiresVersion(t *testing.T) {
	fx := newFixture(t)
	fx.setSpec(func(s *manifestpkg.ChipManifest) { s.Version = "" })
	_, err := resolveChip(fx.input())
	requireErr(t, err, "'version'")
}

func TestResolveChipLocalOverride(t *testing.T) {
	fx := newFixture(t)
	local := fx.spec
	local.Sources = &manifestpkg.ChipSources{Drivers: []string{"drivers/local/drv/x.c"}}
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

func TestResolveChipManifestAuthoritative(t *testing.T) {
	t.Run("manifest values are never overwritten by index", func(t *testing.T) {
		fx := newFixture(t)
		fx.index.Chips[testChip] = registry.ChipInfo{
			Sources:  &registry.ChipSources{Drivers: []string{"drivers/reg/drv/y.c"}},
			Recovery: &registry.ChipRecovery{Console: "idx/console", Flash: "idx/flash"},
		}
		chip := fx.chip()
		if len(chip.driverFiles) != 3 {
			t.Fatalf("driver files %v must stay authoritative from chip_manifest.json", chip.driverFiles)
		}
		if chip.recovery == nil || chip.recovery.Console != "uart/esp_uart_v1" {
			t.Fatalf("recovery %+v must stay authoritative from chip_manifest.json", chip.recovery)
		}
	})

	t.Run("index supplies omitted fields when manifest omits them", func(t *testing.T) {
		fx := newFixture(t)
		fx.setSpec(func(s *manifestpkg.ChipManifest) {
			s.Sources = nil
			s.Recovery = nil
		})
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
			t.Fatalf("driver files %v must come from the index when manifest omits them", chip.driverFiles)
		}
		want := manifestpkg.ChipRecovery{
			Console: "idx/console", Flash: "idx/flash", WDT: "w", Clock: "c", RTC: "r",
			Crypto:  &manifestpkg.RecoveryCrypto{Backend: "rom", Hash: "h"},
			Sources: []string{"s.c"}, Includes: []string{"i"},
		}
		got := chip.recovery
		if got == nil || got.Console != want.Console || got.Flash != want.Flash || got.WDT != want.WDT ||
			got.Clock != want.Clock || got.RTC != want.RTC || got.Crypto == nil || *got.Crypto != *want.Crypto ||
			len(got.Sources) != 1 || len(got.Includes) != 1 {
			t.Fatalf("recovery = %+v, want %+v", got, want)
		}
	})
}

func TestResolveChipErrorsAndClang(t *testing.T) {
	tests := []struct {
		name  string
		setup func(fx *fixture)
		want  string
	}{
		{"nil device", func(fx *fixture) { fx.dev = nil }, "device.toml input is nil"},
		{"empty chip", func(fx *fixture) { fx.dev.Device.Chip = "" }, "must define [device]"},
		{"unsafe chip name", func(fx *fixture) { fx.dev.Device.Chip = "../x" }, "invalid chip name"},
		{"nil registry", func(fx *fixture) { fx.reg = nil }, "registry source is nil"},
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
		{"missing arch", func(fx *fixture) { fx.setSpec(func(s *manifestpkg.ChipManifest) { s.Arch = "" }) }, "'arch'"},
		{"unsafe arch", func(fx *fixture) { fx.setSpec(func(s *manifestpkg.ChipManifest) { s.Arch = "a b" }) }, "invalid arch name"},
		{"unsafe prefix", func(fx *fixture) { fx.setSpec(func(s *manifestpkg.ChipManifest) { s.CompilerPrefix = "a;b-" }) }, "invalid compiler prefix name"},
		{"unsafe compiler flag", func(fx *fixture) {
			fx.setSpec(func(s *manifestpkg.ChipManifest) {
				s.CompilerFlags = &manifestpkg.CompilerFlags{CFlags: []string{"-O2;rm -rf /"}}
			})
		}, "compiler_flags"},
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
			var err error
			switch {
			case tc.setup == nil:
				_, err = resolveChip(fx.input())
			case tc.name == "nil registry":
				in := fx.input()
				in.Registry = nil
				_, err = resolveChip(in)
			default:
				_, err = resolveChip(fx.input())
			}
			requireErr(t, err, tc.want)
		})
	}

	t.Run("empty compiler_prefix selects Clang/LLVM toolchain", func(t *testing.T) {
		fx := newFixture(t)
		fx.setSpec(func(s *manifestpkg.ChipManifest) {
			s.CompilerPrefix = ""
		})
		// Without any Clang/LLVM toolchain entry, Resolve must fail cleanly.
		_, err := fx.resolve()
		requireErr(t, err, "no Clang/LLVM toolchain")

		// Add scoped Clang/LLVM toolchain entry with CompilerBinary.
		fx.index.Toolchains["@toob/clang"] = registry.ToolchainInfo{
			Version:        "18.1.0",
			CompilerBinary: "clang",
		}
		fx.touch(filepath.Join(fx.reg.base, "toolchains", "@toob", "clang", "toolchain.cmake"))
		plan, err := fx.resolve()
		requireNoErr(t, err)
		if plan.Toolchain.Name != "@toob/clang" || plan.Toolchain.CompilerBinary != "clang" {
			t.Fatalf("unexpected Clang toolchain resolution: %+v", plan.Toolchain)
		}
	})
}

func TestResolveArch(t *testing.T) {
	t.Run("registry with arch_manifest flags", func(t *testing.T) {
		fx := newFixture(t)
		archDir := filepath.Join(fx.reg.base, "arch", "riscv")
		fx.writeJSON(filepath.Join(archDir, archManifestFile), manifestpkg.ArchManifest{
			Name:    "riscv",
			Version: "1.4.0",
			License: "Apache-2.0",
			CompilerFlags: &manifestpkg.CompilerFlags{
				CFlags: []string{"-mabi=ilp32"},
			},
		})
		arch, err := resolveArch(fx.input(), fx.chip())
		requireNoErr(t, err)
		if arch.Name != "riscv" || arch.Dir != archDir || arch.Version != "1.4.0" || arch.License != "Apache-2.0" {
			t.Fatalf("unexpected arch %+v", arch)
		}
		if arch.CompilerFlags == nil || !slices.Equal(arch.CompilerFlags.CFlags, []string{"-mabi=ilp32"}) {
			t.Fatalf("arch compiler_flags = %+v", arch.CompilerFlags)
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
