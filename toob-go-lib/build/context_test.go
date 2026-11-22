package build

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoad(t *testing.T) {
	in := writeFixtureInputs(t, testHardware(t))
	// Duplicates (also in non-canonical form) must be collapsed, otherwise the
	// repeated driver would be reported as a trait bound twice.
	in.DriverDirs = append(in.DriverDirs, in.DriverDirs[0]+string(filepath.Separator), "")
	in.CryptoDirs = append(in.CryptoDirs, in.CryptoDirs[0]+string(filepath.Separator), "")
	in.SourceDirs = append(in.SourceDirs, in.SourceDirs[0])

	ctx, err := Load(in, NopLogger{})
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if ctx.Hardware.ChipFamily != "test-chip" || ctx.Chip == nil || ctx.Chip.Arch != "riscv32" {
		t.Errorf("unexpected loaded inputs: hw=%s chip=%+v", ctx.Hardware.ChipFamily, ctx.Chip)
	}
	if len(ctx.Drivers) != len(testDrivers()) {
		t.Errorf("expected %d drivers, got %d", len(testDrivers()), len(ctx.Drivers))
	}
	if len(ctx.Crypto) != len(testCrypto()) {
		t.Errorf("expected %d crypto manifests, got %d", len(testCrypto()), len(ctx.Crypto))
	}
	if ctx.halContract == nil {
		t.Fatal("expected halContract to be loaded")
	}
	if len(ctx.SourceDirs) != 1 {
		t.Errorf("expected deduplicated source dirs, got %v", ctx.SourceDirs)
	}

	in.ChipManifestPath = ""
	in.ArchDir = ""
	in.DriverDirs = nil
	in.CryptoDirs = nil
	ctx, err = Load(in, NopLogger{})
	if err != nil || ctx.Chip != nil || ctx.Arch != nil || len(ctx.Drivers) != 0 || len(ctx.Crypto) != 0 {
		t.Fatalf("expected optional chip/arch manifest and drivers/crypto to be absent, got chip=%v arch=%v drivers=%d crypto=%d err=%v",
			ctx.Chip, ctx.Arch, len(ctx.Drivers), len(ctx.Crypto), err)
	}

	// Auto-discover hal_contract.json from SourceDirs (<dir>/hal_contract.json and <dir>/core/hal_contract.json) when CoreDir == "".
	contractBytes, err := os.ReadFile(filepath.Join(testCoreDir(t), halContractFile))
	if err != nil {
		t.Fatal(err)
	}
	inAuto := writeFixtureInputs(t, testHardware(t))
	inAuto.CoreDir = ""
	writeTempFile(t, filepath.Join(inAuto.SourceDirs[0], "core"), halContractFile, string(contractBytes))
	if _, err := Load(inAuto, NopLogger{}); err != nil {
		t.Fatalf("expected hal_contract.json auto-discovery from <SourceDir>/core/hal_contract.json, got %v", err)
	}
}

func TestLoadErrors(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(t *testing.T, in *Inputs) Logger
		wantErr string
	}{
		{"nil logger", func(*testing.T, *Inputs) Logger { return nil }, "logger must not be nil"},
		{"nil device", func(_ *testing.T, in *Inputs) Logger { in.Device = nil; return NopLogger{} }, "Device must not be nil"},
		{"no hardware path", func(_ *testing.T, in *Inputs) Logger { in.HardwarePath = ""; return NopLogger{} }, "HardwarePath"},
		{"no out dir", func(_ *testing.T, in *Inputs) Logger { in.OutDir = ""; return NopLogger{} }, "OutDir"},
		{"no source dirs", func(_ *testing.T, in *Inputs) Logger { in.SourceDirs = []string{""}; return NopLogger{} }, "SourceDirs"},
		{"missing source dir", func(_ *testing.T, in *Inputs) Logger {
			in.SourceDirs = append(in.SourceDirs, filepath.Join(in.OutDir, "absent"))
			return NopLogger{}
		}, "source directory"},
		{"source dir is file", func(_ *testing.T, in *Inputs) Logger {
			in.SourceDirs = []string{in.HardwarePath}
			return NopLogger{}
		}, "is not a directory"},
		{"missing hardware", func(_ *testing.T, in *Inputs) Logger {
			in.HardwarePath += ".missing"
			return NopLogger{}
		}, "hardware description"},
		{"missing chip manifest", func(_ *testing.T, in *Inputs) Logger {
			in.ChipManifestPath += ".missing"
			return NopLogger{}
		}, "chip manifest"},
		{"malformed chip manifest", func(t *testing.T, in *Inputs) Logger {
			t.Helper()
			writeTempFile(t, filepath.Dir(in.ChipManifestPath), filepath.Base(in.ChipManifestPath), "{broken")
			return NopLogger{}
		}, "chip manifest"},
		{"driver dir without manifest", func(t *testing.T, in *Inputs) Logger {
			t.Helper()
			in.DriverDirs = append(in.DriverDirs, t.TempDir())
			return NopLogger{}
		}, "driver manifest"},
		{"driver without trait", func(t *testing.T, in *Inputs) Logger {
			t.Helper()
			dir := t.TempDir()
			writeTempFile(t, dir, driverManifestFile, `{"name": "anonymous"}`)
			in.DriverDirs = append(in.DriverDirs, dir)
			return NopLogger{}
		}, "does not declare a 'trait'"},
		{"trait bound twice", func(t *testing.T, in *Inputs) Logger {
			t.Helper()
			dir := t.TempDir()
			writeTempFile(t, dir, driverManifestFile, `{"name": "second_flash", "trait": "flash"}`)
			in.DriverDirs = append(in.DriverDirs, dir)
			return NopLogger{}
		}, "trait 'flash' is bound twice"},
		{"arch dir without manifest", func(t *testing.T, in *Inputs) Logger {
			t.Helper()
			in.ArchDir = t.TempDir()
			return NopLogger{}
		}, "arch manifest"},
		{"arch manifest name mismatch", func(t *testing.T, in *Inputs) Logger {
			t.Helper()
			dir := t.TempDir()
			writeTempFile(t, dir, archManifestFile, `{"name": "xtensa", "version": "1.0.0"}`)
			in.ArchDir = dir
			return NopLogger{}
		}, "chip_manifest.json requires 'riscv32'"},
		{"missing hal_contract.json", func(_ *testing.T, in *Inputs) Logger {
			in.CoreDir = ""
			return NopLogger{}
		}, "hal_contract.json not found"},
		{"unknown field in hal_contract.json", func(t *testing.T, in *Inputs) Logger {
			t.Helper()
			dir := t.TempDir()
			writeTempFile(t, dir, halContractFile, `{"schema_version": 1, "unknown_key": true}`)
			in.CoreDir = dir
			return NopLogger{}
		}, "HAL contract"},
		{"unknown field in crypto_manifest.json", func(t *testing.T, in *Inputs) Logger {
			t.Helper()
			dir := t.TempDir()
			writeTempFile(t, dir, cryptoManifestFile, `{"name": "bad_crypto", "category": ["backend"], "unknown_field": 1}`)
			in.CryptoDirs = append(in.CryptoDirs, dir)
			return NopLogger{}
		}, "crypto manifest"},
		{"unknown field in crypto footprint", func(t *testing.T, in *Inputs) Logger {
			t.Helper()
			dir := t.TempDir()
			writeTempFile(t, dir, cryptoManifestFile, `{"name": "bad_fp", "category": ["backend"], "footprint": {"flash_bytes": 100, "extra": 2}}`)
			in.CryptoDirs = append(in.CryptoDirs, dir)
			return NopLogger{}
		}, "crypto manifest"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := writeFixtureInputs(t, testHardware(t))
			log := c.mutate(t, &in)
			ctx, err := Load(in, log)
			if err == nil || ctx != nil {
				t.Fatalf("expected error containing %q, got ctx=%v err=%v", c.wantErr, ctx, err)
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("expected error containing %q, got %v", c.wantErr, err)
			}
		})
	}
}

func TestLoadDoesNotCreateOutDir(t *testing.T) {
	in := writeFixtureInputs(t, testHardware(t))
	if _, err := Load(in, NopLogger{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(in.OutDir); !os.IsNotExist(err) {
		t.Errorf("Load must not touch the output directory, stat err = %v", err)
	}
}
