package build

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestParseToml(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. Valid TOML
	validToml := `
name = "prod-device"
version = "2.1.0"

[identity]
vendor_id = 0x0001
product_id = 0x0042
hw_rev = 1

[device]
chip = "esp32c6"

[build]
compiler = "riscv32-esp-elf-gcc"
core_sdk = "core/v0.1.0"
registry = "https://registry.toob.io"

[partitions]
stage0_size = 16384
stage1_size = 65536
app_size = 524288
wal_sectors = 4
enable_deltas = true

[boot_config]
max_retries = 3
wdt_timeout_ms = 5000
transport_provider = "pointer"
`
	validPath := writeTempFile(t, tmpDir, "valid.toml", validToml)
	dt, err := ParseToml(validPath)
	if err != nil {
		t.Fatalf("ParseToml valid failed: %v", err)
	}
	if dt.Name != "prod-device" || dt.Device.Chip != "esp32c6" || dt.Partitions.AppSize != 524288 ||
		dt.Identity.VendorID != 0x0001 || dt.Identity.ProductID != 0x0042 || dt.Identity.HwRev != 1 {
		t.Errorf("parsed TOML values incorrect: %+v", dt)
	}

	// 2. Strictness check: unknown field MUST be rejected with TOML_STRICT
	unknownFieldToml := validToml + "\nunknown_custom_field = 42\n"
	strictPath := writeTempFile(t, tmpDir, "strict.toml", unknownFieldToml)
	_, err = ParseToml(strictPath)
	if err == nil {
		t.Fatal("expected ParseToml with unknown field to fail, got nil")
	}
	if !strings.Contains(err.Error(), "TOML_STRICT") {
		t.Errorf("expected error to mention TOML_STRICT, got %v", err)
	}

	// 3. Syntax error
	syntaxErrToml := "name = [unclosed array"
	syntaxPath := writeTempFile(t, tmpDir, "syntax.toml", syntaxErrToml)
	_, err = ParseToml(syntaxPath)
	if err == nil {
		t.Fatal("expected syntax error to fail, got nil")
	}
}

func TestParseHardwareJSON(t *testing.T) {
	tmpDir := t.TempDir()
	jsonPath := writeTempFile(t, tmpDir, "hw.json", `{
		"chip_family": "esp32c6",
		"flash": {
			"size": 4194304,
			"write_alignment": 4,
			"regions": [
				{"type": "writable", "base": 0, "sector_size": 4096, "count": 1024}
			]
		},
		"crypto_capabilities": {"arena_size": 8192},
		"memory": {"iram_base": "0x40800000", "iram_size": "0x00080000"},
		"constants": {"cpu_freq_hz": 160000000}
	}`)

	hj, err := ParseHardwareJSON(jsonPath)
	if err != nil {
		t.Fatalf("ParseHardwareJSON failed: %v", err)
	}
	if hj.ChipFamily != "esp32c6" || hj.Flash.Size != 4194304 || len(hj.Flash.Regions) != 1 {
		t.Errorf("unexpected parsed values: %+v", hj)
	}

	if _, err := ParseHardwareJSON(filepath.Join(tmpDir, "missing.json")); err == nil {
		t.Fatal("expected error on missing json, got nil")
	}
	corrupt := writeTempFile(t, tmpDir, "corrupt.json", "{invalid json")
	if _, err := ParseHardwareJSON(corrupt); err == nil || !strings.Contains(err.Error(), "failed to parse") {
		t.Fatalf("expected parse error on corrupted json, got %v", err)
	}
}

func TestParseHardwareJSONStrictness(t *testing.T) {
	dir := t.TempDir()
	const valid = `{"chip_family": "x", "constants": {}}`
	cases := []struct {
		name    string
		content string
		wantErr string // empty = must pass
	}{
		{"valid", valid, ""},
		{"unknown top-level key", `{"chip_family": "x", "chip_famly": "typo"}`, `unknown field "chip_famly"`},
		{"unknown nested key", `{"flash": {"sise": 4096}}`, `unknown field "sise"`},
		{"unknown region key", `{"flash": {"regions": [{"type": "writable", "bse": 0}]}}`, `unknown field "bse"`},
		{"trailing data", valid + ` {}`, "unexpected data"},
		{"empty file", ``, "failed to parse"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := writeTempFile(t, dir, "hw_"+strings.ReplaceAll(c.name, " ", "_")+".json", c.content)
			_, err := ParseHardwareJSON(path)
			if c.wantErr == "" {
				if err != nil {
					t.Fatalf("expected success, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("expected error containing %q, got %v", c.wantErr, err)
			}
		})
	}
}

func TestStrictManifestDecoding(t *testing.T) {
	dir := t.TempDir()
	chip, err := decodeJSONFile[ChipManifest](writeTempFile(t, dir, "chip.json", `{"name": "c", "future_key": 1}`), false)
	if err != nil || chip.Name != "c" {
		t.Fatalf("lax decoding must ignore unknown keys, got %+v (%v)", chip, err)
	}
	if _, err := decodeJSONFile[ChipManifest](writeTempFile(t, dir, "chip_strict.json", `{"name": "c", "future_key": 1}`), true); err == nil {
		t.Fatal("strict decoding must reject unknown keys on chip_manifest.json")
	}

	regRoot := filepath.Join("..", "..", "toob-infra", "registry", "packages")
	chipMatches, _ := filepath.Glob(filepath.Join(regRoot, "chips", "*", "chip_manifest.json"))
	for _, p := range chipMatches {
		if _, err := decodeJSONFile[ChipManifest](p, true); err != nil {
			t.Errorf("strict ChipManifest decode failed for %s: %v", p, err)
		}
	}
	drvMatches, _ := filepath.Glob(filepath.Join(regRoot, "drivers", "*", "*", "driver_manifest.json"))
	for _, p := range drvMatches {
		if _, err := decodeJSONFile[DriverManifest](p, true); err != nil {
			t.Errorf("strict DriverManifest decode failed for %s: %v", p, err)
		}
	}
}

// TestRegistryHardwareJSON parses and validates the shipped chip data so that
// schema drift between the registry and this library surfaces here.
func TestRegistryHardwareJSON(t *testing.T) {
	matches, err := filepath.Glob(filepath.Join("..", "..", "toob-infra", "registry", "packages", "chips", "*", "hardware.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) == 0 {
		t.Skip("toob-infra registry is not checked out next to this module")
	}
	for _, path := range matches {
		t.Run(filepath.Base(filepath.Dir(path)), func(t *testing.T) {
			hw, err := ParseHardwareJSON(path)
			if err != nil {
				t.Fatalf("strict parse failed: %v", err)
			}
			ctx := &Context{Inputs: Inputs{Device: testDevice()}, Hardware: hw}
			for name, rule := range map[string]contextRule{
				"flash geometry": checkFlashGeometry,
				"memory":         checkMemory,
				"reset causes":   checkResetCauses,
			} {
				if err := rule(ctx); err != nil {
					t.Errorf("%s: %v", name, err)
				}
			}
		})
	}
}
