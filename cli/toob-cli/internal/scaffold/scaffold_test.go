package scaffold

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/toob-boot/toob/internal/manifest"
)

func TestGenerateDeviceToml_SanitizesLegacyTemplateFields(t *testing.T) {
	chipDir := t.TempDir()
	projDir := t.TempDir()

	legacyTmpl := `name = "TestDevice"
version = "v1.0.0"

[identity]
vendor_id = 0x0001
product_id = 0x0042
hw_rev = 1

[device]
chip = "esp32c6"

[build]
compiler = "riscv32-esp-elf"
core_sdk = "core/v0.1.0"
registry = "https://github.com/toob-boot/toob-registry"

[partitions]
stage0_size = 32768
stage1_size = 131072
app_size = 393216
wal_sectors = 4
`
	if err := os.WriteFile(filepath.Join(chipDir, "template_device.toml"), []byte(legacyTmpl), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := GenerateDeviceTomlFromChipDir(chipDir, projDir, "my-smart-sensor", "esp32c6"); err != nil {
		t.Fatalf("GenerateDeviceTomlFromChipDir failed: %v", err)
	}

	tomlPath := filepath.Join(projDir, "device.toml")
	dt, err := manifest.ParseToml(tomlPath)
	if err != nil {
		t.Fatalf("ParseToml failed on sanitized device.toml: %v", err)
	}
	if dt.Name != "my-smart-sensor" {
		t.Fatalf("expected dt.Name == 'my-smart-sensor', got %q", dt.Name)
	}
	if dt.Build.Compiler != "" {
		t.Fatalf("expected non-semver build.compiler to be stripped, got %q", dt.Build.Compiler)
	}
	if dt.Build.CoreSDK != "" {
		t.Fatalf("expected legacy build.core_sdk='core/v0.1.0' to be stripped, got %q", dt.Build.CoreSDK)
	}
	if dt.Build.Registry != "" {
		t.Fatalf("expected legacy github build.registry URL to be stripped, got %q", dt.Build.Registry)
	}
}

func TestGenerateDeviceToml_DeclarativeCustomVendorChip(t *testing.T) {
	chipDir := t.TempDir()
	projDir := t.TempDir()

	chipManifest := `{
		"name": "@acme/custom_m33",
		"author": "acme",
		"arch": "cortex-m",
		"compiler_prefix": "arm-none-eabi-",
		"version": "1.0.0",
		"min_core_sdk": "1.0.0",
		"min_compiler": "13.2.0",
		"slot_capabilities": {
			"exec_model": "fixed",
			"slot_count": 2,
			"has_scratch": true,
			"max_erase_cycles": 100000
		},
		"hal_bindings": {
			"flash": "acme_flash",
			"wdt": "acme_wdt",
			"clock": "acme_clk",
			"keystore": "acme_otp",
			"entropy": "acme_trng"
		},
		"sources": {
			"hardware": "hardware.json"
		},
		"recovery": {
			"console": "acme_uart",
			"flash": "acme_flash",
			"crypto": {
				"backend": "none",
				"hash": "sha256_sw"
			}
		}
	}`
	hwJSON := `{
		"chip_family": "acme_m33",
		"flash": {
			"size": 1048576,
			"write_alignment": 8,
			"app_alignment": 4096,
			"base": "0x08000000",
			"xip_base": "0x08000000",
			"regions": [
				{"type": "writable", "base": 134217728, "sector_size": 4096, "count": 256}
			]
		},
		"crypto_capabilities": {
			"aes": {"hw_present": false, "boot_usable": false},
			"ed25519": {"hw_present": false, "boot_usable": false},
			"rng": {"hw_present": true, "boot_usable": true},
			"sha256": {"hw_present": false, "boot_usable": false},
			"pka": {"hw_present": false, "boot_usable": false},
			"arena_size": 4096
		},
		"memory": {
			"iram_base": "0x20000000",
			"iram_size": "0x00020000"
		},
		"constants": {}
	}`
	if err := os.WriteFile(filepath.Join(chipDir, "chip_manifest.json"), []byte(chipManifest), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(chipDir, "hardware.json"), []byte(hwJSON), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := GenerateDeviceTomlFromChipDir(chipDir, projDir, "acme-gateway", "@acme/custom_m33"); err != nil {
		t.Fatalf("declarative GenerateDeviceTomlFromChipDir failed: %v", err)
	}

	dt, err := manifest.ParseToml(filepath.Join(projDir, "device.toml"))
	if err != nil {
		t.Fatalf("ParseToml failed: %v", err)
	}
	if dt.Name != "acme-gateway" || dt.Device.Chip != "@acme/custom_m33" {
		t.Fatalf("unexpected identity/chip in generated device.toml: name=%q chip=%q", dt.Name, dt.Device.Chip)
	}
	if dt.Recovery.Crypto.Justification == "" {
		t.Fatal("expected unsigned recovery justification to be populated automatically")
	}
}

func TestGenerateDeviceToml_All13OfficialChipsCompileManifest(t *testing.T) {
	pkgsDir := filepath.Clean(filepath.Join("..", "..", "..", "..", "toob-infra", "registry", "packages"))
	chipsRoot := filepath.Join(pkgsDir, "chips")
	coreDir := filepath.Clean(filepath.Join("..", "..", "..", "..", "toobloader", "core"))
	bootDir := filepath.Clean(filepath.Join("..", "..", "..", "..", "toobloader"))
	if _, err := os.Stat(chipsRoot); err != nil {
		t.Skipf("monorepo registry chips directory not present at %s", chipsRoot)
	}

	entries, err := os.ReadDir(chipsRoot)
	if err != nil {
		t.Fatal(err)
	}
	chipCount := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		chipCount++
		chipName := entry.Name()
		chipSrcDir := filepath.Join(chipsRoot, chipName)

		t.Run(chipName+"_default", func(t *testing.T) {
			projDir := t.TempDir()
			if err := GenerateDeviceTomlFromChipDir(chipSrcDir, projDir, "proj-"+chipName, chipName); err != nil {
				t.Fatalf("GenerateDeviceTomlFromChipDir(%s) failed: %v", chipName, err)
			}
			dt, pErr := manifest.ParseToml(filepath.Join(projDir, "device.toml"))
			if pErr != nil {
				t.Fatalf("ParseToml(%s) failed: %v", chipName, pErr)
			}
			if dt.Name != "proj-"+chipName {
				t.Fatalf("expected dt.Name == %q, got %q", "proj-"+chipName, dt.Name)
			}
			if dt.Build.CoreSDK == "core/v0.1.0" || strings.Contains(dt.Build.Registry, "github.com") {
				t.Fatalf("legacy build pins leaked into %s device.toml: %+v", chipName, dt.Build)
			}
			if dt.Build.Compiler != "" && !isValidCompilerSemver(dt.Build.Compiler) {
				t.Fatalf("non-semver build.compiler leaked into %s device.toml: %q", chipName, dt.Build.Compiler)
			}
		})

		t.Run(chipName+"_declarative_without_template", func(t *testing.T) {
			// Copy only chip_manifest.json + hardware.json to force declarative synthesis on all 13 chips.
			synthChipDir := t.TempDir()
			for _, fname := range []string{"chip_manifest.json", "hardware.json"} {
				raw, readErr := os.ReadFile(filepath.Join(chipSrcDir, fname))
				if readErr != nil {
					t.Fatal(readErr)
				}
				if writeErr := os.WriteFile(filepath.Join(synthChipDir, fname), raw, 0o644); writeErr != nil {
					t.Fatal(writeErr)
				}
			}
			projDir := t.TempDir()
			if err := GenerateDeviceTomlFromChipDir(synthChipDir, projDir, "decl-"+chipName, chipName); err != nil {
				t.Fatalf("declarative GenerateDeviceTomlFromChipDir(%s) failed: %v", chipName, err)
			}
			verifyGeneratedChipLayout(t, projDir, synthChipDir, pkgsDir, coreDir, bootDir, chipName)
		})
	}
	if chipCount < 13 {
		t.Fatalf("expected at least 13 official chips, found %d", chipCount)
	}
}

func verifyGeneratedChipLayout(t *testing.T, projDir, chipDir, pkgsDir, coreDir, bootDir, chipName string) {
	t.Helper()
	dt, err := manifest.ParseToml(filepath.Join(projDir, "device.toml"))
	if err != nil {
		t.Fatalf("ParseToml(%s) failed: %v", chipName, err)
	}
	if dt.Build.CoreSDK == "core/v0.1.0" || strings.Contains(dt.Build.Registry, "github.com") {
		t.Fatalf("legacy build pins leaked into %s device.toml: %+v", chipName, dt.Build)
	}

	cmPath := filepath.Join(chipDir, "chip_manifest.json")
	if rawCM, rErr := os.ReadFile(cmPath); rErr == nil {
		var rawMap map[string]any
		if json.Unmarshal(rawCM, &rawMap) == nil {
			if _, hasCF := rawMap["compiler_flags"]; hasCF {
				delete(rawMap, "compiler_flags")
				if cleaned, mErr := json.Marshal(rawMap); mErr == nil {
					tmpCM := filepath.Join(projDir, "chip_manifest_compat.json")
					if os.WriteFile(tmpCM, cleaned, 0o644) == nil {
						cmPath = tmpCM
					}
				}
			}
		}
	}
	hwPath := filepath.Join(chipDir, "hardware.json")
	outDir := filepath.Join(projDir, "gen")

	// Provide a synthetic C consumer stub for any hardware.json flat-register constants
	// whose driver files may be under concurrent registry refactoring.
	stubSrcDir := filepath.Join(projDir, "src_stub")
	_ = os.MkdirAll(stubSrcDir, 0o755)
	_ = os.WriteFile(filepath.Join(stubSrcDir, "macro_ref.c"), []byte("/* CHIP_REG_FLASH_XIP_BASE */\n#ifdef CHIP_REG_FLASH_XIP_BASE\ntypedef int use_xip_base_t;\n#endif\n"), 0o644)

	sdkDir := filepath.Clean(filepath.Join("..", "..", "..", "..", "sdk"))
	mctx, err := manifest.LoadSilent(manifest.Inputs{
		Device:           dt,
		HardwarePath:     hwPath,
		ChipManifestPath: cmPath,
		CoreDir:          coreDir,
		SourceDirs:       []string{bootDir, sdkDir, stubSrcDir, filepath.Join(pkgsDir, "chips", chipName), pkgsDir},
		OutDir:           outDir,
	})
	if err != nil {
		t.Fatalf("manifest.LoadSilent(%s) failed: %v", chipName, err)
	}
	res, err := manifest.Generate(mctx)
	if err != nil {
		t.Fatalf("manifest.Generate(%s) failed: %v", chipName, err)
	}
	if res == nil || res.Layout == nil || res.Layout.App.Budget == 0 {
		t.Fatalf("unexpected empty layout for %s", chipName)
	}
}

func TestCopyOrRenderScaffoldTree_TemplateSafetyAndExecBits(t *testing.T) {
	srcDir := t.TempDir()
	dstDir := filepath.Join(t.TempDir(), "toob_integration")

	// 1. Non-.tmpl C and Python files containing '{{...}}' must NOT be parsed by text/template!
	rawC := "int matrix[1][1] = {{0}};\n/* {{.Cache.Sync true true}} */\n"
	rawPy := "#!/usr/bin/env python3\nprint(f'{{not_a_go_template}}')\n"
	rawTmpl := "# Project {{.ProjectName}} on {{.ChipName}} ({{.Arch}})\n"

	if err := os.WriteFile(filepath.Join(srcDir, "glue.c"), []byte(rawC), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "pack.py"), []byte(rawPy), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "GUIDE.md.tmpl"), []byte(rawTmpl), 0o644); err != nil {
		t.Fatal(err)
	}

	td := TemplateData{
		ProjectName: "demo-app",
		ChipName:    "esp32c6",
		Arch:        "riscv32",
	}
	if err := CopyOrRenderScaffoldTree(srcDir, dstDir, td); err != nil {
		t.Fatalf("CopyOrRenderScaffoldTree failed: %v", err)
	}

	gotC, err := os.ReadFile(filepath.Join(dstDir, "glue.c"))
	if err != nil || string(gotC) != rawC {
		t.Fatalf("non-.tmpl C file was mutated or missing: %q (err=%v)", string(gotC), err)
	}
	gotPy, err := os.ReadFile(filepath.Join(dstDir, "pack.py"))
	if err != nil || string(gotPy) != rawPy {
		t.Fatalf("non-.tmpl Python file was mutated or missing: %q (err=%v)", string(gotPy), err)
	}
	if runtime.GOOS != "windows" {
		st, statErr := os.Stat(filepath.Join(dstDir, "pack.py"))
		if statErr != nil || st.Mode()&0o111 == 0 {
			t.Fatalf("expected executable bit preserved on pack.py, got mode %v", st.Mode())
		}
	}

	if _, statErr := os.Stat(filepath.Join(dstDir, "GUIDE.md.tmpl")); !os.IsNotExist(statErr) {
		t.Fatal("expected .tmpl suffix to be stripped on destination")
	}
	gotGuide, err := os.ReadFile(filepath.Join(dstDir, "GUIDE.md"))
	if err != nil || string(gotGuide) != "# Project demo-app on esp32c6 (riscv32)\n" {
		t.Fatalf("unexpected rendered GUIDE.md: %q (err=%v)", string(gotGuide), err)
	}

	// 2. A malicious .tmpl attempting SSTI via {{.Cache}} must fail closed!
	sstiDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(sstiDir, "evil.md.tmpl"), []byte("{{.Cache.Dir}}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := CopyOrRenderScaffoldTree(sstiDir, t.TempDir(), td); err == nil {
		t.Fatal("expected .tmpl referencing {{.Cache}} to fail against pure TemplateData")
	}
}
