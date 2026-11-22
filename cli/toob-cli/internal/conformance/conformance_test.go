package conformance

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEmbeddedHalContractMatchesMonorepoSSoT(t *testing.T) {
	ssotPath := filepath.Clean(filepath.Join("..", "..", "..", "..", "toobloader", "core", "hal_contract.json"))
	ssotBytes, err := os.ReadFile(ssotPath)
	if os.IsNotExist(err) {
		t.Skipf("monorepo hal_contract.json not present at %s (standalone mode)", ssotPath)
	}
	if err != nil {
		t.Fatalf("failed reading %s: %v", ssotPath, err)
	}
	normSSoT := bytes.ReplaceAll(ssotBytes, []byte("\r\n"), []byte("\n"))
	normEmbed := bytes.ReplaceAll(embeddedHalContractJSON, []byte("\r\n"), []byte("\n"))
	if !bytes.Equal(normSSoT, normEmbed) {
		t.Fatalf("embedded hal_contract_embed.json drifted from %s", ssotPath)
	}
}

func TestAuditPackage_DynamicHalContractAndABIVersionValidation(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "ks.h"), []byte("#ifndef KS_H\n#define KS_H\n#endif\n"), 0o644)
	// keystore requires abi_version v3 in hal_contract.json -> v2 must fail!
	_ = os.WriteFile(filepath.Join(dir, "driver_manifest.json"), []byte(`{
		"name": "wrong_abi_ks",
		"trait": "keystore",
		"abi_version": "v2",
		"headers": ["ks.h"],
		"symbols": {
			"read_pubkey": "ks_read_pubkey",
			"read_dslc": "ks_read_dslc",
			"write_dslc": "ks_write_dslc",
			"read_monotonic": "ks_read_monotonic",
			"advance_monotonic": "ks_advance_monotonic"
		}
	}`), 0o644)

	report, err := AuditPackage(dir)
	if err != nil {
		t.Fatalf("AuditPackage unexpected error: %v", err)
	}
	if report.Passed {
		t.Fatal("expected keystore driver with abi_version v2 (instead of v3) to fail")
	}

	// Verify custom ContractPath dynamically drives required methods & ABI version.
	customContract := filepath.Join(t.TempDir(), "custom_hal_contract.json")
	_ = os.WriteFile(customContract, []byte(`{
		"schema_version": 1,
		"platform_struct_type": "boot_platform_t",
		"platform_init_symbol": "boot_platform_init",
		"bringup_function": "boot_platform_bringup",
		"bringup_step_type": "bringup_step_t",
		"core_headers": ["boot_hal.h"],
		"arch": {"required_symbols": ["disable_interrupts"]},
		"traits": [{
			"name": "custom_sensor",
			"platform_field": "sensor",
			"binding_mode": "struct",
			"struct_type": "sensor_hal_t",
			"abi_version": "v4",
			"optional": true,
			"instantiate_when": "driver_bound",
			"driver_traits": ["custom_sensor"],
			"methods": [
				{"field": "sample", "source": "driver", "key": "sample_now", "required": true}
			]
		}]
	}`), 0o644)

	customPkg := t.TempDir()
	_ = os.WriteFile(filepath.Join(customPkg, "sensor.h"), []byte("#ifndef S_H\n#define S_H\n#endif\n"), 0o644)
	_ = os.WriteFile(filepath.Join(customPkg, "driver_manifest.json"), []byte(`{
		"name": "my_sensor",
		"trait": "custom_sensor",
		"abi_version": "v4",
		"headers": ["sensor.h"],
		"symbols": {"sample_now": "my_sensor_sample"}
	}`), 0o644)

	dynReport, err := AuditPackageWithOptions(customPkg, AuditOptions{ContractPath: customContract})
	if err != nil {
		t.Fatalf("AuditPackageWithOptions failed: %v", err)
	}
	if !dynReport.Passed {
		t.Fatalf("expected custom HAL contract package to pass, checks: %+v", dynReport.Checks)
	}
}

func TestAuditPackage_MultipleManifestsRejectedAndAll8CategoriesSupported(t *testing.T) {
	// 1. Multiple manifests at root -> rejected!
	multiDir := t.TempDir()
	_ = os.WriteFile(filepath.Join(multiDir, "driver_manifest.json"), []byte(`{"name":"a"}`), 0o644)
	_ = os.WriteFile(filepath.Join(multiDir, "soc_manifest.json"), []byte(`{"name":"b","version":"1.0.0"}`), 0o644)
	if _, err := AuditPackage(multiDir); err == nil || !strings.Contains(err.Error(), "multiple manifests") {
		t.Fatalf("expected multiple manifests error, got %v", err)
	}

	// 2. SoC package category
	socDir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(socDir, "include"), 0o755)
	_ = os.WriteFile(filepath.Join(socDir, "include", "soc_common.h"), []byte("#ifndef SOC_H\n#define SOC_H\n#endif\n"), 0o644)
	_ = os.WriteFile(filepath.Join(socDir, "bootrom_image.json"), []byte(`{"layout":"flat"}`), 0o644)
	_ = os.WriteFile(filepath.Join(socDir, "soc_manifest.json"), []byte(`{
		"name": "my_soc",
		"version": "1.0.0",
		"license": "Apache-2.0",
		"headers": ["soc_common.h"],
		"includes": ["include"],
		"bootrom_image": "bootrom_image.json"
	}`), 0o644)
	if rep, err := AuditPackage(socDir); err != nil || !rep.Passed {
		t.Fatalf("soc_manifest.json failed: err=%v checks=%+v", err, rep)
	}

	// 3. Integration package category
	intDir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(intDir, "files"), 0o755)
	_ = os.WriteFile(filepath.Join(intDir, "files", "hooks.c"), []byte("void hook_init(void) {}\n"), 0o644)
	_ = os.WriteFile(filepath.Join(intDir, "integration_manifest.json"), []byte(`{
		"name": "custom_rtos",
		"version": "1.0.0",
		"author": "team",
		"description": "Custom RTOS integration"
	}`), 0o644)
	if rep, err := AuditPackage(intDir); err != nil || !rep.Passed {
		t.Fatalf("integration_manifest.json failed: err=%v checks=%+v", err, rep)
	}

	// 4. Toolchain package category
	tcDir := t.TempDir()
	_ = os.WriteFile(filepath.Join(tcDir, "toolchain.cmake"), []byte("set(CMAKE_SYSTEM_NAME Generic)\n"), 0o644)
	_ = os.WriteFile(filepath.Join(tcDir, "toolchain_manifest.json"), []byte(`{
		"author": "arm",
		"version": "15.2.1",
		"upstream_version": "15.2.1",
		"license": "GPL-3.0",
		"urls": {"linux_amd64": "https://example.com/tc.tar.gz"},
		"sha256": {"linux_amd64": "5be906a5194c3173e145a58048e5607ffff947773237802b93e55e23c415f1b6"}
	}`), 0o644)
	if rep, err := AuditPackage(tcDir); err != nil || !rep.Passed {
		t.Fatalf("toolchain_manifest.json failed: err=%v checks=%+v", err, rep)
	}

	// 5. Port package category
	portDir := t.TempDir()
	_ = os.WriteFile(filepath.Join(portDir, "port.h"), []byte("#ifndef PORT_H\n#define PORT_H\n#endif\n"), 0o644)
	_ = os.WriteFile(filepath.Join(portDir, "port.c"), []byte("void port_entry(void) {}\n"), 0o644)
	_ = os.WriteFile(filepath.Join(portDir, "port_manifest.json"), []byte(`{
		"name": "@vendor/board_port",
		"version": "1.0.0",
		"chip": "esp32c6",
		"arch": "riscv32",
		"headers": ["port.h"],
		"sources": ["port.c"],
		"symbols": {"entry": "port_entry"}
	}`), 0o644)
	if rep, err := AuditPackage(portDir); err != nil || !rep.Passed {
		t.Fatalf("port_manifest.json failed: err=%v checks=%+v", err, rep)
	}
}

func TestStrictUnknownFieldsAndPermittedExtendedFields(t *testing.T) {
	// Unknown field in manifest must fail decoding immediately.
	badDir := t.TempDir()
	_ = os.WriteFile(filepath.Join(badDir, "driver_manifest.json"), []byte(`{
		"name": "typo_drv",
		"trait": "entropy",
		"abi_version": "v3",
		"headders_typo": ["a.h"]
	}`), 0o644)
	if _, err := AuditPackage(badDir); err == nil {
		t.Fatal("expected DisallowUnknownFields to reject unknown key 'headders_typo'")
	}

	// Permitted extended metadata + both string and []string chip_binding must succeed!
	for _, bindingJSON := range []string{`"esp32c6"`, `["esp32c6", "esp32h2"]`} {
		dir := t.TempDir()
		_ = os.WriteFile(filepath.Join(dir, "drv.h"), []byte("#ifndef DRV_H\n#define DRV_H\n#endif\n"), 0o644)
		_ = os.WriteFile(filepath.Join(dir, "drv.c"), []byte("int drv_random(void) { return 0; }\n"), 0o644)
		_ = os.WriteFile(filepath.Join(dir, "driver_manifest.json"), []byte(`{
			"name": "@acme/trng",
			"version": "1.0.0",
			"trait": "entropy",
			"abi_version": "v3",
			"license": "MIT",
			"repository": "https://example.com/repo",
			"keywords": ["trng", "security"],
			"min_core_sdk": "1.0.0",
			"compiler_flags": ["-Os"],
			"chip_binding": `+bindingJSON+`,
			"reference_build_context": {
				"chip": "esp32c6",
				"core_sdk_version": "1.0.0",
				"toolchain_version": "13.2.0",
				"target_architecture": "riscv32"
			},
			"headers": ["drv.h"],
			"sources": ["drv.c"],
			"symbols": {"random": "drv_random"}
		}`), 0o644)

		rep, err := AuditPackage(dir)
		if err != nil {
			t.Fatalf("AuditPackage failed for chip_binding=%s: %v", bindingJSON, err)
		}
		if !rep.Passed {
			t.Fatalf("expected driver with extended metadata to pass, checks: %+v", rep.Checks)
		}
	}
}

func TestAuditPackage_MissingSymbols_Negative(t *testing.T) {
	tmpDir := t.TempDir()
	manifestContent := `{
		"name": "broken_flash",
		"trait": "flash",
		"abi_version": "v2",
		"symbols": {
			"init": "broken_init"
		}
	}`
	if err := os.WriteFile(filepath.Join(tmpDir, "driver_manifest.json"), []byte(manifestContent), 0o644); err != nil {
		t.Fatalf("failed to write dummy manifest: %v", err)
	}

	report, err := AuditPackage(tmpDir)
	if err != nil {
		t.Fatalf("AuditPackage unexpected error: %v", err)
	}
	if report.Passed {
		t.Errorf("expected report.Passed == false for driver missing required symbols")
	}

	foundContractFail := false
	for _, chk := range report.Checks {
		if chk.Name == "Trait Symbol Contract" && !chk.Passed {
			foundContractFail = true
		}
	}
	if !foundContractFail {
		t.Errorf("expected Trait Symbol Contract check failure, got passes only")
	}
}

func TestMockEquivalence_NilWhenNoMocks_AndSignatureParserPrecision(t *testing.T) {
	// 1. Single production target with NO mock files -> MockEquivalence MUST be nil!
	noMockDir := t.TempDir()
	_ = os.WriteFile(filepath.Join(noMockDir, "rng.h"), []byte("#ifndef RNG_H\n#define RNG_H\n#endif\n"), 0o644)
	_ = os.WriteFile(filepath.Join(noMockDir, "rng.c"), []byte("boot_status_t rng_random(uint8_t *buf, size_t len) { return BOOT_OK; }\n"), 0o644)
	_ = os.WriteFile(filepath.Join(noMockDir, "driver_manifest.json"), []byte(`{
		"name": "prod_only_rng",
		"trait": "entropy",
		"abi_version": "v3",
		"headers": ["rng.h"],
		"sources": ["rng.c"],
		"symbols": {"random": "rng_random"}
	}`), 0o644)

	noMockRep, err := AuditPackage(noMockDir)
	if err != nil {
		t.Fatalf("AuditPackage failed: %v", err)
	}
	if !noMockRep.Passed {
		t.Fatalf("expected prod_only_rng to pass: %+v", noMockRep.Checks)
	}
	if noMockRep.MockEquivalence != nil {
		t.Fatalf("expected MockEquivalence == nil when no mock files exist, got %+v", noMockRep.MockEquivalence)
	}
	mdPath := filepath.Join(t.TempDir(), "report.md")
	if expErr := ExportReportMarkdown(noMockRep, mdPath); expErr != nil {
		t.Fatal(expErr)
	}
	mdBytes, _ := os.ReadFile(mdPath)
	if strings.Contains(string(mdBytes), "Mock and Real implementation files adhere to identical symbol signatures") {
		t.Fatal("report.md emitted false CRA Mock/Real equivalence attestation when no mock files existed")
	}

	// 2. Arbitrary boot_hal.h types + differing parameter names + static helpers -> PASS!
	eqDir := t.TempDir()
	_ = os.WriteFile(filepath.Join(eqDir, "confirm.h"), []byte("#ifndef C_H\n#define C_H\n#endif\n"), 0o644)
	realCode := `
static uint32_t read_private_hw_reg(void) { return 0U; }
boot_status_t drv_init(void) { (void)read_private_hw_reg(); return BOOT_OK; }
void drv_deinit() {}
bool drv_check_ok(uint64_t expected_nonce) { return expected_nonce != 0ULL; }
const boot_platform_t *drv_get_plat(const confirm_hal_t *confirm_ptr, keystore_hal_t *ks_ptr) { (void)confirm_ptr; (void)ks_ptr; return NULL; }
boot_status_t drv_clear(void) { return BOOT_OK; }
`
	mockCode := `
static uint64_t s_mock_state = 0ULL;
void drv_mock_reset(void) { s_mock_state = 0ULL; }
boot_status_t drv_init() { return BOOT_OK; }
void drv_deinit(void) {}
bool drv_check_ok(uint64_t nonce_arg) { return nonce_arg == s_mock_state; }
const boot_platform_t *drv_get_plat(const confirm_hal_t *a, keystore_hal_t *b) { (void)a; (void)b; return NULL; }
boot_status_t drv_clear(void) { return BOOT_OK; }
`
	_ = os.WriteFile(filepath.Join(eqDir, "confirm_real.c"), []byte(realCode), 0o644)
	_ = os.WriteFile(filepath.Join(eqDir, "confirm_mock.c"), []byte(mockCode), 0o644)
	_ = os.WriteFile(filepath.Join(eqDir, "driver_manifest.json"), []byte(`{
		"name": "eq_confirm",
		"trait": "confirm",
		"abi_version": "v2",
		"headers": ["confirm.h"],
		"sources": ["confirm_real.c"],
		"mock_sources": ["confirm_mock.c"],
		"symbols": {
			"init": "drv_init",
			"deinit": "drv_deinit",
			"check_ok": "drv_check_ok",
			"clear": "drv_clear"
		}
	}`), 0o644)

	eqRep, err := AuditPackage(eqDir)
	if err != nil {
		t.Fatal(err)
	}
	if !eqRep.Passed || eqRep.MockEquivalence == nil || !eqRep.MockEquivalence.Passed {
		t.Fatalf("expected equivalent arbitrary C signatures to pass, checks=%+v mockEq=%+v", eqRep.Checks, eqRep.MockEquivalence)
	}

	// 3. Missing mock function -> FAIL!
	missDir := t.TempDir()
	_ = os.WriteFile(filepath.Join(missDir, "confirm.h"), []byte("#ifndef C_H\n#define C_H\n#endif\n"), 0o644)
	_ = os.WriteFile(filepath.Join(missDir, "confirm_real.c"), []byte(realCode), 0o644)
	_ = os.WriteFile(filepath.Join(missDir, "confirm_mock.c"), []byte(`
boot_status_t drv_init(void) { return BOOT_OK; }
`), 0o644)
	_ = os.WriteFile(filepath.Join(missDir, "driver_manifest.json"), []byte(`{
		"name": "missing_mock_fn",
		"trait": "confirm",
		"abi_version": "v2",
		"headers": ["confirm.h"],
		"sources": ["confirm_real.c"],
		"mock_sources": ["confirm_mock.c"],
		"symbols": {
			"init": "drv_init",
			"deinit": "drv_deinit",
			"check_ok": "drv_check_ok",
			"clear": "drv_clear"
		}
	}`), 0o644)
	missRep, err := AuditPackage(missDir)
	if err != nil {
		t.Fatal(err)
	}
	if missRep.Passed || missRep.MockEquivalence == nil || missRep.MockEquivalence.Passed {
		t.Fatal("expected missing mock functions to fail MockEquivalence")
	}
}

func TestAuditPackage_MockDivergence_Negative(t *testing.T) {
	tmpDir := t.TempDir()
	_ = os.WriteFile(filepath.Join(tmpDir, "drv.h"), []byte("#ifndef D_H\n#define D_H\n#endif\n"), 0o644)
	manifestContent := `{
		"name": "divergent_driver",
		"trait": "entropy",
		"abi_version": "v3",
		"headers": ["drv.h"],
		"symbols": {
			"random": "driver_read_pubkey"
		}
	}`
	if err := os.WriteFile(filepath.Join(tmpDir, "driver_manifest.json"), []byte(manifestContent), 0o644); err != nil {
		t.Fatalf("failed to write dummy manifest: %v", err)
	}

	realC := `boot_status_t driver_read_pubkey(uint8_t *out_pubkey, size_t len) { return 0; }`
	mockC := `void driver_read_pubkey(uint8_t *out_pubkey, size_t len, int extra_arg) { }`

	if err := os.WriteFile(filepath.Join(tmpDir, "driver_real.c"), []byte(realC), 0o644); err != nil {
		t.Fatalf("failed to write real.c: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "driver_mock.c"), []byte(mockC), 0o644); err != nil {
		t.Fatalf("failed to write mock.c: %v", err)
	}

	report, err := AuditPackage(tmpDir)
	if err != nil {
		t.Fatalf("AuditPackage unexpected error: %v", err)
	}
	if report.Passed {
		t.Errorf("expected report.Passed == false due to Mock/Real signature divergence")
	}
	if report.MockEquivalence == nil || report.MockEquivalence.Passed {
		t.Errorf("expected MockEquivalence.Passed == false")
	}
}

func TestExportReports_EscapesPipesAndNewlines(t *testing.T) {
	tmpDir := t.TempDir()
	report := &ConformanceReport{
		PackageName: "test_pkg",
		Trait:       "wdt",
		AbiVersion:  "v2",
		Passed:      false,
		Checks: []ConformanceCheck{
			{Name: "Check | Pipe", Passed: false, Details: "Line 1 | col\nLine 2"},
		},
	}

	jsonPath := filepath.Join(tmpDir, "sub", "conformance_report.json")
	mdPath := filepath.Join(tmpDir, "sub", "conformance_report.md")

	if err := ExportReportJSON(report, jsonPath); err != nil {
		t.Fatalf("ExportReportJSON failed: %v", err)
	}
	if err := ExportReportMarkdown(report, mdPath); err != nil {
		t.Fatalf("ExportReportMarkdown failed: %v", err)
	}

	mdContent, err := os.ReadFile(mdPath)
	if err != nil {
		t.Fatalf("failed to read md report: %v", err)
	}
	mdStr := string(mdContent)
	if !strings.Contains(mdStr, `Check \| Pipe`) || !strings.Contains(mdStr, `Line 1 \| col<br>Line 2`) {
		t.Fatalf("expected Markdown table cells to escape '|' and newlines, got:\n%s", mdStr)
	}
}

func TestLanguagePolicy_AuthorProperNounAllowed_GermanCommentRejected(t *testing.T) {
	// 1. Proper noun in manifest "author" and C copyright header must PASS!
	okDir := t.TempDir()
	_ = os.WriteFile(filepath.Join(okDir, "wdt.h"), []byte("#ifndef WDT_H\n#define WDT_H\n#endif\n"), 0o644)
	_ = os.WriteFile(filepath.Join(okDir, "wdt.c"), []byte("/* Copyright (c) 2026 Jürgen Müller */\nvoid wdt_kick(void) {}\n"), 0o644)
	_ = os.WriteFile(filepath.Join(okDir, "driver_manifest.json"), []byte(`{
		"name": "author_umlaut_driver",
		"author": "Jürgen Müller",
		"license": "MIT",
		"trait": "wdt",
		"abi_version": "v2",
		"headers": ["wdt.h"],
		"sources": ["wdt.c"],
		"symbols": {
			"init": "wdt_init",
			"deinit": "wdt_deinit",
			"kick": "wdt_kick",
			"suspend": "wdt_suspend",
			"resume": "wdt_resume"
		}
	}`), 0o644)

	okRep, err := AuditPackage(okDir)
	if err != nil {
		t.Fatal(err)
	}
	if !okRep.Passed {
		t.Fatalf("expected proper noun in author/copyright to pass REG-035, checks: %+v", okRep.Checks)
	}

	// 2. Actual German prose comment in C code must FAIL!
	badDir := t.TempDir()
	_ = os.WriteFile(filepath.Join(badDir, "wdt.h"), []byte("#ifndef WDT_H\n#define WDT_H\n#endif\n"), 0o644)
	_ = os.WriteFile(filepath.Join(badDir, "wdt.c"), []byte("/* Hier ist eine deutsche Erklärung für den Treiber */\n"), 0o644)
	_ = os.WriteFile(filepath.Join(badDir, "driver_manifest.json"), []byte(`{
		"name": "german_comment_driver",
		"trait": "wdt",
		"abi_version": "v2",
		"headers": ["wdt.h"],
		"symbols": {
			"init": "wdt_init",
			"deinit": "wdt_deinit",
			"kick": "wdt_kick",
			"suspend": "wdt_suspend",
			"resume": "wdt_resume"
		}
	}`), 0o644)

	badRep, err := AuditPackage(badDir)
	if err != nil {
		t.Fatal(err)
	}
	if badRep.Passed {
		t.Fatal("expected German prose comment to fail REG-035")
	}
}

func TestAuditArchPackage_ContainmentKeywordsMacrosAndDedup(t *testing.T) {
	parentDir := t.TempDir()
	// Create outside files to prove CWE-22 path traversal via ../ cannot escape *os.Root!
	_ = os.WriteFile(filepath.Join(parentDir, "outside.h"), []byte("void x(void);\n"), 0o644)
	_ = os.WriteFile(filepath.Join(parentDir, "outside.c"), []byte("void x(void) {}\n"), 0o644)

	pkgDir := filepath.Join(parentDir, "arch_pkg")
	_ = os.MkdirAll(pkgDir, 0o755)
	_ = os.WriteFile(filepath.Join(pkgDir, "arch_manifest.json"), []byte(`{
		"name": "tricore",
		"version": "1.0.0",
		"headers": ["../outside.h"],
		"sources": ["../outside.c"],
		"required_macros": ["123_BAD_MACRO", "while"],
		"symbols": {
			"disable_interrupts": "while",
			"timer_init": "arch_tc_timer_init",
			"get_tick_ms": "arch_tc_get_tick_ms",
			"delay_ms": "arch_tc_delay_ms",
			"foo_bar": "bad-sym",
			"bar": "bad-sym"
		}
	}`), 0o644)

	rep, err := AuditPackage(pkgDir)
	if err != nil {
		t.Fatalf("AuditPackage unexpected error: %v", err)
	}
	if rep.Passed {
		t.Fatal("expected traversal, C keyword symbol, and invalid required_macros to fail")
	}

	failed := make(map[string]string)
	for _, c := range rep.Checks {
		if !c.Passed {
			failed[c.Name] = c.Details
		}
	}
	for _, want := range []string{
		"Arch Manifest: Headers",
		"Arch Manifest: Sources",
		"Arch Manifest: Required Macros",
		"Arch Symbol Contract",
	} {
		if _, ok := failed[want]; !ok {
			t.Errorf("expected check %q to fail, checks: %+v", want, rep.Checks)
		}
	}
	// Verify substring dedup bug is fixed: both foo_bar="bad-sym" and bar="bad-sym" AND disable_interrupts="while" appear!
	symDetails := failed["Arch Symbol Contract"]
	for _, wantSub := range []string{`disable_interrupts="while"`, `bar="bad-sym"`, `foo_bar="bad-sym"`} {
		if !strings.Contains(symDetails, wantSub) {
			t.Errorf("expected Arch Symbol Contract details %q to contain %s", symDetails, wantSub)
		}
	}
}

func TestAuditChipPackage_TraversalBlocked(t *testing.T) {
	parentDir := t.TempDir()
	_ = os.WriteFile(filepath.Join(parentDir, "secret_hw.json"), []byte(`{}`), 0o644)

	chipDir := filepath.Join(parentDir, "evil_chip")
	_ = os.MkdirAll(chipDir, 0o755)
	_ = os.WriteFile(filepath.Join(chipDir, "chip_manifest.json"), []byte(`{
		"name": "evil_chip",
		"arch": "riscv32",
		"version": "1.0.0",
		"slot_capabilities": {"exec_model": "xip_remap", "slot_count": 2},
		"hal_bindings": {"flash": "esp_rom_spi"},
		"sources": {"hardware": "../secret_hw.json"}
	}`), 0o644)

	rep, err := AuditPackage(chipDir)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Passed {
		t.Fatal("expected chip hardware.json traversal '../secret_hw.json' to fail")
	}
}

func TestAuditDriverPackage_HeadersAndKeystoreV3Symbols(t *testing.T) {
	t.Run("keystore V3 driver with headers passes", func(t *testing.T) {
		dir := t.TempDir()
		_ = os.WriteFile(filepath.Join(dir, "efuse.h"), []byte("#ifndef EFUSE_H\n#define EFUSE_H\n#endif\n"), 0o644)
		_ = os.WriteFile(filepath.Join(dir, "efuse.c"), []byte("boot_status_t ks_read_pubkey(void) { return BOOT_OK; }\n"), 0o644)
		manifestJSON := `{
			"name": "test_keystore",
			"trait": "keystore",
			"abi_version": "v3",
			"headers": ["efuse.h"],
			"sources": ["efuse.c"],
			"symbols": {
				"read_pubkey": "ks_read_pubkey",
				"read_dslc": "ks_read_dslc",
				"write_dslc": "ks_write_dslc",
				"read_monotonic": "ks_read_monotonic",
				"advance_monotonic": "ks_advance_monotonic"
			}
		}`
		_ = os.WriteFile(filepath.Join(dir, "driver_manifest.json"), []byte(manifestJSON), 0o644)

		report, err := AuditPackage(dir)
		if err != nil {
			t.Fatalf("AuditPackage failed: %v", err)
		}
		if !report.Passed {
			t.Fatalf("expected keystore V3 driver to pass conformance, checks: %+v", report.Checks)
		}
	})

	t.Run("driver missing declared headers or escaping header path fails", func(t *testing.T) {
		for _, tc := range []struct {
			name    string
			headers string
		}{
			{name: "empty headers", headers: `[]`},
			{name: "missing header on disk", headers: `["missing.h"]`},
			{name: "escaping header path", headers: `["../outside.h"]`},
		} {
			t.Run(tc.name, func(t *testing.T) {
				dir := t.TempDir()
				manifestJSON := `{
					"name": "hdr_driver",
					"trait": "entropy",
					"abi_version": "v3",
					"headers": ` + tc.headers + `,
					"symbols": {"random": "drv_random"}
				}`
				_ = os.WriteFile(filepath.Join(dir, "driver_manifest.json"), []byte(manifestJSON), 0o644)
				report, err := AuditPackage(dir)
				if err != nil {
					t.Fatalf("AuditPackage unexpected error: %v", err)
				}
				if report.Passed {
					t.Fatalf("expected driver with %s to fail conformance", tc.name)
				}
			})
		}
	})
}

func TestAuditCryptoPackage_ValidAndUpstreamLiteralExempt(t *testing.T) {
	dir := t.TempDir()
	upstreamC := `
#include <stdint.h>
uint32_t third_party_k[4] = { 0x6A09E667U, 0xBB67AE85U, 0x3C6EF372U, 0xA54FF53AU };
int upstream_verify(const uint8_t *sig) {
	uint8_t scratch[64];
	scratch[0] = sig[0] ^ 0x5CU;
	return (int)scratch[0];
}
`
	wrapperH := `#ifndef CRYPTO_TEST_H
#define CRYPTO_TEST_H
#include "boot_hal.h"
boot_status_t crypto_test_init(void);
void crypto_test_deinit(void);
boot_status_t crypto_test_verify_signature(const uint8_t *msg, size_t len, const uint8_t *sig, const uint8_t *pk);
#endif
`
	wrapperC := `#include "crypto_test.h"
boot_status_t crypto_test_init(void) { return BOOT_OK; }
void crypto_test_deinit(void) {}
boot_status_t crypto_test_verify_signature(const uint8_t *msg, size_t len, const uint8_t *sig, const uint8_t *pk) {
	if ((sig == NULL) || (pk == NULL) || ((len > 0U) && (msg == NULL))) {
		return BOOT_ERR_INVALID_ARG;
	}
	return BOOT_OK;
}
`
	manifestJSON := `{
		"name": "test_ed25519",
		"version": "1.0.0",
		"abi_version": "v3",
		"category": ["backend"],
		"wrapper": "crypto_test.c",
		"upstream_sources": ["upstream.c"],
		"headers": ["crypto_test.h"],
		"symbols": {
			"init": "crypto_test_init",
			"deinit": "crypto_test_deinit",
			"verify_signature": "crypto_test_verify_signature"
		},
		"footprint": {
			"flash_estimate_bytes": 16384,
			"ram_estimate_bytes": 128
		}
	}`
	for name, body := range map[string]string{
		"upstream.c":           upstreamC,
		"crypto_test.h":        wrapperH,
		"crypto_test.c":        wrapperC,
		"crypto_manifest.json": manifestJSON,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	report, err := AuditPackage(dir)
	if err != nil {
		t.Fatalf("AuditPackage failed on valid crypto package: %v", err)
	}
	if !report.Passed {
		t.Fatalf("expected valid crypto package to pass conformance, checks: %+v", report.Checks)
	}
}

func TestAuditRealRegistryPackagesAcrossCategories(t *testing.T) {
	for _, rel := range []string{
		filepath.Join("drivers", "keystore", "esp_efuse"),
		filepath.Join("drivers", "rtc", "nrf_gpregret"),
		filepath.Join("drivers", "slot", "stm32h7_dualbank"),
		filepath.Join("drivers", "flash", "esp_rom_spi"),
		filepath.Join("chips", "esp32c6"),
		filepath.Join("chips", "stm32h753"),
		filepath.Join("arch", "riscv32"),
		filepath.Join("arch", "cortex-m"),
		filepath.Join("crypto", "backend", "monocypher"),
		filepath.Join("crypto", "hash", "sha256_sw"),
		filepath.Join("crypto", "pqc", "ml_dsa_65"),
		"soc",
		filepath.Join("integrations", "espidf"),
		filepath.Join("toolchains", "arm-none-eabi"),
	} {
		t.Run(filepath.ToSlash(rel), func(t *testing.T) {
			pkgDir := filepath.Clean(filepath.Join("..", "..", "..", "..", "toob-infra", "registry", "packages", rel))
			if _, err := os.Stat(pkgDir); err != nil {
				t.Skipf("registry package directory not present at %s", pkgDir)
			}
			report, err := AuditPackage(pkgDir)
			if err != nil {
				t.Fatalf("AuditPackage(%s) failed: %v", pkgDir, err)
			}
			if !report.Passed {
				t.Fatalf("expected real registry package %s to pass conformance, checks: %+v", rel, report.Checks)
			}
		})
	}
}
