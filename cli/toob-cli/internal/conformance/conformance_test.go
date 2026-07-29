package conformance

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuditPackage_ValidDriver(t *testing.T) {
	// Point to existing flash driver in toob-registry
	halRoot := filepath.Join("..", "..", "..", "..", "toob-registry", "registry", "drivers", "flash", "esp_rom_spi")
	absPath, err := filepath.Abs(halRoot)
	if err != nil {
		t.Fatalf("failed to resolve path: %v", err)
	}

	report, err := AuditPackage(absPath)
	if err != nil {
		t.Fatalf("AuditPackage failed on valid driver: %v", err)
	}

	if !report.Passed {
		t.Errorf("expected report.Passed == true for valid driver, got false")
	}
	if report.PackageName != "esp_rom_spi" {
		t.Errorf("expected PackageName == 'esp_rom_spi', got '%s'", report.PackageName)
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

func TestAuditPackage_MockDivergence_Negative(t *testing.T) {
	tmpDir := t.TempDir()
	manifestContent := `{
		"name": "divergent_driver",
		"trait": "otp",
		"abi_version": "v2",
		"symbols": {
			"read_pubkey": "driver_read_pubkey",
			"read_dslc": "driver_read_dslc",
			"write_dslc": "driver_write_dslc"
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

func TestExportReports(t *testing.T) {
	tmpDir := t.TempDir()
	report := &ConformanceReport{
		PackageName: "test_pkg",
		Trait:       "wdt",
		AbiVersion:  "v2",
		Passed:      true,
		Checks: []ConformanceCheck{
			{Name: "Check 1", Passed: true, Details: "Details 1"},
		},
	}

	jsonPath := filepath.Join(tmpDir, "conformance_report.json")
	mdPath := filepath.Join(tmpDir, "conformance_report.md")

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

	if !strings.Contains(string(mdContent), "HAL Conformance & Verification Report") {
		t.Errorf("md report missing title header")
	}
}

func TestLanguagePolicy_GermanComment_Negative(t *testing.T) {
	tmpDir := t.TempDir()
	manifestContent := `{
		"name": "german_comment_driver",
		"trait": "wdt",
		"abi_version": "v2",
		"symbols": {
			"init": "wdt_init",
			"deinit": "wdt_deinit",
			"kick": "wdt_kick",
			"suspend": "wdt_suspend",
			"resume": "wdt_resume"
		}
	}`
	if err := os.WriteFile(filepath.Join(tmpDir, "driver_manifest.json"), []byte(manifestContent), 0o644); err != nil {
		t.Fatalf("failed to write manifest: %v", err)
	}

	germanC := `/* Hier ist eine deutsche Erklärung für den Treiber */`
	if err := os.WriteFile(filepath.Join(tmpDir, "wdt.c"), []byte(germanC), 0o644); err != nil {
		t.Fatalf("failed to write wdt.c: %v", err)
	}

	report, err := AuditPackage(tmpDir)
	if err != nil {
		t.Fatalf("AuditPackage unexpected error: %v", err)
	}

	if report.Passed {
		t.Errorf("expected report.Passed == false due to German non-ASCII comment")
	}

	foundLangFail := false
	for _, chk := range report.Checks {
		if chk.Name == "Language Policy: English Comments" && !chk.Passed {
			foundLangFail = true
		}
	}
	if !foundLangFail {
		t.Errorf("expected Language Policy check failure, got pass")
	}
}
