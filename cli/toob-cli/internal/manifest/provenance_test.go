package manifest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuditProvenanceAndReport(t *testing.T) {
	hj := &HardwareJson{
		ChipFamily: "test-chip",
		Provenance: &Provenance{
			Source:   "trm",
			Ref:      "Test TRM §1.0",
			Verified: "2026-05-12",
		},
		Flash: struct {
			Size           uint32        `json:"size"`
			WriteAlignment uint32        `json:"write_alignment"`
			AppAlignment   uint32        `json:"app_alignment"`
			BaseAddr       string        `json:"base_addr"`
			XipBase        string        `json:"xip_base"`
			Regions        []FlashRegion `json:"regions"`
			Provenance     *Provenance   `json:"provenance,omitempty"`
		}{
			Size: 4194304,
			Regions: []FlashRegion{
				{
					Name: "bootloader",
					Base: 0,
					Size: 262144,
					Provenance: &Provenance{
						Source: "trm",
						Ref:    "Test TRM §3.1",
					},
				},
				{
					Name: "unverified_region",
					Base: 262144,
					Size: 262144,
					Provenance: &Provenance{
						Source: "scan",
						Ref:    "toobfuzzer blueprint",
					},
				},
			},
		},
	}

	items := AuditProvenance(hj)
	if len(items) != 3 {
		t.Fatalf("expected 3 provenance items, got %d", len(items))
	}

	tmpDir := t.TempDir()
	if err := GenerateProvenanceReport(hj, tmpDir); err != nil {
		t.Fatalf("GenerateProvenanceReport failed: %v", err)
	}

	reportPath := filepath.Join(tmpDir, "provenance_report.md")
	content, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("failed to read report: %v", err)
	}

	reportStr := string(content)
	if !strings.Contains(reportStr, "Hardware Provenance Evidence Report") {
		t.Errorf("report missing title header")
	}
	if !strings.Contains(reportStr, "Hardware Specification Digest (SHA-256)") {
		t.Errorf("report missing SHA-256 digest header")
	}
	if !strings.Contains(reportStr, "SELF_ATTESTED (trm)") {
		t.Errorf("report missing SELF_ATTESTED status")
	}
	if !strings.Contains(reportStr, "UNVERIFIED (SCAN)") {
		t.Errorf("report missing unverified scan status")
	}
	if !strings.Contains(reportStr, "Claimed Value") {
		t.Errorf("report missing Claimed Value column header")
	}
}

func TestGeneratePlatformWiring(t *testing.T) {
	tmpDir := t.TempDir()
	cm := &ChipManifest{Name: "esp32c6", Arch: "riscv32"}
	hj := &HardwareJson{ChipFamily: "esp32c6"}
	drivers := map[string]*DriverManifest{
		"flash": {
			Trait: "flash",
			Symbols: map[string]string{
				"init":             "esp_flash_init",
				"deinit":           "esp_flash_deinit",
				"read":             "esp_flash_read",
				"write":            "esp_flash_write",
				"erase_sector":     "esp_flash_erase_sector",
				"get_sector_size": "esp_flash_get_sector_size",
				"get_vendor_error": "esp_flash_get_vendor_error",
			},
		},
	}

	if err := generatePlatformWiring(cm, hj, drivers, tmpDir); err != nil {
		t.Fatalf("generatePlatformWiring failed: %v", err)
	}

	cPath := filepath.Join(tmpDir, "generated_platform_wiring.c")
	content, err := os.ReadFile(cPath)
	if err != nil {
		t.Fatalf("failed to read generated_platform_wiring.c: %v", err)
	}

	code := string(content)
	if !strings.Contains(code, "boot_platform_bringup") {
		t.Errorf("generated wiring missing boot_platform_bringup call")
	}
	if !strings.Contains(code, "TOOB_FLASH_HAL_V2") {
		t.Errorf("generated wiring missing TOOB_FLASH_HAL_V2 macro")
	}
	if !strings.Contains(code, "esp_flash_init") {
		t.Errorf("generated wiring missing esp_flash_init symbol")
	}
}

func TestGeneratePlatformWiring_MultiArch(t *testing.T) {
	tmpDir := t.TempDir()
	cm := &ChipManifest{Name: "stm32f407", Arch: "armv7m"}
	hj := &HardwareJson{ChipFamily: "stm32f4"}
	drivers := map[string]*DriverManifest{
		"flash": {
			Trait: "flash",
			Symbols: map[string]string{
				"init":             "stm32_flash_init",
				"deinit":           "stm32_flash_deinit",
				"read":             "stm32_flash_read",
				"write":            "stm32_flash_write",
				"erase_sector":     "stm32_flash_erase_sector",
				"get_sector_size": "stm32_flash_get_sector_size",
				"get_vendor_error": "stm32_flash_get_vendor_error",
			},
		},
	}

	if err := generatePlatformWiring(cm, hj, drivers, tmpDir); err != nil {
		t.Fatalf("generatePlatformWiring failed: %v", err)
	}

	cPath := filepath.Join(tmpDir, "generated_platform_wiring.c")
	content, err := os.ReadFile(cPath)
	if err != nil {
		t.Fatalf("failed to read generated_platform_wiring.c: %v", err)
	}

	code := string(content)
	if !strings.Contains(code, "arch_arm.h") {
		t.Errorf("expected arch_arm.h for ARM architecture, got code without it")
	}
	if !strings.Contains(code, "arch_arm_disable_interrupts()") {
		t.Errorf("expected arch_arm_disable_interrupts() call")
	}
	if !strings.Contains(code, "stm32_flash_init") {
		t.Errorf("expected stm32_flash_init symbol from driver manifest")
	}
}
