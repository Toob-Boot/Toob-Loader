package literallint

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRegexScanner_FlaggedLiterals(t *testing.T) {
	tmpDir := t.TempDir()
	srcPath := filepath.Join(tmpDir, "bad.c")

	code := `
#include <stdint.h>

void test_func(void) {
    uint32_t val = 0x50000000; // Hardcoded address - bad!
    uint32_t prescaler = 40000U; // Hardcoded prescaler - bad!
}
`
	if err := os.WriteFile(srcPath, []byte(code), 0o644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	report, err := RunLint(DefaultConfig(tmpDir))
	if err != nil {
		t.Fatalf("RunLint failed: %v", err)
	}

	if report.Passed {
		t.Errorf("expected report.Passed == false for hardcoded literals")
	}

	if len(report.Violations) < 2 {
		t.Errorf("expected at least 2 violations, got %d", len(report.Violations))
	}
}

func TestRegexScanner_AllowedLiteralsAndWhitelisting(t *testing.T) {
	tmpDir := t.TempDir()
	srcPath := filepath.Join(tmpDir, "good.c")

	code := `
#include <stdint.h>

#define CHIP_REG_BASE 0x50000000 // Macro definition - allowed!

void test_func(void) {
    uint32_t mask = (1U << 30); // Shift idiom - allowed!
    uint32_t val = 0U; // Trivial 0U - allowed!
    uint32_t bit = 1; // Trivial 1 - allowed!
    uint32_t byte_mask = 0xFF; // Universal byte mask - allowed!
    
    /* lint-allow: HW spec prescaler derived from TRM */
    uint32_t prescaler = 40000U;
}
`
	if err := os.WriteFile(srcPath, []byte(code), 0o644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	report, err := RunLint(DefaultConfig(tmpDir))
	if err != nil {
		t.Fatalf("RunLint failed: %v", err)
	}

	if !report.Passed {
		t.Errorf("expected report.Passed == true, got violations: %+v", report.Violations)
	}
}

func TestRegression_PreReg004XipRemapSnapshot(t *testing.T) {
	tmpDir := t.TempDir()
	srcPath := filepath.Join(tmpDir, "old_xip_remap.c")

	// Snapshot of hardcoded pre-REG-004 esp32c6_xip_remap_commit
	code := `
#include <stdint.h>

int esp32c6_xip_remap_commit(uint32_t target_addr) {
    for (uint32_t i = 0U; i < 6U; i++) {
        uint32_t paddr = target_addr + (i * 0x10000U);
        uint32_t mmu_val = (paddr >> 16U) | 0x40000000U;

        REG_WRITE(0x60002380, i);
        REG_WRITE(0x6000237C, mmu_val);
    }

    REG_WRITE(0x600C8098, 0x42000000);
    REG_WRITE(0x600C809C, 393216);
    return 0;
}
`
	if err := os.WriteFile(srcPath, []byte(code), 0o644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	report, err := RunLint(DefaultConfig(tmpDir))
	if err != nil {
		t.Fatalf("RunLint failed: %v", err)
	}

	if report.Passed {
		t.Errorf("expected pre-REG-004 snapshot to fail literal lint")
	}

	if len(report.Violations) == 0 {
		t.Errorf("expected multiple violations in pre-REG-004 snapshot")
	}
}
