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
    uint64_t val64 = 0ULL; // Multi-char suffix 0ULL - allowed!
    uint64_t one64 = 1uLL; // Mixed-case 1uLL - allowed!
    unsigned long ul0 = 0UL; // 0UL - allowed!
    unsigned long ul1 = 1UL; // 1UL - allowed!
    uint32_t c23_thousand = 1'000U; // C23 digit separator on allowed 1000U!
    uint32_t bit = 1; // Trivial 1 - allowed!
    uint32_t byte_mask = 0xFF; // Universal byte mask - allowed!
    uint32_t lower_hex = 0xffu; // Lowercase hex + suffix - allowed!
    char nul = '\x00'; // Char literal - allowed!
    char bs = '\\'; // Escaped backslash char literal - allowed!
    const char *s = "escaped \"0xDEADBEEF\" and trailing \\"; // String literal - allowed!
    // Spliced line comment \
    uint32_t inside_spliced_comment = 0xCAFEBABEU;
    
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

func TestC23LexerEdgeCases_CaughtAccurately(t *testing.T) {
	tmpDir := t.TempDir()
	srcPath := filepath.Join(tmpDir, "edge_cases.c")

	// Tests all 5 C lexer defects:
	// 1. Escaped backslash in string literal ("\\") must NOT swallow 0xCAFE0001U on same line!
	// 2. Escaped backslash in char literal ('\\') must NOT swallow 0xCAFE0002U on same line!
	// 3. C23 digit separator (0xDEAD'BEEFU and 40'000U) must NOT toggle inChar and hide literals!
	// 4. Hex float (0x1.0p4) must be flagged as a single literal!
	// 5. sizeof(x) earlier on a line must NOT exempt 0xCAFE0003U later on the same line!
	code := `
#include <stddef.h>
#include <stdint.h>

void edge_cases(void) {
    const char *p = "\\"; uint32_t hidden_after_str = 0xCAFE0001U;
    char c = '\\'; uint32_t hidden_after_char = 0xCAFE0002U;
    uint32_t c23_sep = 0xDEAD'BEEFU;
    uint32_t c23_dec = 40'000U;
    double hex_flt = 0x1.0p4;
    size_t sz = sizeof(uint32_t) + 0xCAFE0003U;
    (void)p; (void)c; (void)c23_sep; (void)c23_dec; (void)hex_flt; (void)sz;
}
`
	if err := os.WriteFile(srcPath, []byte(code), 0o644); err != nil {
		t.Fatal(err)
	}

	report, err := RunLint(DefaultConfig(tmpDir))
	if err != nil {
		t.Fatalf("RunLint failed: %v", err)
	}
	if report.Passed {
		t.Fatal("expected report.Passed == false on C23/escaped-backslash/hex-float edge cases")
	}

	gotLiterals := make(map[string]bool)
	for _, v := range report.Violations {
		gotLiterals[v.Literal] = true
	}
	for _, want := range []string{
		"0xCAFE0001U",
		"0xCAFE0002U",
		"0xDEAD'BEEFU",
		"40'000U",
		"0x1.0p4",
		"0xCAFE0003U",
	} {
		if !gotLiterals[want] {
			t.Errorf("expected literal %q to be flagged, got violations: %+v", want, report.Violations)
		}
	}
}

func TestDeepMode_EnforcesStricterInspection(t *testing.T) {
	tmpDir := t.TempDir()
	srcPath := filepath.Join(tmpDir, "deep_target.c")

	// Passes in standard mode (shift count, 0xFF mask, function-like macro),
	// MUST fail in DeepMode!
	code := `
#define ADD_SECRET_OFFSET(x) ((x) + 0x50000000U)
#define NAMED_CONST 0x40000000U

unsigned int calc(unsigned int v) {
    unsigned int shifted = (1U << 30);
    unsigned int masked = v & 0xFFU;
    return shifted ^ masked;
}
`
	if err := os.WriteFile(srcPath, []byte(code), 0o644); err != nil {
		t.Fatal(err)
	}

	stdReport, err := RunLint(DefaultConfig(tmpDir))
	if err != nil {
		t.Fatalf("standard RunLint failed: %v", err)
	}
	if !stdReport.Passed {
		t.Fatalf("expected standard mode to pass, got: %+v", stdReport.Violations)
	}

	deepCfg := DefaultConfig(tmpDir)
	deepCfg.DeepMode = true
	deepReport, err := RunLint(deepCfg)
	if err != nil {
		t.Fatalf("deep RunLint failed: %v", err)
	}
	if deepReport.Passed {
		t.Fatal("expected DeepMode to flag function-like macro, shift magic number, and 0xFFU mask")
	}
	if len(deepReport.Violations) < 3 {
		t.Fatalf("expected at least 3 deep violations, got %d: %+v", len(deepReport.Violations), deepReport.Violations)
	}
}

func TestRunLint_FailFastOnMissingPath(t *testing.T) {
	if _, err := RunLint(LintConfig{}); err == nil {
		t.Fatal("expected error on empty Paths")
	}
	missing := filepath.Join(t.TempDir(), "does_not_exist")
	if _, err := RunLint(DefaultConfig(missing)); err == nil {
		t.Fatal("expected fail-fast error on non-existent target path")
	}
}

func TestRegression_PreReg004XipRemapSnapshot(t *testing.T) {
	tmpDir := t.TempDir()
	srcPath := filepath.Join(tmpDir, "old_xip_remap.c")

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
