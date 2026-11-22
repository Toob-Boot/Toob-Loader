package build

import (
	"encoding/json"
	"testing"
)

// validTestHardwareJSON builds a structurally valid HardwareJson resembling a real chip.
// All 20 plausibility checks pass against this baseline.
func validTestHardwareJSON(t *testing.T) *HardwareJson {
	t.Helper()
	raw := `{
		"chip_family": "test-chip",
		"provenance": {"source": "trm", "ref": "Test TRM v1.0", "verified": "2026-01-15"},
		"flash": {
			"size": 4194304,
			"write_alignment": 4,
			"xip_base": "0x42000000",
			"regions": [
				{"type": "reserved", "base": 0, "size": 262144,
				 "provenance": {"source": "trm", "ref": "Test TRM §3.2", "verified": "2026-01-15"}},
				{"type": "writable", "base": 262144, "sector_size": 4096, "count": 960,
				 "provenance": {"source": "trm", "ref": "Test TRM §3.3", "verified": "2026-01-15"}}
			]
		},
		"crypto_capabilities": {"arena_size": 2048},
		"memory": {
			"iram_base": "0x40800000",
			"iram_size": "0x7C000",
			"lp_ram_base": "0x50000000",
			"lp_ram_size": "0x4000"
		},
		"register_blocks": {
			"timg0_wdt": {
				"base": "0x60008000",
				"provenance": {"source": "trm", "ref": "Test TRM §22.5", "verified": "2026-01-15"},
				"regs": {"config0": "0x48", "feed": "0x60"}
			},
			"uart0": {
				"base": "0x60000000",
				"provenance": {"source": "trm", "ref": "Test TRM §25.4", "verified": "2026-01-15"},
				"regs": {}
			}
		},
		"registers_flat": {
			"rng_data_reg": "0x60026000"
		},
		"reserved_ram_regions": [
			{"name": "confirm_nonce", "base": "0x50003FC0", "size": 64,
			 "description": "Boot confirm nonce",
			 "provenance": {"source": "trm", "ref": "Test TRM §5.4", "verified": "2026-01-15"}}
		],
		"reset_causes": {
			"register_offset": "0x0410",
			"mask": "0x1F",
			"codes": [
				{"name": "poweron",  "value": 1,  "class": "power",
				 "provenance": {"source": "trm", "ref": "Test TRM Table 9-3", "verified": "2026-01-15"}},
				{"name": "sw_sys",   "value": 3,  "class": "intentional",
				 "provenance": {"source": "trm", "ref": "Test TRM Table 9-3", "verified": "2026-01-15"}},
				{"name": "brownout", "value": 15, "class": "crash",
				 "provenance": {"source": "trm", "ref": "Test TRM Table 9-3", "verified": "2026-01-15"}}
			]
		},
		"constants": {
			"val_wdt_unlock": "0x50D83AA1",
			"cpu_freq_hz": 160000000
		}
	}`

	var hj HardwareJson
	if err := json.Unmarshal([]byte(raw), &hj); err != nil {
		t.Fatalf("failed to parse test hardware JSON: %v", err)
	}
	return &hj
}

func TestVerifyHardwareProvenance_AllPass(t *testing.T) {
	hj := validTestHardwareJSON(t)
	results := VerifyHardwareProvenance(hj)

	for _, r := range results {
		if !r.Passed {
			t.Errorf("[FAIL] %s: %s — %s", r.Check, r.Name, r.Details)
		}
	}

	const expectedChecks = 20
	if len(results) != expectedChecks {
		t.Errorf("expected %d plausibility checks, got %d", expectedChecks, len(results))
		for _, r := range results {
			t.Logf("  %s: %s", r.Check, r.Name)
		}
	}
}

func TestVerifyHardwareProvenance_Failures(t *testing.T) {
	prov := func(src string) *Provenance {
		return &Provenance{Source: src, Ref: "test", Verified: "2026-01-15"}
	}

	tests := []struct {
		name     string
		mutate   func(*HardwareJson)
		wantFail string
	}{
		{
			name:     "PROV-001: unknown source type",
			mutate:   func(hj *HardwareJson) { hj.Provenance.Source = "tmr" },
			wantFail: "PROV-001",
		},
		{
			name:     "PROV-002: future date",
			mutate:   func(hj *HardwareJson) { hj.Provenance.Verified = "2099-01-01" },
			wantFail: "PROV-002",
		},
		{
			name:     "PROV-002: invalid date format",
			mutate:   func(hj *HardwareJson) { hj.Provenance.Verified = "TBD" },
			wantFail: "PROV-002",
		},
		{
			name:     "PROV-003: missing provenance on region",
			mutate:   func(hj *HardwareJson) { hj.Flash.Regions[0].Provenance = nil },
			wantFail: "PROV-003",
		},
		{
			name: "ADDR-001: unaligned register base",
			mutate: func(hj *HardwareJson) {
				hj.RegisterBlocks["bad"] = RegisterBlock{Base: "0x60008001", Regs: map[string]string{}, Provenance: prov("trm")}
			},
			wantFail: "ADDR-001",
		},
		{
			name: "ADDR-004: duplicate base addresses",
			mutate: func(hj *HardwareJson) {
				hj.RegisterBlocks["timg0_copy"] = RegisterBlock{Base: "0x60008000", Regs: map[string]string{}, Provenance: prov("trm")}
			},
			wantFail: "ADDR-004",
		},
		{
			name: "ADDR-005: flat register duplicates block base",
			mutate: func(hj *HardwareJson) {
				hj.RegistersFlat["timg0_copy"] = "0x60008000"
			},
			wantFail: "ADDR-005",
		},
		{
			name: "FLASH-001: overlapping regions",
			mutate: func(hj *HardwareJson) {
				hj.Flash.Regions = []FlashRegion{
					{Type: "reserved", Base: 0, Size: 300000, Provenance: prov("trm")},
					{Type: "writable", Base: 200000, SectorSize: 4096, Count: 960, Provenance: prov("trm")},
				}
			},
			wantFail: "FLASH-001",
		},
		{
			name: "FLASH-002: sector arithmetic mismatch",
			mutate: func(hj *HardwareJson) {
				hj.Flash.Regions = []FlashRegion{
					{Type: "reserved", Base: 0, Size: 262144, Provenance: prov("trm")},
					{Type: "writable", Base: 262144, SectorSize: 4096, Count: 960, Size: 500000, Provenance: prov("trm")},
				}
			},
			wantFail: "FLASH-002",
		},
		{
			name: "FLASH-004: XIP within physical flash",
			mutate: func(hj *HardwareJson) {
				hj.Flash.XipBase = "0x00100000" // 1MB, within 4MB flash
			},
			wantFail: "FLASH-004",
		},
		{
			name: "MEM-001: IRAM too large",
			mutate: func(hj *HardwareJson) {
				hj.Memory.IramSize = "0x10000000" // 256 MB
			},
			wantFail: "MEM-001",
		},
		{
			name: "MEM-002: LP RAM overlaps IRAM",
			mutate: func(hj *HardwareJson) {
				hj.Memory.LpRamBase = "0x40800000" // Same as IRAM base
			},
			wantFail: "MEM-002",
		},
		{
			name: "MEM-003: overlapping reserved RAM regions",
			mutate: func(hj *HardwareJson) {
				hj.ReservedRamRegions = []ReservedRamRegion{
					{Name: "region_a", Base: "0x50000000", Size: 128, Description: "a", Provenance: prov("trm")},
					{Name: "region_b", Base: "0x50000040", Size: 128, Description: "b", Provenance: prov("trm")},
				}
			},
			wantFail: "MEM-003",
		},
		{
			name: "MEM-004: reserved RAM outside LP RAM",
			mutate: func(hj *HardwareJson) {
				hj.ReservedRamRegions = []ReservedRamRegion{
					{Name: "outside", Base: "0x60000000", Size: 64, Description: "outside", Provenance: prov("trm")},
				}
			},
			wantFail: "MEM-004",
		},
		{
			name: "RST-001: duplicate reset cause values",
			mutate: func(hj *HardwareJson) {
				hj.ResetCauses.Codes = append(hj.ResetCauses.Codes, ResetCauseCode{
					Name: "dupe_poweron", Value: 1, Class: "power", Provenance: prov("trm"),
				})
			},
			wantFail: "RST-001",
		},
		{
			name: "RST-002: value exceeds mask",
			mutate: func(hj *HardwareJson) {
				hj.ResetCauses.Codes = append(hj.ResetCauses.Codes, ResetCauseCode{
					Name: "impossible", Value: 32, Class: "crash", Provenance: prov("trm"),
				})
			},
			wantFail: "RST-002",
		},
		{
			name: "RST-003: unrecognized reset class",
			mutate: func(hj *HardwareJson) {
				hj.ResetCauses.Codes[0].Class = "watchdog"
			},
			wantFail: "RST-003",
		},
		{
			name: "CONST-001: hex constant exceeds 32-bit",
			mutate: func(hj *HardwareJson) {
				hj.Constants["some_register_key"] = "0x1FFFFFFFFFF"
			},
			wantFail: "CONST-001",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hj := validTestHardwareJSON(t)
			tt.mutate(hj)
			results := VerifyHardwareProvenance(hj)

			var failedCheck *VerifyResult
			for i, r := range results {
				if r.Check == tt.wantFail && !r.Passed {
					failedCheck = &results[i]
					break
				}
			}

			if failedCheck == nil {
				t.Errorf("expected check %s to FAIL, but it passed", tt.wantFail)
				for _, r := range results {
					status := "PASS"
					if !r.Passed {
						status = "FAIL"
					}
					t.Logf("  [%s] %s: %s — %s", status, r.Check, r.Name, r.Details)
				}
			}
		})
	}
}

func TestHasVerificationFailures(t *testing.T) {
	allPass := []VerifyResult{
		{Check: "A", Passed: true},
		{Check: "B", Passed: true},
	}
	if HasVerificationFailures(allPass) {
		t.Error("expected no failures for all-pass results")
	}

	oneFail := []VerifyResult{
		{Check: "A", Passed: true},
		{Check: "B", Passed: false, Details: "bad"},
	}
	if !HasVerificationFailures(oneFail) {
		t.Error("expected failure for results with one FAIL")
	}
}

func TestVerifyHardwareProvenance_MultiVendorWarningsAndRAMUnion(t *testing.T) {
	prov := &Provenance{Source: "trm", Ref: "TRM", Verified: "2026-01-15"}
	hj := validTestHardwareJSON(t)
	hj.Flash.Size = 6000000  // FLASH-003 warning (6 MB non-power-of-two MCU)
	hj.Flash.XipBase = "0x0" // FLASH-004 allowed when xip_base == 0
	hj.Memory.SramBase = "0x20000000"
	hj.Memory.SramSize = "0x40000"
	// Reserved RAM inside SRAM rather than LP_RAM must pass MEM-004!
	hj.ReservedRamRegions = []ReservedRamRegion{
		{Name: "sram_mailbox", Base: "0x2003FFC0", Size: 64, Description: "SRAM mailbox", Provenance: prov},
	}
	block := hj.RegisterBlocks["timg0_wdt"]
	block.Regs["far_reg"] = "0x100000" // ADDR-002 warning
	hj.RegisterBlocks["timg0_wdt"] = block
	hj.RegisterBlocks["low_mmio"] = RegisterBlock{Base: "0x00008000", Regs: map[string]string{}, Provenance: prov} // ADDR-003 warning

	results := VerifyHardwareProvenance(hj)
	if HasVerificationFailures(results) {
		t.Fatalf("expected warnings not hard failures, got:\n%s", FormatVerificationErrors(results))
	}
	warns := make(map[string]bool)
	for _, r := range results {
		if r.Warning {
			warns[r.Check] = true
		}
	}
	for _, wantWarn := range []string{"ADDR-002", "ADDR-003", "FLASH-003"} {
		if !warns[wantWarn] {
			t.Errorf("expected %s to emit Warning=true, got %+v", wantWarn, warns)
		}
	}
}
