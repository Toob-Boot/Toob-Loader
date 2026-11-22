package build

import (
	"crypto/sha256"
	"encoding/hex"
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
		Flash: FlashSpec{
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
	unverified := 0
	for _, item := range items {
		if item.Unverified() {
			unverified++
		}
	}
	if unverified != 1 {
		t.Errorf("expected exactly one unverified item, got %d", unverified)
	}

	results := VerifyHardwareProvenance(hj)
	content, err := renderProvenanceReportWithRaw(hj, nil, items, results)
	if err != nil {
		t.Fatalf("renderProvenanceReportWithRaw failed: %v", err)
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

	rawBytes := []byte("{\n  \"chip_family\": \"test-chip\"  \n}\n")
	wantDigest := sha256.Sum256(rawBytes)
	rawReport, err := renderProvenanceReportWithRaw(hj, rawBytes, items, results)
	if err != nil {
		t.Fatalf("renderProvenanceReportWithRaw failed: %v", err)
	}
	if !strings.Contains(string(rawReport), hex.EncodeToString(wantDigest[:])) {
		t.Errorf("expected raw hardware.json SHA-256 digest in report")
	}
}
