package manifest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/toob-boot/toob/internal/ui"
)

type ProvenanceItem struct {
	Category     string
	Name         string
	ClaimedValue string
	Source       string
	Ref          string
	Verified     string
	Status       string // e.g. "SELF_ATTESTED (trm)" or "UNVERIFIED (SCAN)"
}

func AuditProvenance(hj *HardwareJson) []ProvenanceItem {
	var items []ProvenanceItem

	addItem := func(category, name, claimedValue string, prov *Provenance) {
		item := ProvenanceItem{
			Category:     category,
			Name:         name,
			ClaimedValue: claimedValue,
		}

		if prov != nil && prov.Source != "" {
			item.Source = prov.Source
			item.Ref = prov.Ref
			item.Verified = prov.Verified
		} else {
			item.Source = "scan"
			item.Ref = "Unspecified / Automated scan"
		}

		if item.Source == "scan" || item.Source == "" {
			item.Status = "UNVERIFIED (SCAN)"
			ui.Warn("WARNING [PROVENANCE_UNVERIFIED]: Hardware constant '%s' (%s) relies on unverified scan source (ref: %s)", item.Name, item.Category, item.Ref)
		} else {
			item.Status = fmt.Sprintf("SELF_ATTESTED (%s)", item.Source)
		}

		items = append(items, item)
	}

	// 1. Top-Level Hardware / Flash Geometry
	if hj.Provenance != nil || hj.Flash.Provenance != nil {
		p := hj.Provenance
		if p == nil {
			p = hj.Flash.Provenance
		}
		claimed := fmt.Sprintf("Size: %d B (%d MB)", hj.Flash.Size, hj.Flash.Size/(1024*1024))
		addItem("Flash Geometry", hj.ChipFamily+"_flash", claimed, p)
	}

	for _, reg := range hj.Flash.Regions {
		name := reg.Name
		if name == "" {
			name = fmt.Sprintf("region_0x%08x", reg.Base)
		}
		claimed := fmt.Sprintf("Base: 0x%08X, Size: %d B", reg.Base, regionEffectiveSize(reg))
		addItem("Flash Region", name, claimed, reg.Provenance)
	}

	// 2. RAM & Reserved Regions
	for _, ram := range hj.ReservedRamRegions {
		claimed := fmt.Sprintf("Base: %s, Size: %d B", ram.Base, ram.Size)
		addItem("Reserved RAM", ram.Name, claimed, ram.Provenance)
	}

	// 3. Register Blocks
	for blockName, block := range hj.RegisterBlocks {
		claimed := fmt.Sprintf("Base: %s, Regs: %d", block.Base, len(block.Regs))
		addItem("Register Block", blockName, claimed, block.Provenance)
	}

	// 4. Reset Causes
	if hj.ResetCauses != nil {
		for _, code := range hj.ResetCauses.Codes {
			claimed := fmt.Sprintf("Value: %d (0x%02X), Class: %s", code.Value, code.Value, code.Class)
			addItem("Reset Cause", code.Name, claimed, code.Provenance)
		}
	}

	sort.Slice(items, func(i, j int) bool {
		if items[i].Category != items[j].Category {
			return items[i].Category < items[j].Category
		}
		return items[i].Name < items[j].Name
	})

	return items
}

func GenerateProvenanceReport(hj *HardwareJson, outDir string) error {
	items := AuditProvenance(hj)
	verifyResults := VerifyHardwareProvenance(hj)

	// Compute SHA-256 hash of hardware specification data
	hjBytes, err := json.Marshal(hj)
	if err != nil {
		return fmt.Errorf("failed to marshal hardware json for hash computation: %w", err)
	}
	hash := sha256.Sum256(hjBytes)
	specHashHex := hex.EncodeToString(hash[:])

	passCount := 0
	for _, r := range verifyResults {
		if r.Passed {
			passCount++
		}
	}
	failCount := len(verifyResults) - passCount

	var b strings.Builder
	b.WriteString("# Hardware Provenance Evidence Report (CRA Annex-I Traceability)\n\n")
	b.WriteString(fmt.Sprintf("**Chip Family:** %s  \n", hj.ChipFamily))
	b.WriteString(fmt.Sprintf("**Hardware Specification Digest (SHA-256):** `%s`  \n", specHashHex))
	b.WriteString(fmt.Sprintf("**Total Elements Audited:** %d  \n", len(items)))
	b.WriteString(fmt.Sprintf("**Plausibility Checks:** %d passed, %d failed  \n\n", passCount, failCount))

	// Traceability Matrix
	b.WriteString("## Traceability Matrix\n\n")
	b.WriteString("| Component / Element | Category | Claimed Value | Source | Reference | Verified Date | Status |\n")
	b.WriteString("|---|---|---|---|---|---|---|\n")

	for _, item := range items {
		sourceStr := item.Source
		if sourceStr == "" {
			sourceStr = "scan"
		}
		refStr := item.Ref
		if refStr == "" {
			refStr = "N/A"
		}
		verStr := item.Verified
		if verStr == "" {
			verStr = "N/A"
		}

		b.WriteString(fmt.Sprintf("| `%s` | %s | `%s` | `%s` | %s | %s | **%s** |\n",
			item.Name, item.Category, item.ClaimedValue, sourceStr, refStr, verStr, item.Status))
	}

	// Plausibility Verification
	b.WriteString("\n## Plausibility Verification\n\n")
	b.WriteString("| Check | Result | Details |\n")
	b.WriteString("|---|---|---|\n")

	for _, r := range verifyResults {
		status := "PASS"
		if !r.Passed {
			status = "FAIL"
		}
		b.WriteString(fmt.Sprintf("| %s: %s | **%s** | %s |\n", r.Check, r.Name, status, r.Details))
	}

	reportPath := filepath.Join(outDir, "provenance_report.md")
	if err := os.WriteFile(reportPath, []byte(b.String()), 0o644); err != nil {
		return err
	}

	// Fail build if any plausibility check failed
	if HasVerificationFailures(verifyResults) {
		return fmt.Errorf("FATAL [PROVENANCE]: Hardware plausibility verification failed:\n%s",
			FormatVerificationErrors(verifyResults))
	}

	return nil
}


