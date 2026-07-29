package manifest

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/toob-boot/toob/internal/ui"
)

type ProvenanceItem struct {
	Category string
	Name     string
	Source   string
	Ref      string
	Verified string
	Status   string // "VERIFIED" or "UNVERIFIED (SCAN)"
}

func AuditProvenance(hj *HardwareJson) []ProvenanceItem {
	var items []ProvenanceItem

	addItem := func(category, name string, prov *Provenance) {
		item := ProvenanceItem{
			Category: category,
			Name:     name,
			Status:   "VERIFIED",
		}

		if prov != nil {
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
		}

		items = append(items, item)
	}

	// 1. Top-Level Hardware / Flash
	if hj.Provenance != nil || hj.Flash.Provenance != nil {
		p := hj.Provenance
		if p == nil {
			p = hj.Flash.Provenance
		}
		addItem("Flash Geometry", hj.ChipFamily+"_flash", p)
	}

	for _, reg := range hj.Flash.Regions {
		name := reg.Name
		if name == "" {
			name = fmt.Sprintf("region_0x%08x", reg.Base)
		}
		addItem("Flash Region", name, reg.Provenance)
	}

	// 2. RAM & Reserved Regions
	for _, ram := range hj.ReservedRamRegions {
		addItem("Reserved RAM", ram.Name, ram.Provenance)
	}

	// 3. Register Blocks
	for blockName, block := range hj.RegisterBlocks {
		addItem("Register Block", blockName, block.Provenance)
	}

	// 4. Reset Causes
	if hj.ResetCauses != nil {
		for _, code := range hj.ResetCauses.Codes {
			addItem("Reset Cause", code.Name, code.Provenance)
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

	var b strings.Builder
	b.WriteString("# Hardware Provenance Evidence Report (CRA Annex-I Traceability)\n\n")
	b.WriteString(fmt.Sprintf("**Chip Family:** %s  \n", hj.ChipFamily))
	b.WriteString(fmt.Sprintf("**Total Elements Audited:** %d  \n\n", len(items)))

	b.WriteString("| Component / Element | Category | Source | Reference | Verified Date | Status |\n")
	b.WriteString("|---|---|---|---|---|---|\n")

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

		b.WriteString(fmt.Sprintf("| `%s` | %s | `%s` | %s | %s | **%s** |\n",
			item.Name, item.Category, sourceStr, refStr, verStr, item.Status))
	}

	reportPath := filepath.Join(outDir, "provenance_report.md")
	return os.WriteFile(reportPath, []byte(b.String()), 0o644)
}
