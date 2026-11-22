package build

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"
	"unicode"
)

// statusUnverified marks items whose provenance is an automated scan or incomplete.
const (
	statusUnverified           = "UNVERIFIED (SCAN)"
	statusUnverifiedMissingRef = "UNVERIFIED (MISSING REF)"
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

// Unverified reports whether the item relies on an unverified or incomplete source.
func (p ProvenanceItem) Unverified() bool { return strings.HasPrefix(p.Status, "UNVERIFIED") }

// AuditProvenance lists every auditable hardware element with its claimed
// provenance, sorted by category and name. It has no side effects.
func AuditProvenance(hj *HardwareJson) []ProvenanceItem {
	var items []ProvenanceItem

	addItem := func(category, name, claimedValue string, prov *Provenance) {
		item := ProvenanceItem{
			Category:     category,
			Name:         name,
			ClaimedValue: claimedValue,
		}

		if prov != nil && strings.TrimSpace(prov.Source) != "" {
			item.Source = strings.TrimSpace(prov.Source)
			item.Ref = strings.TrimSpace(prov.Ref)
			item.Verified = strings.TrimSpace(prov.Verified)
		} else {
			item.Source = "scan"
			item.Ref = "Unspecified / Automated scan"
		}

		switch {
		case item.Source == "scan":
			item.Status = statusUnverified
		case item.Ref == "":
			item.Status = statusUnverifiedMissingRef
		default:
			item.Status = fmt.Sprintf("SELF_ATTESTED (%s)", item.Source)
		}

		items = append(items, item)
	}

	inheritTop := func(p *Provenance) *Provenance {
		if p != nil {
			return p
		}
		return hj.Provenance
	}

	// 1. Top-Level Hardware / Flash Geometry
	if hj.Provenance != nil || hj.Flash.Provenance != nil {
		p := hj.Flash.Provenance
		if p == nil {
			p = hj.Provenance
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

	// 2. Memory, Crypto Capabilities & BootROM Packing
	if hj.Memory.IramBase != "" || hj.Memory.Provenance != nil {
		claimed := fmt.Sprintf("IRAM: %s (%s)", hj.Memory.IramBase, hj.Memory.IramSize)
		addItem("Memory Layout", hj.ChipFamily+"_memory", claimed, inheritTop(hj.Memory.Provenance))
	}
	if hj.CryptoCapabilities.ArenaSize > 0 || hj.CryptoCapabilities.Provenance != nil {
		claimed := fmt.Sprintf("ArenaSize: %d B", hj.CryptoCapabilities.ArenaSize)
		addItem("Crypto Capabilities", hj.ChipFamily+"_crypto", claimed, inheritTop(hj.CryptoCapabilities.Provenance))
	}
	if hj.BootromImage != nil {
		claimed := fmt.Sprintf("Layout: %s, Extends: %s", cmp.Or(hj.BootromImage.Layout, "inherited"), cmp.Or(hj.BootromImage.Extends, "none"))
		addItem("BootROM Image", hj.ChipFamily+"_bootrom_image", claimed, inheritTop(hj.BootromImage.Provenance))
	}

	// 3. RAM & Reserved Regions
	for _, ram := range hj.ReservedRamRegions {
		claimed := fmt.Sprintf("Base: %s, Size: %d B", ram.Base, ram.Size)
		addItem("Reserved RAM", ram.Name, claimed, ram.Provenance)
	}

	// 4. Register Blocks, Flat Registers & Constants
	for _, blockName := range slices.Sorted(maps.Keys(hj.RegisterBlocks)) {
		block := hj.RegisterBlocks[blockName]
		claimed := fmt.Sprintf("Base: %s, Regs: %d", block.Base, len(block.Regs))
		addItem("Register Block", blockName, claimed, block.Provenance)
	}
	for _, flatName := range slices.Sorted(maps.Keys(hj.RegistersFlat)) {
		addItem("Flat Register", flatName, hj.RegistersFlat[flatName], hj.Provenance)
	}
	for _, regName := range slices.Sorted(maps.Keys(hj.Registers)) {
		addItem("Legacy Register", regName, fmt.Sprintf("%v", hj.Registers[regName]), hj.Provenance)
	}
	if len(hj.Constants) > 0 {
		addItem("Hardware Constants", hj.ChipFamily+"_constants", fmt.Sprintf("Count: %d", len(hj.Constants)), hj.Provenance)
	}

	// 5. Reset Causes
	if hj.ResetCauses != nil {
		for _, code := range hj.ResetCauses.Codes {
			val := uint32(code.Value)
			var claimed string
			if code.Mask != 0 {
				claimed = fmt.Sprintf("Value: 0x%08X, Mask: 0x%08X, Class: %s", val, uint32(code.Mask), code.Class)
			} else {
				claimed = fmt.Sprintf("Value: %d (0x%02X), Class: %s", val, val, code.Class)
			}
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

// renderProvenanceReportWithRaw hashes rawBytes directly when provided so the
// SHA-256 digest matches the exact on-disk hardware.json bytes (MED-13).
func renderProvenanceReportWithRaw(hj *HardwareJson, rawBytes []byte, items []ProvenanceItem, verifyResults []VerifyResult) ([]byte, error) {
	hjBytes := rawBytes
	rawMissing := len(hjBytes) == 0
	if rawMissing {
		var err error
		hjBytes, err = json.Marshal(hj)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal hardware json for hash computation: %w", err)
		}
	}
	hash := sha256.Sum256(hjBytes)
	specHashHex := hex.EncodeToString(hash[:])

	passCount, warnCount, failCount := 0, 0, 0
	for _, r := range verifyResults {
		switch {
		case !r.Passed:
			failCount++
		case r.Warning:
			warnCount++
			passCount++
		default:
			passCount++
		}
	}

	var b strings.Builder
	b.WriteString("# Hardware Provenance Evidence Report (CRA Annex-I Traceability)\n\n")
	fmt.Fprintf(&b, "**Chip Family:** %s  \n", sanitizeMarkdownCell(hj.ChipFamily))
	if rawMissing {
		fmt.Fprintf(&b, "**Hardware Specification Digest (SHA-256):** `%s` *(canonical-JSON SHA-256; raw file bytes unavailable)*  \n", specHashHex)
	} else {
		fmt.Fprintf(&b, "**Hardware Specification Digest (SHA-256):** `%s`  \n", specHashHex)
	}
	fmt.Fprintf(&b, "**Total Elements Audited:** %d  \n", len(items))
	if warnCount > 0 {
		fmt.Fprintf(&b, "**Plausibility Checks:** %d passed (%d warning), %d failed  \n\n", passCount, warnCount, failCount)
	} else {
		fmt.Fprintf(&b, "**Plausibility Checks:** %d passed, %d failed  \n\n", passCount, failCount)
	}

	b.WriteString("## Traceability Matrix\n\n")
	b.WriteString("| Component / Element | Category | Claimed Value | Source | Reference | Verified Date | Status |\n")
	b.WriteString("|---|---|---|---|---|---|---|\n")
	for _, item := range items {
		fmt.Fprintf(&b, "| `%s` | %s | `%s` | `%s` | %s | %s | **%s** |\n",
			sanitizeMarkdownCode(item.Name),
			sanitizeMarkdownCell(item.Category),
			sanitizeMarkdownCode(item.ClaimedValue),
			sanitizeMarkdownCode(item.Source),
			sanitizeMarkdownCell(cmp.Or(item.Ref, "N/A")),
			sanitizeMarkdownCell(cmp.Or(item.Verified, "N/A")),
			sanitizeMarkdownCell(item.Status))
	}

	b.WriteString("\n## Plausibility Verification\n\n")
	b.WriteString("| Check | Result | Details |\n")
	b.WriteString("|---|---|---|\n")
	for _, r := range verifyResults {
		status := "PASS"
		if !r.Passed {
			status = "FAIL"
		} else if r.Warning {
			status = "WARN"
		}
		fmt.Fprintf(&b, "| %s: %s | **%s** | %s |\n",
			sanitizeMarkdownCell(r.Check),
			sanitizeMarkdownCell(r.Name),
			status,
			sanitizeMarkdownCell(r.Details))
	}

	return []byte(b.String()), nil
}

// sanitizeMarkdownCell neutralizes control characters and table/inline-code
// delimiters so untrusted manifest text cannot forge Markdown rows or columns.
func sanitizeMarkdownCell(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if unicode.IsControl(r) || r == unicode.ReplacementChar {
			b.WriteByte(' ')
			continue
		}
		switch r {
		case '\\', '|', '`':
			b.WriteByte('\\')
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// sanitizeMarkdownCode neutralizes backticks, pipes, and control characters
// inside backtick-delimited table cells.
func sanitizeMarkdownCode(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if unicode.IsControl(r) || r == unicode.ReplacementChar {
			b.WriteByte(' ')
			continue
		}
		switch r {
		case '`':
			b.WriteByte('\'')
		case '|':
			b.WriteString(`\|`)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
