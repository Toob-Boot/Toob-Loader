package elfaudit

import (
	"debug/elf"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// AuditELF inspects a linked ELF binary for mock contamination,
// memory reservation collisions, flash LMA containment, and partition budget overruns.
func AuditELF(elfPath string, config ELFAuditConfig) (*ELFAuditReport, error) {
	switch config.Profile {
	case ProfileProduction, ProfileDev:
	default:
		return nil, fmt.Errorf("elfaudit: invalid profile %q (must be %q or %q)",
			config.Profile, ProfileProduction, ProfileDev)
	}

	f, err := elf.Open(elfPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open ELF binary: %w", err)
	}
	defer func() { _ = f.Close() }()

	report := &ELFAuditReport{
		Timestamp:  time.Now().UTC(),
		BinaryPath: elfPath,
		Profile:    config.Profile,
		Passed:     true,
		Checks:     make([]AuditCheck, 0, 4),
	}

	auditPoisonPill(f, config, report)
	auditMemoryOverlap(f, config, report)
	if config.FlashBounds != nil && config.FlashBounds.Size > 0 {
		auditFlashBounds(f, *config.FlashBounds, report)
	}
	auditBudgetFootprint(f, config, report)

	return report, nil
}

// ExportReportJSON marshals report as indented JSON and writes it to outPath,
// propagating any directory-creation or file-write error.
func ExportReportJSON(report *ELFAuditReport, outPath string) error {
	if report == nil {
		return errors.New("elfaudit: report must not be nil")
	}
	if strings.TrimSpace(outPath) == "" {
		return errors.New("elfaudit: output path must not be empty")
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal ELF audit report: %w", err)
	}
	dir := filepath.Dir(outPath)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return fmt.Errorf("failed to create report directory %s: %w", dir, err)
		}
	}
	if err := os.WriteFile(outPath, data, 0o600); err != nil {
		return fmt.Errorf("failed to write ELF audit report %s: %w", outPath, err)
	}
	return nil
}

func isMockToken(s string) bool {
	lower := strings.ToLower(s)
	return lower == "mock" ||
		strings.HasPrefix(lower, "mock_") ||
		strings.HasSuffix(lower, "_mock") ||
		strings.Contains(lower, "_mock_")
}

func isMockSymbol(sym elf.Symbol) bool {
	if sym.Name == "" {
		return false
	}
	if elf.ST_TYPE(sym.Info) == elf.STT_FILE {
		base := filepath.Base(filepath.FromSlash(sym.Name))
		stem := strings.TrimSuffix(base, filepath.Ext(base))
		return isMockToken(stem)
	}
	return isMockToken(sym.Name)
}

// auditPoisonPill verifies no mock symbols, mock TU file entries, or non-empty
// mock sections leaked into a production binary.
func auditPoisonPill(f *elf.File, config ELFAuditConfig, report *ELFAuditReport) {
	if config.Profile != ProfileProduction {
		addCheck(report, "Mock Poison-Pill", true, "Skipped (profile is 'dev')")
		return
	}

	if sec := f.Section(".toob_mock_section"); sec != nil && sec.Size > 0 {
		addCheck(report, "Mock Poison-Pill", false,
			fmt.Sprintf("Production ELF contains non-empty .toob_mock_section (%d bytes)", sec.Size))
		return
	}

	symbols, err := f.Symbols()
	if err != nil {
		addCheck(report, "Mock Poison-Pill", false, fmt.Sprintf("Cannot read symbol table: %v", err))
		return
	}

	var mockSymbols []string
	for _, sym := range symbols {
		if isMockSymbol(sym) {
			if elf.ST_TYPE(sym.Info) == elf.STT_FILE {
				mockSymbols = append(mockSymbols, sym.Name+" (STT_FILE)")
			} else {
				mockSymbols = append(mockSymbols, sym.Name)
			}
		}
	}

	if len(mockSymbols) > 0 {
		addCheck(report, "Mock Poison-Pill", false,
			fmt.Sprintf("Production ELF contains %d mock symbol(s): %s",
				len(mockSymbols), strings.Join(mockSymbols, ", ")))
	} else {
		addCheck(report, "Mock Poison-Pill", true, "No mock symbols or mock TUs found in production binary")
	}
}

// auditMemoryOverlap checks ELF allocated section placement against reserved hardware regions.
func auditMemoryOverlap(f *elf.File, config ELFAuditConfig, report *ELFAuditReport) {
	if len(config.ReservedRegions) == 0 {
		addCheck(report, "Memory Overlap", true, "No reserved regions configured — check skipped")
		return
	}

	var collisions []string
	for _, section := range f.Sections {
		if section == nil || section.Size == 0 {
			continue
		}
		if section.Flags&elf.SHF_ALLOC == 0 {
			continue
		}
		if section.Size > math.MaxUint64-section.Addr {
			collisions = append(collisions, fmt.Sprintf(
				"section '%s' [0x%X + 0x%X) overflows 64-bit address space",
				section.Name, section.Addr, section.Size,
			))
			continue
		}

		sectionRegion := MemoryRegion{
			Name: section.Name,
			Base: section.Addr,
			Size: section.Size,
		}

		for _, reserved := range config.ReservedRegions {
			if sectionRegion.Overlaps(reserved) {
				collisions = append(collisions, fmt.Sprintf(
					"section '%s' [0x%08X..0x%08X) overlaps reserved '%s' [0x%08X..0x%08X)",
					section.Name, section.Addr, sectionRegion.End(),
					reserved.Name, reserved.Base, reserved.End(),
				))
			}
		}
	}

	if len(collisions) > 0 {
		addCheck(report, "Memory Overlap", false,
			fmt.Sprintf("%d collision(s): %s", len(collisions), strings.Join(collisions, "; ")))
	} else {
		addCheck(report, "Memory Overlap", true,
			fmt.Sprintf("All allocated sections clear of %d reserved region(s)", len(config.ReservedRegions)))
	}
}

// auditFlashBounds verifies that every loadable PT_LOAD segment with Filesz > 0
// has its LMA (p.Paddr) range fully contained within flashBounds.
func auditFlashBounds(f *elf.File, flashBounds MemoryRegion, report *ELFAuditReport) {
	var outOfBounds []string
	checked := 0
	for idx, prog := range f.Progs {
		if prog == nil || prog.Type != elf.PT_LOAD || prog.Filesz == 0 {
			continue
		}
		checked++
		if prog.Filesz > math.MaxUint64-prog.Paddr {
			outOfBounds = append(outOfBounds, fmt.Sprintf(
				"PT_LOAD[%d] LMA [0x%X + 0x%X) overflows 64-bit address space",
				idx, prog.Paddr, prog.Filesz,
			))
			continue
		}
		segLMA := MemoryRegion{
			Name: fmt.Sprintf("PT_LOAD[%d]", idx),
			Base: prog.Paddr,
			Size: prog.Filesz,
		}
		if !flashBounds.ContainsRegion(segLMA) {
			outOfBounds = append(outOfBounds, fmt.Sprintf(
				"PT_LOAD[%d] LMA [0x%08X..0x%08X) (VMA 0x%08X) outside flash window '%s' [0x%08X..0x%08X)",
				idx, segLMA.Base, segLMA.End(), prog.Vaddr,
				flashBounds.Name, flashBounds.Base, flashBounds.End(),
			))
		}
	}

	if len(outOfBounds) > 0 {
		addCheck(report, "Flash LMA Bounds", false, strings.Join(outOfBounds, "; "))
	} else {
		addCheck(report, "Flash LMA Bounds", true,
			fmt.Sprintf("Verified %d loadable PT_LOAD segment LMA(s) within '%s' [0x%08X..0x%08X)",
				checked, flashBounds.Name, flashBounds.Base, flashBounds.End()))
	}
}

// auditBudgetFootprint checks both sum(Filesz) and total occupied flash image span
// max(LMA + Filesz) - min(LMA) across PT_LOAD segments with Filesz > 0 against Stage1MaxBytes.
func auditBudgetFootprint(f *elf.File, config ELFAuditConfig, report *ELFAuditReport) {
	if config.Stage1MaxBytes == 0 {
		addCheck(report, "Budget Footprint", true, "No stage1_size budget configured — check skipped")
		return
	}

	var totalLoadable uint64
	var minLMA uint64 = math.MaxUint64
	var maxLMAEnd uint64
	loadableCount := 0

	for idx, prog := range f.Progs {
		if prog == nil || prog.Type != elf.PT_LOAD || prog.Filesz == 0 {
			continue
		}
		loadableCount++
		if prog.Filesz > math.MaxUint64-totalLoadable {
			addCheck(report, "Budget Footprint", false, "Loadable PT_LOAD segment file sizes overflow uint64")
			return
		}
		totalLoadable += prog.Filesz

		if prog.Filesz > math.MaxUint64-prog.Paddr {
			addCheck(report, "Budget Footprint", false,
				fmt.Sprintf("PT_LOAD[%d] LMA [0x%X + 0x%X) overflows uint64", idx, prog.Paddr, prog.Filesz))
			return
		}
		segEnd := prog.Paddr + prog.Filesz
		if prog.Paddr < minLMA {
			minLMA = prog.Paddr
		}
		if segEnd > maxLMAEnd {
			maxLMAEnd = segEnd
		}
	}

	occupiedSpan := totalLoadable
	if loadableCount > 0 && !config.SegmentedBootrom {
		lmaSpan := maxLMAEnd - minLMA
		if lmaSpan > occupiedSpan {
			occupiedSpan = lmaSpan
		}
	}

	if occupiedSpan > config.Stage1MaxBytes {
		if occupiedSpan > totalLoadable {
			addCheck(report, "Budget Footprint", false,
				fmt.Sprintf("Occupied flash image span %d bytes [0x%08X..0x%08X) (sum(Filesz)=%d bytes) exceeds budget of %d bytes (over by %d)",
					occupiedSpan, minLMA, maxLMAEnd, totalLoadable, config.Stage1MaxBytes, occupiedSpan-config.Stage1MaxBytes))
		} else {
			addCheck(report, "Budget Footprint", false,
				fmt.Sprintf("Loadable footprint %d bytes exceeds stage1_size budget of %d bytes (over by %d)",
					totalLoadable, config.Stage1MaxBytes, totalLoadable-config.Stage1MaxBytes))
		}
		return
	}

	utilization := float64(occupiedSpan) / float64(config.Stage1MaxBytes) * 100
	addCheck(report, "Budget Footprint", true,
		fmt.Sprintf("Occupied flash footprint %d / %d bytes (%.1f%% utilization)",
			occupiedSpan, config.Stage1MaxBytes, utilization))
}

func addCheck(report *ELFAuditReport, name string, passed bool, details string) {
	chk := AuditCheck{
		Name:    name,
		Passed:  passed,
		Details: details,
	}
	report.Checks = append(report.Checks, chk)
	if !passed {
		report.Passed = false
		report.Violations = append(report.Violations, chk)
	}
}
