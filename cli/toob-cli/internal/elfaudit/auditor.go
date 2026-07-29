package elfaudit

import (
	"debug/elf"
	"fmt"
	"strings"
	"time"
)

// AuditELF inspects a linked ELF binary for mock contamination,
// memory reservation collisions, and stage-1 budget overruns.
func AuditELF(elfPath string, config ELFAuditConfig) (*ELFAuditReport, error) {
	f, err := elf.Open(elfPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open ELF binary: %w", err)
	}
	defer f.Close()

	report := &ELFAuditReport{
		Timestamp:  time.Now().UTC(),
		BinaryPath: elfPath,
		Profile:    config.Profile,
		Passed:     true,
		Checks:     make([]AuditCheck, 0, 3),
	}

	auditPoisonPill(f, config, report)
	auditMemoryOverlap(f, config, report)
	auditBudgetFootprint(f, config, report)

	return report, nil
}

// auditPoisonPill verifies no mock symbols leaked into a production binary.
func auditPoisonPill(f *elf.File, config ELFAuditConfig, report *ELFAuditReport) {
	if config.Profile != "production" {
		addCheck(report, "Mock Poison-Pill", true, "Skipped (profile is not 'production')")
		return
	}

	symbols, err := f.Symbols()
	if err != nil {
		addCheck(report, "Mock Poison-Pill", false, fmt.Sprintf("Cannot read symbol table: %v", err))
		return
	}

	var mockSymbols []string
	for _, sym := range symbols {
		if strings.Contains(sym.Name, "_mock") {
			mockSymbols = append(mockSymbols, sym.Name)
		}
	}

	if len(mockSymbols) > 0 {
		report.Passed = false
		addCheck(report, "Mock Poison-Pill", false,
			fmt.Sprintf("Production ELF contains %d mock symbol(s): %s",
				len(mockSymbols), strings.Join(mockSymbols, ", ")))
	} else {
		addCheck(report, "Mock Poison-Pill", true, "No mock symbols found in production binary")
	}
}

// auditMemoryOverlap checks ELF section placement against reserved hardware regions.
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
		// Only check allocated sections (SHF_ALLOC flag set)
		if section.Flags&elf.SHF_ALLOC == 0 {
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
					section.Name, section.Addr, section.Addr+section.Size,
					reserved.Name, reserved.Base, reserved.End()))
			}
		}
	}

	if len(collisions) > 0 {
		report.Passed = false
		addCheck(report, "Memory Overlap", false,
			fmt.Sprintf("%d collision(s): %s", len(collisions), strings.Join(collisions, "; ")))
	} else {
		addCheck(report, "Memory Overlap", true,
			fmt.Sprintf("All allocated sections clear of %d reserved region(s)", len(config.ReservedRegions)))
	}
}

// auditBudgetFootprint sums all loadable ELF content and compares against Stage1MaxBytes.
func auditBudgetFootprint(f *elf.File, config ELFAuditConfig, report *ELFAuditReport) {
	if config.Stage1MaxBytes == 0 {
		addCheck(report, "Budget Footprint", true, "No stage1_size budget configured — check skipped")
		return
	}

	var totalLoadable uint64
	for _, prog := range f.Progs {
		if prog.Type == elf.PT_LOAD {
			totalLoadable += prog.Memsz
		}
	}

	if totalLoadable > config.Stage1MaxBytes {
		report.Passed = false
		addCheck(report, "Budget Footprint", false,
			fmt.Sprintf("Loadable footprint %d bytes exceeds stage1_size budget of %d bytes (over by %d)",
				totalLoadable, config.Stage1MaxBytes, totalLoadable-config.Stage1MaxBytes))
	} else {
		utilization := float64(0)
		if config.Stage1MaxBytes > 0 {
			utilization = float64(totalLoadable) / float64(config.Stage1MaxBytes) * 100
		}
		addCheck(report, "Budget Footprint", true,
			fmt.Sprintf("Loadable footprint %d / %d bytes (%.1f%% utilization)",
				totalLoadable, config.Stage1MaxBytes, utilization))
	}
}

func addCheck(report *ELFAuditReport, name string, passed bool, details string) {
	report.Checks = append(report.Checks, AuditCheck{
		Name:    name,
		Passed:  passed,
		Details: details,
	})
}
