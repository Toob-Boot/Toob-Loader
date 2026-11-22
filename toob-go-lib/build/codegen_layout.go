package build

import (
	"cmp"
	"fmt"
)

// renderBootLayout renders boot_layout.h from the layout region table.
func renderBootLayout(l *PartitionLayout) *cSource {
	s := newCHeader("BOOT_LAYOUT_H")
	for _, r := range l.regions() {
		s.define(r.addrMacro, hex32(r.slot.Addr))
		s.define(r.sizeMacro, hex32(r.slot.Budget))
		for _, m := range r.extras {
			s.define(m.name, m.value)
		}
		s.blank()
	}
	immutableEnd := l.FlashBase
	if l.Stage0.Budget > 0 {
		immutableEnd = uint64(l.Stage0.Addr) + uint64(l.Stage0.Budget)
	}
	s.define("CHIP_FLASH_IMMUTABLE_BOOT_END", cAddrUint64(immutableEnd))
	defineLayoutHint(s, "CHIP_STAGE0_BYTE_SIZE", hex32(l.Stage0.Budget))

	execBase := l.FlashBase
	if l.XipBaseVal != 0 {
		execBase = l.XipBaseVal
	}
	xipEnd := slotExecOrigin(l.Stage0, l.FlashBase, execBase) + uint64(l.Stage0.Budget)
	defineLayoutHint(s, "CHIP_FLASH_IMMUTABLE_BOOT_XIP_END", cAddrUint64(xipEnd))
	s.blank()
	return s
}

// renderLayoutAsserts renders boot_layout_assert.h, which re-checks the layout
// invariants inside the C compiler so a hand-edited header cannot slip through.
func renderLayoutAsserts(cfg *ResolvedConfig, hw *HardwareJson, l *PartitionLayout) *cSource {
	regions := l.regions()
	s := newCHeader("BOOT_LAYOUT_ASSERT_H")
	s.line("#include <stdint.h>")
	s.line(`#include "` + fileBootLayout + `"`)
	s.blank()

	s.line("/* Helper macro to assert two regions do not overlap (64-bit wrap-safe, MED-13) */")
	s.line("#define BOOT_CHECK_DISJOINT(a_base, a_size, b_base, b_size) \\")
	s.line("    ( ((uint64_t)(a_size) == 0ULL) || ((uint64_t)(b_size) == 0ULL) || \\")
	s.line("      (((uint64_t)(a_base) + (uint64_t)(a_size)) <= (uint64_t)(b_base)) || \\")
	s.line("      (((uint64_t)(b_base) + (uint64_t)(b_size)) <= (uint64_t)(a_base)) )")
	s.blank()

	s.line("/* 1. Pairwise Disjointness (Overlap-Free) Assertions */")
	for i, a := range regions {
		for _, b := range regions[i+1:] {
			staticAssert(s, fmt.Sprintf("BOOT_CHECK_DISJOINT(%s, %s, %s, %s)", a.addrMacro, a.sizeMacro, b.addrMacro, b.sizeMacro),
				fmt.Sprintf("Layout Overlap: %s and %s overlap!", a.slot.Name, b.slot.Name))
		}
	}
	s.blank()

	s.line("/* 2. Local Sector Alignment Assertions (CRIT-19) */")
	for _, r := range regions {
		secAlign := l.slotSectorAlign(r.slot)
		staticAssert(s, fmt.Sprintf("%s == 0U || (%s %% %dU) == 0U", r.sizeMacro, r.addrMacro, secAlign),
			fmt.Sprintf("Layout Alignment: %s is not aligned to local sector size %d!", r.slot.Name, secAlign))
	}

	vtorAlign := l.VtorAlign
	if vtorAlign == 0 && cfg != nil {
		vtorAlign = cfg.VtorAlign
	}
	if vtorAlign == 0 && hw != nil {
		vtorAlign = cmp.Or(hw.Flash.VtorAlignment, hw.Memory.VtorAlignment)
	}
	if vtorAlign > 0 {
		vSlots := []struct{ addr, size, label string }{
			{"CHIP_APP_SLOT_ABS_ADDR", "CHIP_APP_SLOT_SIZE", "App Slot"},
			{"CHIP_STAGING_SLOT_ABS_ADDR", "CHIP_STAGING_SLOT_SIZE", "Staging Slot"},
			{"CHIP_RECOVERY_OS_ABS_ADDR", "CHIP_RECOVERY_OS_SIZE", "Recovery OS"},
		}
		if cfg == nil || cfg.Stage0ExecMode != "ram" {
			vSlots = append([]struct{ addr, size, label string }{
				{"CHIP_STAGE1A_ABS_ADDR", "CHIP_STAGE1A_SIZE", "Stage 1 Bank A"},
				{"CHIP_STAGE1B_ABS_ADDR", "CHIP_STAGE1B_SIZE", "Stage 1 Bank B"},
			}, vSlots...)
		}
		for _, vSlot := range vSlots {
			staticAssert(s, fmt.Sprintf("%s == 0U || (((uint64_t)%s + (uint64_t)CHIP_IMAGE_HEADER_OFFSET) %% %dULL) == 0ULL",
				vSlot.size, vSlot.addr, vtorAlign),
				fmt.Sprintf("HIGH-20: %s + image_header_offset violates vtor_alignment (%d)!", vSlot.label, vtorAlign))
		}
	}
	s.blank()

	s.line("/* 3. Minimum & Maximum Bounds Assertions */")
	s.line("#ifdef CHIP_FLASH_WRITE_ALIGNMENT")
	staticAssert(s, "CHIP_FLASH_WRITE_ALIGNMENT > 0U && CHIP_FLASH_WRITE_ALIGNMENT <= 32U",
		"CRIT-40: CHIP_FLASH_WRITE_ALIGNMENT must be in [1..32] bytes!")
	s.line("#endif")
	staticAssert(s, fmt.Sprintf("TOOB_WAL_SECTORS >= %dU && TOOB_WAL_SECTORS <= %dU", minWalSectors, maxWalSectors),
		fmt.Sprintf("WAL sector count: TOOB_WAL_SECTORS must be in [%d..%d]!", minWalSectors, maxWalSectors))
	for i := range l.WalSectors {
		staticAssert(s, fmt.Sprintf("CHIP_WAL_SECTOR_%d_SIZE >= %dU", i, minWalSectorBytes),
			fmt.Sprintf("WAL sector %d minimum size: must be >= %d bytes (Header+Entry)!", i, minWalSectorBytes))
	}
	scratchSec := l.slotSectorAlign(l.Scratch)
	staticAssert(s, fmt.Sprintf("CHIP_SCRATCH_SLOT_SIZE == 0U || CHIP_SCRATCH_SLOT_SIZE >= %dU", scratchSec),
		fmt.Sprintf("Scratch Slot minimum size: must be >= local sector size %d!", scratchSec))
	if cfg != nil && cfg.Transport == TransportSwapScratch {
		staticAssert(s, "CHIP_SCRATCH_SLOT_SIZE >= CHIP_FLASH_MAX_SECTOR_SIZE",
			"ARCH-T04: scratch_size must be >= max_sector_size for swapscratch")
		if swapSec := l.swapScratchBlockAlign(); swapSec > 0 {
			staticAssert(s, fmt.Sprintf("(CHIP_APP_SLOT_ABS_ADDR %% %dU) == 0U", swapSec),
				fmt.Sprintf("HIGH-41: App Slot must align to swapscratch block size %d!", swapSec))
			staticAssert(s, fmt.Sprintf("CHIP_STAGING_SLOT_SIZE == 0U || (CHIP_STAGING_SLOT_ABS_ADDR %% %dU) == 0U", swapSec),
				fmt.Sprintf("HIGH-41: Staging Slot must align to swapscratch block size %d!", swapSec))
			staticAssert(s, fmt.Sprintf("(CHIP_SCRATCH_SLOT_ABS_ADDR %% %dU) == 0U", swapSec),
				fmt.Sprintf("HIGH-41: Scratch Slot must align to swapscratch block size %d!", swapSec))
		}
	}
	isSwapMoveOrOffset := (cfg != nil && (cfg.Transport == TransportSwapMove || cfg.Transport == TransportSwapOffset)) ||
		l.Transport == TransportSwapMove || l.Transport == TransportSwapOffset
	if isSwapMoveOrOffset {
		stgSec := l.slotSectorAlign(l.Staging)
		staticAssert(s, fmt.Sprintf("CHIP_STAGING_SLOT_SIZE > 0U && ((uint64_t)CHIP_APP_SLOT_SIZE == (uint64_t)CHIP_STAGING_SLOT_SIZE + %dULL)", stgSec),
			fmt.Sprintf("HIGH-44: swapmove/swapoffset requires CHIP_APP_SLOT_SIZE == CHIP_STAGING_SLOT_SIZE + %d!", stgSec))
	}
	if cfg != nil && cfg.EnableDeltas && cfg.Transport != TransportPointer {
		staticAssert(s, "CHIP_SCRATCH_SLOT_SIZE >= CHIP_APP_SLOT_SIZE",
			"HIGH-33: non-pointer delta updates require CHIP_SCRATCH_SLOT_SIZE >= CHIP_APP_SLOT_SIZE")
	}
	if l.IsBankSwap {
		staticAssert(s, fmt.Sprintf("((uint64_t)CHIP_STAGING_SLOT_ABS_ADDR - 0x%XULL) == ((uint64_t)CHIP_APP_SLOT_ABS_ADDR - 0x%XULL)",
			l.Bank2Base, l.Bank1Base),
			"CRIT-41: bank_swap requires mirrored intra-bank offset between App and Staging!")
		staticAssert(s, "CHIP_STAGING_SLOT_SIZE == CHIP_APP_SLOT_SIZE",
			"CRIT-41: bank_swap requires equal App and Staging slot budgets!")
	}
	if l.Stage0Pow2Lock {
		staticAssert(s, "CHIP_STAGE0_SIZE > 0U && (CHIP_STAGE0_SIZE & (CHIP_STAGE0_SIZE - 1U)) == 0U",
			"HIGH-59: Stage 0 size must be a power of two for Cortex-M MPU / NOR lock!")
	}

	kdmSec := l.slotSectorAlign(l.KDM)
	staticAssert(s, fmt.Sprintf("((uint64_t)CHIP_KDM_QUORUM_SIZE) >= %dULL * %dULL", kdmQuorumSectors, kdmSec),
		fmt.Sprintf("KDM Quorum minimum size: must be >= %d sectors for Phase 4 quorum!", kdmQuorumSectors))
	if len(l.KdmSlots) == kdmQuorumSectors {
		for i, ks := range l.KdmSlots {
			ksSec := l.slotSectorAlign(ks)
			staticAssert(s, fmt.Sprintf("(CHIP_KDM_SLOT_%d_ADDR %% %dU) == 0U && CHIP_KDM_SLOT_%d_SIZE == %dU", i, ksSec, i, ksSec),
				fmt.Sprintf("CRIT-37: KDM slot %d must occupy one aligned physical sector (%d)!", i, ksSec))
			staticAssert(s, fmt.Sprintf("(uint64_t)CHIP_KDM_SLOT_%d_ADDR >= (uint64_t)CHIP_KDM_QUORUM_ABS_ADDR && ((uint64_t)CHIP_KDM_SLOT_%d_ADDR + (uint64_t)CHIP_KDM_SLOT_%d_SIZE) <= ((uint64_t)CHIP_KDM_QUORUM_ABS_ADDR + (uint64_t)CHIP_KDM_QUORUM_SIZE)", i, i, i),
				fmt.Sprintf("CRIT-37: KDM slot %d must lie within KDM Quorum partition!", i))
			for j := i + 1; j < len(l.KdmSlots); j++ {
				staticAssert(s, fmt.Sprintf("((uint64_t)CHIP_KDM_SLOT_%d_ADDR + (uint64_t)CHIP_KDM_SLOT_%d_SIZE) <= (uint64_t)CHIP_KDM_SLOT_%d_ADDR", i, i, j),
					fmt.Sprintf("CRIT-37: KDM slots %d and %d overlap or are out of order!", i, j))
			}
		}
	}
	s.blank()

	s.line("/* 4. Wrap-Around / 32-Bit Overflow Protection (MED-13) */")
	for _, r := range regions {
		staticAssert(s, fmt.Sprintf("((uint64_t)%s + (uint64_t)%s) <= 0x100000000ULL && ((uint64_t)%s + (uint64_t)%s) >= (uint64_t)%s",
			r.addrMacro, r.sizeMacro, r.addrMacro, r.sizeMacro, r.addrMacro),
			fmt.Sprintf("Layout Overflow: %s address range wraps around!", r.slot.Name))
	}
	staticAssert(s, "((uint64_t)CHIP_FLASH_IMMUTABLE_BOOT_END) >= ((uint64_t)CHIP_STAGE0_ABS_ADDR + (uint64_t)CHIP_STAGE0_SIZE)",
		"Stage 0 immutable boot firewall must cover Stage 0!")
	s.blank()
	return s
}

func staticAssert(s *cSource, cond, msg string) {
	s.linef("_Static_assert(%s,", cond)
	s.linef("               %q);", msg)
}
