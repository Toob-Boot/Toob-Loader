package build

import (
	"cmp"
	"errors"
	"fmt"
	"math"
	"strings"
)

const (
	carvedNoinitBytes   uint64 = 0x200
	minLinkerStackBytes uint64 = 0x400
)

type parsedMemoryMap struct {
	iramBase, iramSize   uint64
	sramBase, sramSize   uint64
	hasSram              bool
	lpRAMBase, lpRAMSize uint64
	lpUsableSize         uint64
	hasLpRAM             bool
}

func parseLinkerMemory(hw *HardwareJson) (parsedMemoryMap, error) {
	var m parsedMemoryMap
	if hw == nil {
		return m, errors.New("hardware specification is nil")
	}
	parseWindow := func(labelBase, rawBase, labelSize, rawSize string) (uint64, uint64, error) {
		base, err := parseU64Literal(rawBase)
		if err != nil {
			return 0, 0, fmt.Errorf("%s: %w", labelBase, err)
		}
		size, err := parseU64Literal(rawSize)
		if err != nil {
			return 0, 0, fmt.Errorf("%s: %w", labelSize, err)
		}
		if size == 0 {
			return 0, 0, fmt.Errorf("%s must be greater than zero", labelSize)
		}
		if base <= math.MaxUint32 && base+size > 0x100000000 {
			return 0, 0, fmt.Errorf("[%s + %s] exceeds 32-bit address space", labelBase, labelSize)
		}
		if base > math.MaxUint32 && size > math.MaxUint64-base {
			return 0, 0, fmt.Errorf("[%s + %s] overflows 64-bit address space", labelBase, labelSize)
		}
		return base, size, nil
	}

	rawIramBase, rawIramSize, err := parseWindow("memory.iram_base", hw.Memory.IramBase, "memory.iram_size", hw.Memory.IramSize)
	if err != nil {
		return m, err
	}
	m.iramBase, m.iramSize, err = usableRAMWindow(rawIramBase, rawIramSize, hw.ReservedRamRegions)
	if err != nil {
		return m, fmt.Errorf("memory.iram: %w", err)
	}

	if hw.Memory.SramBase != "" || hw.Memory.SramSize != "" {
		if hw.Memory.SramBase == "" || hw.Memory.SramSize == "" {
			return m, errors.New("memory.sram_base and memory.sram_size must both be set")
		}
		rawSramBase, rawSramSize, sErr := parseWindow("memory.sram_base", hw.Memory.SramBase, "memory.sram_size", hw.Memory.SramSize)
		if sErr != nil {
			return m, sErr
		}
		m.sramBase, m.sramSize, err = usableRAMWindow(rawSramBase, rawSramSize, hw.ReservedRamRegions)
		if err != nil {
			return m, fmt.Errorf("memory.sram: %w", err)
		}
		m.hasSram = true
	} else {
		m.sramBase, m.sramSize = m.iramBase, m.iramSize
	}

	if hw.Memory.LpRamBase != "" || hw.Memory.LpRamSize != "" {
		if hw.Memory.LpRamBase == "" || hw.Memory.LpRamSize == "" {
			return m, errors.New("memory.lp_ram_base and memory.lp_ram_size must both be set")
		}
		rawLpBase, rawLpSize, lErr := parseWindow("memory.lp_ram_base", hw.Memory.LpRamBase, "memory.lp_ram_size", hw.Memory.LpRamSize)
		if lErr != nil {
			return m, lErr
		}
		lpBase, lpLen, uErr := usableRAMWindow(rawLpBase, rawLpSize, hw.ReservedRamRegions)
		if uErr != nil {
			return m, fmt.Errorf("memory.lp_ram: %w", uErr)
		}
		m.lpRAMBase = lpBase
		m.lpRAMSize = rawLpSize
		m.lpUsableSize = lpLen
		m.hasLpRAM = m.lpUsableSize > 0
		return m, nil
	}

	// CRIT-44: When lp_ram_base is omitted, carve a fixed 512-byte (8-byte aligned)
	// .noinit region at the top of usable SRAM so _noinit_base is identical across
	// Stage 0, Stage 1, Recovery OS, and App without overlapping .bss or stack.
	if m.sramSize <= carvedNoinitBytes {
		return m, fmt.Errorf("usable SRAM (%d bytes) is too small to carve %d-byte shared .noinit region",
			m.sramSize, carvedNoinitBytes)
	}
	noinitBase := (m.sramBase + m.sramSize - carvedNoinitBytes) &^ 7
	if noinitBase <= m.sramBase {
		return m, errors.New("usable SRAM cannot accommodate aligned 512-byte .noinit carve-out")
	}
	m.sramSize = noinitBase - m.sramBase
	if m.iramBase < noinitBase+carvedNoinitBytes && noinitBase < m.iramBase+m.iramSize {
		if noinitBase <= m.iramBase {
			return m, errors.New("usable IRAM overlaps .noinit carve-out with zero remaining code space")
		}
		m.iramSize = noinitBase - m.iramBase
	}
	m.lpRAMBase = noinitBase
	m.lpRAMSize = carvedNoinitBytes
	m.lpUsableSize = carvedNoinitBytes
	m.hasLpRAM = true
	return m, nil
}

// usableRAMWindow subtracts every reserved RAM region from [base, base+size)
// (trimming head, tail, and interior carve-outs) and returns the largest
// remaining contiguous usable window (MED-46).
func usableRAMWindow(base, size uint64, reserved []ReservedRamRegion) (uint64, uint64, error) {
	type span struct{ start, end uint64 }
	spans := []span{{base, base + size}}

	for _, r := range reserved {
		rBase, err := parseU64Literal(r.Base)
		if err != nil {
			return 0, 0, fmt.Errorf("reserved_ram_regions[%s].base: %w", r.Name, err)
		}
		if r.Size == 0 {
			return 0, 0, fmt.Errorf("reserved_ram_regions[%s].size must be > 0", r.Name)
		}
		if uint64(r.Size) > math.MaxUint64-rBase {
			return 0, 0, fmt.Errorf("reserved_ram_regions[%s] overflows uint64", r.Name)
		}
		rEnd := rBase + uint64(r.Size)

		next := make([]span, 0, len(spans)+1)
		for _, sp := range spans {
			if rEnd <= sp.start || rBase >= sp.end {
				next = append(next, sp)
				continue
			}
			if rBase > sp.start {
				next = append(next, span{sp.start, rBase})
			}
			if rEnd < sp.end {
				next = append(next, span{rEnd, sp.end})
			}
		}
		spans = next
	}

	var best span
	for _, sp := range spans {
		if sp.end > sp.start && (sp.end-sp.start) > (best.end-best.start) {
			best = sp
		}
	}
	if best.end <= best.start {
		return 0, 0, fmt.Errorf("reserved_ram_regions consume entire RAM window [0x%X..0x%X)", base, base+size)
	}
	return best.start, best.end - best.start, nil
}

// execFlashBase returns xip_base when non-zero, otherwise physical flash.base (CRIT-20).
func execFlashBase(cfg *ResolvedConfig, hw *HardwareJson) (uint64, error) {
	if cfg != nil {
		if cfg.XipBaseVal != 0 {
			return cfg.XipBaseVal, nil
		}
		return uint64(cfg.FlashBase), nil
	}
	if hw != nil {
		if hw.Flash.XipBase != "" {
			v, err := parseU64Literal(hw.Flash.XipBase)
			if err != nil {
				return 0, fmt.Errorf("flash.xip_base: %w", err)
			}
			if v != 0 {
				return v, nil
			}
		}
		physBase, _, err := resolveFlashBase(&hw.Flash)
		if err != nil {
			return 0, err
		}
		return uint64(physBase), nil
	}
	return 0, nil
}

func slotExecOrigin(slot PartitionSlot, windowBase, execBase uint64) uint64 {
	if slot.Budget == 0 {
		return execBase
	}
	rel := uint64(slot.Addr)
	if rel >= windowBase {
		rel -= windowBase
	}
	return execBase + rel
}

func checkSlotExecBounds(slot PartitionSlot, windowBase, execBase uint64) error {
	if slot.Budget == 0 {
		return nil
	}
	origin := slotExecOrigin(slot, windowBase, execBase)
	if execBase <= math.MaxUint32 && origin+uint64(slot.Budget) > 0x100000000 {
		return fmt.Errorf("%s execution window [0x%X..0x%X) exceeds 32-bit address space",
			slot.Name, origin, origin+uint64(slot.Budget))
	}
	return nil
}

func resolveStage0ExecMode(ctx *Context, hw *HardwareJson) string {
	mode, err := resolveStage0ExecModeChecked(ctx, hw)
	if err != nil {
		return "xip"
	}
	return mode
}

func resolveStage0ExecModeChecked(ctx *Context, hw *HardwareJson) (string, error) {
	var raw string
	switch {
	case ctx != nil && ctx.Chip != nil && ctx.Chip.Stage0ExecMode != "":
		raw = ctx.Chip.Stage0ExecMode
	case hw != nil && hw.Flash.Stage0ExecMode != "":
		raw = hw.Flash.Stage0ExecMode
	}
	if raw != "" {
		mode := strings.ToLower(strings.TrimSpace(raw))
		if mode != "ram" && mode != "xip" {
			return "", fmt.Errorf("invalid stage0_exec_mode %q (must be 'ram' or 'xip')", raw)
		}
		return mode, nil
	}
	return "xip", nil
}

func resolveLinkerEntry(ctx *Context, hw *HardwareJson, fallback string) (string, error) {
	var sym string
	switch {
	case ctx != nil && ctx.Chip != nil && ctx.Chip.EntrySymbol != "":
		sym = ctx.Chip.EntrySymbol
	case hw != nil && hw.Flash.EntrySymbol != "":
		sym = hw.Flash.EntrySymbol
	default:
		sym = fallback
	}
	if !isCSymbol(sym) {
		return "", fmt.Errorf("invalid entry_symbol %q", sym)
	}
	return sym, nil
}

func ldHex(v uint64) string {
	if v > math.MaxUint32 {
		return fmt.Sprintf("0x%016X", v)
	}
	return fmt.Sprintf("0x%08X", v)
}

func flashDromBase(hw *HardwareJson) (uint64, error) {
	if hw == nil {
		return 0, nil
	}
	raw, ok := hw.RegistersFlat["flash_drom_base"]
	if !ok || raw == "" {
		return 0, nil
	}
	v, err := parseU64Literal(raw)
	if err != nil {
		return 0, fmt.Errorf("registers_flat.flash_drom_base: %w", err)
	}
	return v, nil
}

func isSegmentedBootrom(hw *HardwareJson) bool {
	if hw == nil || hw.BootromImage == nil {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(hw.BootromImage.Layout), BootromLayoutSegmented) {
		return true
	}
	ext := strings.ToLower(strings.TrimSpace(hw.BootromImage.Extends))
	return strings.Contains(ext, "soc/esp/")
}

// renderMemoryLD renders generated_memory.ld with all partition and RAM origins/lengths
// (CRIT-18, HIGH-19, CRIT-20, CRIT-44). Emits symbol definitions only so chip scripts
// that INCLUDE generated_memory.ld before their own MEMORY block remain valid.
func renderMemoryLD(ctx *Context, cfg *ResolvedConfig, l *PartitionLayout) *cSource {
	s := newCFile()
	var hw *HardwareJson
	if ctx != nil {
		hw = ctx.Hardware
	}
	execBase, err := execFlashBase(cfg, hw)
	if err != nil {
		s.err = fmt.Errorf("generated_memory.ld: %w", err)
		return s
	}
	dromBase, err := flashDromBase(hw)
	if err != nil {
		s.err = fmt.Errorf("generated_memory.ld: %w", err)
		return s
	}
	windowBase := l.FlashBase

	emitSlot := func(prefix string, slot PartitionSlot) {
		if s.err == nil {
			s.err = checkSlotExecBounds(slot, windowBase, execBase)
		}
		s.linef("__%s_ORIGIN = %s;", prefix, ldHex(slotExecOrigin(slot, windowBase, execBase)))
		s.linef("__%s_LENGTH = 0x%08X;", prefix, slot.Budget)
		if dromBase != 0 && dromBase != execBase {
			if s.err == nil {
				s.err = checkSlotExecBounds(slot, windowBase, dromBase)
			}
			s.linef("__%s_DROM_ORIGIN = %s;", prefix, ldHex(slotExecOrigin(slot, windowBase, dromBase)))
		}
	}
	emitSlot("STAGE0", l.Stage0)
	emitSlot("STAGE1A", l.Stage1A)
	emitSlot("STAGE1B", l.Stage1B)
	emitSlot("APP_SLOT", l.App)
	emitSlot("STAGING_SLOT", l.Staging)
	emitSlot("RECOVERY_SLOT", l.Recovery)
	emitSlot("SCRATCH_SLOT", l.Scratch)
	emitSlot("WAL", l.Wal)
	emitSlot("MAILBOX", l.Mailbox)
	s.blank()

	if hw != nil {
		mem, err := parseLinkerMemory(hw)
		if err != nil {
			s.err = fmt.Errorf("generated_memory.ld: %w", err)
			return s
		}
		s.linef("__IRAM_ORIGIN = %s;", ldHex(mem.iramBase))
		s.linef("__IRAM_LENGTH = %s;", ldHex(mem.iramSize))
		s.linef("__SRAM_ORIGIN = %s;", ldHex(mem.sramBase))
		s.linef("__SRAM_LENGTH = %s;", ldHex(mem.sramSize))
		s.linef("__LP_RAM_ORIGIN = %s;", ldHex(mem.lpRAMBase))
		s.linef("__LP_RAM_LENGTH = %s;", ldHex(mem.lpUsableSize))
		s.blank()
	}

	var s1MaxPayload uint32
	if l.Stage1A.Budget >= stage1SignedEnvelopeBytes {
		s1MaxPayload = l.Stage1A.Budget - stage1SignedEnvelopeBytes
	}

	// Backward-compatible budget aliases for existing chip linker scripts.
	s.linef("__S0_BUDGET_START = %s;", ldHex(slotExecOrigin(l.Stage0, windowBase, execBase)))
	s.linef("__S0_BUDGET_SIZE = 0x%08X;", l.Stage0.Budget)
	s.linef("__S1A_BUDGET_START = %s;", ldHex(slotExecOrigin(l.Stage1A, windowBase, execBase)))
	s.linef("__S1B_BUDGET_START = %s;", ldHex(slotExecOrigin(l.Stage1B, windowBase, execBase)))
	s.linef("__S1_BUDGET_SIZE = 0x%08X;", l.Stage1A.Budget)
	s.linef("__S1_MAX_PAYLOAD_SIZE = 0x%08X;", s1MaxPayload)
	s.linef("__APP_BUDGET_START = %s;", ldHex(slotExecOrigin(l.App, windowBase, execBase)))
	s.linef("__APP_BUDGET_SIZE = 0x%08X;", l.App.Budget)
	return s
}

func renderStage0LDForContext(ctx *Context, hw *HardwareJson) *cSource {
	s := newCFile()
	if hw == nil && ctx != nil {
		hw = ctx.Hardware
	}
	mem, err := parseLinkerMemory(hw)
	if err != nil {
		s.err = fmt.Errorf("stage0 linker layout: %w", err)
		return s
	}
	mode, err := resolveStage0ExecModeChecked(ctx, hw)
	if err != nil {
		s.err = fmt.Errorf("stage0 linker layout: %w", err)
		return s
	}
	entrySym, err := resolveLinkerEntry(ctx, hw, "_stage0_start")
	if err != nil {
		s.err = fmt.Errorf("stage0 linker layout: %w", err)
		return s
	}

	isRAMExec := mode == "ram"
	harvardRAMExec := isRAMExec && mem.hasSram && mem.sramBase != mem.iramBase
	segmentedBootrom := isSegmentedBootrom(hw)
	ramBase, ramSize := mem.iramBase, mem.iramSize
	if mem.hasSram && (!isRAMExec || harvardRAMExec) {
		ramBase, ramSize = mem.sramBase, mem.sramSize
	}
	noinitRegion := "S0_RAM"
	if mem.hasLpRAM {
		noinitRegion = "LP_RAM"
	}

	s.linef("/* Stage 0 Linker Layout (mode: %s) */", mode)
	if entrySym == "_stage0_start" {
		s.line("PROVIDE(_stage0_start = main);")
	}
	s.linef("ENTRY(%s)", entrySym)
	s.blank()
	s.line("INCLUDE " + fileMemoryLD)
	s.blank()
	s.line("MEMORY {")
	if harvardRAMExec {
		s.linef("    S0_IRAM (rx) : ORIGIN = %s, LENGTH = %s", ldHex(mem.iramBase), ldHex(mem.iramSize))
	}
	s.linef("    S0_RAM (rwx) : ORIGIN = %s, LENGTH = %s", ldHex(ramBase), ldHex(ramSize))
	s.line("    S0_ROM (rx)  : ORIGIN = __STAGE0_ORIGIN, LENGTH = __STAGE0_LENGTH")
	if mem.hasLpRAM {
		s.line("    LP_RAM (rw)  : ORIGIN = __LP_RAM_ORIGIN, LENGTH = __LP_RAM_LENGTH")
	}
	s.line("}")
	s.blank()

	outRegion := "S0_ROM"
	switch {
	case harvardRAMExec:
		outRegion = "S0_IRAM"
	case isRAMExec:
		outRegion = "S0_RAM"
	}

	s.line("SECTIONS {")
	s.line("    .text : ALIGN(4) {")
	s.line("        KEEP(*(.isr_vector))")
	s.line("        KEEP(*(.vectors))")
	s.line("        KEEP(*(.stage0_entry))")
	s.line("        KEEP(*(.text.main))")
	s.line("        *(.literal .literal.*)")
	s.line("        *(.text .text.*)")
	s.line("        . = ALIGN(4);")
	s.linef("    } > %s", outRegion)
	s.blank()
	if !harvardRAMExec {
		s.line("    .rodata : ALIGN(4) {")
		s.line("        *(.rodata .rodata.*)")
		s.line("        *(.srodata .srodata.*)")
		s.linef("    } > %s", outRegion)
		s.blank()
	}
	switch {
	case isRAMExec && (!harvardRAMExec || segmentedBootrom):
		s.line("    _sidata = ADDR(.data);")
	default:
		s.line("    _sidata = LOADADDR(.data);")
	}
	s.line("    .data : ALIGN(4) {")
	s.line("        _sdata = .;")
	s.line("        _data_start = .;")
	s.line("        PROVIDE(__global_pointer$ = . + 0x800);")
	if harvardRAMExec {
		s.line("        *(.rodata .rodata.*)")
		s.line("        *(.srodata .srodata.*)")
	}
	s.line("        *(.data .data.*)")
	s.line("        *(.sdata .sdata.*)")
	s.line("        . = ALIGN(4);")
	s.line("        _edata = .;")
	s.line("        _data_end = .;")
	switch {
	case harvardRAMExec && segmentedBootrom:
		s.line("    } > S0_RAM")
	case harvardRAMExec:
		s.line("    } > S0_RAM AT > S0_IRAM")
	case isRAMExec:
		s.line("    } > S0_RAM")
	default:
		s.line("    } > S0_RAM AT > S0_ROM")
	}
	s.blank()
	s.line("    .bss (NOLOAD) : ALIGN(8) {")
	s.line("        _sbss = .;")
	s.line("        _bss_start = .;")
	s.line("        *(.bss .bss.*)")
	s.line("        *(.sbss .sbss.*)")
	s.line("        *(COMMON)")
	s.line("        _ebss = .;")
	s.line("        _bss_end = .;")
	s.line("    } > S0_RAM")
	s.blank()
	s.line("    .noinit (NOLOAD) : ALIGN(8) {")
	s.line("        _noinit_base = .;")
	s.line("        KEEP(*(.noinit.toob_handoff_state))")
	s.line("        . = MAX(., _noinit_base + 0x50);")
	s.line("        KEEP(*(.noinit.toob_diag_state))")
	s.line("        . = MAX(., _noinit_base + 0xD8);")
	s.line("        KEEP(*(.noinit.toob_ota_resume_state))")
	s.line("        . = MAX(., _noinit_base + 0x118);")
	s.line("        . = ALIGN(8);")
	s.line("        *(.noinit .noinit.*)")
	s.linef("    } > %s", noinitRegion)
	s.blank()
	s.line("    .toob_mock_section : ALIGN(4) {")
	s.line("        KEEP(*(.toob_mock_section))")
	s.linef("    } > %s", outRegion)
	s.blank()
	s.line("    _stack_top = ORIGIN(S0_RAM) + LENGTH(S0_RAM);")
	s.linef("    ASSERT(_stack_top >= _ebss + 0x%X, \"Stage 0: insufficient stack space (< %d bytes)\");", minLinkerStackBytes, minLinkerStackBytes)
	if isRAMExec {
		if harvardRAMExec {
			s.line("    ASSERT((SIZEOF(.text) + SIZEOF(.data)) <= LENGTH(S0_ROM), \"Stage 0 RAM-exec image exceeds Stage 0 flash partition budget\");")
		} else {
			s.line("    ASSERT((SIZEOF(.text) + SIZEOF(.rodata) + SIZEOF(.data)) <= LENGTH(S0_ROM), \"Stage 0 RAM-exec image exceeds Stage 0 flash partition budget\");")
		}
	} else {
		s.line("    ASSERT((LOADADDR(.data) + SIZEOF(.data)) <= (ORIGIN(S0_ROM) + LENGTH(S0_ROM)), \"Stage 0 XIP image exceeds Stage 0 flash partition budget\");")
	}
	s.line("}")
	return s
}

// renderFlashLD renders flash_layout.ld for Stage-1A XIP/Flash execution (CRIT-18, HIGH-19).
func renderFlashLD(ctx *Context, cfg *ResolvedConfig, l *PartitionLayout) *cSource {
	return renderSlotExecLD(ctx, cfg, l, "Stage 1A Flash Layout", "__STAGE1A_ORIGIN", "__STAGE1A_DROM_ORIGIN", "__STAGE1A_LENGTH", true, true)
}

// renderFlashStage1BLD renders flash_layout_stage1b.ld for dual-linked Stage-1B XIP execution (CRIT-43).
func renderFlashStage1BLD(ctx *Context, cfg *ResolvedConfig, l *PartitionLayout) *cSource {
	return renderSlotExecLD(ctx, cfg, l, "Stage 1B Flash Layout", "__STAGE1B_ORIGIN", "__STAGE1B_DROM_ORIGIN", "__STAGE1B_LENGTH", true, true)
}

// renderRecoveryLD renders recovery_layout.ld linking Recovery OS to its dedicated
// recovery partition when configured (CRIT-18, HIGH-19).
func renderRecoveryLD(ctx *Context, cfg *ResolvedConfig, l *PartitionLayout) *cSource {
	originSym, dromSym, lengthSym := "__RECOVERY_SLOT_ORIGIN", "__RECOVERY_SLOT_DROM_ORIGIN", "__RECOVERY_SLOT_LENGTH"
	title := "Recovery OS Flash Layout (linked to CHIP_RECOVERY_OS_ABS_ADDR)"
	if l.Recovery.Budget == 0 {
		originSym, dromSym, lengthSym = cmp.Or("", "__APP_SLOT_ORIGIN"), "__APP_SLOT_DROM_ORIGIN", "__APP_SLOT_LENGTH"
		title = "Recovery OS Flash Layout (recovery_size == 0; fallback slot window)"
	}
	return renderSlotExecLD(ctx, cfg, l, title, originSym, dromSym, lengthSym, true, false)
}

func renderSlotExecLD(ctx *Context, cfg *ResolvedConfig, l *PartitionLayout, title, flashOriginSym, dromOriginSym, flashLenSym string, reserveImageHdr, isStage1 bool) *cSource {
	s := newCFile()
	var hw *HardwareJson
	if ctx != nil {
		hw = ctx.Hardware
	}
	mem, err := parseLinkerMemory(hw)
	if err != nil {
		s.err = fmt.Errorf("%s: %w", title, err)
		return s
	}
	entrySym, err := resolveLinkerEntry(ctx, hw, "_start")
	if err != nil {
		s.err = fmt.Errorf("%s: %w", title, err)
		return s
	}

	execBase, err := execFlashBase(cfg, hw)
	if err != nil {
		s.err = fmt.Errorf("%s: %w", title, err)
		return s
	}
	dromBase, err := flashDromBase(hw)
	if err != nil {
		s.err = fmt.Errorf("%s: %w", title, err)
		return s
	}
	hasSeparateDrom := dromBase != 0 && dromBase != execBase

	noinitRegion := "ram"
	if mem.hasLpRAM {
		noinitRegion = "lp_ram"
	}

	s.linef("/* %s */", title)
	s.line("INCLUDE " + fileMemoryLD)
	s.blank()
	s.linef("ENTRY(%s)", entrySym)
	s.blank()
	s.line("MEMORY {")
	s.linef("    flash  (rx)  : ORIGIN = %s, LENGTH = %s", flashOriginSym, flashLenSym)
	if hasSeparateDrom {
		s.linef("    drom   (r)   : ORIGIN = %s, LENGTH = %s", dromOriginSym, flashLenSym)
	}
	s.line("    ram    (rwx) : ORIGIN = __SRAM_ORIGIN, LENGTH = __SRAM_LENGTH")
	if mem.hasLpRAM {
		s.line("    lp_ram (rw)  : ORIGIN = __LP_RAM_ORIGIN, LENGTH = __LP_RAM_LENGTH")
	}
	s.line("}")
	s.blank()
	s.line("SECTIONS {")
	if reserveImageHdr {
		var hdrOff uint32
		switch {
		case cfg != nil && cfg.ImageHeaderOffset >= 0x14:
			hdrOff = cfg.ImageHeaderOffset
		case l != nil && l.ImageHeaderOffset >= 0x14:
			hdrOff = l.ImageHeaderOffset
		default:
			var arch string
			if ctx != nil && ctx.Chip != nil {
				arch = ctx.Chip.Arch
			}
			_, hdrOff = effectiveVtorAndHeaderOffset(arch, hw)
		}
		s.linef("    /* Reserve space for prepended toob_image_header_t (0x14 bytes, entry offset 0x%X) */", hdrOff)
		s.line("    .text (ORIGIN(flash) + 0x14) : AT(ORIGIN(flash) + 0x14) ALIGN(4) {")
		s.line("        _text_start = .;")
		if hdrOff > 0x14 {
			s.line("        FILL(0xFF);")
			if hdrOff >= 0x18 {
				s.line("        LONG(0xFFFFFFFF);")
			}
			s.linef("        . = ORIGIN(flash) + 0x%X;", hdrOff)
		}
	} else {
		s.line("    .text : ALIGN(16) {")
		s.line("        _text_start = .;")
	}
	s.line("        KEEP(*(.isr_vector))")
	s.line("        KEEP(*(.vectors))")
	s.line("        KEEP(*(.entry))")
	s.line("        KEEP(*(.text.main))")
	s.line("        *(.iram1.text .iram1.text.*)")
	s.line("        *(.literal .literal.*)")
	s.line("        *(.text .text.*)")
	s.line("        . = ALIGN(16);")
	s.line("        _text_end = .;")
	s.line("    } > flash")
	s.blank()
	if hasSeparateDrom {
		s.line("    _rodata_lma = ALIGN(LOADADDR(.text) + SIZEOF(.text), 16);")
		s.line("    .rodata (ORIGIN(drom) + (_rodata_lma - ORIGIN(flash))) : AT(_rodata_lma) ALIGN(16) {")
		s.line("        *(.rodata .rodata.*)")
		s.line("        *(.srodata .srodata.*)")
		s.line("        *(.gnu.linkonce.r.*)")
		s.line("        . = ALIGN(16);")
		s.line("    } > drom")
		s.blank()
		s.line("    _data_lma = ALIGN(LOADADDR(.rodata) + SIZEOF(.rodata), 16);")
		s.line("    _sidata = ORIGIN(drom) + (_data_lma - ORIGIN(flash));")
		s.line("    .data : AT(_data_lma) ALIGN(16) {")
	} else {
		s.line("    .rodata : ALIGN(16) {")
		s.line("        *(.rodata .rodata.*)")
		s.line("        *(.srodata .srodata.*)")
		s.line("        *(.gnu.linkonce.r.*)")
		s.line("    } > flash")
		s.blank()
		s.line("    _sidata = LOADADDR(.data);")
		s.line("    .data : ALIGN(16) {")
	}
	s.line("        _sdata = .;")
	s.line("        _data_start = .;")
	s.line("        PROVIDE(__global_pointer$ = . + 0x800);")
	s.line("        *(.data .data.*)")
	s.line("        *(.sdata .sdata.*)")
	s.line("        . = ALIGN(4);")
	s.line("        _edata = .;")
	s.line("        _data_end = .;")
	if hasSeparateDrom {
		s.line("    } > ram")
	} else {
		s.line("    } > ram AT > flash")
	}
	s.blank()
	s.line("    .bss (NOLOAD) : ALIGN(16) {")
	s.line("        _sbss = .;")
	s.line("        _bss_start = .;")
	s.line("        *(.bss .bss.*)")
	s.line("        *(.sbss .sbss.*)")
	s.line("        *(COMMON)")
	s.line("        _ebss = .;")
	s.line("        _bss_end = .;")
	s.line("    } > ram")
	s.blank()
	s.line("    .noinit (NOLOAD) : ALIGN(8) {")
	s.line("        _noinit_base = .;")
	s.line("        KEEP(*(.noinit.toob_handoff_state))")
	s.line("        . = MAX(., _noinit_base + 0x50);")
	s.line("        KEEP(*(.noinit.toob_diag_state))")
	s.line("        . = MAX(., _noinit_base + 0xD8);")
	s.line("        KEEP(*(.noinit.toob_ota_resume_state))")
	s.line("        . = MAX(., _noinit_base + 0x118);")
	s.line("        . = ALIGN(8);")
	s.line("        *(.noinit .noinit.*)")
	s.linef("    } > %s", noinitRegion)
	s.blank()
	if hasSeparateDrom {
		s.line("    _mock_lma = ALIGN(LOADADDR(.data) + SIZEOF(.data), 4);")
		s.line("    .toob_mock_section (_mock_lma) : AT(_mock_lma) ALIGN(4) {")
		s.line("        KEEP(*(.toob_mock_section))")
		s.line("    } > flash")
	} else {
		s.line("    .toob_mock_section : ALIGN(4) {")
		s.line("        KEEP(*(.toob_mock_section))")
		s.line("    } > flash")
	}
	s.blank()
	s.line("    _stack_top = ORIGIN(ram) + LENGTH(ram);")
	s.linef("    ASSERT(_stack_top >= _ebss + 0x%X, \"Insufficient stack space (< %d bytes)\");", minLinkerStackBytes, minLinkerStackBytes)
	lmaExpr := "LOADADDR(.data)"
	if hasSeparateDrom {
		lmaExpr = "_data_lma"
	}
	if isStage1 {
		s.linef("    ASSERT(LENGTH(flash) >= 0x54 && (%s + SIZEOF(.data)) <= (ORIGIN(flash) + LENGTH(flash) - 0x40), \"Stage 1 image + 64-byte signature exceeds Stage 1 partition budget\");", lmaExpr)
	} else {
		s.linef("    ASSERT((%s + SIZEOF(.data)) <= (ORIGIN(flash) + LENGTH(flash)), \"Image exceeds flash partition budget\");", lmaExpr)
	}
	s.line("}")
	return s
}
