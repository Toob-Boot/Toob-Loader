package build

import (
	"cmp"
	"errors"
	"fmt"
	"maps"
	"math"
	"slices"
	"strings"
)

// renderBootConfig renders generated_boot_config.h. The returned source still
// has to be finished; its defines feed the macro consumption audit.
func renderBootConfig(ctx *Context, cfg *ResolvedConfig, l *PartitionLayout) (*cSource, error) {
	dt, hw := ctx.Device, ctx.Hardware
	s := newCHeader("GENERATED_BOOT_CONFIG_H")
	s.line("#include <stdint.h>")
	s.blank()
	renderPartitionMap(s, l)

	flashBase, err := cU32Literal(cfg.FlashBaseAddr)
	if err != nil {
		return nil, fmt.Errorf("flash.base_addr: %w", err)
	}
	xipBase, _, err := cAddrLiteral(cfg.XipBase)
	if err != nil {
		return nil, fmt.Errorf("flash.xip_base: %w", err)
	}

	s.definef("CHIP_FLASH_WRITE_ALIGNMENT", "%dU", hw.Flash.WriteAlignment)
	s.define("CHIP_FLASH_BASE_ADDR", flashBase)
	s.blank()
	s.definef("CHIP_STAGING_SLOT_ID", "%dU", cfg.StagingSlotID)
	s.blank()

	walAddrs := make([]string, len(l.WalSectors))
	walSizes := make([]string, len(l.WalSectors))
	for i, w := range l.WalSectors {
		walAddrs[i] = hex32(w.Addr)
		walSizes[i] = fmt.Sprintf("%dU", w.Budget)
	}
	s.definef("TOOB_WAL_SECTORS", "%dU", cfg.WalSectors)
	s.defineList("TOOB_WAL_SECTOR_ADDRS", walAddrs)
	s.defineList("TOOB_WAL_SECTOR_SIZES", walSizes)
	s.blank()

	kdmSlots := l.KdmSlots
	if len(kdmSlots) == 0 && l.KDM.Budget >= kdmQuorumSectors {
		unit := l.KDM.Budget / kdmQuorumSectors
		kdmSlots = []PartitionSlot{
			{Addr: l.KDM.Addr, Budget: unit},
			{Addr: l.KDM.Addr + unit, Budget: unit},
			{Addr: l.KDM.Addr + 2*unit, Budget: l.KDM.Budget - 2*unit},
		}
	}
	if len(kdmSlots) > 0 {
		kdmAddrs := make([]string, len(kdmSlots))
		kdmSizes := make([]string, len(kdmSlots))
		for i, ks := range kdmSlots {
			kdmAddrs[i] = hex32(ks.Addr)
			kdmSizes[i] = fmt.Sprintf("%dU", ks.Budget)
		}
		defineLayoutHintList(s, "TOOB_KDM_SLOT_ADDRS", kdmAddrs)
		defineLayoutHintList(s, "TOOB_KDM_SLOT_SIZES", kdmSizes)
		s.blank()
	}

	arenaSize, err := resolveCryptoArenaSize(dt, hw, cfg, l)
	if err != nil {
		return nil, err
	}
	s.definef("BOOT_CRYPTO_ARENA_SIZE", "%dU", arenaSize)
	s.definef("BOOT_WDT_TIMEOUT_MS", "%dU", cfg.WdtTimeoutMs)
	s.blank()
	s.define("CHIP_FLASH_XIP_BASE", xipBase)
	s.define("CHIP_FLASH_TOTAL_SIZE", hex32(hw.Flash.Size))
	s.definef("CHIP_FLASH_MAX_SECTOR_SIZE", "%dU", l.MaxSectorSize)
	s.definef("BOOT_CONFIG_MAX_RETRIES", "%dU", dt.BootConfig.MaxRetries)
	s.definef("BOOT_CONFIG_MAX_RECOVERY_RETRIES", "%dU", dt.BootConfig.MaxRecoveryRetries)
	s.define("BOOT_CONFIG_EDGE_UNATTENDED_MODE", cBool(dt.BootConfig.EdgeUnattendedMode))
	s.definef("BOOT_CONFIG_BACKOFF_BASE_S", "%dU", dt.BootConfig.BackoffBaseS)
	s.definef("BOOT_STAGE1_SVN", "%dU", dt.BootConfig.Stage1Svn)
	s.blank()
	s.definef("TOOB_DEVICE_PRODUCT_ID", "0x%04XU", dt.Identity.ProductID)
	s.definef("TOOB_DEVICE_VENDOR_ID", "0x%04XU", dt.Identity.VendorID)
	s.definef("TOOB_DEVICE_HW_REV", "%dU", dt.Identity.HwRev)

	s.blank()
	s.section("BOOTLOADER FEATURE FLAGS (from device.toml features)")
	defineLayoutHint(s, "TOOB_FEATURE_CLOUD_COMMANDS", cBool(cfg.FeatureCloudCommands))
	defineLayoutHint(s, "TOOB_FEATURE_UART_PROVISIONING", cBool(cfg.FeatureUartProvisioning))
	defineLayoutHint(s, "TOOB_FEATURE_MULTIIMAGE", cBool(cfg.FeatureMultiImage))
	defineLayoutHint(s, "TOOB_FEATURE_DELTA", cBool(cfg.FeatureDelta))
	defineLayoutHint(s, "TOOB_FEATURE_DECOMP", cBool(cfg.FeatureCompression))
	s.blank()

	s.line("#ifndef TOOB_TRANSPORT_SWAPSCRATCH")
	s.line("#define TOOB_TRANSPORT_SWAPSCRATCH 1")
	s.line("#define TOOB_TRANSPORT_ONEWAY      2")
	s.line("#define TOOB_TRANSPORT_SWAPMOVE    3")
	s.line("#define TOOB_TRANSPORT_POINTER     4")
	s.line("#define TOOB_TRANSPORT_SWAPOFFSET  5")
	s.line("#endif")
	s.line("#ifndef TOOB_ONEWAY_BACKUP_NONE")
	s.line("#define TOOB_ONEWAY_BACKUP_NONE          0")
	s.line("#define TOOB_ONEWAY_BACKUP_FULL          1")
	s.line("#define TOOB_ONEWAY_BACKUP_REVERSE_DELTA 2")
	s.line("#endif")
	s.define("TOOB_TRANSPORT_PROVIDER", cfg.Transport.cMacro())
	if cfg.Transport == TransportOneway {
		s.define("TOOB_ONEWAY_BACKUP_MODE", cfg.BackupMode.cMacro())
	}

	if cfg.PqcEnabled {
		if err := ValidatePackageRef("crypto.pqc", cfg.Pqc); err != nil {
			return nil, err
		}
	} else if pqc := strings.TrimSpace(dt.Crypto.Pqc); pqc != "" && !strings.EqualFold(pqc, "none") {
		if err := ValidatePackageRef("crypto.pqc", pqc); err != nil {
			return nil, err
		}
	}
	if dt.Crypto.Hash != "" {
		if strings.EqualFold(strings.TrimSpace(dt.Crypto.Hash), "none") {
			return nil, fmt.Errorf("crypto.hash = %q is forbidden", dt.Crypto.Hash)
		}
		if err := ValidatePackageRef("crypto.hash", dt.Crypto.Hash); err != nil {
			return nil, err
		}
	}
	s.define("TOOB_PQC_ENABLED", cBool(cfg.PqcEnabled))
	if dt.Crypto.Backend != "" {
		if strings.EqualFold(strings.TrimSpace(dt.Crypto.Backend), "none") {
			return nil, fmt.Errorf("crypto.backend = %q is forbidden", dt.Crypto.Backend)
		}
		if err := ValidatePackageRef("crypto.backend", dt.Crypto.Backend); err != nil {
			return nil, err
		}
		defineLayoutHint(s, "TOOB_CRYPTO_BACKEND", `"`+dt.Crypto.Backend+`"`)
	}
	s.blank()

	for _, render := range []func(*cSource, *Context) error{
		renderRegisterBlocks,
		renderFlatRegisters,
		renderLegacyRegisters,
		renderConstants,
		renderResetCauseConstants,
		renderConfirmStorageAlias,
		renderDriverConfig,
		renderSramAndVtor,
		renderLpRAM,
	} {
		if err := render(s, ctx); err != nil {
			return nil, err
		}
	}

	s.line(`#include "` + fileBootLayout + `"`)
	s.line(`#include "` + fileLayoutAssert + `"`)
	s.blank()
	return s, nil
}

func cBool(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// resolveCryptoArenaSize computes BOOT_CRYPTO_ARENA_SIZE from the exact peak
// C arena formula across Merkle leaf verification, streaming SHA-256/decompression,
// and optional ML-DSA PQC verification (HIGH-58 / CRIT-39).
func resolveCryptoArenaSize(dt *DeviceToml, hw *HardwareJson, cfg *ResolvedConfig, l *PartitionLayout) (uint32, error) {
	maxSlot := max(l.App.Budget, l.Staging.Budget, l.Recovery.Budget, l.NetCore.Budget)
	if maxSlot == 0 && dt != nil {
		maxSlot = dt.Partitions.AppSize
	}
	chunks := (uint64(maxSlot) + 4095) / 4096
	if chunks == 0 {
		chunks = 1
	}
	streamOverhead := uint64(512)
	if cfg != nil && cfg.FeatureCompression {
		streamOverhead = 1024
	}
	required := uint64(576) + chunks*32 + streamOverhead
	if cfg != nil && cfg.PqcEnabled {
		required = max(required, uint64(576)+chunks*32+5264, 8192)
	}
	required = (required + 7) &^ 7
	required = max(required, 2048)
	if required > math.MaxUint32 {
		return 0, fmt.Errorf("BOOT_CRYPTO_ARENA_SIZE requirement (%d) overflows uint32", required)
	}

	if cfg != nil && cfg.CryptoArenaOverride > 0 {
		if uint64(cfg.CryptoArenaOverride) < required {
			return 0, fmt.Errorf("FATAL: boot_config.crypto_arena_size (%d) is smaller than peak Merkle/crypto requirement (%d bytes for %d KB slot)",
				cfg.CryptoArenaOverride, required, maxSlot/1024)
		}
		return cfg.CryptoArenaOverride, nil
	}

	base := hw.CryptoCapabilities.ArenaSize
	if base == 8192 && (cfg == nil || !cfg.PqcEnabled) && required <= 4096 {
		return 4096, nil
	}
	return max(base, uint32(required)), nil
}

// mapEntry is one row of the partition map comment.
type mapEntry struct {
	slot PartitionSlot
	end  uint64
}

func renderPartitionMap(s *cSource, l *PartitionLayout) {
	var entries []mapEntry
	for _, r := range l.regions() {
		if r.slot.Budget > 0 {
			entries = append(entries, mapEntry{r.slot, uint64(r.slot.Addr) + uint64(r.slot.Budget)})
		}
	}
	for _, r := range l.Reserved {
		entries = append(entries, mapEntry{r, uint64(r.Addr) + uint64(r.Budget)})
	}
	slices.SortStableFunc(entries, func(a, b mapEntry) int { return cmp.Compare(a.slot.Addr, b.slot.Addr) })

	stats := make(map[SlotKind]uint32, 4)
	s.line("/* ========================================================================")
	s.line(" * PARTITION MAP (Auto-Generated by Manifest Compiler)")
	s.line(" * ========================================================================")
	for _, e := range entries {
		if s.err == nil {
			s.err = validateDisplayText("partition slot name", e.slot.Name)
		}
		stats[e.slot.Kind] += e.slot.Budget
		s.linef(" *   ├──────────────────────────────────────────────────┤ 0x%08X - 0x%08X", e.slot.Addr, e.end)
		s.linef(" *   │  [%-6s] %s (%d KB)", e.slot.Kind, e.slot.Name, e.slot.Budget/1024)
	}
	s.line(" *   └──────────────────────────────────────────────────┘")
	s.line(" *")
	s.line(" * STORAGE SUMMARY:")
	s.linef(" *   Physical Flash Size:   %8d KB", l.FlashSize/1024)
	s.linef(" *   Hardware Reserved:     %8d KB", stats[SlotReserved]/1024)
	s.linef(" *   Bootloader Core:       %8d KB", stats[SlotBoot]/1024)
	s.linef(" *   System & Scratch:      %8d KB", stats[SlotSystem]/1024)
	s.linef(" *   Usable App Space:      %8d KB", stats[SlotApp]/1024)
	usedCapacity := uint64(stats[SlotReserved]) + uint64(stats[SlotBoot]) + uint64(stats[SlotSystem]) + uint64(stats[SlotApp])
	var freeBytes uint64
	if uint64(l.FlashSize) > usedCapacity {
		freeBytes = uint64(l.FlashSize) - usedCapacity
	}
	s.linef(" *   Unallocated / Free:    %8d KB", freeBytes/1024)
	s.line(" * ======================================================================== */")
	s.blank()
}

// renderRegisterBlocks emits base and per-register offset macros (REG-031, MED-16).
func renderRegisterBlocks(s *cSource, ctx *Context) error {
	blocks := ctx.Hardware.RegisterBlocks
	if len(blocks) == 0 {
		return nil
	}
	s.section("HARDWARE REGISTER BLOCKS (from hardware.json register_blocks)")
	for _, name := range slices.Sorted(maps.Keys(blocks)) {
		block := blocks[name]
		baseLit, baseVal, err := cAddrLiteral(block.Base)
		if err != nil {
			return fmt.Errorf("register_blocks.%s.base: %w", name, err)
		}
		baseMacro := "CHIP_REG_" + strings.ToUpper(name) + "_BASE"
		s.define(baseMacro, baseLit)
		for _, reg := range slices.Sorted(maps.Keys(block.Regs)) {
			rawOff := block.Regs[reg]
			offLit, offVal, err := cAddrLiteral(rawOff)
			if err != nil {
				return fmt.Errorf("register_blocks.%s.regs.%s: %w", name, reg, err)
			}
			switch {
			case baseVal <= math.MaxUint32:
				if offVal > math.MaxUint32 || baseVal+offVal > math.MaxUint32 {
					return fmt.Errorf("register_blocks.%s.regs.%s: base + offset overflows uint32", name, reg)
				}
			case offVal > math.MaxUint64-baseVal:
				return fmt.Errorf("register_blocks.%s.regs.%s: base + offset overflows uint64", name, reg)
			case offVal <= math.MaxUint32:
				offLit = rawOff + "ULL"
			}
			s.definef("CHIP_REG_"+strings.ToUpper(name)+"_"+strings.ToUpper(reg), "(%s + %s)", baseMacro, offLit)
		}
		s.blank()
	}
	return nil
}

// renderFlatRegisters emits standalone register addresses (REG-031, MED-16).
func renderFlatRegisters(s *cSource, ctx *Context) error {
	flat := ctx.Hardware.RegistersFlat
	if len(flat) == 0 {
		return nil
	}
	s.section("HARDWARE REGISTERS FLAT (from hardware.json registers_flat)")
	for _, key := range slices.Sorted(maps.Keys(flat)) {
		addr, _, err := cAddrLiteral(flat[key])
		if err != nil {
			return fmt.Errorf("registers_flat.%s: %w", key, err)
		}
		s.define("CHIP_REG_"+strings.ToUpper(key), addr)
	}
	s.blank()
	return nil
}

// renderLegacyRegisters supports the deprecated untyped "registers" map, used
// only when neither register_blocks nor registers_flat is present.
func renderLegacyRegisters(s *cSource, ctx *Context) error {
	hw := ctx.Hardware
	if len(hw.RegisterBlocks) > 0 || len(hw.RegistersFlat) > 0 || len(hw.Registers) == 0 {
		return nil
	}
	s.section("HARDWARE REGISTERS (deprecated: use register_blocks / registers_flat)")
	return renderScalarMap(s, "registers", "CHIP_REG_", hw.Registers)
}

func renderConstants(s *cSource, ctx *Context) error {
	if len(ctx.Hardware.Constants) == 0 {
		return nil
	}
	s.section("CHIP CONSTANTS (from hardware.json constants)")
	return renderScalarMap(s, "constants", "CHIP_", ctx.Hardware.Constants)
}

func renderScalarMap(s *cSource, field, prefix string, m map[string]any) error {
	for _, key := range slices.Sorted(maps.Keys(m)) {
		value, err := cUnsigned(m[key])
		if err != nil {
			return fmt.Errorf("%s.%s: %w", field, key, err)
		}
		s.define(prefix+strings.ToUpper(key), value)
	}
	s.blank()
	return nil
}

// renderResetCauseConstants emits vendor-neutral reset cause constants (HIGH-14, CRIT-21).
func renderResetCauseConstants(s *cSource, ctx *Context) error {
	rc := ctx.Hardware.ResetCauses
	if rc == nil || len(rc.Codes) == 0 {
		return nil
	}
	s.section("RESET CAUSE CONSTANTS (from hardware.json reset_causes)")
	if rc.RegisterOffset != "" {
		offset, err := cU32Literal(rc.RegisterOffset)
		if err != nil {
			return fmt.Errorf("reset_causes.register_offset: %w", err)
		}
		s.define("CHIP_RST_CAUSE_OFFSET", offset)
	}
	if rc.Mask != "" {
		mask, err := cU32Literal(rc.Mask)
		if err != nil {
			return fmt.Errorf("reset_causes.mask: %w", err)
		}
		s.define("CHIP_RST_CAUSE_MASK", mask)
	}
	for _, code := range rc.Codes {
		val := uint32(code.Value)
		if val <= 0xFF && code.Mask == 0 {
			defineLayoutHint(s, "CHIP_RST_"+strings.ToUpper(code.Name), fmt.Sprintf("%dU", val))
		} else {
			defineLayoutHint(s, "CHIP_RST_"+strings.ToUpper(code.Name), fmt.Sprintf("0x%08XU", val))
		}
	}
	s.blank()
	return nil
}

// renderConfirmStorageAlias emits the vendor-neutral ADDR_CONFIRM_RTC_RAM alias
// guarded by #ifdef CHIP_REG_CONFIRM_STORAGE_BASE (HIGH-14).
func renderConfirmStorageAlias(s *cSource, _ *Context) error {
	s.line("#ifdef CHIP_REG_CONFIRM_STORAGE_BASE")
	if _, ok := s.seen["CHIP_REG_CONFIRM_STORAGE_BASE"]; ok {
		s.define("ADDR_CONFIRM_RTC_RAM", "CHIP_REG_CONFIRM_STORAGE_BASE")
	} else {
		s.line("#define ADDR_CONFIRM_RTC_RAM                     CHIP_REG_CONFIRM_STORAGE_BASE")
	}
	s.line("#endif")
	s.blank()
	return nil
}

// renderDriverConfig emits user driver settings from device.toml [driver_config].
// String values must be a safe C constant identifier or unsigned 32-bit literal.
func renderDriverConfig(s *cSource, ctx *Context) error {
	cfg := ctx.Device.DriverConfig
	if len(cfg) == 0 {
		return nil
	}
	s.section("USER DRIVER CONFIGURATION (from device.toml driver_config)")
	for _, key := range slices.Sorted(maps.Keys(cfg)) {
		if !isCSymbol(key) {
			return fmt.Errorf("driver_config.%s: invalid C symbol identifier", key)
		}
		macro := "TOOB_DRIVER_" + strings.ToUpper(key)
		switch v := cfg[key].(type) {
		case string:
			if v == "" || strings.ContainsAny(v, "\r\n\\") || strings.Contains(v, "/*") || strings.Contains(v, "//") {
				return fmt.Errorf("driver_config.%s: string value must be non-empty, single-line and free of comment delimiters", key)
			}
			if isCSymbol(v) {
				s.define(macro, v)
			} else if lit, err := cU32Literal(v); err == nil {
				s.define(macro, lit)
			} else {
				return fmt.Errorf("driver_config.%s: string value %q must be a valid C constant identifier or uint32 literal", key, v)
			}
		case bool:
			s.define(macro, cBool(v))
		default:
			value, err := cUnsigned(v)
			if err != nil {
				return fmt.Errorf("driver_config.%s: %w", key, err)
			}
			s.define(macro, value)
		}
		if strings.EqualFold(key, "uart_baudrate") {
			defineLayoutHint(s, "BOOT_UART_BAUDRATE", macro)
		}
	}
	s.blank()
	return nil
}

// defineLayoutHint emits a macro into the header and tracks uniqueness in s.seen
// without forcing C translation units to reference purely linker/assert hints.
func defineLayoutHint(s *cSource, name, value string) {
	if s.err == nil {
		s.err = s.checkNewMacro(name, value)
	}
	if s.seen == nil {
		s.seen = make(map[string]struct{})
	}
	s.seen[name] = struct{}{}
	s.linef("#define %-40s %s", name, value)
}

// renderSramAndVtor emits IRAM, optional SRAM, and Cortex-M VTOR / header-offset macros (HIGH-20, HIGH-57, MED-48).
func renderSramAndVtor(s *cSource, ctx *Context) error {
	hw := ctx.Hardware
	mem := &hw.Memory
	if mem.IramBase != "" || mem.IramSize != "" {
		if mem.IramBase == "" || mem.IramSize == "" {
			return errors.New("memory.iram_base and memory.iram_size must both be set")
		}
		iramBaseLit, iramBaseVal, err := cAddrLiteral(mem.IramBase)
		if err != nil {
			return fmt.Errorf("memory.iram_base: %w", err)
		}
		iramSizeLit, iramSizeVal, err := cAddrLiteral(mem.IramSize)
		if err != nil {
			return fmt.Errorf("memory.iram_size: %w", err)
		}
		if iramSizeVal == 0 {
			return errors.New("memory.iram_size: must be greater than zero")
		}
		if iramBaseVal <= math.MaxUint32 && iramBaseVal+iramSizeVal > 0x100000000 {
			return errors.New("memory.iram_base + memory.iram_size exceeds the 32-bit address space")
		}
		if iramBaseVal > math.MaxUint32 && iramSizeVal > math.MaxUint64-iramBaseVal {
			return errors.New("memory.iram_base + memory.iram_size overflows the 64-bit address space")
		}
		s.section("IRAM LAYOUT (Instruction / Unified Execution RAM)")
		defineLayoutHint(s, "CHIP_IRAM_BASE", iramBaseLit)
		defineLayoutHint(s, "CHIP_IRAM_SIZE", iramSizeLit)
		s.blank()
	}
	if mem.SramBase != "" || mem.SramSize != "" {
		if mem.SramBase == "" {
			return errors.New("memory.sram_base: must be set when memory.sram_size is configured")
		}
		if mem.SramSize == "" {
			return errors.New("memory.sram_size: must be set when memory.sram_base is configured")
		}
		baseLit, baseVal, err := cAddrLiteral(mem.SramBase)
		if err != nil {
			return fmt.Errorf("memory.sram_base: %w", err)
		}
		sizeLit, sizeVal, err := cAddrLiteral(mem.SramSize)
		if err != nil {
			return fmt.Errorf("memory.sram_size: %w", err)
		}
		if sizeVal == 0 {
			return errors.New("memory.sram_size: must be greater than zero")
		}
		if baseVal <= math.MaxUint32 && baseVal+sizeVal > 0x100000000 {
			return errors.New("memory.sram_base + memory.sram_size exceeds the 32-bit address space")
		}
		if baseVal > math.MaxUint32 && sizeVal > math.MaxUint64-baseVal {
			return errors.New("memory.sram_base + memory.sram_size overflows the 64-bit address space")
		}
		s.section("SRAM LAYOUT (Data / Stack SRAM)")
		defineLayoutHint(s, "CHIP_SRAM_BASE", baseLit)
		defineLayoutHint(s, "CHIP_SRAM_SIZE", sizeLit)
		s.blank()
	}

	var arch string
	if ctx.Chip != nil {
		arch = ctx.Chip.Arch
	}
	vtorAlign, imgHdrOff := effectiveVtorAndHeaderOffset(arch, hw)
	s.section("VECTOR TABLE & IMAGE HEADER ALIGNMENT (HIGH-20 / HIGH-57)")
	if vtorAlign > 0 {
		defineLayoutHint(s, "CHIP_VTOR_ALIGNMENT", fmt.Sprintf("0x%XU", vtorAlign))
	}
	defineLayoutHint(s, "CHIP_IMAGE_HEADER_OFFSET", fmt.Sprintf("0x%XU", imgHdrOff))
	s.blank()
	return nil
}

// renderLpRAM emits the low-power / carved-out .noinit SRAM window that survives
// across boot stages (CRIT-44, MED-48).
func renderLpRAM(s *cSource, ctx *Context) error {
	mem := &ctx.Hardware.Memory
	if mem.LpRamBase != "" || mem.LpRamSize != "" {
		baseLit, baseVal, err := cAddrLiteral(mem.LpRamBase)
		if err != nil {
			return fmt.Errorf("memory.lp_ram_base: %w", err)
		}
		sizeLit, sizeVal, err := cAddrLiteral(mem.LpRamSize)
		if err != nil {
			return fmt.Errorf("memory.lp_ram_size: %w", err)
		}
		if sizeVal == 0 {
			return errors.New("memory.lp_ram_size: must be greater than zero")
		}
		if baseVal <= math.MaxUint32 && baseVal+sizeVal > 0x100000000 {
			return errors.New("memory.lp_ram_base + memory.lp_ram_size exceeds the 32-bit address space")
		}
		if baseVal > math.MaxUint32 && sizeVal > math.MaxUint64-baseVal {
			return errors.New("memory.lp_ram_base + memory.lp_ram_size overflows the 64-bit address space")
		}
		s.section("LP_RAM LAYOUT (Low-Power SRAM, survives resets)")
		defineLayoutHint(s, "CHIP_LP_RAM_BASE", baseLit)
		defineLayoutHint(s, "CHIP_LP_RAM_BASE_ADDR", baseLit)
		defineLayoutHint(s, "CHIP_LP_RAM_SIZE", sizeLit)
		s.blank()
		return nil
	}
	parsed, err := parseLinkerMemory(ctx.Hardware)
	if err != nil {
		return err
	}
	if parsed.hasLpRAM {
		baseLit := cAddrUint64(parsed.lpRAMBase)
		sizeLit := cAddrUint64(parsed.lpUsableSize)
		s.section("LP_RAM LAYOUT (Shared .noinit SRAM carve-out, CRIT-44)")
		defineLayoutHint(s, "CHIP_LP_RAM_BASE", baseLit)
		defineLayoutHint(s, "CHIP_LP_RAM_BASE_ADDR", baseLit)
		defineLayoutHint(s, "CHIP_LP_RAM_SIZE", sizeLit)
		s.blank()
	}
	return nil
}

func cAddrUint64(v uint64) string {
	if v > math.MaxUint32 {
		return fmt.Sprintf("0x%XULL", v)
	}
	return fmt.Sprintf("0x%08XU", uint32(v))
}

// renderChipConfigShim renders chip_config.h, which forwards to the generated config.
func renderChipConfigShim() *cSource {
	s := newCHeader("CHIP_CONFIG_H")
	s.line("/* Compatibility shim (REG-023). */")
	s.line(`#include "` + fileBootConfig + `"`)
	s.blank()
	return s
}
