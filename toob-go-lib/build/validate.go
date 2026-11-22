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

// contextRule is one independent semantic check over the loaded inputs.
type contextRule func(*Context) error

// contextRules is evaluated in order; the first violation aborts the build.
var contextRules = []contextRule{
	checkChipIdentity,
	checkProductIdentity,
	checkFlashGeometry,
	checkMemory,
	checkMandatoryPartitions,
	checkBootConfig,
	checkResetCauses,
	checkHardwareConstantsAndMaps,
	checkDeltaCoherence,
	checkRecoveryJustification,
	checkVersionPins,
	checkManifestReferences,
	checkMetadataText,
}

func validateContext(ctx *Context) error {
	for _, rule := range contextRules {
		if err := rule(ctx); err != nil {
			return err
		}
	}
	return nil
}

// normalizeChipName makes "ESP32-C6" and "esp32c6" compare equal.
func normalizeChipName(s string) string {
	return strings.ToLower(strings.ReplaceAll(s, "-", ""))
}

func checkChipIdentity(ctx *Context) error {
	device := normalizeChipName(ctx.Device.Device.Chip)
	hardware := normalizeChipName(ctx.Hardware.ChipFamily)
	if device == "" {
		return errors.New("FATAL: device.toml must define [device] chip")
	}
	if err := ValidateName("chip", ctx.Device.Device.Chip); err != nil {
		return fmt.Errorf("FATAL: device.toml [device] chip: %w", err)
	}
	if err := ValidateName("chip_family", ctx.Hardware.ChipFamily); err != nil {
		return fmt.Errorf("FATAL: hardware.json chip_family: %w", err)
	}
	if device != hardware {
		return fmt.Errorf("FATAL: device.toml chip (%s) does not match hardware.json chip_family (%s)", device, hardware)
	}
	if ctx.Chip != nil {
		if ctx.Chip.Name != "" {
			if err := ValidateName("chip", ctx.Chip.Name); err != nil {
				return fmt.Errorf("FATAL: chip_manifest.json name: %w", err)
			}
			if normalizeChipName(ctx.Chip.Name) != hardware {
				return fmt.Errorf("FATAL: chip_manifest.json name (%s) does not match hardware.json chip_family (%s)",
					normalizeChipName(ctx.Chip.Name), hardware)
			}
		}
		if ctx.Chip.CompilerPrefix != "" {
			if err := ValidateName("compiler prefix", ctx.Chip.CompilerPrefix); err != nil {
				return fmt.Errorf("FATAL: chip_manifest.json compiler_prefix: %w", err)
			}
		}
		if ctx.Chip.SlotCapabilities != nil {
			caps := ctx.Chip.SlotCapabilities
			switch caps.ExecModel {
			case "fixed", "relocatable", "xip_remap", "bank_swap":
			default:
				return fmt.Errorf("FATAL: chip_manifest.json slot_capabilities.exec_model %q must be one of [fixed, relocatable, xip_remap, bank_swap]",
					caps.ExecModel)
			}
			if caps.SlotCount < 1 || caps.SlotCount > 2 {
				return fmt.Errorf("FATAL: chip_manifest.json slot_capabilities.slot_count (%d) must be 1 or 2",
					caps.SlotCount)
			}
			if dm, ok := ctx.Drivers["slot_caps"]; ok && dm != nil && dm.ExecModel != "" && dm.ExecModel != caps.ExecModel {
				return fmt.Errorf("FATAL: slot_caps driver '%s' exec_model (%s) conflicts with chip_manifest.json slot_capabilities.exec_model (%s)",
					dm.Name, dm.ExecModel, caps.ExecModel)
			}
		}
	}
	return nil
}

func checkProductIdentity(ctx *Context) error {
	id := ctx.Device.Identity
	if id.ProductID == 0 || id.ProductID == 0xFFFF {
		return errors.New("FATAL: device.toml must define non-zero [identity] product_id (0xFFFF is reserved/skipped)")
	}
	if id.VendorID == 0 || id.VendorID == 0xFFFF {
		return errors.New("FATAL: device.toml must define non-zero [identity] vendor_id (0xFFFF is reserved/skipped)")
	}
	return nil
}

func checkRAMWindow(baseField, rawBase, sizeField, rawSize string) (uint64, uint64, error) {
	base, err := parseU64Literal(rawBase)
	if err != nil {
		return 0, 0, fmt.Errorf("FATAL: %s: %w", baseField, err)
	}
	if base%4 != 0 {
		return 0, 0, fmt.Errorf("FATAL: %s (0x%X) must be 4-byte aligned", baseField, base)
	}
	size, err := parseU64Literal(rawSize)
	if err != nil {
		return 0, 0, fmt.Errorf("FATAL: %s: %w", sizeField, err)
	}
	if size == 0 {
		return 0, 0, fmt.Errorf("FATAL: %s must be greater than zero", sizeField)
	}
	if base <= math.MaxUint32 {
		if size > 0x100000000-base {
			return 0, 0, fmt.Errorf("FATAL: %s (0x%08X) + %s (0x%X) exceeds the 32-bit address space",
				baseField, base, sizeField, size)
		}
		return base, size, nil
	}
	if size > math.MaxUint64-base {
		return 0, 0, fmt.Errorf("FATAL: %s (0x%X) + %s (0x%X) overflows the 64-bit address space",
			baseField, base, sizeField, size)
	}
	return base, size, nil
}

func checkMemory(ctx *Context) error {
	hw := ctx.Hardware
	if hw.CryptoCapabilities.ArenaSize == 0 {
		return errors.New("FATAL: crypto_capabilities.arena_size is mandatory in hardware.json")
	}
	_, pqcEnabled := effectiveCryptoPqc(ctx)
	minArena := uint32(2048)
	if pqcEnabled {
		minArena = 8192
	}
	if hw.CryptoCapabilities.ArenaSize < minArena || hw.CryptoCapabilities.ArenaSize%8 != 0 {
		return fmt.Errorf("FATAL: crypto_capabilities.arena_size = %d must be >= %d and 8-byte aligned",
			hw.CryptoCapabilities.ArenaSize, minArena)
	}
	if hw.Memory.IramBase == "" || hw.Memory.IramSize == "" {
		return errors.New("FATAL: memory.iram_base and memory.iram_size are mandatory in hardware.json")
	}
	iramBase, iramSize, err := checkRAMWindow("memory.iram_base", hw.Memory.IramBase, "memory.iram_size", hw.Memory.IramSize)
	if err != nil {
		return err
	}

	if (hw.Memory.SramBase == "") != (hw.Memory.SramSize == "") {
		if hw.Memory.SramBase == "" {
			return errors.New("FATAL: memory.sram_base must be set when memory.sram_size is configured")
		}
		return errors.New("FATAL: memory.sram_size must be set when memory.sram_base is configured")
	}
	sramBase, sramSize := iramBase, iramSize
	if hw.Memory.SramBase != "" {
		sramBase, sramSize, err = checkRAMWindow("memory.sram_base", hw.Memory.SramBase, "memory.sram_size", hw.Memory.SramSize)
		if err != nil {
			return err
		}
	}
	minSramBytes := uint64(hw.CryptoCapabilities.ArenaSize) + 512
	if sramSize < minSramBytes {
		return fmt.Errorf("FATAL: data SRAM size (0x%X) must be >= crypto_capabilities.arena_size (%d) + 512 bytes",
			sramSize, hw.CryptoCapabilities.ArenaSize)
	}

	if (hw.Memory.LpRamBase == "") != (hw.Memory.LpRamSize == "") {
		if hw.Memory.LpRamBase == "" {
			return errors.New("FATAL: memory.lp_ram_base must be set when memory.lp_ram_size is configured")
		}
		return errors.New("FATAL: memory.lp_ram_size must be set when memory.lp_ram_base is configured")
	}
	var lpBase, lpSize uint64
	hasLp := hw.Memory.LpRamBase != ""
	if hasLp {
		lpBase, lpSize, err = checkRAMWindow("memory.lp_ram_base", hw.Memory.LpRamBase, "memory.lp_ram_size", hw.Memory.LpRamSize)
		if err != nil {
			return err
		}
		if lpBase < iramBase+iramSize && iramBase < lpBase+lpSize {
			return fmt.Errorf("FATAL: memory.lp_ram [0x%X..0x%X) overlaps memory.iram [0x%X..0x%X)",
				lpBase, lpBase+lpSize, iramBase, iramBase+iramSize)
		}
		if lpBase < sramBase+sramSize && sramBase < lpBase+lpSize {
			return fmt.Errorf("FATAL: memory.lp_ram [0x%X..0x%X) overlaps memory.sram [0x%X..0x%X)",
				lpBase, lpBase+lpSize, sramBase, sramBase+sramSize)
		}
	}

	physBase, _, fbErr := resolveFlashBase(&hw.Flash)
	if fbErr != nil {
		return fbErr
	}
	xipVal, xipErr := parseU64Literal(orDefault(hw.Flash.XipBase, defaultXipBase))
	if xipErr == nil {
		var cpuFlashSpans [][2]uint64
		if physBase > 0 || xipVal == 0 {
			cpuFlashSpans = append(cpuFlashSpans, [2]uint64{uint64(physBase), uint64(physBase) + uint64(hw.Flash.Size)})
		}
		if xipVal > 0 {
			cpuFlashSpans = append(cpuFlashSpans, [2]uint64{xipVal, xipVal + uint64(hw.Flash.Size)})
		}
		ramSpans := []struct {
			name       string
			start, end uint64
		}{
			{"memory.iram", iramBase, iramBase + iramSize},
			{"memory.sram", sramBase, sramBase + sramSize},
		}
		if hasLp {
			ramSpans = append(ramSpans, struct {
				name       string
				start, end uint64
			}{"memory.lp_ram", lpBase, lpBase + lpSize})
		}
		for _, rs := range ramSpans {
			for _, fs := range cpuFlashSpans {
				if rs.start < fs[1] && fs[0] < rs.end {
					return fmt.Errorf("FATAL: %s [0x%X..0x%X) overlaps CPU-mapped flash [0x%X..0x%X)",
						rs.name, rs.start, rs.end, fs[0], fs[1])
				}
			}
		}
	}

	if hw.Flash.VtorAlignment != 0 && !isPowerOfTwo(uint64(hw.Flash.VtorAlignment)) {
		return fmt.Errorf("FATAL: flash.vtor_alignment %d is not a power of two", hw.Flash.VtorAlignment)
	}
	if hw.Memory.VtorAlignment != 0 && !isPowerOfTwo(uint64(hw.Memory.VtorAlignment)) {
		return fmt.Errorf("FATAL: memory.vtor_alignment %d is not a power of two", hw.Memory.VtorAlignment)
	}
	if hw.Flash.VtorAlignment != 0 && hw.Memory.VtorAlignment != 0 && hw.Flash.VtorAlignment != hw.Memory.VtorAlignment {
		return fmt.Errorf("FATAL: flash.vtor_alignment (%d) conflicts with memory.vtor_alignment (%d)",
			hw.Flash.VtorAlignment, hw.Memory.VtorAlignment)
	}
	if hw.Flash.ImageHeaderOffset != 0 && (hw.Flash.ImageHeaderOffset < 0x14 || hw.Flash.ImageHeaderOffset%4 != 0) {
		return fmt.Errorf("FATAL: flash.image_header_offset (%d) must be >= 20 (0x14) and 4-byte aligned",
			hw.Flash.ImageHeaderOffset)
	}
	if hw.Memory.ImageHeaderOffset != 0 && (hw.Memory.ImageHeaderOffset < 0x14 || hw.Memory.ImageHeaderOffset%4 != 0) {
		return fmt.Errorf("FATAL: memory.image_header_offset (%d) must be >= 20 (0x14) and 4-byte aligned",
			hw.Memory.ImageHeaderOffset)
	}
	if hw.Flash.ImageHeaderOffset != 0 && hw.Memory.ImageHeaderOffset != 0 && hw.Flash.ImageHeaderOffset != hw.Memory.ImageHeaderOffset {
		return fmt.Errorf("FATAL: flash.image_header_offset (%d) conflicts with memory.image_header_offset (%d)",
			hw.Flash.ImageHeaderOffset, hw.Memory.ImageHeaderOffset)
	}

	if err := checkExecModeAndEntry(ctx); err != nil {
		return err
	}

	for _, r := range hw.ReservedRamRegions {
		if err := ValidateName("reserved RAM region", r.Name); err != nil {
			return fmt.Errorf("FATAL: reserved_ram_regions: %w", err)
		}
		base, err := parseU64Literal(r.Base)
		if err != nil {
			return fmt.Errorf("FATAL: reserved_ram_regions[%s].base: %w", r.Name, err)
		}
		if r.Size == 0 {
			return fmt.Errorf("FATAL: reserved_ram_regions[%s].size must be greater than zero", r.Name)
		}
		if base <= math.MaxUint32 && base+uint64(r.Size) > 0x100000000 {
			return fmt.Errorf("FATAL: reserved_ram_regions[%s] exceeds the 32-bit address space", r.Name)
		}
		if base > math.MaxUint32 && uint64(r.Size) > math.MaxUint64-base {
			return fmt.Errorf("FATAL: reserved_ram_regions[%s] overflows the 64-bit address space", r.Name)
		}
	}
	return nil
}

func checkExecModeAndEntry(ctx *Context) error {
	validateMode := func(field, mode string) (string, error) {
		if mode == "" {
			return "", nil
		}
		m := strings.ToLower(strings.TrimSpace(mode))
		if m != "ram" && m != "xip" {
			return "", fmt.Errorf("FATAL: %s %q must be 'ram' or 'xip'", field, mode)
		}
		return m, nil
	}
	fMode, err := validateMode("flash.stage0_exec_mode", ctx.Hardware.Flash.Stage0ExecMode)
	if err != nil {
		return err
	}
	if sym := ctx.Hardware.Flash.EntrySymbol; sym != "" && !isCSymbol(sym) {
		return fmt.Errorf("FATAL: flash.entry_symbol %q must be a valid C symbol identifier", sym)
	}
	if ctx.Chip != nil {
		cMode, err := validateMode("chip_manifest.json stage0_exec_mode", ctx.Chip.Stage0ExecMode)
		if err != nil {
			return err
		}
		if fMode != "" && cMode != "" && fMode != cMode {
			return fmt.Errorf("FATAL: flash.stage0_exec_mode (%s) conflicts with chip_manifest.json stage0_exec_mode (%s)",
				fMode, cMode)
		}
		if sym := ctx.Chip.EntrySymbol; sym != "" && !isCSymbol(sym) {
			return fmt.Errorf("FATAL: chip_manifest.json entry_symbol %q must be a valid C symbol identifier", sym)
		}
	}
	return nil
}

func checkMandatoryPartitions(ctx *Context) error {
	p := &ctx.Device.Partitions
	if p.Stage0Size == 0 || p.Stage1Size == 0 || p.AppSize == 0 {
		return errors.New("FATAL: stage0_size, stage1_size, app_size are mandatory in [partitions]")
	}
	return nil
}

// checkBootConfig requires the retry limit and bounds exponential backoff and build profile.
func checkBootConfig(ctx *Context) error {
	if ctx.Device.BootConfig.MaxRetries == 0 {
		return errors.New("FATAL: boot_config.max_retries is mandatory in device.toml and must be greater than zero")
	}
	if ctx.Device.BootConfig.BackoffBaseS > math.MaxUint32/24 {
		return fmt.Errorf("FATAL: boot_config.backoff_base_s = %d exceeds maximum %d (32-bit overflow in 24x backoff)",
			ctx.Device.BootConfig.BackoffBaseS, uint32(math.MaxUint32/24))
	}
	if prof := ctx.Device.Build.Profile; prof != "" && prof != "dev" && prof != "production" {
		return fmt.Errorf("FATAL: build.profile = %q must be 'dev' or 'production'", prof)
	}
	return nil
}

// checkResetCauses ensures every 32-bit code/mask entry has valid C identifiers,
// consistent bitmask bits, and unambiguous (value, mask) pairs (CRIT-21).
func checkResetCauses(ctx *Context) error {
	rc := ctx.Hardware.ResetCauses
	if rc == nil {
		return nil
	}
	if rc.ClearReg != "" && !isCSymbol(rc.ClearReg) {
		return fmt.Errorf("FATAL: reset_causes.clear_reg %q must be a valid C identifier", rc.ClearReg)
	}
	names := make(map[string]bool, len(rc.Codes))
	pairs := make(map[[2]uint32]string, len(rc.Codes))
	for _, code := range rc.Codes {
		if !isCSymbol(code.Name) {
			return fmt.Errorf("FATAL: reset cause name %q must be a valid C identifier", code.Name)
		}
		if code.ClearReg != "" && !isCSymbol(code.ClearReg) {
			return fmt.Errorf("FATAL: reset cause '%s' clear_reg %q must be a valid C identifier", code.Name, code.ClearReg)
		}
		val, mask := uint32(code.Value), uint32(code.Mask)
		if mask != 0 && (val & ^mask) != 0 {
			return fmt.Errorf("FATAL: reset cause '%s' value 0x%X has bits outside its mask 0x%X", code.Name, val, mask)
		}
		key := strings.ToUpper(code.Name)
		if names[key] {
			return fmt.Errorf("FATAL: reset cause '%s' is defined more than once", code.Name)
		}
		pair := [2]uint32{val, mask}
		if prev, dup := pairs[pair]; dup {
			return fmt.Errorf("FATAL: reset causes '%s' and '%s' share the hardware code 0x%X (mask 0x%X)",
				prev, code.Name, val, mask)
		}
		names[key], pairs[pair] = true, code.Name
	}
	return nil
}

func parseConstantUint32(val any) (uint32, error) {
	if str, ok := val.(string); ok {
		return parseU32Literal(str)
	}
	lit, err := cUnsigned(val)
	if err != nil {
		return 0, err
	}
	return parseU32Literal(strings.TrimSuffix(lit, "U"))
}

func checkHardwareConstantsAndMaps(ctx *Context) error {
	hw := ctx.Hardware
	for _, blockName := range slices.Sorted(maps.Keys(hw.RegisterBlocks)) {
		if !isCIdentifier(blockName) {
			return fmt.Errorf("FATAL: register_blocks key %q must be a valid C identifier", blockName)
		}
		block := hw.RegisterBlocks[blockName]
		for _, regName := range slices.Sorted(maps.Keys(block.Regs)) {
			if !isCIdentifier(regName) {
				return fmt.Errorf("FATAL: register_blocks.%s.regs key %q must be a valid C identifier", blockName, regName)
			}
		}
	}
	for _, flatName := range slices.Sorted(maps.Keys(hw.RegistersFlat)) {
		if !isCIdentifier(flatName) {
			return fmt.Errorf("FATAL: registers_flat key %q must be a valid C identifier", flatName)
		}
	}
	for _, regKey := range slices.Sorted(maps.Keys(hw.Registers)) {
		if !isCIdentifier(regKey) {
			return fmt.Errorf("FATAL: registers key %q must be a valid C identifier", regKey)
		}
		if _, err := parseConstantUint32(hw.Registers[regKey]); err != nil {
			return fmt.Errorf("FATAL: registers[%s]: %w", regKey, err)
		}
	}
	for _, constName := range slices.Sorted(maps.Keys(hw.Constants)) {
		if !isCIdentifier(constName) {
			return fmt.Errorf("FATAL: constants key %q must be a valid C identifier", constName)
		}
		if strings.EqualFold(constName, "flash_erased_byte") {
			v, err := parseConstantUint32(hw.Constants[constName])
			if err != nil {
				return fmt.Errorf("FATAL: constants.%s: %w", constName, err)
			}
			if v != 0xFF {
				return fmt.Errorf("FATAL: constants.%s = 0x%X is unsupported (Toob-Loader NOR flash runtime requires 0xFF erased state)", constName, v)
			}
		}
	}
	for _, cfgKey := range slices.Sorted(maps.Keys(ctx.Device.DriverConfig)) {
		if !isCSymbol(cfgKey) {
			return fmt.Errorf("FATAL: driver_config key %q (macro TOOB_DRIVER_%s) must be a valid C symbol identifier",
				cfgKey, strings.ToUpper(cfgKey))
		}
	}
	if hw.MultiCore != nil {
		for i, cp := range hw.MultiCore.Coprocessors {
			if err := ValidateName("coprocessor", cp.Name); err != nil {
				return fmt.Errorf("FATAL: multi_core.coprocessors[%d]: %w", i, err)
			}
			if cp.AppAlignmentBytes != nil && !isPowerOfTwo(uint64(*cp.AppAlignmentBytes)) {
				return fmt.Errorf("FATAL: multi_core.coprocessors[%d].app_alignment_bytes (%d) must be a non-zero power of two",
					i, *cp.AppAlignmentBytes)
			}
		}
	}
	if hw.BootromImage != nil {
		mode := resolveStage0ExecMode(ctx, hw)
		if err := validateRawBootromSpec(hw.BootromImage, mode); err != nil {
			return fmt.Errorf("FATAL: bootrom_image: %w", err)
		}
	}
	return nil
}

func validateRawBootromSpec(spec *BootromImageSpec, stage0ExecMode string) error {
	if spec == nil {
		return nil
	}
	if spec.Extends != "" {
		if err := validateRelPath("bootrom_image.extends", spec.Extends); err != nil {
			return err
		}
		if !strings.HasSuffix(spec.Extends, ".json") {
			return fmt.Errorf("extends %q must reference a .json file", spec.Extends)
		}
	}
	if spec.MinSize < 0 || spec.MinSize > maxBootromImageSpan {
		return fmt.Errorf("min_size (%d) must be in range [0..%d]", spec.MinSize, maxBootromImageSpan)
	}
	if spec.FillByte != nil && uint32(*spec.FillByte) > 0xFF {
		return fmt.Errorf("fill_byte (0x%X) exceeds 0xFF", uint32(*spec.FillByte))
	}
	if spec.Header != nil {
		if spec.Header.Size < 0 || spec.Header.Size > maxBootromImageSpan {
			return fmt.Errorf("header.size (%d) out of range", spec.Header.Size)
		}
		if spec.Header.FillByte != nil && uint32(*spec.Header.FillByte) > 0xFF {
			return fmt.Errorf("header.fill_byte (0x%X) exceeds 0xFF", uint32(*spec.Header.FillByte))
		}
	}
	if spec.Segments != nil {
		if spec.Segments.MaxCount < 0 {
			return fmt.Errorf("segments.max_count (%d) must not be negative", spec.Segments.MaxCount)
		}
		if spec.Segments.HeaderSize < 0 || spec.Segments.HeaderSize > maxBootromImageSpan {
			return fmt.Errorf("segments.header_size (%d) out of range", spec.Segments.HeaderSize)
		}
		if spec.Segments.Align < 0 || (spec.Segments.Align > 0 && !isPowerOfTwo(uint64(spec.Segments.Align))) {
			return fmt.Errorf("segments.align (%d) must be a positive power of two", spec.Segments.Align)
		}
	}
	layout := strings.ToLower(strings.TrimSpace(spec.Layout))
	if layout != "" && layout != "flat" && layout != "segmented" {
		return fmt.Errorf("layout %q must be 'flat' or 'segmented'", spec.Layout)
	}
	if layout == "segmented" {
		if stage0ExecMode == "xip" {
			return errors.New("layout 'segmented' cannot be paired with stage0_exec_mode 'xip'")
		}
		if spec.Extends == "" {
			if spec.Header == nil || spec.Header.Size <= 0 {
				return errors.New("layout 'segmented' requires header.size > 0")
			}
			if spec.Segments == nil || spec.Segments.HeaderSize <= 0 {
				return errors.New("layout 'segmented' requires segments.header_size > 0")
			}
		}
	}
	return nil
}

// checkDeltaCoherence (REG-003): enable_deltas requires either a scratch area
// or an execution model that applies deltas without one.
func checkDeltaCoherence(ctx *Context) error {
	if !ctx.Device.Partitions.EnableDeltas || ctx.Chip == nil || ctx.Chip.SlotCapabilities == nil {
		return nil
	}
	caps := ctx.Chip.SlotCapabilities
	if caps.HasScratch || ctx.Device.Partitions.ScratchSize > 0 || isRemappable(caps.ExecModel) {
		return nil
	}
	return fmt.Errorf("FATAL [REG-003]: enable_deltas = true requires either has_scratch = true or a "+
		"scratch-less execution model (xip_remap, bank_swap, relocatable), but chip '%s' has "+
		"has_scratch = %v and exec_model = '%s'", ctx.Hardware.ChipFamily, caps.HasScratch, caps.ExecModel)
}

// checkRecoveryJustification (REG-007): unsigned recovery (whether configured in
// device.toml or inherited from chip_manifest.json) must be justified explicitly.
func checkRecoveryJustification(ctx *Context) error {
	dtCrypto := &ctx.Device.Recovery.Crypto
	var chipRecBackend, chipRecHash, chipBackend, chipHash string
	if ctx.Chip != nil {
		if ctx.Chip.Recovery != nil && ctx.Chip.Recovery.Crypto != nil {
			chipRecBackend = ctx.Chip.Recovery.Crypto.Backend
			chipRecHash = ctx.Chip.Recovery.Crypto.Hash
		}
		if ctx.Chip.Crypto != nil {
			chipBackend = ctx.Chip.Crypto.Backend
			chipHash = ctx.Chip.Crypto.Hash
		}
	}
	effBackend := strings.TrimSpace(cmp.Or(dtCrypto.Backend, chipRecBackend, ctx.Device.Crypto.Backend, chipBackend))
	effHash := strings.TrimSpace(cmp.Or(dtCrypto.Hash, chipRecHash, ctx.Device.Crypto.Hash, chipHash))

	if (strings.EqualFold(effBackend, "none") || strings.EqualFold(effHash, "none")) &&
		strings.TrimSpace(dtCrypto.Justification) == "" {
		return errors.New("FATAL [REG-007]: unsigned recovery (backend or hash = \"none\") requires a non-empty " +
			"'justification' field explaining why unsigned recovery is acceptable for this device's security posture")
	}

	for _, sentinel := range []struct{ field, val string }{
		{"device.toml recovery.crypto.backend", dtCrypto.Backend},
		{"device.toml recovery.crypto.hash", dtCrypto.Hash},
		{"chip_manifest.json recovery.crypto.backend", chipRecBackend},
		{"chip_manifest.json recovery.crypto.hash", chipRecHash},
	} {
		v := strings.TrimSpace(sentinel.val)
		if (strings.EqualFold(v, "none") && v != "none") || (strings.EqualFold(v, "rom") && v != "rom") {
			return fmt.Errorf("FATAL: %s = %q must use exact lowercase %q", sentinel.field, sentinel.val, strings.ToLower(v))
		}
	}
	return nil
}

// checkVersionPins (REG-009): "latest" is not a minimum version.
func checkVersionPins(ctx *Context) error {
	if ctx.Chip == nil {
		return nil
	}
	if strings.EqualFold(ctx.Chip.MinCompiler, "latest") {
		return errors.New("FATAL [REG-009]: chip_manifest.json min_compiler = \"latest\" is not a valid " +
			"minimum version pin — use a concrete version (e.g., \"14.2.0\")")
	}
	if strings.EqualFold(ctx.Chip.MinCoreSDK, "latest") {
		return errors.New("FATAL [REG-009]: chip_manifest.json min_core_sdk = \"latest\" is not a valid " +
			"minimum version pin — use a concrete semver (e.g., \"core/v0.1.0\")")
	}
	return nil
}

// checkManifestReferences validates driver bindings, recovery paths, and
// driver manifests present on Context even when constructed in memory.
func checkManifestReferences(ctx *Context) error {
	dt := ctx.Device
	for trait, ref := range dt.Drivers {
		if err := ValidateName("driver trait", trait); err != nil {
			return fmt.Errorf("FATAL: device.toml [drivers]: %w", err)
		}
		trimmed := strings.TrimSpace(ref)
		if trimmed != "" && !strings.EqualFold(trimmed, "none") {
			if err := validatePackageOrRelPath("driver", trimmed); err != nil {
				return fmt.Errorf("FATAL: device.toml [drivers.%s]: %w", trait, err)
			}
		}
	}
	for _, entry := range []struct{ field, val string }{
		{"recovery.console", dt.Recovery.Console},
		{"recovery.flash", dt.Recovery.Flash},
		{"recovery.wdt", dt.Recovery.WDT},
		{"recovery.clock", dt.Recovery.Clock},
		{"recovery.rtc", dt.Recovery.RTC},
	} {
		if entry.val != "" {
			if err := validatePackageOrRelPath("recovery driver", entry.val); err != nil {
				return fmt.Errorf("FATAL: device.toml %s: %w", entry.field, err)
			}
		}
	}
	for _, entry := range []struct{ field, val string }{
		{"crypto.backend", dt.Crypto.Backend},
		{"crypto.hash", dt.Crypto.Hash},
	} {
		if v := strings.TrimSpace(entry.val); v != "" {
			if strings.EqualFold(v, "none") {
				return fmt.Errorf("FATAL: device.toml %s = %q is forbidden (Stage-1 crypto cannot be disabled)", entry.field, entry.val)
			}
			if err := ValidatePackageRef(entry.field, v); err != nil {
				return fmt.Errorf("FATAL: device.toml %s: %w", entry.field, err)
			}
		}
	}
	if pqc := strings.TrimSpace(dt.Crypto.Pqc); pqc != "" && !strings.EqualFold(pqc, "none") {
		if err := ValidatePackageRef("crypto.pqc", pqc); err != nil {
			return fmt.Errorf("FATAL: device.toml crypto.pqc: %w", err)
		}
	}
	if ctx.Chip != nil && ctx.Chip.Crypto != nil {
		for _, entry := range []struct{ field, val string }{
			{"crypto.backend", ctx.Chip.Crypto.Backend},
			{"crypto.hash", ctx.Chip.Crypto.Hash},
		} {
			if v := strings.TrimSpace(entry.val); v != "" {
				if strings.EqualFold(v, "none") {
					return fmt.Errorf("FATAL: chip_manifest.json %s = %q is forbidden", entry.field, entry.val)
				}
				if err := ValidatePackageRef(entry.field, v); err != nil {
					return fmt.Errorf("FATAL: chip_manifest.json %s: %w", entry.field, err)
				}
			}
		}
		if pqc := strings.TrimSpace(ctx.Chip.Crypto.Pqc); pqc != "" && !strings.EqualFold(pqc, "none") {
			if err := ValidatePackageRef("crypto.pqc", pqc); err != nil {
				return fmt.Errorf("FATAL: chip_manifest.json crypto.pqc: %w", err)
			}
		}
	}
	targetChip := normalizeChipName(ctx.Hardware.ChipFamily)
	for _, list := range [][]*CryptoManifest{ctx.Crypto, ctx.RecoveryCrypto} {
		for _, cm := range list {
			if cm == nil {
				continue
			}
			for _, flag := range cm.Cflags {
				if err := ValidateCompilerFlag("crypto["+cm.Name+"].cflags", flag); err != nil {
					return fmt.Errorf("FATAL: %w", err)
				}
			}
			bindings := cm.ChipBindings()
			if len(bindings) == 0 {
				continue
			}
			matched := false
			for _, b := range bindings {
				if err := ValidateName("crypto chip_binding", b); err != nil {
					return fmt.Errorf("FATAL: crypto[%s]: %w", cm.Name, err)
				}
				if normalizeChipName(b) == targetChip {
					matched = true
				}
			}
			if !matched {
				return fmt.Errorf("FATAL: crypto package '%s' is chip-bound to %v, which does not match target chip '%s'",
					cm.Name, bindings, ctx.Hardware.ChipFamily)
			}
		}
	}
	if pqcRef, pqcEnabled := effectiveCryptoPqc(ctx); pqcEnabled && len(ctx.Crypto) > 0 {
		hasPqc := false
		for _, cm := range ctx.Crypto {
			if slices.Contains(cm.Category, "pqc") && cm.Symbols["verify_pqc"] != "" {
				hasPqc = true
				break
			}
		}
		if !hasPqc {
			return fmt.Errorf("FATAL: crypto.pqc = %q is enabled, but no bound PQC crypto manifest provides 'verify_pqc'", pqcRef)
		}
	}
	for _, entry := range []struct{ field, val string }{
		{"recovery.crypto.backend", dt.Recovery.Crypto.Backend},
		{"recovery.crypto.hash", dt.Recovery.Crypto.Hash},
	} {
		if entry.val != "" {
			if err := ValidatePackageRef(entry.field, entry.val); err != nil {
				return fmt.Errorf("FATAL: device.toml %s: %w", entry.field, err)
			}
		}
	}
	projectDir := cmp.Or(ctx.ProjectDir, ".")
	for _, src := range dt.Recovery.Sources {
		if err := validateRelPath("recovery source", src); err != nil {
			return fmt.Errorf("FATAL: device.toml recovery.sources: %w", err)
		}
		if _, err := containPath(projectDir, src); err != nil {
			return fmt.Errorf("FATAL: device.toml recovery.sources: %w", err)
		}
	}
	for _, inc := range dt.Recovery.Includes {
		if err := validateRelPath("recovery include", inc); err != nil {
			return fmt.Errorf("FATAL: device.toml recovery.includes: %w", err)
		}
		if _, err := containPath(projectDir, inc); err != nil {
			return fmt.Errorf("FATAL: device.toml recovery.includes: %w", err)
		}
	}
	if ctx.Chip != nil {
		if err := ValidateCompilerFlags("chip_manifest.json compiler_flags", ctx.Chip.CompilerFlags); err != nil {
			return fmt.Errorf("FATAL: %w", err)
		}
		for trait, ref := range ctx.Chip.HalBindings {
			if err := ValidateName("driver trait", trait); err != nil {
				return fmt.Errorf("FATAL: chip_manifest.json hal_bindings: %w", err)
			}
			if err := validatePackageOrRelPath("driver", ref); err != nil {
				return fmt.Errorf("FATAL: chip_manifest.json hal_bindings.%s: %w", trait, err)
			}
		}
	}
	if ctx.Arch != nil {
		if err := ValidateCompilerFlags("arch_manifest.json compiler_flags", ctx.Arch.CompilerFlags); err != nil {
			return fmt.Errorf("FATAL: %w", err)
		}
	}
	return nil
}

func checkReferenceBuildContext(label string, rbc *ReferenceBuildContext) error {
	if rbc == nil {
		return nil
	}
	if rbc.Chip != "" {
		if err := ValidatePackageRef(label+".chip", rbc.Chip); err != nil {
			return fmt.Errorf("FATAL: %w", err)
		}
	}
	for _, entry := range []struct{ field, val string }{
		{label + ".core_sdk_version", rbc.CoreSDKVersion},
		{label + ".toolchain_version", rbc.ToolchainVersion},
	} {
		if err := validateSafeText(entry.field, entry.val); err != nil {
			return fmt.Errorf("FATAL: %w", err)
		}
	}
	return nil
}

func checkKeywords(label string, keywords []string) error {
	for i, kw := range keywords {
		if err := validateSafeText(fmt.Sprintf("%s[%d]", label, i), kw); err != nil {
			return fmt.Errorf("FATAL: %w", err)
		}
	}
	return nil
}

// checkMetadataText rejects control characters in human-readable strings that
// are emitted into logs, comments, or Markdown reports.
func checkMetadataText(ctx *Context) error {
	dt := ctx.Device
	for _, entry := range []struct{ field, val string }{
		{"device.toml name", dt.Name},
		{"device.toml version", dt.Version},
		{"device.toml build.compiler", dt.Build.Compiler},
		{"device.toml build.core_sdk", dt.Build.CoreSDK},
		{"device.toml build.registry", dt.Build.Registry},
		{"device.toml recovery.crypto.justification", dt.Recovery.Crypto.Justification},
	} {
		if err := validateSafeText(entry.field, entry.val); err != nil {
			return fmt.Errorf("FATAL: %w", err)
		}
	}
	if ctx.Chip != nil {
		for _, entry := range []struct{ field, val string }{
			{"chip_manifest.json author", ctx.Chip.Author},
			{"chip_manifest.json tier", ctx.Chip.Tier},
			{"chip_manifest.json description", ctx.Chip.Description},
			{"chip_manifest.json license", ctx.Chip.License},
			{"chip_manifest.json repository", ctx.Chip.Repository},
			{"chip_manifest.json version", ctx.Chip.Version},
			{"chip_manifest.json min_core_sdk", ctx.Chip.MinCoreSDK},
			{"chip_manifest.json min_compiler", ctx.Chip.MinCompiler},
		} {
			if err := validateSafeText(entry.field, entry.val); err != nil {
				return fmt.Errorf("FATAL: %w", err)
			}
		}
		if err := checkKeywords("chip_manifest.json keywords", ctx.Chip.Keywords); err != nil {
			return err
		}
		if err := checkReferenceBuildContext("chip_manifest.json reference_build_context", ctx.Chip.ReferenceBuildContext); err != nil {
			return err
		}
	}
	if ctx.Arch != nil {
		for _, entry := range []struct{ field, val string }{
			{"arch_manifest.json author", ctx.Arch.Author},
			{"arch_manifest.json tier", ctx.Arch.Tier},
			{"arch_manifest.json version", ctx.Arch.Version},
			{"arch_manifest.json description", ctx.Arch.Description},
			{"arch_manifest.json license", ctx.Arch.License},
			{"arch_manifest.json repository", ctx.Arch.Repository},
			{"arch_manifest.json min_core_sdk", ctx.Arch.MinCoreSDK},
		} {
			if err := validateSafeText(entry.field, entry.val); err != nil {
				return fmt.Errorf("FATAL: %w", err)
			}
		}
		if err := checkKeywords("arch_manifest.json keywords", ctx.Arch.Keywords); err != nil {
			return err
		}
		if err := checkReferenceBuildContext("arch_manifest.json reference_build_context", ctx.Arch.ReferenceBuildContext); err != nil {
			return err
		}
	}
	for _, drvMap := range []map[string]*DriverManifest{ctx.Drivers, ctx.RecoveryDrivers} {
		for trait, dm := range drvMap {
			if dm == nil {
				continue
			}
			for _, entry := range []struct{ field, val string }{
				{"driver[" + trait + "].author", dm.Author},
				{"driver[" + trait + "].tier", dm.Tier},
				{"driver[" + trait + "].version", dm.Version},
				{"driver[" + trait + "].description", dm.Description},
				{"driver[" + trait + "].license", dm.License},
				{"driver[" + trait + "].repository", dm.Repository},
				{"driver[" + trait + "].min_core_sdk", dm.MinCoreSDK},
			} {
				if err := validateSafeText(entry.field, entry.val); err != nil {
					return fmt.Errorf("FATAL: %w", err)
				}
			}
			if err := checkKeywords("driver["+trait+"].keywords", dm.Keywords); err != nil {
				return err
			}
			if err := checkReferenceBuildContext("driver["+trait+"].reference_build_context", dm.ReferenceBuildContext); err != nil {
				return err
			}
		}
	}
	for _, cryList := range [][]*CryptoManifest{ctx.Crypto, ctx.RecoveryCrypto} {
		for _, cm := range cryList {
			if cm == nil {
				continue
			}
			for _, entry := range []struct{ field, val string }{
				{"crypto[" + cm.Name + "].author", cm.Author},
				{"crypto[" + cm.Name + "].tier", cm.Tier},
				{"crypto[" + cm.Name + "].version", cm.Version},
				{"crypto[" + cm.Name + "].description", cm.Description},
				{"crypto[" + cm.Name + "].license", cm.License},
				{"crypto[" + cm.Name + "].repository", cm.Repository},
				{"crypto[" + cm.Name + "].min_core_sdk", cm.MinCoreSdk},
			} {
				if err := validateSafeText(entry.field, entry.val); err != nil {
					return fmt.Errorf("FATAL: %w", err)
				}
			}
			if err := checkKeywords("crypto["+cm.Name+"].keywords", cm.Keywords); err != nil {
				return err
			}
			if err := checkReferenceBuildContext("crypto["+cm.Name+"].reference_build_context", cm.ReferenceBuildContext); err != nil {
				return err
			}
		}
	}

	hw := ctx.Hardware
	checkProv := func(label string, p *Provenance) error {
		if p == nil {
			return nil
		}
		if err := validateSafeText(label+".source", p.Source); err != nil {
			return fmt.Errorf("FATAL: %w", err)
		}
		if err := validateSafeText(label+".ref", p.Ref); err != nil {
			return fmt.Errorf("FATAL: %w", err)
		}
		if err := validateSafeText(label+".verified", p.Verified); err != nil {
			return fmt.Errorf("FATAL: %w", err)
		}
		return nil
	}
	for _, entry := range []struct {
		label string
		prov  *Provenance
	}{
		{"provenance", hw.Provenance},
		{"flash.provenance", hw.Flash.Provenance},
		{"crypto_capabilities.provenance", hw.CryptoCapabilities.Provenance},
		{"memory.provenance", hw.Memory.Provenance},
	} {
		if err := checkProv(entry.label, entry.prov); err != nil {
			return err
		}
	}
	for i, r := range hw.Flash.Regions {
		if err := validateSafeText(fmt.Sprintf("flash.regions[%d].description", i), r.Description); err != nil {
			return fmt.Errorf("FATAL: %w", err)
		}
		if err := checkProv(fmt.Sprintf("flash.regions[%d].provenance", i), r.Provenance); err != nil {
			return err
		}
	}
	for _, r := range hw.ReservedRamRegions {
		if err := validateSafeText(fmt.Sprintf("reserved_ram_regions[%s].description", r.Name), r.Description); err != nil {
			return fmt.Errorf("FATAL: %w", err)
		}
		if err := checkProv(fmt.Sprintf("reserved_ram_regions[%s].provenance", r.Name), r.Provenance); err != nil {
			return err
		}
	}
	for name, b := range hw.RegisterBlocks {
		if err := checkProv("register_blocks."+name+".provenance", b.Provenance); err != nil {
			return err
		}
	}
	if hw.ResetCauses != nil {
		if err := checkProv("reset_causes.provenance", hw.ResetCauses.Provenance); err != nil {
			return err
		}
		for _, c := range hw.ResetCauses.Codes {
			if err := checkProv("reset_causes."+c.Name+".provenance", c.Provenance); err != nil {
				return err
			}
		}
	}
	return nil
}
