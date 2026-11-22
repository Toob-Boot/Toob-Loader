package build

import (
	"cmp"
	"errors"
	"fmt"
	"math"
	"strings"
)

// Documented defaults for optional device.toml / hardware.json fields.
// Each value is applied in exactly one place: resolveConfig.
const (
	defaultWalSectors    uint32 = 4
	defaultWdtTimeoutMs  uint32 = 4100
	defaultStagingSlotID uint32 = 2
	defaultFlashBaseAddr        = "0x00000000"
	defaultXipBase              = "0x0"

	// minWalSectors and maxWalSectors mirror the C WAL static SectorMap[8] bounds.
	minWalSectors uint32 = 4
	maxWalSectors uint32 = 8
)

// ResolvedConfig holds every derived build parameter. It is computed once from
// the Context, so codegen never re-applies defaults or re-parses inputs.
type ResolvedConfig struct {
	Transport               Transport
	BackupMode              BackupMode // BackupUnset unless Transport is oneway.
	SlotCount               int        // Chip slot_count (defaults to 1 when unspecified).
	WalSectors              uint32
	WdtTimeoutMs            uint32
	StagingSlotID           uint32
	EnableDeltas            bool
	CryptoArenaOverride     uint32
	Pqc                     string
	PqcEnabled              bool
	FeatureCloudCommands    bool
	FeatureUartProvisioning bool
	FeatureMultiImage       bool
	FeatureDelta            bool
	FeatureCompression      bool
	FlashBase               uint32 // Physical flash base address (CRIT-20).
	FlashBaseAddr           string // Validated uint32 literal.
	XipBase                 string // Validated address literal.
	XipBaseVal              uint64 // Parsed XIP base value (0 when none).
	ExecModel               string // Chip slot_capabilities.exec_model ("" when unspecified).
	Arch                    string // Chip architecture ("" when unspecified).
	Stage0ExecMode          string // "xip" or "ram".
	VtorAlign               uint32 // Effective VTOR alignment (0 when none).
	ImageHeaderOffset       uint32 // Effective image header offset (>= 0x14, 4-byte aligned).
}

func boolOrTrue(p *bool) bool {
	if p == nil {
		return true
	}
	return *p
}

// effectiveCryptoPqc returns the resolved PQC package reference (DeviceToml overriding
// ChipManifest) and whether PQC verification is enabled ("" and "none" disable PQC).
func effectiveCryptoPqc(ctx *Context) (string, bool) {
	if ctx == nil || ctx.Device == nil {
		return "", false
	}
	raw := strings.TrimSpace(ctx.Device.Crypto.Pqc)
	if raw == "" && ctx.Chip != nil && ctx.Chip.Crypto != nil {
		raw = strings.TrimSpace(ctx.Chip.Crypto.Pqc)
	}
	if raw == "" || strings.EqualFold(raw, "none") {
		return raw, false
	}
	return raw, true
}

// resolveConfig validates the context and derives the effective configuration.
// It never mutates the parsed inputs.
func resolveConfig(ctx *Context) (*ResolvedConfig, error) {
	if err := validateContext(ctx); err != nil {
		return nil, err
	}
	transport, backup, err := resolveTransport(ctx)
	if err != nil {
		return nil, err
	}

	dt, hw := ctx.Device, ctx.Hardware
	stagingSlotID := defaultStagingSlotID
	if dt.Partitions.StagingSlotID != nil {
		stagingSlotID = *dt.Partitions.StagingSlotID
		if stagingSlotID == 0 || stagingSlotID > 254 {
			return nil, fmt.Errorf("FATAL: partitions.staging_slot_id = %d must be in range [1..254]", stagingSlotID)
		}
	}

	flashBase, flashBaseAddr, err := resolveFlashBase(&hw.Flash)
	if err != nil {
		return nil, err
	}

	xipRaw := orDefault(hw.Flash.XipBase, defaultXipBase)
	xipVal, err := parseU64Literal(xipRaw)
	if err != nil {
		return nil, fmt.Errorf("FATAL: flash.xip_base: %w", err)
	}
	if xipVal > 0 && (xipVal > math.MaxUint32 || xipVal+uint64(hw.Flash.Size) > 0x100000000) {
		return nil, fmt.Errorf("FATAL [FLASH_005]: flash.xip_base (0x%X) + flash.size (0x%X) exceeds the 32-bit address space",
			xipVal, hw.Flash.Size)
	}

	slotCount := 1
	var execModel, arch string
	if ctx.Chip != nil {
		arch = ctx.Chip.Arch
		if ctx.Chip.SlotCapabilities != nil {
			execModel = ctx.Chip.SlotCapabilities.ExecModel
			if ctx.Chip.SlotCapabilities.SlotCount > 0 {
				slotCount = ctx.Chip.SlotCapabilities.SlotCount
			}
		}
	}
	stage0ExecMode := resolveStage0ExecMode(ctx, hw)
	vtorAlign, imgHdrOff := effectiveVtorAndHeaderOffset(arch, hw)

	pqcRef, pqcEnabled := effectiveCryptoPqc(ctx)

	if dt.BootConfig.CryptoArenaSize > 0 {
		minArena := uint32(2048)
		if pqcEnabled {
			minArena = 8192
		}
		if dt.BootConfig.CryptoArenaSize < minArena || dt.BootConfig.CryptoArenaSize%8 != 0 {
			return nil, fmt.Errorf("FATAL: boot_config.crypto_arena_size = %d must be >= %d and 8-byte aligned",
				dt.BootConfig.CryptoArenaSize, minArena)
		}
	}

	featureDelta := boolOrTrue(dt.Features.Delta)
	if transport == TransportOneway && backup == BackupReverseDelta && !featureDelta {
		return nil, errors.New("FATAL: boot_config.backup_mode = 'reverse_delta' requires features.delta = true")
	}
	if dt.Partitions.EnableDeltas && !featureDelta {
		return nil, errors.New("FATAL [REG-003]: partitions.enable_deltas = true conflicts with features.delta = false")
	}
	if dt.Partitions.EnableDeltas && dt.Partitions.ScratchSize > 0 && dt.Partitions.ScratchSize < dt.Partitions.AppSize {
		return nil, fmt.Errorf("FATAL [REG-003]: partitions.scratch_size (%d) must be >= partitions.app_size (%d) when enable_deltas = true",
			dt.Partitions.ScratchSize, dt.Partitions.AppSize)
	}

	featureCompression := boolOrTrue(dt.Features.Compression)
	if transport == TransportSwapScratch {
		if dt.Features.Compression != nil && *dt.Features.Compression {
			return nil, errors.New("FATAL: boot_config.transport_provider = 'swapscratch' cannot be combined with features.compression = true (shared scratch corruption)")
		}
		featureCompression = false
	}

	cfg := &ResolvedConfig{
		Transport:               transport,
		BackupMode:              backup,
		SlotCount:               slotCount,
		WalSectors:              orDefault(dt.Partitions.WalSectors, defaultWalSectors),
		WdtTimeoutMs:            orDefault(dt.BootConfig.WdtTimeoutMs, defaultWdtTimeoutMs),
		StagingSlotID:           stagingSlotID,
		EnableDeltas:            dt.Partitions.EnableDeltas,
		CryptoArenaOverride:     dt.BootConfig.CryptoArenaSize,
		Pqc:                     pqcRef,
		PqcEnabled:              pqcEnabled,
		FeatureCloudCommands:    boolOrTrue(dt.Features.CloudCommands),
		FeatureUartProvisioning: boolOrTrue(dt.Features.UartProvisioning),
		FeatureMultiImage:       boolOrTrue(dt.Features.MultiImage),
		FeatureDelta:            featureDelta,
		FeatureCompression:      featureCompression,
		FlashBase:               flashBase,
		FlashBaseAddr:           flashBaseAddr,
		XipBase:                 xipRaw,
		XipBaseVal:              xipVal,
		ExecModel:               execModel,
		Arch:                    arch,
		Stage0ExecMode:          stage0ExecMode,
		VtorAlign:               vtorAlign,
		ImageHeaderOffset:       imgHdrOff,
	}

	if cfg.WalSectors < minWalSectors {
		return nil, fmt.Errorf("FATAL: partitions.wal_sectors = %d is below the minimum of %d", cfg.WalSectors, minWalSectors)
	}
	if cfg.WalSectors > maxWalSectors {
		return nil, fmt.Errorf("FATAL: partitions.wal_sectors = %d exceeds the maximum of %d", cfg.WalSectors, maxWalSectors)
	}
	return cfg, nil
}

// resolveFlashBase derives the physical flash base from flash.base and/or flash.base_addr.
func resolveFlashBase(flash *FlashSpec) (uint32, string, error) {
	if flash == nil {
		return 0, defaultFlashBaseAddr, nil
	}
	if flash.BaseAddr != "" {
		parsed, err := parseU32Literal(flash.BaseAddr)
		if err != nil {
			return 0, "", fmt.Errorf("FATAL: flash.base_addr: %w", err)
		}
		if flash.Base != 0 && uint32(flash.Base) != parsed {
			return 0, "", fmt.Errorf("FATAL: flash.base (0x%08X) conflicts with flash.base_addr (%s)",
				uint32(flash.Base), flash.BaseAddr)
		}
		return parsed, flash.BaseAddr, nil
	}
	if flash.Base != 0 {
		b := uint32(flash.Base)
		return b, fmt.Sprintf("0x%08X", b), nil
	}
	return 0, defaultFlashBaseAddr, nil
}

// effectiveVtorAndHeaderOffset computes the single authoritative VTOR alignment
// and Stage-1/App/Recovery image header offset shared across layout, C headers,
// and GNU LD scripts (HIGH-57).
func effectiveVtorAndHeaderOffset(arch string, hw *HardwareJson) (uint32, uint32) {
	if hw == nil {
		return 0, 0x14
	}
	vtorAlign := cmp.Or(hw.Flash.VtorAlignment, hw.Memory.VtorAlignment)
	if vtorAlign == 0 && strings.EqualFold(strings.TrimSpace(arch), "cortex-m") {
		hasVtorDisabled := false
		if raw, ok := hw.Constants["has_vtor"]; ok {
			if v, err := parseConstantUint32(raw); err == nil && v == 0 {
				hasVtorDisabled = true
			}
		}
		if !hasVtorDisabled {
			vtorAlign = 0x80
		}
	}
	rawHdr := cmp.Or(hw.Flash.ImageHeaderOffset, hw.Memory.ImageHeaderOffset)
	if rawHdr > 0 {
		return vtorAlign, max(uint32(0x14), rawHdr)
	}
	if vtorAlign > 0 {
		return vtorAlign, max(uint32(0x20), vtorAlign)
	}
	return 0, 0x14
}

// orDefault returns def if v is the zero value of T (i.e. the field was omitted).
func orDefault[T comparable](v, def T) T {
	var zero T
	if v == zero {
		return def
	}
	return v
}
