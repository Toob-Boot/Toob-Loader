package build

import (
	"cmp"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
)

// SlotKind classifies a partition for the storage summary.
type SlotKind string

const (
	SlotBoot     SlotKind = "BOOT"
	SlotApp      SlotKind = "APP"
	SlotSystem   SlotKind = "SYSTEM"
	SlotReserved SlotKind = "RSVD"
)

// PartitionSlot is one allocated (or hardware-reserved) flash range.
// A zero Budget marks an optional partition that is not configured.
type PartitionSlot struct {
	Name       string
	Addr       uint32
	Budget     uint32
	SectorSize uint32
	Kind       SlotKind
}

// PartitionLayout is the complete, validated flash layout of a device.
type PartitionLayout struct {
	Stage0     PartitionSlot
	Stage1A    PartitionSlot
	Stage1B    PartitionSlot
	App        PartitionSlot
	Staging    PartitionSlot
	Scratch    PartitionSlot
	Wal        PartitionSlot   // Covers all WAL sectors as one contiguous range.
	WalSectors []PartitionSlot // Individual sectors of Wal, in ring order.
	Recovery   PartitionSlot
	NetCore    PartitionSlot
	KDM        PartitionSlot
	KdmSlots   []PartitionSlot // 3 individual physical sectors of KDM Quorum (CRIT-37).
	CloudCmd   PartitionSlot
	Mailbox    PartitionSlot
	Forensic   PartitionSlot
	Reserved   []PartitionSlot

	MaxSectorSize     uint32
	FlashBase         uint64 // Physical flash base address (CRIT-38).
	XipBaseVal        uint64 // CPU XIP base address (0 when direct physical mapping).
	FlashSize         uint32
	Used              uint32 // First address after the highest allocation (clamped to uint32).
	Used64            uint64 // Exact 64-bit end of the highest allocation.
	Transport         Transport
	IsBankSwap        bool
	Bank1Base         uint32
	Bank2Base         uint32
	VtorAlign         uint32
	ImageHeaderOffset uint32
	Arch              string
	Stage0Pow2Lock    bool
	Gaps              []AllocationGap
	FlashRegions      []FlashRegion
}

// SectorSizeAt returns the physical erase sector size at offset (CRIT-19).
func (l *PartitionLayout) SectorSizeAt(offset uint32) (uint32, error) {
	if len(l.FlashRegions) == 0 {
		if l.MaxSectorSize == 0 {
			return 0, fmt.Errorf("no flash regions available to resolve sector size at 0x%08X", offset)
		}
		return l.MaxSectorSize, nil
	}
	return sectorSizeInRegions(l.FlashRegions, offset)
}

// Fixed system partition sizes in units of local sectors.
const (
	kdmQuorumSectors   = 3
	cloudCmdSectors    = 1
	mailboxSectors     = 2 // Double-slot OS->Core mailbox.
	forensicSectors    = 1
	defaultSwapSectors = 4   // Default bounded scratch sectors for swapscratch (HIGH-17).
	minWalSectorBytes  = 256 // Minimum WAL sector size in bytes (CRIT-36 / MED-43).
)

type layoutPassParams struct {
	stage1Align  uint32
	stage1Budget uint32
	appAlign     uint32
	appBudget    uint32
	scratchAlign uint32
	vtorAlign    uint32
	imgHdrOff    uint32
}

func alignBudgetToAppAlign(budget, appAlign uint32, name string) (uint32, error) {
	if budget == 0 || appAlign == 0 {
		return budget, nil
	}
	aligned, err := alignUp(budget, appAlign)
	if err != nil {
		return 0, fmt.Errorf("FATAL [LAYOUT_002]: %s budget %d aligned to flash.app_alignment %d overflows uint32",
			name, budget, appAlign)
	}
	return aligned, nil
}

// planLayout allocates all partitions in a fixed, deterministic order.
func planLayout(dt *DeviceToml, hw *HardwareJson, cfg *ResolvedConfig) (*PartitionLayout, error) {
	if hw.Flash.AppAlignment != 0 && !isPowerOfTwo(uint64(hw.Flash.AppAlignment)) {
		return nil, fmt.Errorf("FATAL [FLASH_005]: flash.app_alignment %d is not a power of two", hw.Flash.AppAlignment)
	}
	vtorAlign, imgHdrOff := cfg.VtorAlign, cfg.ImageHeaderOffset
	if vtorAlign == 0 && imgHdrOff == 0 {
		vtorAlign, imgHdrOff = effectiveVtorAndHeaderOffset(cfg.Arch, hw)
	}
	if vtorAlign != 0 && !isPowerOfTwo(uint64(vtorAlign)) {
		return nil, fmt.Errorf("FATAL [FLASH_005]: vtor_alignment %d is not a power of two", vtorAlign)
	}

	appBaseBudget, err := alignBudgetToAppAlign(dt.Partitions.AppSize, hw.Flash.AppAlignment, "App Slot")
	if err != nil {
		return nil, err
	}

	params := layoutPassParams{
		stage1Budget: dt.Partitions.Stage1Size,
		appAlign:     hw.Flash.AppAlignment,
		appBudget:    appBaseBudget,
		vtorAlign:    vtorAlign,
		imgHdrOff:    imgHdrOff,
	}

	isSwapMoveOrOffset := cfg.Transport == TransportSwapMove || cfg.Transport == TransportSwapOffset
	isBankSwap := cfg.ExecModel == "bank_swap"

	var l *PartitionLayout
	var alloc *Allocator
	const maxLayoutPasses = 6
	converged := false
	for attempt := range maxLayoutPasses {
		if isBankSwap {
			l, alloc, err = runBankSwapAllocationPass(dt, hw, cfg, params)
		} else {
			l, alloc, err = runAllocationPass(dt, hw, cfg, params)
		}
		if err != nil {
			return nil, err
		}

		retry := false
		if l.Stage1A.Budget != l.Stage1B.Budget {
			sec := max(alloc.maxSectorSizeInRange(l.Stage1A.Addr, l.Stage1A.Budget),
				alloc.maxSectorSizeInRange(l.Stage1B.Addr, l.Stage1B.Budget))
			if sec > params.stage1Align && attempt == 0 {
				params.stage1Align = sec
			} else {
				params.stage1Budget = max(l.Stage1A.Budget, l.Stage1B.Budget)
			}
			retry = true
		}

		if isSwapMoveOrOffset {
			stgSec := l.slotSectorAlign(l.Staging)
			wantApp := uint64(l.Staging.Budget) + uint64(stgSec)
			if uint64(l.App.Budget) != wantApp {
				sec := max(alloc.maxSectorSizeInRange(l.App.Addr, l.App.Budget),
					alloc.maxSectorSizeInRange(l.Staging.Addr, l.Staging.Budget))
				if sec > params.appAlign && attempt == 0 {
					params.appAlign = sec
				} else {
					targetStg := l.Staging.Budget
					if uint64(l.App.Budget) > uint64(stgSec) && l.App.Budget-stgSec > targetStg {
						targetStg = l.App.Budget - stgSec
					}
					params.appBudget = targetStg
				}
				retry = true
			}
		} else if l.Staging.Budget > 0 && l.App.Budget != l.Staging.Budget {
			sec := max(alloc.maxSectorSizeInRange(l.App.Addr, l.App.Budget),
				alloc.maxSectorSizeInRange(l.Staging.Addr, l.Staging.Budget))
			if sec > params.appAlign && attempt == 0 {
				params.appAlign = sec
			} else {
				params.appBudget = max(l.App.Budget, l.Staging.Budget)
			}
			retry = true
		}

		if cfg.Transport == TransportSwapScratch && l.Scratch.Budget > 0 {
			swapSec := l.swapScratchBlockAlign()
			if swapSec > 0 && (l.App.Addr%swapSec != 0 ||
				(l.Staging.Budget > 0 && l.Staging.Addr%swapSec != 0) ||
				l.Scratch.Addr%swapSec != 0) {
				if swapSec > params.appAlign || swapSec > params.scratchAlign {
					params.appAlign = max(params.appAlign, swapSec)
					params.scratchAlign = max(params.scratchAlign, swapSec)
					retry = true
				}
			}
		}
		if !retry {
			converged = true
			break
		}
	}
	if !converged {
		return nil, fmt.Errorf("FATAL [LAYOUT_003]: Partition layout failed to converge after %d alignment passes", maxLayoutPasses)
	}

	for _, r := range hw.Flash.Regions {
		if isReservedRegion(r) {
			name := r.Name
			if name == "" {
				name = "Hardware Reserved"
			} else if err := validateDisplayText("flash region name", name); err != nil {
				return nil, fmt.Errorf("FATAL [FLASH_004]: %w", err)
			}
			l.Reserved = append(l.Reserved, PartitionSlot{Name: name, Addr: r.Base, Budget: r.Size, Kind: SlotReserved})
		}
	}

	maxWindowEnd := l.allowedUpperBound()
	if l.Used64 > maxWindowEnd {
		return nil, fmt.Errorf("FATAL [FLASH_003]: Partitions exceed physical flash size! End: 0x%X, Limit: 0x%X",
			l.Used64, maxWindowEnd)
	}
	if err := l.validate(); err != nil {
		return nil, err
	}
	if cfg.Transport == TransportSwapScratch {
		if l.Scratch.Budget == 0 {
			return nil, errors.New("FATAL [LAYOUT_006]: transport 'swapscratch' requires a non-empty Scratch partition")
		}
		minScratchSec := l.minSlotSectorInRange(l.Scratch)
		maxScratchSec := l.maxSlotSectorInRange(l.Scratch)
		if minScratchSec != maxScratchSec {
			return nil, fmt.Errorf("FATAL [LAYOUT_006]: Scratch partition [0x%08X..0x%X) spans heterogeneous sector sizes (%d vs %d), unsupported by swapscratch",
				l.Scratch.Addr, uint64(l.Scratch.Addr)+uint64(l.Scratch.Budget), minScratchSec, maxScratchSec)
		}
		swapSec := l.swapScratchBlockAlign()
		if swapSec > 0 {
			if l.Scratch.Budget < swapSec {
				return nil, fmt.Errorf("FATAL [LAYOUT_006]: Scratch budget (%d) is smaller than swapscratch block size (%d)",
					l.Scratch.Budget, swapSec)
			}
			for _, slot := range []PartitionSlot{l.App, l.Staging, l.Scratch} {
				if slot.Budget > 0 && slot.Addr%swapSec != 0 {
					return nil, fmt.Errorf("FATAL [LAYOUT_006]: %s starts at 0x%08X, which is not aligned to swapscratch block size %d",
						slot.Name, slot.Addr, swapSec)
				}
			}
		}
	}
	if strings.EqualFold(strings.TrimSpace(cfg.Arch), "cortex-m") {
		if !isPowerOfTwo(uint64(l.Stage0.Budget)) {
			return nil, fmt.Errorf("FATAL [LAYOUT_008]: Stage 0 size (0x%X) on Cortex-M must be a power of two for MPU/flash-lock protection",
				l.Stage0.Budget)
		}
		if (uint64(l.Stage0.Addr)-l.FlashBase)%uint64(l.Stage0.Budget) != 0 {
			return nil, fmt.Errorf("FATAL [LAYOUT_008]: Stage 0 start (0x%08X) must be naturally aligned to its power-of-two size (0x%X)",
				l.Stage0.Addr, l.Stage0.Budget)
		}
		l.Stage0Pow2Lock = true
		if normalizeChipName(hw.ChipFamily) == "rp2040" && l.Stage0.Budget != 32768 && l.Stage0.Budget != 65536 {
			return nil, fmt.Errorf("FATAL [LAYOUT_008]: RP2040 NOR block-protect lock supports only 32 KB or 64 KB Stage 0, got %d bytes",
				l.Stage0.Budget)
		}
	}

	l.Gaps = alloc.Gaps()
	return l, nil
}

func newBaseLayout(hw *HardwareJson, cfg *ResolvedConfig, maxSec uint32) *PartitionLayout {
	return &PartitionLayout{
		MaxSectorSize:     maxSec,
		FlashBase:         uint64(cfg.FlashBase),
		XipBaseVal:        cfg.XipBaseVal,
		FlashSize:         hw.Flash.Size,
		Transport:         cfg.Transport,
		VtorAlign:         cfg.VtorAlign,
		ImageHeaderOffset: cfg.ImageHeaderOffset,
		Arch:              cfg.Arch,
		FlashRegions:      slices.Clone(hw.Flash.Regions),
	}
}

func runAllocationPass(dt *DeviceToml, hw *HardwareJson, cfg *ResolvedConfig, params layoutPassParams) (*PartitionLayout, *Allocator, error) {
	alloc, err := NewAllocator(hw.Flash.Regions)
	if err != nil {
		return nil, nil, err
	}
	p := &dt.Partitions
	maxSec := alloc.maxSectorSize
	l := newBaseLayout(hw, cfg, maxSec)

	recoveryBudget, err := alignBudgetToAppAlign(p.RecoverySize, hw.Flash.AppAlignment, "Recovery OS")
	if err != nil {
		return nil, nil, err
	}
	netcoreBudget, err := alignBudgetToAppAlign(p.NetcoreSize, hw.Flash.AppAlignment, "NetCore Slot")
	if err != nil {
		return nil, nil, err
	}

	stage1XipVtor := cfg.Stage0ExecMode != "ram"
	stagingBudget := params.appBudget
	appBudget := params.appBudget
	isSwapMoveOrOffset := cfg.Transport == TransportSwapMove || cfg.Transport == TransportSwapOffset

	preAppSteps := []struct {
		slot    *PartitionSlot
		name    string
		kind    SlotKind
		budget  uint32
		align   uint32
		useVtor bool
	}{
		{&l.Stage0, "Stage 0", SlotBoot, p.Stage0Size, 0, false},
		{&l.Stage1A, "Stage 1 Bank A", SlotBoot, params.stage1Budget, params.stage1Align, stage1XipVtor},
		{&l.Stage1B, "Stage 1 Bank B", SlotBoot, params.stage1Budget, params.stage1Align, stage1XipVtor},
	}
	for _, s := range preAppSteps {
		*s.slot = PartitionSlot{Name: s.name, Kind: s.kind}
		if s.budget == 0 {
			continue
		}
		var vtor, hdr uint32
		if s.useVtor {
			vtor, hdr = params.vtorAlign, params.imgHdrOff
		}
		if s.slot.Addr, s.slot.Budget, err = alloc.AllocateWithVtor(s.budget, s.align, vtor, hdr, s.name); err != nil {
			return nil, nil, err
		}
		s.slot.SectorSize, _ = alloc.GetSectorSizeAt(s.slot.Addr)
	}

	if isSwapMoveOrOffset {
		probeStart, pErr := alloc.advanceToWritable(alloc.CurrentOffset64(), params.appAlign, params.vtorAlign, params.imgHdrOff)
		if pErr != nil {
			return nil, nil, fmt.Errorf("allocating 'App Slot': %w", pErr)
		}
		appSec, sErr := alloc.GetSectorSizeAt(probeStart)
		if sErr != nil {
			return nil, nil, fmt.Errorf("allocating 'App Slot': %w", sErr)
		}
		sum := uint64(stagingBudget) + uint64(appSec)
		if sum > math.MaxUint32 {
			return nil, nil, errors.New("FATAL [LAYOUT_005]: App Slot +1 spare sector overflows uint32")
		}
		appBudget = uint32(sum)
	}

	postSteps := []struct {
		slot    *PartitionSlot
		name    string
		kind    SlotKind
		budget  uint32
		align   uint32
		useVtor bool
	}{
		{&l.App, "App Slot", SlotApp, appBudget, params.appAlign, true},
		{&l.Staging, "Staging Slot", SlotApp, stagingBudget, params.appAlign, true},
		{&l.Recovery, "Recovery OS", SlotSystem, recoveryBudget, hw.Flash.AppAlignment, true},
		{&l.NetCore, "NetCore Slot", SlotApp, netcoreBudget, hw.Flash.AppAlignment, false},
	}
	for _, s := range postSteps {
		*s.slot = PartitionSlot{Name: s.name, Kind: s.kind}
		if s.budget == 0 {
			continue
		}
		var vtor, hdr uint32
		if s.useVtor {
			vtor, hdr = params.vtorAlign, params.imgHdrOff
		}
		if s.slot.Addr, s.slot.Budget, err = alloc.AllocateWithVtor(s.budget, s.align, vtor, hdr, s.name); err != nil {
			return nil, nil, err
		}
		s.slot.SectorSize, _ = alloc.GetSectorSizeAt(s.slot.Addr)
	}

	if err := allocateTailPartitions(alloc, l, dt, cfg, params.scratchAlign); err != nil {
		return nil, nil, err
	}
	l.Used = alloc.CurrentOffset()
	l.Used64 = alloc.CurrentOffset64()
	return l, alloc, nil
}

func allocateTailPartitions(alloc *Allocator, l *PartitionLayout, dt *DeviceToml, cfg *ResolvedConfig, scratchAlign uint32) error {
	p := &dt.Partitions
	maxSec := alloc.maxSectorSize
	deltaScratch := needsDeltaScratch(cfg.Transport, p.EnableDeltas)
	l.Scratch = PartitionSlot{Name: "Scratch / Delta Safe", Kind: SlotSystem}
	if p.ScratchSize > 0 || deltaScratch || needsDedicatedScratch(cfg.Transport, cfg.BackupMode, cfg.SlotCount) {
		var budget uint32
		switch {
		case p.ScratchSize > 0:
			budget = p.ScratchSize
			if deltaScratch && budget < l.App.Budget {
				budget = l.App.Budget
			}
		case cfg.Transport == TransportSwapScratch && !deltaScratch:
			bounded := uint64(defaultSwapSectors) * uint64(maxSec)
			if bounded > uint64(l.App.Budget) {
				bounded = uint64(l.App.Budget)
			}
			if bounded > math.MaxUint32 {
				bounded = math.MaxUint32
			}
			budget = max(maxSec, uint32(bounded))
		default:
			budget = l.App.Budget
		}
		var err error
		if l.Scratch.Addr, l.Scratch.Budget, err = alloc.Allocate(budget, scratchAlign, l.Scratch.Name); err != nil {
			return err
		}
		l.Scratch.SectorSize, _ = alloc.GetSectorSizeAt(l.Scratch.Addr)
	}

	if err := planWal(alloc, l, cfg.WalSectors); err != nil {
		return err
	}

	return allocateSystemMetadataSlots(alloc, l, false, 0)
}

func allocateSystemMetadataSlots(alloc *Allocator, l *PartitionLayout, allowWrap bool, wrapBase uint64) error {
	type sysSpec struct {
		slot       *PartitionSlot
		name       string
		sectors    uint32
		equalSplit bool
		isKdm      bool
	}
	var fixed []sysSpec
	if allowWrap {
		// In multi-hole bank_swap layouts, place equalSplit (Mailbox) first so
		// single-sector metadata does not fragment a 2-sector uniform hole.
		fixed = []sysSpec{
			{&l.Mailbox, "Mailbox", mailboxSectors, true, false},
			{&l.KDM, "KDM Quorum", kdmQuorumSectors, false, true},
			{&l.CloudCmd, "Cloud Command", cloudCmdSectors, false, false},
			{&l.Forensic, "Forensic Slot", forensicSectors, false, false},
		}
	} else {
		fixed = []sysSpec{
			{&l.KDM, "KDM Quorum", kdmQuorumSectors, false, true},
			{&l.CloudCmd, "Cloud Command", cloudCmdSectors, false, false},
			{&l.Mailbox, "Mailbox", mailboxSectors, true, false},
			{&l.Forensic, "Forensic Slot", forensicSectors, false, false},
		}
	}
	for _, f := range fixed {
		*f.slot = PartitionSlot{Name: f.name, Kind: SlotSystem}
		subSlots, err := allocateLocalSectorsWithSlots(alloc, f.slot, f.sectors, f.equalSplit)
		if err != nil && allowWrap {
			alloc.offset = wrapBase
			subSlots, err = allocateLocalSectorsWithSlots(alloc, f.slot, f.sectors, f.equalSplit)
		}
		if err != nil {
			return err
		}
		if f.isKdm {
			l.KdmSlots = subSlots
		}
		if allowWrap {
			alloc.regions = append(alloc.regions, FlashRegion{
				Type: "reserved", Base: f.slot.Addr, Size: f.slot.Budget, Name: f.name,
			})
		}
	}
	return nil
}

func discoverDualBanks(regions []FlashRegion) (uint64, uint64, uint64, uint64, error) {
	var writables []FlashRegion
	for _, r := range regions {
		if isWritableRegion(r) {
			writables = append(writables, r)
		}
	}
	slices.SortFunc(writables, func(a, b FlashRegion) int { return cmp.Compare(a.Base, b.Base) })
	if len(writables) < 2 {
		return 0, 0, 0, 0, errors.New("FATAL [LAYOUT_007]: exec_model \"bank_swap\" requires at least 2 physical writable flash bank regions")
	}

	var bestB1Base, bestB1End, bestB2Base, bestB2End, bestCap uint64
	for split := 1; split < len(writables); split++ {
		b1Base := uint64(writables[0].Base)
		b1End := regionEnd(writables[0])
		contiguous1 := true
		for i := 1; i < split; i++ {
			if uint64(writables[i].Base) != b1End {
				contiguous1 = false
				break
			}
			b1End = regionEnd(writables[i])
		}
		if !contiguous1 || b1End <= b1Base {
			continue
		}
		bankCap := b1End - b1Base
		if bankCap <= bestCap {
			continue
		}

		b2Base := uint64(writables[split].Base)
		if b2Base < b1End {
			continue
		}
		b2End := regionEnd(writables[split])
		for j := split + 1; j <= len(writables); j++ {
			if b2End-b2Base == bankCap {
				bestB1Base, bestB1End, bestB2Base, bestB2End, bestCap = b1Base, b1End, b2Base, b2End, bankCap
				break
			}
			if j == len(writables) || uint64(writables[j].Base) != b2End {
				break
			}
			b2End = regionEnd(writables[j])
		}
	}
	if bestCap > 0 {
		return bestB1Base, bestB1End, bestB2Base, bestB2End, nil
	}
	return 0, 0, 0, 0, errors.New("FATAL [LAYOUT_007]: exec_model \"bank_swap\" requires two equal-capacity physical writable banks")
}

func clipRegionsToWindow(regions []FlashRegion, winStart, winEnd uint64) []FlashRegion {
	var out []FlashRegion
	for _, r := range regions {
		rStart, rEnd := uint64(r.Base), regionEnd(r)
		if rEnd <= winStart || rStart >= winEnd {
			continue
		}
		cStart := max(rStart, winStart)
		cEnd := min(rEnd, winEnd)
		if cEnd <= cStart {
			continue
		}
		cSpan := cEnd - cStart
		if cStart > math.MaxUint32 || cSpan > math.MaxUint32 {
			continue
		}
		if isReservedRegion(r) {
			out = append(out, FlashRegion{
				Type: "reserved", Base: uint32(cStart), Size: uint32(cSpan), Name: r.Name,
			})
			continue
		}
		if r.SectorSize == 0 {
			continue
		}
		alignedStart := cStart
		if rem := (alignedStart - rStart) % uint64(r.SectorSize); rem != 0 {
			alignedStart += uint64(r.SectorSize) - rem
		}
		if alignedStart >= cEnd || alignedStart > math.MaxUint32 {
			continue
		}
		cnt := (cEnd - alignedStart) / uint64(r.SectorSize)
		if cnt == 0 || cnt > math.MaxUint32 {
			continue
		}
		out = append(out, FlashRegion{
			Type: "writable", Base: uint32(alignedStart), SectorSize: r.SectorSize, Count: uint32(cnt), Name: r.Name,
		})
	}
	return out
}

// runBankSwapAllocationPass implements Option 1C symmetric mirrored Dual-Bank layout (CRIT-41):
// App in Bank 1 and Staging in Bank 2 sit at the exact same intra-bank offset delta,
// Stage1B sits in Bank 2's prefix before Staging, and WAL never lands at bank2Base + 0.
func runBankSwapAllocationPass(dt *DeviceToml, hw *HardwareJson, cfg *ResolvedConfig, params layoutPassParams) (*PartitionLayout, *Allocator, error) {
	b1Base, b1End, b2Base, b2End, err := discoverDualBanks(hw.Flash.Regions)
	if err != nil {
		return nil, nil, err
	}
	if b1Base > math.MaxUint32 || b2Base > math.MaxUint32 {
		return nil, nil, errors.New("FATAL [LAYOUT_007]: Dual-Bank base exceeds 32-bit address space")
	}

	fullAlloc, err := NewAllocator(hw.Flash.Regions)
	if err != nil {
		return nil, nil, err
	}
	l := newBaseLayout(hw, cfg, fullAlloc.maxSectorSize)
	l.IsBankSwap = true
	l.Bank1Base = uint32(b1Base)
	l.Bank2Base = uint32(b2Base)

	p := &dt.Partitions
	stage1XipVtor := cfg.Stage0ExecMode != "ram"
	var s1Vtor, s1Hdr uint32
	if stage1XipVtor {
		s1Vtor, s1Hdr = params.vtorAlign, params.imgHdrOff
	}

	recoveryBudget, err := alignBudgetToAppAlign(p.RecoverySize, hw.Flash.AppAlignment, "Recovery OS")
	if err != nil {
		return nil, nil, err
	}
	netcoreBudget, err := alignBudgetToAppAlign(p.NetcoreSize, hw.Flash.AppAlignment, "NetCore Slot")
	if err != nil {
		return nil, nil, err
	}

	appTarget := params.appBudget
	stagingTarget := params.appBudget
	if cfg.Transport == TransportSwapMove || cfg.Transport == TransportSwapOffset {
		b1Probe, pErr := NewAllocator(clipRegionsToWindow(hw.Flash.Regions, b1Base, b1End))
		if pErr != nil {
			return nil, nil, pErr
		}
		sec, sErr := b1Probe.GetSectorSizeAt(uint32(b1Base))
		if sErr != nil {
			return nil, nil, sErr
		}
		if uint64(stagingTarget)+uint64(sec) > math.MaxUint32 {
			return nil, nil, errors.New("FATAL [LAYOUT_005]: App Slot +1 spare sector overflows uint32")
		}
		appTarget = stagingTarget + sec
	}

	b1Alloc, err := NewAllocator(clipRegionsToWindow(hw.Flash.Regions, b1Base, b1End))
	if err != nil {
		return nil, nil, err
	}
	l.Stage0 = PartitionSlot{Name: "Stage 0", Kind: SlotBoot}
	if l.Stage0.Addr, l.Stage0.Budget, err = b1Alloc.Allocate(p.Stage0Size, 0, l.Stage0.Name); err != nil {
		return nil, nil, err
	}
	l.Stage0.SectorSize, _ = b1Alloc.GetSectorSizeAt(l.Stage0.Addr)

	l.Stage1A = PartitionSlot{Name: "Stage 1 Bank A", Kind: SlotBoot}
	if l.Stage1A.Addr, l.Stage1A.Budget, err = b1Alloc.AllocateWithVtor(params.stage1Budget, params.stage1Align, s1Vtor, s1Hdr, l.Stage1A.Name); err != nil {
		return nil, nil, err
	}
	l.Stage1A.SectorSize, _ = b1Alloc.GetSectorSizeAt(l.Stage1A.Addr)
	if s1MaxSec := b1Alloc.maxSectorSizeInRange(l.Stage1A.Addr, l.Stage1A.Budget); s1MaxSec > l.Stage1A.SectorSize && l.Stage1A.Budget > params.stage1Budget {
		if b1RetryS1, rErr := NewAllocator(clipRegionsToWindow(hw.Flash.Regions, uint64(l.Stage0.Addr)+uint64(l.Stage0.Budget), b1End)); rErr == nil {
			if addr, bud, aErr := b1RetryS1.AllocateWithVtor(params.stage1Budget, max(params.stage1Align, s1MaxSec), s1Vtor, s1Hdr, l.Stage1A.Name); aErr == nil && bud <= l.Stage1A.Budget {
				l.Stage1A.Addr, l.Stage1A.Budget = addr, bud
				l.Stage1A.SectorSize, _ = b1RetryS1.GetSectorSizeAt(addr)
				b1Alloc = b1RetryS1
			}
		}
	}

	preAppCursor := b1Alloc.CurrentOffset64()
	l.App = PartitionSlot{Name: "App Slot", Kind: SlotApp}
	if l.App.Addr, l.App.Budget, err = b1Alloc.AllocateWithVtor(appTarget, params.appAlign, params.vtorAlign, params.imgHdrOff, l.App.Name); err != nil {
		return nil, nil, err
	}
	l.App.SectorSize, _ = b1Alloc.GetSectorSizeAt(l.App.Addr)
	delta := uint64(l.App.Addr) - b1Base

	// Place Stage1B inside Bank 2's prefix [b2Base .. b2Base + delta), preferring the
	// exact mirrored Stage1A intra-bank offset so asymmetric small sectors stay free.
	s1bAlign := max(params.stage1Align, l.Stage1A.SectorSize)
	l.Stage1B = PartitionSlot{Name: "Stage 1 Bank B", Kind: SlotBoot}
	placedS1B := false
	s1aRel := uint64(l.Stage1A.Addr) - b1Base
	if delta > 0 && s1aRel < delta {
		if mirRegs := clipRegionsToWindow(hw.Flash.Regions, b2Base+s1aRel, b2Base+delta); len(mirRegs) > 0 {
			if mirAlloc, mErr := NewAllocator(mirRegs); mErr == nil {
				if addr, bud, aErr := mirAlloc.AllocateWithVtor(params.stage1Budget, s1bAlign, s1Vtor, s1Hdr, l.Stage1B.Name); aErr == nil {
					l.Stage1B.Addr, l.Stage1B.Budget = addr, bud
					l.Stage1B.SectorSize, _ = mirAlloc.GetSectorSizeAt(addr)
					placedS1B = true
				}
			}
		}
	}
	if !placedS1B && delta > 0 {
		if prefRegs := clipRegionsToWindow(hw.Flash.Regions, b2Base, b2Base+delta); len(prefRegs) > 0 {
			if prefAlloc, pErr := NewAllocator(prefRegs); pErr == nil {
				if addr, bud, aErr := prefAlloc.AllocateWithVtor(params.stage1Budget, s1bAlign, s1Vtor, s1Hdr, l.Stage1B.Name); aErr == nil {
					l.Stage1B.Addr, l.Stage1B.Budget = addr, bud
					l.Stage1B.SectorSize, _ = prefAlloc.GetSectorSizeAt(addr)
					placedS1B = true
				}
			}
		}
	}
	if !placedS1B {
		b2FullAlloc, bErr := NewAllocator(clipRegionsToWindow(hw.Flash.Regions, b2Base, b2End))
		if bErr != nil {
			return nil, nil, bErr
		}
		if l.Stage1B.Addr, l.Stage1B.Budget, err = b2FullAlloc.AllocateWithVtor(params.stage1Budget, s1bAlign, s1Vtor, s1Hdr, l.Stage1B.Name); err != nil {
			return nil, nil, err
		}
		l.Stage1B.SectorSize, _ = b2FullAlloc.GetSectorSizeAt(l.Stage1B.Addr)
		reqDelta := uint64(l.Stage1B.Addr) + uint64(l.Stage1B.Budget) - b2Base
		if reqDelta > delta {
			b1Retry, rErr := NewAllocator(clipRegionsToWindow(hw.Flash.Regions, max(preAppCursor, b1Base+reqDelta), b1End))
			if rErr != nil {
				return nil, nil, rErr
			}
			if l.App.Addr, l.App.Budget, err = b1Retry.AllocateWithVtor(appTarget, params.appAlign, params.vtorAlign, params.imgHdrOff, l.App.Name); err != nil {
				return nil, nil, err
			}
			l.App.SectorSize, _ = b1Retry.GetSectorSizeAt(l.App.Addr)
			delta = uint64(l.App.Addr) - b1Base
		}
	}

	b2StgRegs := clipRegionsToWindow(hw.Flash.Regions, b2Base+delta, b2End)
	b2StgAlloc, err := NewAllocator(b2StgRegs)
	if err != nil {
		return nil, nil, fmt.Errorf("allocating 'Staging Slot' in Bank 2 at offset 0x%X: %w", delta, err)
	}
	l.Staging = PartitionSlot{Name: "Staging Slot", Kind: SlotApp}
	if l.Staging.Addr, l.Staging.Budget, err = b2StgAlloc.AllocateWithVtor(stagingTarget, params.appAlign, params.vtorAlign, params.imgHdrOff, l.Staging.Name); err != nil {
		return nil, nil, err
	}
	l.Staging.SectorSize, _ = b2StgAlloc.GetSectorSizeAt(l.Staging.Addr)

	if stgDelta := uint64(l.Staging.Addr) - b2Base; stgDelta > delta {
		b1Sync, rErr := NewAllocator(clipRegionsToWindow(hw.Flash.Regions, b1Base+stgDelta, b1End))
		if rErr != nil {
			return nil, nil, rErr
		}
		if l.App.Addr, l.App.Budget, err = b1Sync.AllocateWithVtor(appTarget, params.appAlign, params.vtorAlign, params.imgHdrOff, l.App.Name); err != nil {
			return nil, nil, err
		}
		l.App.SectorSize, _ = b1Sync.GetSectorSizeAt(l.App.Addr)
		delta = uint64(l.App.Addr) - b1Base
	}
	if (uint64(l.Staging.Addr) - b2Base) != delta {
		return nil, nil, fmt.Errorf("FATAL [LAYOUT_007]: Dual-Bank mirror mismatch: App offset 0x%X != Staging offset 0x%X",
			delta, uint64(l.Staging.Addr)-b2Base)
	}

	// Build residual allocator with committed Bank 1/2 slots marked as reserved carve-outs
	// and guard bank2Base + 0 so WAL and post-App partitions never clobber Bank 2 base.
	resRegions := slices.Clone(hw.Flash.Regions)
	for _, s := range []PartitionSlot{l.Stage0, l.Stage1A, l.App, l.Stage1B, l.Staging} {
		if s.Budget > 0 {
			resRegions = append(resRegions, FlashRegion{Type: "reserved", Base: s.Addr, Size: s.Budget, Name: s.Name})
		}
	}
	if b2FirstSec, sErr := fullAlloc.GetSectorSizeAt(uint32(b2Base)); sErr == nil && uint64(l.Stage1B.Addr) != b2Base {
		resRegions = append(resRegions, FlashRegion{
			Type: "reserved", Base: uint32(b2Base), Size: b2FirstSec, Name: "bank2_origin_guard",
		})
	}
	resAlloc, err := NewAllocator(resRegions)
	if err != nil {
		return nil, nil, err
	}
	resAlloc.offset = uint64(l.App.Addr) + uint64(l.App.Budget)

	l.Recovery = PartitionSlot{Name: "Recovery OS", Kind: SlotSystem}
	if recoveryBudget > 0 {
		if l.Recovery.Addr, l.Recovery.Budget, err = resAlloc.AllocateWithVtor(recoveryBudget, hw.Flash.AppAlignment, params.vtorAlign, params.imgHdrOff, l.Recovery.Name); err != nil {
			return nil, nil, err
		}
		l.Recovery.SectorSize, _ = resAlloc.GetSectorSizeAt(l.Recovery.Addr)
		resAlloc.regions = append(resAlloc.regions, FlashRegion{Type: "reserved", Base: l.Recovery.Addr, Size: l.Recovery.Budget, Name: l.Recovery.Name})
	}

	l.NetCore = PartitionSlot{Name: "NetCore Slot", Kind: SlotApp}
	if netcoreBudget > 0 {
		if l.NetCore.Addr, l.NetCore.Budget, err = resAlloc.Allocate(netcoreBudget, hw.Flash.AppAlignment, l.NetCore.Name); err != nil {
			return nil, nil, err
		}
		l.NetCore.SectorSize, _ = resAlloc.GetSectorSizeAt(l.NetCore.Addr)
		resAlloc.regions = append(resAlloc.regions, FlashRegion{Type: "reserved", Base: l.NetCore.Addr, Size: l.NetCore.Budget, Name: l.NetCore.Name})
	}

	deltaScratch := needsDeltaScratch(cfg.Transport, p.EnableDeltas)
	l.Scratch = PartitionSlot{Name: "Scratch / Delta Safe", Kind: SlotSystem}
	if p.ScratchSize > 0 || deltaScratch || needsDedicatedScratch(cfg.Transport, cfg.BackupMode, cfg.SlotCount) {
		budget := l.App.Budget
		if p.ScratchSize > 0 {
			budget = p.ScratchSize
			if deltaScratch && budget < l.App.Budget {
				budget = l.App.Budget
			}
		}
		if l.Scratch.Addr, l.Scratch.Budget, err = resAlloc.Allocate(budget, params.scratchAlign, l.Scratch.Name); err != nil {
			return nil, nil, err
		}
		l.Scratch.SectorSize, _ = resAlloc.GetSectorSizeAt(l.Scratch.Addr)
		resAlloc.regions = append(resAlloc.regions, FlashRegion{Type: "reserved", Base: l.Scratch.Addr, Size: l.Scratch.Budget, Name: l.Scratch.Name})
	}

	if err := advanceToContiguousSectors(resAlloc, cfg.WalSectors); err != nil {
		return nil, nil, err
	}
	if err := planWal(resAlloc, l, cfg.WalSectors); err != nil {
		return nil, nil, err
	}
	// WAL is now safely committed away from bank2Base + 0; drop the temporary
	// origin guard so non-WAL system metadata can utilize small prefix sectors if needed.
	resAlloc.regions = slices.DeleteFunc(resAlloc.regions, func(r FlashRegion) bool {
		return r.Name == "bank2_origin_guard"
	})
	resAlloc.regions = append(resAlloc.regions, FlashRegion{Type: "reserved", Base: l.Wal.Addr, Size: l.Wal.Budget, Name: l.Wal.Name})

	if err := allocateSystemMetadataSlots(resAlloc, l, true, b1Base); err != nil {
		return nil, nil, err
	}

	var maxEnd uint64
	for _, r := range l.regions() {
		if r.slot.Budget > 0 {
			maxEnd = max(maxEnd, uint64(r.slot.Addr)+uint64(r.slot.Budget))
		}
	}
	l.Used64 = maxEnd
	if maxEnd > math.MaxUint32 {
		l.Used = math.MaxUint32
	} else {
		l.Used = uint32(maxEnd)
	}
	return l, resAlloc, nil
}

func advanceToContiguousSectors(alloc *Allocator, sectors uint32) error {
	searchFrom := alloc.CurrentOffset64()
	for {
		probe, err := alloc.advanceToWritable(searchFrom, 0, 0, 0)
		if err != nil {
			return fmt.Errorf("allocating WAL (%d contiguous sectors): %w", sectors, err)
		}
		cur := uint64(probe)
		interrupted := false
		for range sectors {
			if cur > math.MaxUint32 {
				return errors.New("FATAL: WAL sector search exceeds 32-bit address space")
			}
			cur32 := uint32(cur)
			if r, inside := alloc.reservedRegionAt(cur32); inside {
				end, err := reservedEnd(r)
				if err != nil {
					return err
				}
				searchFrom = end
				interrupted = true
				break
			}
			secSz, err := alloc.GetSectorSizeAt(cur32)
			if err != nil {
				if nextBase, ok := alloc.nextWritableBase(cur32); ok {
					searchFrom = uint64(nextBase)
					interrupted = true
					break
				}
				return err
			}
			if cur+uint64(secSz) > 0x100000000 {
				return errors.New("FATAL: WAL sector search exceeds 32-bit address space")
			}
			if r, hit := alloc.lowestReservedOverlap(cur, cur+uint64(secSz)); hit {
				end, err := reservedEnd(r)
				if err != nil {
					return err
				}
				searchFrom = end
				interrupted = true
				break
			}
			cur += uint64(secSz)
		}
		if !interrupted {
			alloc.offset = uint64(probe)
			return nil
		}
	}
}

// allocateLocalSectorsWithSlots allocates `sectors` contiguous physical sectors for a
// fixed system partition using local sector sizes (CRIT-19 / CRIT-37). When equalSplit
// is true (e.g. Mailbox), all sectors in the range must have identical size.
func allocateLocalSectorsWithSlots(alloc *Allocator, slot *PartitionSlot, sectors uint32, equalSplit bool) ([]PartitionSlot, error) {
	if sectors == 0 {
		return nil, fmt.Errorf("allocating '%s': sector count must be greater than zero", slot.Name)
	}
	searchFrom := alloc.CurrentOffset64()
	for {
		probe, err := alloc.advanceToWritable(searchFrom, 0, 0, 0)
		if err != nil {
			return nil, fmt.Errorf("allocating '%s': %w", slot.Name, err)
		}
		var total uint64
		cur := uint64(probe)
		uniform := true
		var firstSec uint32
		interrupted := false
		subSlots := make([]PartitionSlot, 0, sectors)
		for i := range sectors {
			if cur > math.MaxUint32 {
				return nil, fmt.Errorf("FATAL [LAYOUT_005]: %s exceeds 32-bit address space", slot.Name)
			}
			cur32 := uint32(cur)
			if r, inside := alloc.reservedRegionAt(cur32); inside {
				end, err := reservedEnd(r)
				if err != nil {
					return nil, fmt.Errorf("allocating '%s': %w", slot.Name, err)
				}
				searchFrom = end
				interrupted = true
				break
			}
			secSz, err := alloc.GetSectorSizeAt(cur32)
			if err != nil {
				if nextBase, ok := alloc.nextWritableBase(cur32); ok {
					searchFrom = uint64(nextBase)
					interrupted = true
					break
				}
				return nil, fmt.Errorf("allocating '%s': %w", slot.Name, err)
			}
			if cur+uint64(secSz) > 0x100000000 || total+uint64(secSz) > math.MaxUint32 {
				return nil, fmt.Errorf("FATAL [LAYOUT_005]: %s budget overflows 32-bit address space", slot.Name)
			}
			if r, hit := alloc.lowestReservedOverlap(cur, cur+uint64(secSz)); hit {
				end, err := reservedEnd(r)
				if err != nil {
					return nil, fmt.Errorf("allocating '%s': %w", slot.Name, err)
				}
				searchFrom = end
				interrupted = true
				break
			}
			if i == 0 {
				firstSec = secSz
			} else if secSz != firstSec {
				uniform = false
			}
			subSlots = append(subSlots, PartitionSlot{
				Name: fmt.Sprintf("%s Sector %d", slot.Name, i),
				Addr: cur32, Budget: secSz, SectorSize: secSz, Kind: slot.Kind,
			})
			total += uint64(secSz)
			cur += uint64(secSz)
		}
		if interrupted {
			continue
		}
		if equalSplit && !uniform {
			if uint64(probe)+uint64(firstSec) > 0x100000000 {
				return nil, fmt.Errorf("FATAL [LAYOUT_005]: %s alignment search exceeds 32-bit address space", slot.Name)
			}
			searchFrom = uint64(probe) + uint64(firstSec)
			continue
		}
		alloc.commitRange(probe, cur, slot.Name)
		slot.Addr = probe
		slot.Budget = uint32(total)
		slot.SectorSize = firstSec
		return subSlots, nil
	}
}

// planWal allocates the WAL ring sector by sector and requires the sectors to
// be physically contiguous, because Stage 1 addresses the WAL as one range.
func planWal(alloc *Allocator, l *PartitionLayout, sectors uint32) error {
	if sectors < minWalSectors || sectors > maxWalSectors {
		return fmt.Errorf("FATAL: partitions.wal_sectors = %d must be between %d and %d", sectors, minWalSectors, maxWalSectors)
	}
	l.WalSectors = make([]PartitionSlot, 0, sectors)
	for i := range sectors {
		name := fmt.Sprintf("WAL Sector %d", i)
		addr, size, err := alloc.AllocateSector(name, 0)
		if err != nil {
			return err
		}
		if size < minWalSectorBytes {
			return fmt.Errorf("FATAL [LAYOUT_001]: %s size (%d bytes) is below minimum %d bytes",
				name, size, minWalSectorBytes)
		}
		if i > 0 {
			prev := l.WalSectors[i-1]
			expected := uint64(prev.Addr) + uint64(prev.Budget)
			if uint64(addr) != expected {
				return fmt.Errorf("FATAL: WAL sectors must be contiguous, but sector %d starts at 0x%08X instead of 0x%08X",
					i, addr, expected)
			}
		}
		l.WalSectors = append(l.WalSectors, PartitionSlot{
			Name: name, Addr: addr, Budget: size, SectorSize: size, Kind: SlotSystem,
		})
	}

	l.Wal = PartitionSlot{Name: fmt.Sprintf("WAL Journal (%d sec)", sectors), Kind: SlotSystem}
	if len(l.WalSectors) > 0 {
		last := l.WalSectors[len(l.WalSectors)-1]
		l.Wal.Addr = l.WalSectors[0].Addr
		l.Wal.SectorSize = l.WalSectors[0].SectorSize
		total := uint64(last.Addr) + uint64(last.Budget) - uint64(l.Wal.Addr)
		if total > math.MaxUint32 {
			return fmt.Errorf("FATAL: WAL total size 0x%X exceeds 32-bit bounds", total)
		}
		l.Wal.Budget = uint32(total)
	}
	return nil
}

// maxSlotSectorInRange returns the largest physical erase sector touched by s.
func (l *PartitionLayout) maxSlotSectorInRange(s PartitionSlot) uint32 {
	if s.Budget == 0 {
		return 0
	}
	var maxSec uint32
	end := uint64(s.Addr) + uint64(s.Budget)
	for _, r := range l.FlashRegions {
		if !isWritableRegion(r) {
			continue
		}
		if uint64(r.Base) < end && uint64(s.Addr) < regionEnd(r) {
			maxSec = max(maxSec, r.SectorSize)
		}
	}
	if maxSec != 0 {
		return maxSec
	}
	return l.slotSectorAlign(s)
}

// minSlotSectorInRange returns the smallest physical erase sector touched by s.
func (l *PartitionLayout) minSlotSectorInRange(s PartitionSlot) uint32 {
	if s.Budget == 0 {
		return 0
	}
	minSec := uint32(math.MaxUint32)
	end := uint64(s.Addr) + uint64(s.Budget)
	for _, r := range l.FlashRegions {
		if !isWritableRegion(r) {
			continue
		}
		if uint64(r.Base) < end && uint64(s.Addr) < regionEnd(r) {
			minSec = min(minSec, r.SectorSize)
		}
	}
	if minSec != math.MaxUint32 {
		return minSec
	}
	return l.slotSectorAlign(s)
}

func (l *PartitionLayout) allowedUpperBound() uint64 {
	upper := l.FlashBase + uint64(l.FlashSize)
	for _, r := range l.FlashRegions {
		upper = max(upper, regionEnd(r))
	}
	return min(upper, 0x100000000)
}

// swapScratchBlockAlign returns max(dest_sec, src_sec, scratch_sec) across App,
// Staging, and Scratch so boot_swap_in_place never steps across an unaligned
// larger sector boundary on asymmetric Dual-Bank flash (HIGH-41 / Finding O).
func (l *PartitionLayout) swapScratchBlockAlign() uint32 {
	return max(
		l.maxSlotSectorInRange(l.App),
		l.maxSlotSectorInRange(l.Staging),
		l.maxSlotSectorInRange(l.Scratch),
	)
}

// slotSectorAlign returns the local erase sector size for s, falling back to
// l.SectorSizeAt(s.Addr) or l.MaxSectorSize when synthetic test slots omit SectorSize.
func (l *PartitionLayout) slotSectorAlign(s PartitionSlot) uint32 {
	if s.SectorSize != 0 {
		return s.SectorSize
	}
	if sec, err := l.SectorSizeAt(s.Addr); err == nil && sec != 0 {
		return sec
	}
	return l.MaxSectorSize
}

// validate re-checks the invariants the C-side layout assertions and the
// swap transports rely on.
func (l *PartitionLayout) validate() error {
	if l.MaxSectorSize == 0 || !isPowerOfTwo(uint64(l.MaxSectorSize)) {
		return fmt.Errorf("FATAL [LAYOUT_001]: invalid MaxSectorSize %d (must be a non-zero power of two)", l.MaxSectorSize)
	}
	regions := l.regions()
	for _, r := range regions {
		s := r.slot
		if s.Budget == 0 {
			continue
		}
		startSec := l.slotSectorAlign(s)
		if startSec == 0 || !isPowerOfTwo(uint64(startSec)) || s.Addr%startSec != 0 {
			return fmt.Errorf("FATAL [LAYOUT_001]: %s starts at 0x%08X, which is not a multiple of its local sector size %d",
				s.Name, s.Addr, startSec)
		}
		if !r.sectorGranular {
			endAddr := uint64(s.Addr) + uint64(s.Budget)
			endSec := startSec
			if endAddr > 0 && endAddr <= math.MaxUint32 {
				if sec, err := l.SectorSizeAt(uint32(endAddr - 1)); err == nil && sec != 0 {
					endSec = sec
				}
			}
			if endAddr%uint64(endSec) != 0 || (endSec == startSec && s.Budget%startSec != 0) {
				return fmt.Errorf("FATAL [LAYOUT_002]: %s [0x%08X..0x%X) size %d is not aligned to its ending sector size %d",
					s.Name, s.Addr, endAddr, s.Budget, endSec)
			}
		}
	}
	for _, ks := range l.KdmSlots {
		kSec := l.slotSectorAlign(ks)
		if kSec == 0 || !isPowerOfTwo(uint64(kSec)) || ks.Addr%kSec != 0 || ks.Budget != kSec {
			return fmt.Errorf("FATAL [LAYOUT_001]: %s [0x%08X..0x%X) must occupy exactly one aligned physical sector (%d)",
				ks.Name, ks.Addr, uint64(ks.Addr)+uint64(ks.Budget), kSec)
		}
	}
	if l.Stage1A.Budget != l.Stage1B.Budget {
		return fmt.Errorf("FATAL [LAYOUT_003]: %s (%d bytes) and %s (%d bytes) must be equally large",
			l.Stage1A.Name, l.Stage1A.Budget, l.Stage1B.Name, l.Stage1B.Budget)
	}
	if l.Transport == TransportSwapMove || l.Transport == TransportSwapOffset {
		if l.Staging.Budget == 0 {
			return fmt.Errorf("FATAL [LAYOUT_003]: transport '%s' requires a non-empty Staging Slot", l.Transport)
		}
		stgSec := l.slotSectorAlign(l.Staging)
		if l.minSlotSectorInRange(l.App) != stgSec || l.maxSlotSectorInRange(l.App) != stgSec ||
			l.minSlotSectorInRange(l.Staging) != stgSec || l.maxSlotSectorInRange(l.Staging) != stgSec {
			return fmt.Errorf("FATAL [LAYOUT_006]: transport '%s' requires uniform physical sectors (%d bytes) across App and Staging",
				l.Transport, stgSec)
		}
		if uint64(l.App.Budget) != uint64(l.Staging.Budget)+uint64(stgSec) {
			return fmt.Errorf("FATAL [LAYOUT_003]: transport '%s' requires App Slot (%d) == Staging Slot (%d) + 1 spare sector (%d)",
				l.Transport, l.App.Budget, l.Staging.Budget, stgSec)
		}
	} else if l.Staging.Budget > 0 && l.App.Budget != l.Staging.Budget {
		return fmt.Errorf("FATAL [LAYOUT_003]: %s (%d bytes) and %s (%d bytes) must be equally large",
			l.App.Name, l.App.Budget, l.Staging.Name, l.Staging.Budget)
	}
	if l.IsBankSwap {
		appOff := uint64(l.App.Addr) - uint64(l.Bank1Base)
		stgOff := uint64(l.Staging.Addr) - uint64(l.Bank2Base)
		if appOff != stgOff || l.Staging.Budget != l.App.Budget {
			return fmt.Errorf("FATAL [LAYOUT_007]: bank_swap requires mirrored App/Staging intra-bank offset (0x%X vs 0x%X) and equal size",
				appOff, stgOff)
		}
	}
	mbSec := l.slotSectorAlign(l.Mailbox)
	mailboxUnit := uint64(mailboxSectors) * uint64(mbSec)
	if mailboxUnit == 0 || uint64(l.Mailbox.Budget)%mailboxUnit != 0 {
		return fmt.Errorf("FATAL [LAYOUT_004]: %s (%d bytes) cannot be split into %d sector-aligned slots (sector %d)",
			l.Mailbox.Name, l.Mailbox.Budget, mailboxSectors, mbSec)
	}

	windowEnd := l.allowedUpperBound()
	var totalBytes uint64
	for i, a := range regions {
		if a.slot.Budget == 0 {
			continue
		}
		aEnd := uint64(a.slot.Addr) + uint64(a.slot.Budget)
		totalBytes += uint64(a.slot.Budget)
		if aEnd > 0x100000000 || (l.FlashSize > 0 && (uint64(a.slot.Addr) < l.FlashBase || aEnd > windowEnd)) {
			return fmt.Errorf("FATAL [LAYOUT_005]: %s [0x%08X..0x%X) exceeds flash bounds [0x%08X..0x%X)",
				a.slot.Name, a.slot.Addr, aEnd, l.FlashBase, windowEnd)
		}
		for _, b := range regions[i+1:] {
			if b.slot.Budget == 0 {
				continue
			}
			bEnd := uint64(b.slot.Addr) + uint64(b.slot.Budget)
			if uint64(a.slot.Addr) < bEnd && uint64(b.slot.Addr) < aEnd {
				return fmt.Errorf("FATAL [LAYOUT_005]: %s [0x%08X..0x%X) overlaps %s [0x%08X..0x%X)",
					a.slot.Name, a.slot.Addr, aEnd, b.slot.Name, b.slot.Addr, bEnd)
			}
		}
		for _, res := range l.Reserved {
			if res.Budget == 0 {
				continue
			}
			resEnd := uint64(res.Addr) + uint64(res.Budget)
			if uint64(a.slot.Addr) < resEnd && uint64(res.Addr) < aEnd {
				return fmt.Errorf("FATAL [LAYOUT_005]: %s [0x%08X..0x%X) overlaps hardware reserved region '%s' [0x%08X..0x%X)",
					a.slot.Name, a.slot.Addr, aEnd, res.Name, res.Addr, resEnd)
			}
		}
	}
	for _, res := range l.Reserved {
		totalBytes += uint64(res.Budget)
	}
	if l.FlashSize > 0 && totalBytes > uint64(l.FlashSize) {
		return fmt.Errorf("FATAL [FLASH_003]: Total partition + reserved bytes (%d) exceed physical flash capacity (%d)",
			totalBytes, l.FlashSize)
	}
	return nil
}

// layoutRegion binds a partition to the C macros that publish it.
type layoutRegion struct {
	slot           PartitionSlot
	addrMacro      string
	sizeMacro      string
	extras         []cMacro // Additional macros emitted right after the region.
	sectorGranular bool     // Size is a sum of physical sectors across potentially differing regions.
}

// regions is the single source of truth for every published partition. It
// drives boot_layout.h, boot_layout_assert.h and the partition map.
func (l *PartitionLayout) regions() []layoutRegion {
	walExtras := make([]cMacro, 0, 2*len(l.WalSectors))
	for i, s := range l.WalSectors {
		walExtras = append(walExtras,
			cMacro{fmt.Sprintf("CHIP_WAL_SECTOR_%d_ADDR", i), hex32(s.Addr)},
			cMacro{fmt.Sprintf("CHIP_WAL_SECTOR_%d_SIZE", i), hex32(s.Budget)})
	}
	kdmExtras := make([]cMacro, 0, 2*len(l.KdmSlots))
	for i, s := range l.KdmSlots {
		kdmExtras = append(kdmExtras,
			cMacro{fmt.Sprintf("CHIP_KDM_SLOT_%d_ADDR", i), hex32(s.Addr)},
			cMacro{fmt.Sprintf("CHIP_KDM_SLOT_%d_SIZE", i), hex32(s.Budget)})
	}
	return []layoutRegion{
		{slot: l.Stage0, addrMacro: "CHIP_STAGE0_ABS_ADDR", sizeMacro: "CHIP_STAGE0_SIZE"},
		{slot: l.Stage1A, addrMacro: "CHIP_STAGE1A_ABS_ADDR", sizeMacro: "CHIP_STAGE1A_SIZE"},
		{slot: l.Stage1B, addrMacro: "CHIP_STAGE1B_ABS_ADDR", sizeMacro: "CHIP_STAGE1B_SIZE"},
		{slot: l.App, addrMacro: "CHIP_APP_SLOT_ABS_ADDR", sizeMacro: "CHIP_APP_SLOT_SIZE"},
		{slot: l.Staging, addrMacro: "CHIP_STAGING_SLOT_ABS_ADDR", sizeMacro: "CHIP_STAGING_SLOT_SIZE"},
		{slot: l.Scratch, addrMacro: "CHIP_SCRATCH_SLOT_ABS_ADDR", sizeMacro: "CHIP_SCRATCH_SLOT_SIZE"},
		{slot: l.Wal, addrMacro: "CHIP_WAL_ABS_ADDR", sizeMacro: "CHIP_WAL_SIZE", extras: walExtras, sectorGranular: true},
		{slot: l.Recovery, addrMacro: "CHIP_RECOVERY_OS_ABS_ADDR", sizeMacro: "CHIP_RECOVERY_OS_SIZE"},
		{slot: l.NetCore, addrMacro: "CHIP_NETCORE_SLOT_ABS_ADDR", sizeMacro: "CHIP_NETCORE_SLOT_SIZE"},
		{slot: l.KDM, addrMacro: "CHIP_KDM_QUORUM_ABS_ADDR", sizeMacro: "CHIP_KDM_QUORUM_SIZE", extras: kdmExtras, sectorGranular: true},
		{slot: l.CloudCmd, addrMacro: "CHIP_CLOUD_CMD_SLOT_ABS_ADDR", sizeMacro: "CHIP_CLOUD_CMD_SLOT_SIZE"},
		{
			slot: l.Mailbox, addrMacro: "CHIP_MAILBOX_ABS_ADDR", sizeMacro: "CHIP_MAILBOX_SIZE",
			extras: []cMacro{{"CHIP_MAILBOX_SLOT_SIZE", hex32(l.Mailbox.Budget / mailboxSectors)}},
		},
		{slot: l.Forensic, addrMacro: "CHIP_FORENSIC_SLOT_ABS_ADDR", sizeMacro: "CHIP_FORENSIC_SLOT_SIZE"},
	}
}
