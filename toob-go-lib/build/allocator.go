package build

import (
	"errors"
	"fmt"
	"math"
	"slices"
)

// AllocationGap records flash skipped in front of a partition, either to
// bypass a reserved/unmapped region or to satisfy an alignment constraint.
type AllocationGap struct {
	Partition string
	From      uint32
	Size      uint32
}

// Allocator performs sequential allocations across heterogeneous and
// non-contiguous flash regions. Each allocation aligns its start to the
// starting region's local sector size and rounds its end to the ending
// region's local sector size (CRIT-19), skipping reserved and unmapped
// Dual-Bank gaps cleanly (CRIT-20).
type Allocator struct {
	offset        uint64
	maxSectorSize uint32
	regions       []FlashRegion
	gaps          []AllocationGap
}

func isWritableRegion(r FlashRegion) bool { return r.Type == "writable" || r.Type == "" }
func isReservedRegion(r FlashRegion) bool { return r.Type == "reserved" }

// regionEnd returns the first address behind r in 64-bit arithmetic, so that
// callers can detect 32-bit overflow instead of wrapping around.
func regionEnd(r FlashRegion) uint64 {
	if isReservedRegion(r) {
		return uint64(r.Base) + uint64(r.Size)
	}
	return uint64(r.Base) + uint64(r.SectorSize)*uint64(r.Count)
}

func checkWritableSpansDisjoint(regions []FlashRegion) error {
	var spans []flashSpan
	for _, r := range regions {
		if isWritableRegion(r) {
			spans = append(spans, flashSpan{uint64(r.Base), regionEnd(r), regionDisplayName(r)})
		}
	}
	sortSpans(spans)
	for i := 1; i < len(spans); i++ {
		if spans[i].start < spans[i-1].end {
			return fmt.Errorf("FATAL [FLASH_005]: Writable flash regions '%s' and '%s' overlap",
				spans[i-1].name, spans[i].name)
		}
	}
	return nil
}

// NewAllocator validates the writable regions and determines the largest sector size.
func NewAllocator(regions []FlashRegion) (*Allocator, error) {
	var maxSec uint32
	minBase := uint64(math.MaxUint64)
	for _, r := range regions {
		minBase = min(minBase, uint64(r.Base))
		if isReservedRegion(r) {
			if regionEnd(r) > 0x100000000 {
				return nil, fmt.Errorf("FATAL [FLASH_005]: Reserved flash region '%s' exceeds the 32-bit address space",
					regionDisplayName(r))
			}
			continue
		}
		if !isWritableRegion(r) {
			return nil, fmt.Errorf("FATAL [FLASH_004]: Flash region '%s' has unknown type '%s'",
				regionDisplayName(r), r.Type)
		}
		if r.SectorSize == 0 || r.Count == 0 {
			return nil, fmt.Errorf("FATAL [FLASH_004]: Writable flash region '%s' must specify both 'sector_size' and 'count'",
				regionDisplayName(r))
		}
		if !isPowerOfTwo(uint64(r.SectorSize)) {
			return nil, fmt.Errorf("FATAL [FLASH_005]: Writable flash region '%s' has sector_size %d, which is not a power of two",
				regionDisplayName(r), r.SectorSize)
		}
		if r.Base%r.SectorSize != 0 {
			return nil, fmt.Errorf("FATAL [FLASH_005]: Writable flash region '%s' starts at 0x%08X, which is not a multiple of its sector_size %d",
				regionDisplayName(r), r.Base, r.SectorSize)
		}
		if regionEnd(r) > 0x100000000 {
			return nil, fmt.Errorf("FATAL [FLASH_005]: Writable flash region '%s' exceeds the 32-bit address space",
				regionDisplayName(r))
		}
		maxSec = max(maxSec, r.SectorSize)
	}
	if maxSec == 0 {
		return nil, errors.New("FATAL: no writable flash regions defined")
	}
	if err := checkWritableSpansDisjoint(regions); err != nil {
		return nil, err
	}
	return &Allocator{offset: minBase, maxSectorSize: maxSec, regions: slices.Clone(regions)}, nil
}

// GetSectorSizeAt returns the sector size of the writable region containing addr.
func (a *Allocator) GetSectorSizeAt(addr uint32) (uint32, error) {
	return sectorSizeInRegions(a.regions, addr)
}

// SectorSizeAt is an alias for GetSectorSizeAt (CRIT-19).
func (a *Allocator) SectorSizeAt(addr uint32) (uint32, error) {
	return a.GetSectorSizeAt(addr)
}

func sectorSizeInRegions(regions []FlashRegion, addr uint32) (uint32, error) {
	for _, r := range regions {
		if !isWritableRegion(r) {
			continue
		}
		if uint64(addr) >= uint64(r.Base) && uint64(addr) < regionEnd(r) {
			return r.SectorSize, nil
		}
	}
	return 0, fmt.Errorf("address 0x%08X does not fall within any writable flash region", addr)
}

// maxSectorSizeInRange returns the largest sector size touched by [start, start+size).
func (a *Allocator) maxSectorSizeInRange(start, size uint32) uint32 {
	var maxSec uint32
	end := uint64(start) + uint64(size)
	for _, r := range a.regions {
		if !isWritableRegion(r) {
			continue
		}
		if uint64(r.Base) < end && uint64(start) < regionEnd(r) {
			maxSec = max(maxSec, r.SectorSize)
		}
	}
	return maxSec
}

// CurrentOffset returns the first address after the last allocation, clamped to uint32.
func (a *Allocator) CurrentOffset() uint32 {
	if a.offset > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(a.offset)
}

// CurrentOffset64 returns the exact 64-bit cursor (allowing 0x100000000 at top of 4 GiB).
func (a *Allocator) CurrentOffset64() uint64 { return a.offset }

// Gaps returns all skipped areas in allocation order.
func (a *Allocator) Gaps() []AllocationGap { return slices.Clone(a.gaps) }

// Allocate reserves a contiguous range of whole physical sectors covering at
// least budget bytes. Start is aligned to max(localSectorSize, align) and end
// is aligned to the ending region's local sector size (CRIT-19).
func (a *Allocator) Allocate(budget, align uint32, name string) (uint32, uint32, error) {
	return a.AllocateWithVtor(budget, align, 0, 0, name)
}

// AllocateWithVtor reserves a contiguous range of physical sectors whose start
// satisfies both addr % max(localSectorSize, align) == 0 and, when vtorAlign > 0,
// (addr + headerOffset) % vtorAlign == 0 (HIGH-20).
func (a *Allocator) AllocateWithVtor(budget, align, vtorAlign, headerOffset uint32, name string) (uint32, uint32, error) {
	if budget == 0 {
		return 0, 0, fmt.Errorf("allocation budget for '%s' must be greater than zero", name)
	}
	if align != 0 && !isPowerOfTwo(uint64(align)) {
		return 0, 0, fmt.Errorf("allocating '%s': alignment %d is not a power of two", name, align)
	}
	if vtorAlign != 0 && !isPowerOfTwo(uint64(vtorAlign)) {
		return 0, 0, fmt.Errorf("allocating '%s': vtor_alignment %d is not a power of two", name, vtorAlign)
	}

	start, err := a.advanceToWritable(a.offset, align, vtorAlign, headerOffset)
	if err != nil {
		return 0, 0, fmt.Errorf("allocating '%s': %w", name, err)
	}

	for {
		end, blocker, err := a.extendSectors(start, budget)
		if err != nil {
			return 0, 0, fmt.Errorf("allocating '%s': %w", name, err)
		}
		if blocker == nil {
			span := end - uint64(start)
			if span > math.MaxUint32 {
				return 0, 0, fmt.Errorf("allocating '%s': size 0x%X exceeds uint32", name, span)
			}
			a.commitRange(start, end, name)
			return start, uint32(span), nil
		}
		// A reserved region or unmapped Dual-Bank gap interrupts the range; restart behind it.
		restart, err := reservedEnd(*blocker)
		if err != nil {
			return 0, 0, fmt.Errorf("allocating '%s': %w", name, err)
		}
		if start, err = a.advanceToWritable(restart, align, vtorAlign, headerOffset); err != nil {
			return 0, 0, fmt.Errorf("allocating '%s': %w", name, err)
		}
	}
}

// AllocateSector reserves exactly one sector at the next writable address,
// aligned to align (a power of two, or 0 for the sector size alone), re-querying
// the local sector size whenever a reserved carve-out forces a restart (HIGH-54).
func (a *Allocator) AllocateSector(name string, align uint32) (uint32, uint32, error) {
	if align != 0 && !isPowerOfTwo(uint64(align)) {
		return 0, 0, fmt.Errorf("allocating '%s': alignment %d is not a power of two", name, align)
	}
	start, err := a.advanceToWritable(a.offset, align, 0, 0)
	if err != nil {
		return 0, 0, fmt.Errorf("allocating '%s': %w", name, err)
	}
	for {
		secSz, err := a.GetSectorSizeAt(start)
		if err != nil {
			return 0, 0, fmt.Errorf("allocating '%s': %w", name, err)
		}
		end, blocker, err := a.extendSectors(start, secSz)
		if err != nil {
			return 0, 0, fmt.Errorf("allocating '%s': %w", name, err)
		}
		if blocker == nil {
			span := end - uint64(start)
			if span > math.MaxUint32 {
				return 0, 0, fmt.Errorf("allocating '%s': size 0x%X exceeds uint32", name, span)
			}
			a.commitRange(start, end, name)
			return start, uint32(span), nil
		}
		restart, err := reservedEnd(*blocker)
		if err != nil {
			return 0, 0, fmt.Errorf("allocating '%s': %w", name, err)
		}
		if start, err = a.advanceToWritable(restart, align, 0, 0); err != nil {
			return 0, 0, fmt.Errorf("allocating '%s': %w", name, err)
		}
	}
}

// extendSectors grows [start, end) physical sector by physical sector until it
// covers budget. If a reserved region or unmapped Dual-Bank gap blocks growth,
// it returns a blocker region so the caller can restart cleanly behind it.
func (a *Allocator) extendSectors(start, budget uint32) (uint64, *FlashRegion, error) {
	end := uint64(start)
	for end-uint64(start) < uint64(budget) {
		if end > math.MaxUint32 {
			return 0, nil, errors.New("allocation exceeds the 32-bit address space")
		}
		cur := uint32(end)
		if r, inside := a.reservedRegionAt(cur); inside {
			return 0, &r, nil
		}
		secSz, err := a.GetSectorSizeAt(cur)
		if err != nil {
			if nextBase, ok := a.nextWritableBase(cur); ok {
				gap := FlashRegion{Type: "reserved", Base: cur, Size: nextBase - cur, Name: "unmapped_gap"}
				return 0, &gap, nil
			}
			return 0, nil, err
		}
		if end+uint64(secSz) > 0x100000000 {
			return 0, nil, errors.New("allocation exceeds the 32-bit address space")
		}
		end += uint64(secSz)

		if r, hit := a.lowestReservedOverlap(uint64(start), end); hit {
			return 0, &r, nil
		}
	}
	return end, nil, nil
}

// advanceToWritable returns the first address >= addr that lies outside every
// reserved/unmapped gap, inside a writable region, aligned to max(sector, align),
// and satisfying (addr + headerOffset) % vtorAlign == 0 when vtorAlign > 0.
func (a *Allocator) advanceToWritable(addr uint64, align, vtorAlign, headerOffset uint32) (uint32, error) {
	for {
		if addr > math.MaxUint32 {
			return 0, fmt.Errorf("address 0x%X exceeds the 32-bit address space", addr)
		}
		cur := uint32(addr)
		if r, inside := a.reservedRegionAt(cur); inside {
			end, err := reservedEnd(r)
			if err != nil {
				return 0, err
			}
			addr = end
			continue
		}
		secSz, err := a.GetSectorSizeAt(cur)
		if err != nil {
			if nextBase, ok := a.nextWritableBase(cur); ok {
				addr = uint64(nextBase)
				continue
			}
			return 0, err
		}
		aligned, err := alignSlotStart(cur, max(secSz, align), vtorAlign, headerOffset)
		if err != nil {
			return 0, err
		}
		if aligned == cur {
			return cur, nil
		}
		addr = uint64(aligned)
	}
}

func (a *Allocator) commitRange(start uint32, end uint64, name string) {
	if uint64(start) > a.offset && a.offset <= math.MaxUint32 {
		gapSz := uint64(start) - a.offset
		if gapSz <= math.MaxUint32 {
			a.gaps = append(a.gaps, AllocationGap{Partition: name, From: uint32(a.offset), Size: uint32(gapSz)})
		}
	}
	a.offset = end
}

// alignSlotStart returns the smallest address >= addr that is a multiple of
// slotAlign and satisfies (cand + headerOffset) % vtorAlign == 0.
func alignSlotStart(addr, slotAlign, vtorAlign, headerOffset uint32) (uint32, error) {
	if slotAlign != 0 && !isPowerOfTwo(uint64(slotAlign)) {
		return 0, fmt.Errorf("slot alignment %d is not a power of two", slotAlign)
	}
	if vtorAlign != 0 && !isPowerOfTwo(uint64(vtorAlign)) {
		return 0, fmt.Errorf("vtor_alignment %d is not a power of two", vtorAlign)
	}
	cand, err := alignUp(addr, slotAlign)
	if err != nil {
		return 0, err
	}
	if vtorAlign == 0 {
		return cand, nil
	}
	rem := headerOffset % vtorAlign
	targetMod := (vtorAlign - rem) % vtorAlign
	if vtorAlign <= slotAlign {
		if targetMod != 0 {
			return 0, fmt.Errorf("image_header_offset (%d) is incompatible with vtor_alignment (%d) and slot alignment (%d)",
				headerOffset, vtorAlign, slotAlign)
		}
		return cand, nil
	}
	if slotAlign > 0 && targetMod%slotAlign != 0 {
		return 0, fmt.Errorf("image_header_offset (%d) is incompatible with vtor_alignment (%d) and slot alignment (%d)",
			headerOffset, vtorAlign, slotAlign)
	}
	delta := (uint64(targetMod) + uint64(vtorAlign) - uint64(cand)%uint64(vtorAlign)) % uint64(vtorAlign)
	res := uint64(cand) + delta
	if res > math.MaxUint32 {
		return 0, fmt.Errorf("aligning 0x%08X to vtor_alignment %d exceeds the 32-bit address space", addr, vtorAlign)
	}
	return uint32(res), nil
}

// nextWritableBase returns the lowest Base > addr among writable regions, if any.
func (a *Allocator) nextWritableBase(addr uint32) (uint32, bool) {
	var best uint32
	found := false
	for _, r := range a.regions {
		if !isWritableRegion(r) || r.Base <= addr {
			continue
		}
		if !found || r.Base < best {
			best, found = r.Base, true
		}
	}
	return best, found
}

// reservedRegionAt returns the reserved region containing addr, if any.
func (a *Allocator) reservedRegionAt(addr uint32) (FlashRegion, bool) {
	for _, r := range a.regions {
		if isReservedRegion(r) && uint64(addr) >= uint64(r.Base) && uint64(addr) < regionEnd(r) {
			return r, true
		}
	}
	return FlashRegion{}, false
}

// lowestReservedOverlap returns the reserved region with the lowest base that
// overlaps [start, end), if any.
func (a *Allocator) lowestReservedOverlap(start, end uint64) (FlashRegion, bool) {
	var found FlashRegion
	hit := false
	for _, r := range a.regions {
		if !isReservedRegion(r) || r.Size == 0 {
			continue
		}
		overlaps := uint64(r.Base) < end && start < regionEnd(r)
		if overlaps && (!hit || r.Base < found.Base) {
			found, hit = r, true
		}
	}
	return found, hit
}

// reservedEnd returns the first address after r, rejecting > 4 GiB wrap-around.
func reservedEnd(r FlashRegion) (uint64, error) {
	end := regionEnd(r)
	if end > 0x100000000 {
		return 0, fmt.Errorf("reserved region '%s' exceeds the 32-bit address space", regionDisplayName(r))
	}
	return end, nil
}

// alignUp rounds addr up to the next multiple of align (align 0 means none).
func alignUp(addr, align uint32) (uint32, error) {
	if align == 0 || addr%align == 0 {
		return addr, nil
	}
	aligned := uint64(addr) + uint64(align-addr%align)
	if aligned > math.MaxUint32 {
		return 0, fmt.Errorf("aligning 0x%08X to %d exceeds the 32-bit address space", addr, align)
	}
	return uint32(aligned), nil
}
