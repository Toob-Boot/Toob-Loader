package build

import (
	"cmp"
	"errors"
	"fmt"
	"math"
	"slices"
)

// flashSpan is a half-open address range [start, end).
type flashSpan struct {
	start, end uint64
	name       string
}

// checkFlashGeometry verifies that hardware.json describes a physically
// consistent flash: valid alignments, regions within the device bounds, and
// unambiguous sector sizes. Non-overlapping unmapped gaps between banks are
// allowed for Dual-Bank MCUs (CRIT-20 / HIGH-53).
func checkFlashGeometry(ctx *Context) error {
	flash := &ctx.Hardware.Flash
	switch {
	case flash.Size == 0:
		return errors.New("FATAL: flash.size is mandatory in hardware.json")
	case flash.WriteAlignment == 0:
		return errors.New("FATAL: flash.write_alignment is mandatory in hardware.json")
	case len(flash.Regions) == 0:
		return errors.New("FATAL: flash.regions array is mandatory in hardware.json")
	case !isPowerOfTwo(uint64(flash.WriteAlignment)):
		return fmt.Errorf("FATAL [FLASH_005]: flash.write_alignment %d is not a power of two", flash.WriteAlignment)
	case flash.AppAlignment != 0 && !isPowerOfTwo(uint64(flash.AppAlignment)):
		return fmt.Errorf("FATAL [FLASH_005]: flash.app_alignment %d is not a power of two", flash.AppAlignment)
	}

	physBase, _, err := resolveFlashBase(flash)
	if err != nil {
		return err
	}
	if uint64(physBase)+uint64(flash.Size) > 0x100000000 {
		return fmt.Errorf("FATAL [FLASH_005]: flash.base (0x%08X) + flash.size (0x%08X) exceeds the 32-bit address space",
			physBase, flash.Size)
	}

	windowBase := uint64(physBase)
	windowEnd := windowBase + uint64(flash.Size)

	minSector := uint32(math.MaxUint32)
	writableCount := 0
	var totalCapacity uint64
	for _, r := range flash.Regions {
		if err := checkFlashRegion(r, windowBase); err != nil {
			return err
		}
		if isWritableRegion(r) {
			writableCount++
			minSector = min(minSector, r.SectorSize)
		}
		totalCapacity += regionEffectiveSize(r)
	}
	if minSector == math.MaxUint32 {
		return errors.New("FATAL [FLASH_004]: hardware.json must define at least one writable flash region")
	}
	if flash.WriteAlignment > minSector {
		return fmt.Errorf("FATAL [FLASH_005]: flash.write_alignment %d exceeds the smallest sector size %d",
			flash.WriteAlignment, minSector)
	}
	if flash.WriteAlignment > 32 {
		return fmt.Errorf("FATAL [FLASH_005]: flash.write_alignment %d exceeds maximum supported write_alignment 32",
			flash.WriteAlignment)
	}
	if err := checkRegionOverlap(flash.Regions); err != nil {
		return err
	}
	if totalCapacity > uint64(flash.Size) {
		return fmt.Errorf("FATAL [FLASH_005]: Flash regions total 0x%X bytes, beyond the flash size 0x%08X",
			totalCapacity, flash.Size)
	}
	// Single-bank flash must remain within [windowBase, windowEnd]; multi-bank
	// flash (writableCount >= 2) may span unmapped inter-bank address gaps so
	// long as Bank 1 starts inside the flash window and totalCapacity <= flash.Size.
	minBase := uint64(math.MaxUint64)
	for _, r := range flash.Regions {
		minBase = min(minBase, uint64(r.Base))
		end := regionEnd(r)
		if writableCount < 2 && end > windowEnd {
			return fmt.Errorf("FATAL [FLASH_005]: Flash region '%s' ends at 0x%08X, beyond the flash size 0x%08X",
				regionDisplayName(r), end, windowEnd)
		}
	}
	if minBase >= windowEnd {
		return fmt.Errorf("FATAL [FLASH_005]: Flash regions start at 0x%08X, beyond the flash size 0x%08X",
			minBase, windowEnd)
	}
	return nil
}

// checkFlashRegion validates one region in isolation.
func checkFlashRegion(r FlashRegion, windowBase uint64) error {
	name := regionDisplayName(r)
	if r.Name != "" {
		if err := validateDisplayText("flash region name", r.Name); err != nil {
			return fmt.Errorf("FATAL [FLASH_004]: %w", err)
		}
	}

	switch {
	case isWritableRegion(r):
		if r.SectorSize == 0 || r.Count == 0 {
			return fmt.Errorf("FATAL [FLASH_004]: Writable flash region '%s' must specify both 'sector_size' and 'count'", name)
		}
		if !isPowerOfTwo(uint64(r.SectorSize)) {
			return fmt.Errorf("FATAL [FLASH_005]: Writable flash region '%s' has sector_size %d, which is not a power of two",
				name, r.SectorSize)
		}
		if r.Base%r.SectorSize != 0 {
			return fmt.Errorf("FATAL [FLASH_005]: Writable flash region '%s' starts at 0x%08X, which is not a multiple of its sector_size %d",
				name, r.Base, r.SectorSize)
		}
		computed := uint64(r.SectorSize) * uint64(r.Count)
		if computed > math.MaxUint32 {
			return fmt.Errorf("FATAL [FLASH_005]: Writable flash region '%s' sector_size(%d) * count(%d) overflows uint32",
				name, r.SectorSize, r.Count)
		}
		if r.Size != 0 && uint64(r.Size) != computed {
			return fmt.Errorf("FATAL [FLASH_005]: Writable flash region '%s' size (%d) != sector_size(%d) * count(%d) (%d)",
				name, r.Size, r.SectorSize, r.Count, computed)
		}
	case isReservedRegion(r):
		if r.Size == 0 {
			return fmt.Errorf("FATAL [FLASH_004]: Reserved flash region '%s' must specify 'size'", name)
		}
		if r.SectorSize > 0 || r.Count > 0 {
			if r.SectorSize == 0 || r.Count == 0 {
				return fmt.Errorf("FATAL [FLASH_005]: Reserved flash region '%s' must specify both 'sector_size' and 'count' when sectored", name)
			}
			if !isPowerOfTwo(uint64(r.SectorSize)) {
				return fmt.Errorf("FATAL [FLASH_005]: Reserved flash region '%s' has sector_size %d, which is not a power of two",
					name, r.SectorSize)
			}
			if r.Base%r.SectorSize != 0 {
				return fmt.Errorf("FATAL [FLASH_005]: Reserved flash region '%s' starts at 0x%08X, which is not a multiple of its sector_size %d",
					name, r.Base, r.SectorSize)
			}
			computed := uint64(r.SectorSize) * uint64(r.Count)
			if uint64(r.Size) != computed {
				return fmt.Errorf("FATAL [FLASH_005]: Reserved flash region '%s' size (%d) != sector_size(%d) * count(%d) (%d)",
					name, r.Size, r.SectorSize, r.Count, computed)
			}
		}
	default:
		return fmt.Errorf("FATAL [FLASH_004]: Flash region '%s' has unknown type '%s' (must be 'writable' or 'reserved')",
			name, r.Type)
	}

	if uint64(r.Base) < windowBase {
		return fmt.Errorf("FATAL [FLASH_005]: Flash region '%s' starts at 0x%08X, below flash base 0x%08X",
			name, r.Base, windowBase)
	}
	end := regionEnd(r)
	if end > 0x100000000 {
		return fmt.Errorf("FATAL [FLASH_005]: Flash region '%s' ends at 0x%X, beyond the flash size (32-bit address space)",
			name, end)
	}
	return nil
}

// checkRegionOverlap rejects any overlapping flash regions (writable or reserved)
// in hardware.json using running maxEnd tracking.
func checkRegionOverlap(regions []FlashRegion) error {
	spans := make([]flashSpan, 0, len(regions))
	for _, r := range regions {
		spans = append(spans, flashSpan{uint64(r.Base), regionEnd(r), regionDisplayName(r)})
	}
	sortSpans(spans)
	if len(spans) == 0 {
		return nil
	}
	maxEnd := spans[0].end
	maxName := spans[0].name
	for i := 1; i < len(spans); i++ {
		if spans[i].start < maxEnd {
			return fmt.Errorf("FATAL [FLASH_005]: Flash regions '%s' and '%s' overlap",
				maxName, spans[i].name)
		}
		if spans[i].end > maxEnd {
			maxEnd = spans[i].end
			maxName = spans[i].name
		}
	}
	return nil
}

func sortSpans(spans []flashSpan) {
	slices.SortFunc(spans, func(a, b flashSpan) int { return cmp.Compare(a.start, b.start) })
}
