package manifest

import (
	"fmt"
)

type Allocator struct {
	offset        uint32
	maxSectorSize uint32
	regions       []FlashRegion
}

func NewAllocator(regions []FlashRegion) (*Allocator, error) {
	var maxSec uint32
	for _, r := range regions {
		if r.Type == "writable" || r.Type == "" {
			if r.SectorSize > maxSec {
				maxSec = r.SectorSize
			}
		}
	}
	if maxSec == 0 {
		return nil, fmt.Errorf("no writable regions defined with valid sector_size")
	}

	return &Allocator{
		offset:        0,
		maxSectorSize: maxSec,
		regions:       regions,
	}, nil
}

func (a *Allocator) GetSectorSizeAt(addr uint32) (uint32, error) {
	for _, r := range a.regions {
		if r.Type == "writable" || r.Type == "" {
			base := r.Base
			secSz := r.SectorSize
			if secSz == 0 {
				secSz = a.maxSectorSize
			}
			count := r.Count
			if addr >= base && addr < base+(secSz*count) {
				return secSz, nil
			}
		}
	}
	return 0, fmt.Errorf("address 0x%X does not fall within any writable flash region", addr)
}

func (a *Allocator) advanceToWritable(addr uint32) (uint32, error) {
	for {
		inReserved := false
		for _, r := range a.regions {
			if r.Type == "reserved" {
				base := r.Base
				size := r.Size
				if addr >= base && addr < base+size {
					addr = base + size
					inReserved = true
					break
				}
			}
		}
		if !inReserved {
			break
		}
	}

	secSz, err := a.GetSectorSizeAt(addr)
	if err != nil {
		return 0, fmt.Errorf("advanceToWritable pushed address out of bounds: %w", err)
	}
	if secSz > 0 {
		if addr%secSz != 0 {
			addr = ((addr + secSz - 1) / secSz) * secSz
			return a.advanceToWritable(addr)
		}
	}
	return addr, nil
}

func (a *Allocator) Allocate(budgetReq uint32, forceAlign uint32, name string) (uint32, uint32, error) {
	if forceAlign > 0 {
		a.offset = ((a.offset + forceAlign - 1) / forceAlign) * forceAlign
	}

	preJumpOffset := a.offset
	newOffset, err := a.advanceToWritable(a.offset)
	if err != nil {
		return 0, 0, err
	}
	a.offset = newOffset

	if a.offset > preJumpOffset {
		wasted := a.offset - preJumpOffset
		fmt.Printf("WARNING: Allocation for '%s' skipped %d bytes of writable flash to bypass reserved region at 0x%X.\n", name, wasted, preJumpOffset)
	}

	addr := a.offset
	accumulatedBudget := uint32(0)

	for accumulatedBudget < budgetReq {
		secSz, err := a.GetSectorSizeAt(a.offset)
		if err != nil {
			return 0, 0, err
		}
		accumulatedBudget += secSz
		a.offset += secSz

		// Fast-forward past reserved regions
		for _, r := range a.regions {
			if r.Type == "reserved" {
				base := r.Base
				size := r.Size
				if a.offset > base && addr < base+size {
					// Restart allocation after reserved block
					newOffset, err := a.advanceToWritable(base + size)
					if err != nil {
						return 0, 0, err
					}
					a.offset = newOffset
					return a.Allocate(budgetReq, forceAlign, name)
				}
			}
		}
	}

	return addr, accumulatedBudget, nil
}

func (a *Allocator) CurrentOffset() uint32 {
	return a.offset
}
