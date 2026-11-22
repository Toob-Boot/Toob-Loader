package build

import (
	"strings"
	"testing"
)

func TestAllocatorBasic(t *testing.T) {
	regions := []FlashRegion{
		{Type: "writable", Base: 0x00000000, SectorSize: 4096, Count: 256}, // 1 MB
	}

	alloc, err := NewAllocator(regions)
	if err != nil {
		t.Fatalf("NewAllocator failed: %v", err)
	}

	// 1. Allocate 8 KB (2 sectors)
	addr1, budget1, err := alloc.Allocate(8192, 0, "Slot1")
	if err != nil {
		t.Fatalf("Allocate Slot1 failed: %v", err)
	}
	if addr1 != 0x00000000 || budget1 != 8192 {
		t.Errorf("expected addr 0x0, budget 8192, got addr 0x%X, budget %d", addr1, budget1)
	}

	// 2. Allocate 5 KB (should round up to 2 sectors = 8192 bytes)
	addr2, budget2, err := alloc.Allocate(5000, 0, "Slot2")
	if err != nil {
		t.Fatalf("Allocate Slot2 failed: %v", err)
	}
	if addr2 != 8192 || budget2 != 8192 {
		t.Errorf("expected addr 0x2000 (8192), budget 8192, got addr 0x%X, budget %d", addr2, budget2)
	}

	if alloc.CurrentOffset() != 16384 {
		t.Errorf("expected current offset 16384, got %d", alloc.CurrentOffset())
	}
}

func TestAllocatorForceAlign(t *testing.T) {
	regions := []FlashRegion{
		{Type: "writable", Base: 0x00000000, SectorSize: 4096, Count: 256},
	}
	alloc, err := NewAllocator(regions)
	if err != nil {
		t.Fatalf("NewAllocator failed: %v", err)
	}

	// First take 4 KB
	_, _, err = alloc.Allocate(4096, 0, "Prefix")
	if err != nil {
		t.Fatalf("Allocate Prefix failed: %v", err)
	}

	// Now allocate with 64 KB force alignment (e.g., XIP remap)
	addr, _, err := alloc.Allocate(65536, 65536, "AlignedSlot")
	if err != nil {
		t.Fatalf("Allocate AlignedSlot failed: %v", err)
	}
	if addr != 65536 {
		t.Errorf("expected aligned address 0x10000 (65536), got 0x%X", addr)
	}
	if addr%65536 != 0 {
		t.Errorf("address 0x%X is not aligned to 64KB", addr)
	}
}

func TestAllocatorReservedRegionPreservesAlignment(t *testing.T) {
	// Writable 0x00000 to 0x40000 (256 KB)
	// Reserved 0x00000 to 0x14000 (crosses 0x10000 64KB boundary!)
	regions := []FlashRegion{
		{Type: "writable", Base: 0x00000000, SectorSize: 4096, Count: 64},
		{Type: "reserved", Base: 0x00000000, Size: 0x00014000, Name: "BootloaderReserved"},
	}

	alloc, err := NewAllocator(regions)
	if err != nil {
		t.Fatalf("NewAllocator failed: %v", err)
	}

	// Allocate with 64 KB alignment constraint
	addr, budget, err := alloc.Allocate(32768, 65536, "AppSlot")
	if err != nil {
		t.Fatalf("Allocate AppSlot failed: %v", err)
	}

	// 0x14000 is base + size of reserved region.
	// Aligning 0x14000 to 64KB gives 0x20000 (131072).
	if addr%65536 != 0 {
		t.Errorf("critical bug: allocated address 0x%X violates forceAlign 65536!", addr)
	}
	if addr < 0x00020000 {
		t.Errorf("expected address >= 0x20000, got 0x%X", addr)
	}
	if budget < 32768 {
		t.Errorf("expected budget >= 32768, got %d", budget)
	}
}

func TestAllocatorContiguousStraddleRestart(t *testing.T) {
	// Layout:
	// 0x0000 - 0x3000: Writable (12 KB)
	// 0x3000 - 0x5000: Reserved (8 KB)
	// 0x5000 - 0x20000: Writable
	regions := []FlashRegion{
		{Type: "writable", Base: 0x00000000, SectorSize: 4096, Count: 32},
		{Type: "reserved", Base: 0x00003000, Size: 0x00002000, Name: "SecurityReserved"},
	}

	alloc, err := NewAllocator(regions)
	if err != nil {
		t.Fatalf("NewAllocator failed: %v", err)
	}

	// Request 16 KB (4 sectors) starting at 0.
	// Sectors 0, 1, 2 fit, but sector 3 would hit 0x3000 which is reserved!
	// Allocator must detect the straddle, restart after 0x5000, and allocate 16 KB contiguously!
	addr, budget, err := alloc.Allocate(16384, 0, "BigSlot")
	if err != nil {
		t.Fatalf("Allocate BigSlot failed: %v", err)
	}

	if addr < 0x00005000 {
		t.Errorf("expected allocation to restart after reserved region >= 0x5000, got 0x%X", addr)
	}
	if budget != 16384 {
		t.Errorf("expected budget 16384, got %d", budget)
	}
}

func TestAllocatorZeroBudgetRejection(t *testing.T) {
	regions := []FlashRegion{
		{Type: "writable", Base: 0x00000000, SectorSize: 4096, Count: 16},
	}
	alloc, err := NewAllocator(regions)
	if err != nil {
		t.Fatalf("NewAllocator failed: %v", err)
	}

	_, _, err = alloc.Allocate(0, 0, "ZeroBudget")
	if err == nil {
		t.Fatal("expected error allocating zero budget, got nil")
	}
}

func TestAllocatorOutOfFlash(t *testing.T) {
	regions := []FlashRegion{
		{Type: "writable", Base: 0x00000000, SectorSize: 4096, Count: 2}, // only 8 KB
	}
	alloc, err := NewAllocator(regions)
	if err != nil {
		t.Fatalf("NewAllocator failed: %v", err)
	}

	_, _, err = alloc.Allocate(16384, 0, "TooLarge")
	if err == nil {
		t.Fatal("expected out of flash error, got nil")
	}
}

func TestAllocatorAsymmetricSectors(t *testing.T) {
	// Emulate STM32F4 flash:
	// Region 1: 4 sectors of 16 KB (0x00000 to 0x10000)
	// Region 2: 1 sector of 64 KB  (0x10000 to 0x20000)
	// Region 3: 3 sectors of 128 KB (0x20000 to 0x80000)
	regions := []FlashRegion{
		{Type: "writable", Base: 0x00000000, SectorSize: 16384, Count: 4},
		{Type: "writable", Base: 0x00010000, SectorSize: 65536, Count: 1},
		{Type: "writable", Base: 0x00020000, SectorSize: 131072, Count: 3},
	}

	alloc, err := NewAllocator(regions)
	if err != nil {
		t.Fatalf("NewAllocator failed: %v", err)
	}
	if alloc.maxSectorSize != 131072 {
		t.Errorf("expected maxSectorSize 131072, got %d", alloc.maxSectorSize)
	}

	sec1, err := alloc.GetSectorSizeAt(0x00004000)
	if err != nil || sec1 != 16384 {
		t.Errorf("expected 16KB at 0x4000, got %d (err: %v)", sec1, err)
	}

	sec2, err := alloc.GetSectorSizeAt(0x00015000)
	if err != nil || sec2 != 65536 {
		t.Errorf("expected 64KB at 0x15000, got %d (err: %v)", sec2, err)
	}

	sec3, err := alloc.GetSectorSizeAt(0x00030000)
	if err != nil || sec3 != 131072 {
		t.Errorf("expected 128KB at 0x30000, got %d (err: %v)", sec3, err)
	}

	_, err = alloc.GetSectorSizeAt(0x00100000)
	if err == nil {
		t.Errorf("expected out of bounds error at 0x100000, got nil")
	}
}

func TestAllocatorNoWritableRegions(t *testing.T) {
	regions := []FlashRegion{
		{Type: "reserved", Base: 0x00000000, Size: 4096},
	}
	_, err := NewAllocator(regions)
	if err == nil {
		t.Fatal("expected error with no writable regions, got nil")
	}
}

func TestAllocatorRejectsIncompleteWritableRegion(t *testing.T) {
	for _, r := range []FlashRegion{
		{Type: "writable", Base: 0, SectorSize: 0, Count: 16},
		{Type: "", Base: 0, SectorSize: 4096, Count: 0},
	} {
		if _, err := NewAllocator([]FlashRegion{r}); err == nil || !strings.Contains(err.Error(), "FLASH_004") {
			t.Errorf("expected FLASH_004 for %+v, got %v", r, err)
		}
	}
}

func TestAllocatorRecordsGaps(t *testing.T) {
	alloc, err := NewAllocator([]FlashRegion{
		{Type: "writable", Base: 0, SectorSize: 4096, Count: 64},
		{Type: "reserved", Base: 0, Size: 0x3000, Name: "ROM"},
	})
	if err != nil {
		t.Fatal(err)
	}

	addr, _, err := alloc.Allocate(4096, 0, "First")
	if err != nil || addr != 0x3000 {
		t.Fatalf("expected First at 0x3000, got 0x%X (err %v)", addr, err)
	}
	addr, _, err = alloc.Allocate(4096, 0x10000, "Aligned")
	if err != nil || addr != 0x10000 {
		t.Fatalf("expected Aligned at 0x10000, got 0x%X (err %v)", addr, err)
	}
	if _, _, err = alloc.Allocate(4096, 0, "Dense"); err != nil {
		t.Fatal(err)
	}

	want := []AllocationGap{
		{Partition: "First", From: 0, Size: 0x3000},
		{Partition: "Aligned", From: 0x4000, Size: 0xC000},
	}
	got := alloc.Gaps()
	if len(got) != len(want) {
		t.Fatalf("expected %d gaps, got %+v", len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("gap %d: expected %+v, got %+v", i, want[i], got[i])
		}
	}

	got[0].Size = 1
	if alloc.Gaps()[0].Size != 0x3000 {
		t.Error("Gaps must return a copy")
	}
}

func TestAllocatorAllocateSector(t *testing.T) {
	alloc, err := NewAllocator([]FlashRegion{
		{Type: "writable", Base: 0x0000, SectorSize: 16384, Count: 1},
		{Type: "writable", Base: 0x4000, SectorSize: 4096, Count: 4},
		{Type: "reserved", Base: 0x4000, Size: 0x1000},
	})
	if err != nil {
		t.Fatal(err)
	}

	addr, size, err := alloc.AllocateSector("WAL 0", 0)
	if err != nil || addr != 0 || size != 16384 {
		t.Fatalf("expected 16 KB sector at 0, got 0x%X/%d (err %v)", addr, size, err)
	}
	// The next sector would be 0x4000, which is reserved: skip to 0x5000.
	addr, size, err = alloc.AllocateSector("WAL 1", 0)
	if err != nil || addr != 0x5000 || size != 4096 {
		t.Fatalf("expected 4 KB sector at 0x5000, got 0x%X/%d (err %v)", addr, size, err)
	}
}

func TestAllocatorReservedHoleBetweenRegions(t *testing.T) {
	// The reserved hole is not covered by any writable region; the allocator
	// must restart behind it instead of failing on the sector lookup.
	alloc, err := NewAllocator([]FlashRegion{
		{Type: "writable", Base: 0x0000, SectorSize: 4096, Count: 2},
		{Type: "reserved", Base: 0x2000, Size: 0x2000},
		{Type: "writable", Base: 0x4000, SectorSize: 4096, Count: 8},
	})
	if err != nil {
		t.Fatal(err)
	}
	addr, size, err := alloc.Allocate(3*4096, 0, "Big")
	if err != nil || addr != 0x4000 || size != 3*4096 {
		t.Fatalf("expected 12 KB at 0x4000, got 0x%X/%d (err %v)", addr, size, err)
	}
}

func TestAllocatorAddressSpaceOverflow(t *testing.T) {
	if _, err := alignUp(0xFFFFF001, 0x1000); err == nil {
		t.Error("expected alignUp overflow error")
	}
	if got, err := alignUp(0x1001, 0); err != nil || got != 0x1001 {
		t.Errorf("align 0 must be a no-op, got 0x%X (err %v)", got, err)
	}
	if end, err := reservedEnd(FlashRegion{Type: "reserved", Base: 0xFFFFF000, Size: 0x1000}); err != nil || end != 0x100000000 {
		t.Errorf("expected reserved region ending at 2^32 to succeed with end=0x100000000, got 0x%X (err %v)", end, err)
	}
	if _, err := reservedEnd(FlashRegion{Type: "reserved", Base: 0xFFFFF000, Size: 0x2000}); err == nil {
		t.Error("expected reservedEnd overflow error for a region exceeding 2^32")
	}

	alloc, err := NewAllocator([]FlashRegion{
		{Type: "writable", Base: 0xFFFF0000, SectorSize: 0x8000, Count: 2},
	})
	if err != nil {
		t.Fatal(err)
	}
	addr, size, err := alloc.Allocate(0x10000, 0, "TopOfMemory")
	if err != nil || addr != 0xFFFF0000 || size != 0x10000 {
		t.Fatalf("expected allocation ending exactly at 2^32 to succeed, got 0x%X/0x%X (err %v)", addr, size, err)
	}
	if _, _, err := alloc.Allocate(0x1000, 0, "PastTop"); err == nil {
		t.Error("expected allocation past 2^32 to fail")
	}
}

func TestAllocatorRegionAwareLocalSectorAllocation(t *testing.T) {
	alloc, err := NewAllocator(stm32f4Regions())
	if err != nil {
		t.Fatal(err)
	}

	// Stage 0 fits in a single 16 KB sector at 0x0000 without wasting 112 KB!
	addr, size, err := alloc.Allocate(16384, 0, "Stage0")
	if err != nil || addr != 0 || size != 0x4000 {
		t.Fatalf("expected 16 KB Stage0 at 0, got 0x%X/0x%X (err %v)", addr, size, err)
	}
	// A 64 KB allocation starting at 0x4000 spans three 16 KB sectors (48 KB) into
	// the 64 KB sector [0x10000..0x20000), so its end aligns to 0x20000 (size 0x1C000).
	addr, size, err = alloc.Allocate(0x10000, 0, "Spanning")
	if err != nil || addr != 0x4000 || size != 0x1C000 {
		t.Fatalf("expected spanning allocation 0x4000..0x20000, got 0x%X/0x%X (err %v)", addr, size, err)
	}
	// Next allocation lands in the 128 KB region at 0x20000 and rounds up to 128 KB.
	addr, size, err = alloc.Allocate(0x10000, 0, "App")
	if err != nil || addr != 0x20000 || size != 0x20000 {
		t.Fatalf("expected 128 KB unit at 0x20000, got 0x%X/0x%X (err %v)", addr, size, err)
	}
}

func TestAllocatorSmallSectorWalKeepsFollowingPartitionAligned(t *testing.T) {
	alloc, err := NewAllocator(stm32f4Regions())
	if err != nil {
		t.Fatal(err)
	}

	addr, size, err := alloc.AllocateSector("WAL 0", alloc.maxSectorSize)
	if err != nil || addr != 0 || size != 16384 {
		t.Fatalf("expected 16 KB WAL sector at 0, got 0x%X/%d (err %v)", addr, size, err)
	}
	// Requesting a 128 KB-aligned slot advances to 0x20000; an unforced 16 KB slot stays at 0x4000.
	addr, size, err = alloc.Allocate(16384, 0, "Stage1A")
	if err != nil || addr != 0x4000 || size != 16384 {
		t.Fatalf("expected 16 KB Stage1A at 0x4000, got 0x%X/%d (err %v)", addr, size, err)
	}
	addr, _, err = alloc.Allocate(0x20000, alloc.maxSectorSize, "Slot")
	if err != nil || addr%alloc.maxSectorSize != 0 || addr != 0x20000 {
		t.Fatalf("expected Slot at the next 128 KB boundary 0x20000, got 0x%X (err %v)", addr, err)
	}
}

func TestAllocatorDualBankGapAndVtorAlignment(t *testing.T) {
	// Dual-bank STM32 with physical base 0x08000000 and an unmapped gap 0x08040000..0x08100000.
	regions := []FlashRegion{
		{Type: "writable", Base: 0x08000000, SectorSize: 0x4000, Count: 16}, // 256 KB
		{Type: "writable", Base: 0x08100000, SectorSize: 0x4000, Count: 16}, // 256 KB
	}
	alloc, err := NewAllocator(regions)
	if err != nil {
		t.Fatal(err)
	}
	// Take 240 KB in Bank 1, leaving 16 KB.
	addr, _, err := alloc.Allocate(0x3C000, 0, "Bank1Prefix")
	if err != nil || addr != 0x08000000 {
		t.Fatalf("expected Bank1Prefix at 0x08000000, got 0x%X (%v)", addr, err)
	}
	// Request 64 KB with VTOR alignment: (addr + 0x200) % 0x400 == 0 cannot be satisfied on a 16 KB
	// boundary with 0x200 header offset unless... wait: (0x08100000 + 0x400) % 0x400 == 0!
	// With vtorAlign=0x8000 and headerOffset=0x4000, addr must be congruent to 0x4000 mod 0x8000!
	addr, size, err := alloc.AllocateWithVtor(0x10000, 0, 0x8000, 0x4000, "Bank2VtorApp")
	if err != nil {
		t.Fatalf("AllocateWithVtor across dual-bank gap failed: %v", err)
	}
	if addr != 0x08104000 || size != 0x10000 || (addr+0x4000)%0x8000 != 0 {
		t.Fatalf("expected VTOR-aligned Bank2 slot at 0x08104000, got 0x%X/0x%X", addr, size)
	}
}

func TestAllocatorRejectsNonPowerOfTwoAlignment(t *testing.T) {
	alloc, err := NewAllocator([]FlashRegion{
		{Type: "writable", Base: 0, SectorSize: 4096, Count: 16},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := alloc.Allocate(4096, 3000, "Odd"); err == nil || !strings.Contains(err.Error(), "power of two") {
		t.Fatalf("expected power-of-two error, got %v", err)
	}
}

func TestAllocatorAllocateSectorWithAlignment(t *testing.T) {
	alloc, err := NewAllocator([]FlashRegion{
		{Type: "writable", Base: 0, SectorSize: 4096, Count: 64},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, aErr := alloc.Allocate(4096, 0, "Prefix"); aErr != nil {
		t.Fatal(aErr)
	}
	addr, size, err := alloc.AllocateSector("WAL 0", 0x10000)
	if err != nil || addr != 0x10000 || size != 4096 {
		t.Fatalf("expected 4 KB sector at 0x10000, got 0x%X/%d (err %v)", addr, size, err)
	}
}

// stm32f4Regions emulates the STM32F4 sector map: 4x16K, 1x64K, 3x128K.
func stm32f4Regions() []FlashRegion {
	return []FlashRegion{
		{Type: "writable", Base: 0x00000, SectorSize: 16384, Count: 4},
		{Type: "writable", Base: 0x10000, SectorSize: 65536, Count: 1},
		{Type: "writable", Base: 0x20000, SectorSize: 131072, Count: 3},
	}
}
