package build

import (
	"encoding/binary"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHigh33DeltaScratchCoherence(t *testing.T) {
	t.Run("2-slot fixed chip with has_scratch=true and enable_deltas=true auto-allocates AppSize scratch on oneway", func(t *testing.T) {
		ctx := testContext(t)
		ctx.Chip.SlotCapabilities = &SlotCapabilities{
			ExecModel:      "fixed",
			SlotCount:      2,
			HasScratch:     true,
			MaxEraseCycles: 100000,
		}
		ctx.Device.Partitions.EnableDeltas = true
		ctx.Device.Partitions.ScratchSize = 0

		cfg, layout := testLayout(t, ctx)
		if cfg.Transport != TransportOneway || cfg.BackupMode != BackupFull {
			t.Fatalf("expected oneway/full, got %s/%s", cfg.Transport, cfg.BackupMode)
		}
		if layout.Scratch.Budget < layout.App.Budget || layout.Scratch.Budget == 0 {
			t.Fatalf("HIGH-33: expected Scratch.Budget >= App.Budget (%d), got %d", layout.App.Budget, layout.Scratch.Budget)
		}
		assertBytes, err := renderLayoutAsserts(cfg, ctx.Hardware, layout).finish()
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(assertBytes), "CHIP_SCRATCH_SLOT_SIZE >= CHIP_APP_SLOT_SIZE") {
			t.Fatalf("expected HIGH-33 _Static_assert in boot_layout_assert.h:\n%s", assertBytes)
		}
	})

	t.Run("swapmove and swapoffset with enable_deltas=true allocate full AppSize scratch while swapscratch fails fast", func(t *testing.T) {
		ctxBad := testContext(t)
		ctxBad.Chip.SlotCapabilities = &SlotCapabilities{
			ExecModel:      "fixed",
			SlotCount:      2,
			HasScratch:     true,
			MaxEraseCycles: 100000,
		}
		ctxBad.Device.BootConfig.TransportProvider = "swapscratch"
		ctxBad.Device.Partitions.EnableDeltas = true
		if _, err := resolveConfig(ctxBad); err == nil {
			t.Fatal("expected swapscratch + enable_deltas=true to fail fast")
		}

		for _, tr := range []string{"swapmove", "swapoffset"} {
			ctx := testContext(t)
			ctx.Chip.SlotCapabilities = &SlotCapabilities{
				ExecModel:      "fixed",
				SlotCount:      2,
				HasScratch:     true,
				MaxEraseCycles: 100000,
			}
			ctx.Device.BootConfig.TransportProvider = tr
			ctx.Device.Partitions.EnableDeltas = true
			ctx.Device.Partitions.ScratchSize = 0

			_, layout := testLayout(t, ctx)
			if layout.Scratch.Budget < layout.App.Budget {
				t.Fatalf("transport %s: expected Scratch.Budget >= App.Budget (%d), got %d",
					tr, layout.App.Budget, layout.Scratch.Budget)
			}
		}
	})

	t.Run("pointer transport with enable_deltas=true keeps zero-copy scratch-less layout", func(t *testing.T) {
		ctx := testContext(t)
		ctx.Device.Partitions.EnableDeltas = true
		ctx.Device.Partitions.ScratchSize = 0

		cfg, layout := testLayout(t, ctx)
		if cfg.Transport != TransportPointer || layout.Scratch.Budget != 0 {
			t.Fatalf("expected pointer transport with 0 scratch, got %s / %d", cfg.Transport, layout.Scratch.Budget)
		}
	})

	t.Run("forced non-pointer transport on scratch-less xip_remap chip with enable_deltas=true is rejected", func(t *testing.T) {
		for _, tr := range []string{"oneway", "swapmove", "swapoffset"} {
			ctx := testContext(t)
			ctx.Chip.SlotCapabilities = &SlotCapabilities{
				ExecModel:      "xip_remap",
				SlotCount:      2,
				HasScratch:     false,
				MaxEraseCycles: 100000,
			}
			ctx.Device.BootConfig.TransportProvider = tr
			ctx.Device.Partitions.EnableDeltas = true
			ctx.Device.Partitions.ScratchSize = 0

			if _, err := resolveConfig(ctx); err == nil || !strings.Contains(err.Error(), "REG-003") {
				t.Fatalf("transport %s: expected REG-003 rejection without scratch, got %v", tr, err)
			}
		}
	})

	t.Run("enable_deltas conflicts with features.delta=false or undersized scratch_size", func(t *testing.T) {
		ctx := testContext(t)
		f := false
		ctx.Device.Partitions.EnableDeltas = true
		ctx.Device.Features.Delta = &f
		if _, err := resolveConfig(ctx); err == nil || !strings.Contains(err.Error(), "REG-003") {
			t.Fatalf("expected REG-003 conflict when features.delta=false, got %v", err)
		}

		ctx2 := testContext(t)
		ctx2.Device.Partitions.EnableDeltas = true
		ctx2.Device.Partitions.ScratchSize = 4096 // < AppSize (262144)
		if _, err := resolveConfig(ctx2); err == nil || !strings.Contains(err.Error(), "REG-003") {
			t.Fatalf("expected REG-003 rejection when scratch_size < app_size, got %v", err)
		}
	})
}

func TestAllocateLocalSectorsEdgeCases(t *testing.T) {
	t.Run("reserved region interrupting KDM Quorum skips cleanly without hanging", func(t *testing.T) {
		alloc, err := NewAllocator([]FlashRegion{
			{Type: "writable", Base: 0x0000, SectorSize: 4096, Count: 16},
			{Type: "reserved", Base: 0x1000, Size: 0x1000, Name: "OTP"},
		})
		if err != nil {
			t.Fatal(err)
		}
		slot := PartitionSlot{Name: "KDM Quorum", Kind: SlotSystem}
		if err := allocateLocalSectors(alloc, &slot, 3, false); err != nil {
			t.Fatalf("allocateLocalSectors failed: %v", err)
		}
		if slot.Addr != 0x2000 || slot.Budget != 3*4096 {
			t.Fatalf("expected KDM Quorum at 0x2000 (12 KB), got 0x%X (%d)", slot.Addr, slot.Budget)
		}
	})

	t.Run("dual-bank unmapped gap interrupting KDM Quorum skips to bank 2", func(t *testing.T) {
		alloc, err := NewAllocator([]FlashRegion{
			{Type: "writable", Base: 0x08000000, SectorSize: 4096, Count: 2},
			{Type: "writable", Base: 0x08100000, SectorSize: 4096, Count: 8},
		})
		if err != nil {
			t.Fatal(err)
		}
		slot := PartitionSlot{Name: "KDM Quorum", Kind: SlotSystem}
		if err := allocateLocalSectors(alloc, &slot, 3, false); err != nil {
			t.Fatalf("allocateLocalSectors across dual-bank gap failed: %v", err)
		}
		if slot.Addr != 0x08100000 || slot.Budget != 3*4096 {
			t.Fatalf("expected KDM Quorum at 0x08100000, got 0x%X (%d)", slot.Addr, slot.Budget)
		}
	})

	t.Run("Mailbox equalSplit across large-to-small sector boundary advances to uniform sectors", func(t *testing.T) {
		regions := []FlashRegion{
			{Type: "writable", Base: 0x00000, SectorSize: 16384, Count: 4}, // 0x00000..0x10000
			{Type: "writable", Base: 0x10000, SectorSize: 4096, Count: 16}, // 0x10000..0x20000
		}
		alloc, err := NewAllocator(regions)
		if err != nil {
			t.Fatal(err)
		}
		// Consume 3 x 16 KB = 0xC000, leaving one 16 KB sector before 4 KB sectors.
		if _, _, err := alloc.Allocate(3*16384, 0, "Prefix"); err != nil {
			t.Fatal(err)
		}
		mb := PartitionSlot{Name: "Mailbox", Kind: SlotSystem}
		if err := allocateLocalSectors(alloc, &mb, mailboxSectors, true); err != nil {
			t.Fatalf("allocateLocalSectors(Mailbox) failed: %v", err)
		}
		if mb.Addr != 0x10000 || mb.Budget != 2*4096 || mb.SectorSize != 4096 {
			t.Fatalf("expected Mailbox at 0x10000 (2x4KB), got addr=0x%X budget=%d sec=%d",
				mb.Addr, mb.Budget, mb.SectorSize)
		}
	})
}

func TestBootromOverlapAndBounds(t *testing.T) {
	// Build a minimal ELF32 with two overlapping PROGBITS sections.
	buildTwoSectionELF := func(addr1 uint32, len1 int, addr2 uint32, len2 int) []byte {
		const (
			ehdrSize = 52
			shdrSize = 40
		)
		shstrtab := []byte("\x00.s1\x00.s2\x00.shstrtab\x00")
		off1 := ehdrSize
		off2 := off1 + len1
		shstrOff := off2 + len2
		if pad := (4 - (shstrOff % 4)) % 4; pad > 0 {
			shstrOff += pad
		}
		shdrOff := shstrOff + len(shstrtab)
		if pad := (4 - (shdrOff % 4)) % 4; pad > 0 {
			shdrOff += pad
		}
		buf := make([]byte, shdrOff+4*shdrSize)
		copy(buf[0:4], []byte{0x7F, 'E', 'L', 'F'})
		buf[4], buf[5], buf[6] = 1, 1, 1
		binary.LittleEndian.PutUint16(buf[16:18], 2)
		binary.LittleEndian.PutUint16(buf[18:20], 0xF3)
		binary.LittleEndian.PutUint32(buf[20:24], 1)
		binary.LittleEndian.PutUint32(buf[24:28], addr1)
		binary.LittleEndian.PutUint32(buf[32:36], uint32(shdrOff))
		binary.LittleEndian.PutUint16(buf[40:42], ehdrSize)
		binary.LittleEndian.PutUint16(buf[46:48], shdrSize)
		binary.LittleEndian.PutUint16(buf[48:50], 4)
		binary.LittleEndian.PutUint16(buf[50:52], 3)

		for i := range len1 {
			buf[off1+i] = 0xAA
		}
		for i := range len2 {
			buf[off2+i] = 0xBB
		}
		copy(buf[shstrOff:], shstrtab)

		putSH := func(idx int, nameOff, shType, flags, addr, off, sz uint32) {
			sh := buf[shdrOff+idx*shdrSize : shdrOff+(idx+1)*shdrSize]
			binary.LittleEndian.PutUint32(sh[0:4], nameOff)
			binary.LittleEndian.PutUint32(sh[4:8], shType)
			binary.LittleEndian.PutUint32(sh[8:12], flags)
			binary.LittleEndian.PutUint32(sh[12:16], addr)
			binary.LittleEndian.PutUint32(sh[16:20], off)
			binary.LittleEndian.PutUint32(sh[20:24], sz)
			binary.LittleEndian.PutUint32(sh[32:36], 4)
		}
		putSH(1, 1, 1, 0x6, addr1, uint32(off1), uint32(len1))
		putSH(2, 5, 1, 0x6, addr2, uint32(off2), uint32(len2))
		putSH(3, 9, 3, 0x0, 0, uint32(shstrOff), uint32(len(shstrtab)))
		return buf
	}

	elfPath := filepath.Join(t.TempDir(), "overlap.elf")
	if err := os.WriteFile(elfPath, buildTwoSectionELF(0x10000000, 256, 0x10000080, 32), 0o644); err != nil {
		t.Fatal(err)
	}
	hw := &HardwareJson{ChipFamily: "test-overlap"}
	if _, err := PackStage0ELF(elfPath, hw); err == nil || !strings.Contains(err.Error(), "overlap") {
		t.Fatalf("expected overlap rejection in PackStage0ELF(flat), got %v", err)
	}

	// Overflowing patch/field offsets must fail cleanly without slice panic.
	if err := writeBootromField(make([]byte, 16), BootromFieldSpec{Offset: math.MaxInt, Size: 4, Source: "const"}, bootromEvalCtx{}); err == nil {
		t.Fatal("expected overflow offset rejection in writeBootromField")
	}
	if err := applyBootromPatch(make([]byte, 16), BootromPatchSpec{Op: "const", Offset: math.MaxInt, Size: 4}, bootromEvalCtx{}); err == nil {
		t.Fatal("expected overflow offset rejection in applyBootromPatch")
	}
}

func TestRegistryAllChipsAndTemplates(t *testing.T) {
	chipsRoot := filepath.Clean(filepath.Join("..", "..", "toob-infra", "registry", "packages", "chips"))
	entries, err := os.ReadDir(chipsRoot)
	if err != nil {
		t.Skipf("registry chips directory not present at %s: %v", chipsRoot, err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		chipName := entry.Name()
		chipDir := filepath.Join(chipsRoot, chipName)
		hwPath := filepath.Join(chipDir, "hardware.json")
		cmPath := filepath.Join(chipDir, "chip_manifest.json")
		if _, err := os.Stat(hwPath); err != nil {
			continue
		}

		t.Run(chipName, func(t *testing.T) {
			hj, err := ParseHardwareJSON(hwPath)
			if err != nil {
				t.Fatalf("ParseHardwareJSON(%s): %v", chipName, err)
			}
			results := VerifyHardwareProvenance(hj)
			if HasVerificationFailures(results) {
				t.Fatalf("%s failed provenance verification:\n%s", chipName, FormatVerificationErrors(results))
			}

			var dt *DeviceToml
			tmplPath := filepath.Join(chipDir, "template_device.toml")
			if _, statErr := os.Stat(tmplPath); statErr == nil {
				dt, err = ParseToml(tmplPath)
				if err != nil {
					t.Fatalf("ParseToml(%s): %v", tmplPath, err)
				}
			} else {
				dt = &DeviceToml{Name: "test-" + chipName, Version: "1.0.0"}
				dt.Device.Chip = chipName
				dt.Identity.VendorID = 0x0001
				dt.Identity.ProductID = 0x0042
				dt.Identity.HwRev = 1
				// Scale partition sizes to fit compact 256-512 KB MCUs (e.g. STM32F072, STM32F103) as well as multi-MB chips.
				if hj.Flash.Size <= 524288 {
					dt.Partitions.Stage0Size = 16384
					dt.Partitions.Stage1Size = 32768
					dt.Partitions.AppSize = 65536
				} else {
					dt.Partitions.Stage0Size = 32768
					dt.Partitions.Stage1Size = 131072
					dt.Partitions.AppSize = 131072
				}
				dt.BootConfig.MaxRetries = 3
				dt.Recovery.Crypto.Justification = "Synthetic chip matrix fixture"
			}

			ctx, err := Load(Inputs{
				Device:           dt,
				HardwarePath:     hwPath,
				ChipManifestPath: cmPath,
				CoreDir:          testCoreDir(t),
				SourceDirs:       []string{t.TempDir()},
				OutDir:           filepath.Join(t.TempDir(), "generated"),
			}, NopLogger{})
			if err != nil {
				t.Fatalf("Load(%s): %v", chipName, err)
			}
			cfg, err := resolveConfig(ctx)
			if err != nil {
				t.Fatalf("resolveConfig(%s): %v", chipName, err)
			}
			layout, err := planLayout(ctx.Device, ctx.Hardware, cfg)
			if err != nil {
				t.Fatalf("planLayout(%s): %v", chipName, err)
			}
			if cfg.EnableDeltas && cfg.Transport != TransportPointer && layout.Scratch.Budget < layout.App.Budget {
				t.Fatalf("%s: HIGH-33 violated: EnableDeltas=true on %s has Scratch=%d < App=%d",
					chipName, cfg.Transport, layout.Scratch.Budget, layout.App.Budget)
			}

			// Verify every C header and LD script renders cleanly without sticky errors.
			cfgSrc, err := renderBootConfig(ctx, cfg, layout)
			if err != nil {
				t.Fatalf("renderBootConfig(%s): %v", chipName, err)
			}
			for name, src := range map[string]*cSource{
				fileBootConfig:   cfgSrc,
				fileBootLayout:   renderBootLayout(layout),
				fileLayoutAssert: renderLayoutAsserts(cfg, ctx.Hardware, layout),
				fileMemoryLD:     renderMemoryLD(ctx, cfg, layout),
				fileStage0LD:     renderStage0LDForContext(ctx, ctx.Hardware),
				fileFlashLD:      renderFlashLD(ctx, cfg, layout),
				fileRecoveryLD:   renderRecoveryLD(ctx, cfg, layout),
			} {
				if _, err := src.finish(); err != nil {
					t.Fatalf("%s render %s failed: %v", chipName, name, err)
				}
			}
		})
	}
}

func FuzzAlignSlotStart(f *testing.F) {
	f.Add(uint32(0), uint32(4096), uint32(256), uint32(256))
	f.Add(uint32(0x08004000), uint32(2048), uint32(256), uint32(20))
	f.Add(uint32(0x08100000), uint32(16384), uint32(32768), uint32(16384))
	f.Add(uint32(0xFFFFF000), uint32(4096), uint32(8192), uint32(4096))
	f.Add(uint32(123), uint32(6), uint32(4), uint32(2))
	f.Add(uint32(0), uint32(0), uint32(128), uint32(20))

	f.Fuzz(func(t *testing.T, addr, slotAlign, vtorAlign, headerOffset uint32) {
		got, err := alignSlotStart(addr, slotAlign, vtorAlign, headerOffset)
		if (slotAlign != 0 && !isPowerOfTwo(uint64(slotAlign))) || (vtorAlign != 0 && !isPowerOfTwo(uint64(vtorAlign))) {
			if err == nil {
				t.Fatalf("expected non-power-of-two rejection for slotAlign=%d vtorAlign=%d", slotAlign, vtorAlign)
			}
			return
		}
		if err != nil {
			return
		}
		if got < addr {
			t.Fatalf("alignSlotStart wrapped around: got 0x%X < addr 0x%X", got, addr)
		}
		if slotAlign > 0 && got%slotAlign != 0 {
			t.Fatalf("got 0x%X is not aligned to slotAlign %d", got, slotAlign)
		}
		if vtorAlign > 0 && (uint64(got)+uint64(headerOffset))%uint64(vtorAlign) != 0 {
			t.Fatalf("(0x%X + 0x%X) %% 0x%X != 0", got, headerOffset, vtorAlign)
		}
		// Verify minimality over small bounded steps when alignment step is reasonable.
		step := uint64(1)
		if slotAlign > 1 {
			step = uint64(slotAlign)
		}
		firstAligned, aErr := alignUp(addr, slotAlign)
		if aErr == nil && uint64(got) > uint64(firstAligned) && (uint64(got)-uint64(firstAligned))/step <= 64 {
			for cand := uint64(firstAligned); cand < uint64(got); cand += step {
				if vtorAlign == 0 || (cand+uint64(headerOffset))%uint64(vtorAlign) == 0 {
					t.Fatalf("non-minimal solution 0x%X: earlier valid candidate 0x%X exists", got, cand)
				}
			}
		}
	})
}

func FuzzAllocatorInvariants(f *testing.F) {
	f.Add([]byte{0, 12, 16, 1, 14, 8, 2, 1, 2, 4, 8, 3, 1})
	f.Add([]byte{8, 11, 32, 0, 11, 2, 1, 15, 4, 2, 2, 6, 4})

	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) < 6 {
			return
		}
		var regions []FlashRegion
		cursor := uint64(raw[0]&0x0F) << 20 // 0..15 MiB aligned base
		idx := 1
		for idx+2 < len(raw) && len(regions) < 5 {
			kind := raw[idx] % 4
			shift := 10 + (raw[idx+1] % 8) // 1 KB .. 128 KB power-of-two sector size
			secSz := uint32(1) << shift
			cnt := uint32(1 + (raw[idx+2] % 16))
			idx += 3

			alignedBase := (cursor + uint64(secSz) - 1) &^ (uint64(secSz) - 1)
			span := uint64(secSz) * uint64(cnt)
			if alignedBase+span > 0xFFFFFFFF {
				break
			}
			if kind == 3 {
				regions = append(regions, FlashRegion{
					Type: "reserved",
					Base: uint32(alignedBase),
					Size: secSz,
					Name: "rsvd",
				})
				cursor = alignedBase + uint64(secSz)
			} else {
				regions = append(regions, FlashRegion{
					Type:       "writable",
					Base:       uint32(alignedBase),
					SectorSize: secSz,
					Count:      cnt,
				})
				cursor = alignedBase + span
				if kind == 2 {
					cursor += uint64(secSz) * 2 // Dual-bank unmapped gap
				}
			}
		}

		alloc, err := NewAllocator(regions)
		if err != nil {
			return
		}

		type span struct{ start, end uint64 }
		var allocated []span
		for step := 0; idx < len(raw) && step < 8; step++ {
			op := raw[idx]
			idx++
			var addr, size, reqAlign, vtorAlign, hdrOff uint32
			switch op % 3 {
			case 0:
				budget := uint32(1+(op%32)) * 1024
				if op&0x20 != 0 {
					reqAlign = uint32(1) << (10 + (op % 7))
				}
				if op&0x40 != 0 {
					vtorAlign = 256
					hdrOff = 256
				}
				addr, size, err = alloc.AllocateWithVtor(budget, reqAlign, vtorAlign, hdrOff, "slot")
			case 1:
				addr, size, err = alloc.AllocateSector("wal", 0)
			case 2:
				var slot PartitionSlot
				slot.Name = "sys"
				sectors := uint32(1 + (op % 3))
				equalSplit := (op & 0x80) != 0
				err = allocateLocalSectors(alloc, &slot, sectors, equalSplit)
				addr, size = slot.Addr, slot.Budget
				if err == nil && equalSplit {
					sec, sErr := alloc.GetSectorSizeAt(addr)
					if sErr != nil || uint64(size) != uint64(sectors)*uint64(sec) {
						t.Fatalf("equalSplit violated: addr=0x%X size=%d sectors=%d sec=%d (%v)", addr, size, sectors, sec, sErr)
					}
				}
			}
			if err != nil {
				continue
			}
			if size == 0 {
				t.Fatal("allocated zero size on success")
			}
			sEnd := uint64(addr) + uint64(size)
			if sEnd > math.MaxUint32 {
				t.Fatalf("allocation [0x%X..0x%X) exceeded uint32", addr, sEnd)
			}
			startSec, err := alloc.GetSectorSizeAt(addr)
			if err != nil || addr%startSec != 0 {
				t.Fatalf("start 0x%X not aligned to local sector %d (%v)", addr, startSec, err)
			}
			if reqAlign > 0 && addr%reqAlign != 0 {
				t.Fatalf("start 0x%X violated reqAlign %d", addr, reqAlign)
			}
			if vtorAlign > 0 && (uint64(addr)+uint64(hdrOff))%uint64(vtorAlign) != 0 {
				t.Fatalf("start 0x%X violated vtorAlign %d", addr, vtorAlign)
			}
			endSec, err := alloc.GetSectorSizeAt(uint32(sEnd - 1))
			if err != nil || sEnd%uint64(endSec) != 0 {
				t.Fatalf("end 0x%X not aligned to ending sector %d (%v)", sEnd, endSec, err)
			}
			for _, r := range regions {
				if isReservedRegion(r) && r.Size > 0 {
					if uint64(addr) < regionEnd(r) && uint64(r.Base) < sEnd {
						t.Fatalf("allocation [0x%X..0x%X) overlapped reserved [0x%X..0x%X)",
							addr, sEnd, r.Base, regionEnd(r))
					}
				}
			}
			for _, prev := range allocated {
				if uint64(addr) < prev.end && prev.start < sEnd {
					t.Fatalf("allocation [0x%X..0x%X) overlapped previous [0x%X..0x%X)",
						addr, sEnd, prev.start, prev.end)
				}
			}
			allocated = append(allocated, span{uint64(addr), sEnd})
		}
	})
}

func TestHigh41SwapScratchAsymmetricDualBankAlign(t *testing.T) {
	// STM32F429-like symmetric 2 MB Dual-Bank flash (4x16KB + 1x64KB + 7x128KB per 1 MB bank)
	// where App and Staging could otherwise land on 16 KB offsets with equal budgets while
	// Scratch sits in a 128 KB sector (CBMC Wave 5A Finding O).
	ctx := testContext(t)
	ctx.Hardware.Flash.BaseAddr = "0x08000000"
	ctx.Hardware.Flash.Size = 0x00200000
	ctx.Hardware.Flash.WriteAlignment = 4
	ctx.Hardware.Flash.Regions = []FlashRegion{
		{Type: "writable", Base: 0x08000000, SectorSize: 16384, Count: 4},
		{Type: "writable", Base: 0x08010000, SectorSize: 65536, Count: 1},
		{Type: "writable", Base: 0x08020000, SectorSize: 131072, Count: 7},
		{Type: "writable", Base: 0x08100000, SectorSize: 16384, Count: 4},
		{Type: "writable", Base: 0x08110000, SectorSize: 65536, Count: 1},
		{Type: "writable", Base: 0x08120000, SectorSize: 131072, Count: 7},
	}
	ctx.Chip.SlotCapabilities = &SlotCapabilities{
		ExecModel:      "fixed",
		SlotCount:      2,
		HasScratch:     true,
		MaxEraseCycles: 10000,
	}
	ctx.Device.BootConfig.TransportProvider = "swapscratch"
	ctx.Device.Partitions.Stage0Size = 16384
	ctx.Device.Partitions.Stage1Size = 16384
	ctx.Device.Partitions.AppSize = 112 * 1024 // Fits in 3x16KB + 64KB if unaligned at +0x4000!

	cfg, layout := testLayout(t, ctx)
	swapSec := layout.swapScratchBlockAlign()
	if swapSec != 131072 {
		t.Fatalf("expected swapSec = 131072, got %d", swapSec)
	}
	for _, slot := range []PartitionSlot{layout.App, layout.Staging, layout.Scratch} {
		if slot.Addr%swapSec != 0 {
			t.Fatalf("%s at 0x%08X is not aligned to swapscratch block size %d", slot.Name, slot.Addr, swapSec)
		}
	}
	asserts, err := renderLayoutAsserts(cfg, ctx.Hardware, layout).finish()
	if err != nil {
		t.Fatalf("renderLayoutAsserts: %v", err)
	}
	if !strings.Contains(string(asserts), "HIGH-41: App Slot must align to swapscratch block size 131072!") {
		t.Fatalf("missing HIGH-41 static assertion in boot_layout_assert.h:\n%s", asserts)
	}
}
