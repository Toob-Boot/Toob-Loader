package build

import (
	"encoding/binary"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuditRemediationsCritical36To44(t *testing.T) {
	t.Run("CRIT-36 WAL sector count <= 8 and sector size >= 256", func(t *testing.T) {
		ctx := testContext(t)
		ctx.Device.Partitions.WalSectors = 9
		if _, err := resolveConfig(ctx); err == nil || !strings.Contains(err.Error(), "exceeds the maximum of 8") {
			t.Fatalf("expected wal_sectors=9 to fail, got %v", err)
		}

		ctx = testContext(t)
		ctx.Device.Partitions.WalSectors = 8
		cfg, layout := testLayout(t, ctx)
		assertBytes, err := renderLayoutAsserts(cfg, ctx.Hardware, layout).finish()
		if err != nil {
			t.Fatal(err)
		}
		text := string(assertBytes)
		if !strings.Contains(text, "TOOB_WAL_SECTORS >= 4U && TOOB_WAL_SECTORS <= 8U") {
			t.Errorf("missing WAL [4..8] _Static_assert:\n%s", text)
		}
		if !strings.Contains(text, "CHIP_WAL_SECTOR_0_SIZE >= 256U") {
			t.Errorf("missing WAL >= 256U _Static_assert:\n%s", text)
		}

		smallAlloc, err := NewAllocator([]FlashRegion{
			{Type: "writable", Base: 0, SectorSize: 128, Count: 64},
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := planWal(smallAlloc, &PartitionLayout{}, 4); err == nil || !strings.Contains(err.Error(), "minimum 256 bytes") {
			t.Fatalf("expected 128-byte WAL sector to fail, got %v", err)
		}
	})

	t.Run("CRIT-37 KDM 3 physical sector slots emitted and asserted", func(t *testing.T) {
		ctx := testContext(t)
		ctx.Hardware.Flash.Size = 0x300000
		ctx.Hardware.Flash.Regions = []FlashRegion{
			{Type: "writable", Base: 0x00000, SectorSize: 16384, Count: 4},
			{Type: "writable", Base: 0x10000, SectorSize: 65536, Count: 1},
			{Type: "writable", Base: 0x20000, SectorSize: 131072, Count: 23},
		}
		cfg, layout := testLayout(t, ctx)
		if len(layout.KdmSlots) != 3 {
			t.Fatalf("expected 3 KDM physical slots, got %d", len(layout.KdmSlots))
		}
		bootCfg, err := renderBootConfig(ctx, cfg, layout)
		if err != nil {
			t.Fatal(err)
		}
		cfgTextBytes, err := bootCfg.finish()
		if err != nil {
			t.Fatal(err)
		}
		cfgText := string(cfgTextBytes)
		for _, want := range []string{"TOOB_KDM_SLOT_ADDRS", "TOOB_KDM_SLOT_SIZES"} {
			if !strings.Contains(cfgText, want) {
				t.Errorf("generated_boot_config.h missing %s", want)
			}
		}
		layoutBytes, err := renderBootLayout(layout).finish()
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"CHIP_KDM_SLOT_0_ADDR", "CHIP_KDM_SLOT_1_ADDR", "CHIP_KDM_SLOT_2_ADDR", "CHIP_KDM_SLOT_2_SIZE"} {
			if !strings.Contains(string(layoutBytes), want) {
				t.Errorf("boot_layout.h missing %s", want)
			}
		}
		assertBytes, err := renderLayoutAsserts(cfg, ctx.Hardware, layout).finish()
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(assertBytes), "3ULL *") || !strings.Contains(string(assertBytes), "CHIP_KDM_SLOT_0_ADDR") {
			t.Errorf("boot_layout_assert.h missing 64-bit KDM assertions:\n%s", assertBytes)
		}
	})

	t.Run("CRIT-38 sub-base flash region rejected and 4GiB immutable end safe", func(t *testing.T) {
		ctx := testContext(t)
		ctx.Hardware.Flash.Base = 0x08000000
		ctx.Hardware.Flash.Regions = []FlashRegion{
			{Type: "writable", Base: 0, SectorSize: 4096, Count: 256},
		}
		if err := checkFlashGeometry(ctx); err == nil || !strings.Contains(err.Error(), "below flash base") {
			t.Fatalf("expected 0-based region on 0x08000000 flash to fail, got %v", err)
		}

		topLayout := &PartitionLayout{
			MaxSectorSize: 4096,
			FlashBase:     0xFFFF0000,
			XipBaseVal:    0xFFFF0000,
			Stage0:        PartitionSlot{Name: "Stage 0", Addr: 0xFFFF0000, Budget: 0x10000, SectorSize: 4096},
		}
		blBytes, err := renderBootLayout(topLayout).finish()
		if err != nil {
			t.Fatal(err)
		}
		blText := string(blBytes)
		for _, want := range []string{
			"#define CHIP_FLASH_IMMUTABLE_BOOT_END            0x100000000ULL",
			"#define CHIP_STAGE0_BYTE_SIZE                    0x00010000U",
			"#define CHIP_FLASH_IMMUTABLE_BOOT_XIP_END        0x100000000ULL",
		} {
			if !strings.Contains(blText, want) {
				t.Errorf("missing %q in:\n%s", want, blText)
			}
		}
	})

	t.Run("CRIT-39 PQC resolution handles none and chip inheritance", func(t *testing.T) {
		ctx := testContext(t)
		ctx.Device.Crypto.Pqc = "none"
		cfg, layout := testLayout(t, ctx)
		if cfg.PqcEnabled {
			t.Fatal("crypto.pqc = 'none' must disable PQC")
		}
		bootCfg, err := renderBootConfig(ctx, cfg, layout)
		if err != nil {
			t.Fatal(err)
		}
		cfgBytes, err := bootCfg.finish()
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(cfgBytes), "#define TOOB_PQC_ENABLED                         0") {
			t.Fatalf("expected TOOB_PQC_ENABLED = 0 when pqc='none':\n%s", cfgBytes)
		}

		// Chip-inherited PQC without bound verify_pqc manifest must fail fast.
		ctxChipPqc := testContext(t)
		ctxChipPqc.Hardware.CryptoCapabilities.ArenaSize = 8192
		ctxChipPqc.Chip.Crypto = &ChipCrypto{Pqc: "ml_dsa_65"}
		if _, err := resolveConfig(ctxChipPqc); err == nil || !strings.Contains(err.Error(), "verify_pqc") {
			t.Fatalf("expected missing PQC manifest error, got %v", err)
		}
	})

	t.Run("CRIT-40 write_alignment > 32 rejected", func(t *testing.T) {
		ctx := testContext(t)
		ctx.Hardware.Flash.WriteAlignment = 64
		if err := checkFlashGeometry(ctx); err == nil || !strings.Contains(err.Error(), "maximum supported write_alignment 32") {
			t.Fatalf("expected write_alignment=64 to fail, got %v", err)
		}
	})

	t.Run("CRIT-41 bank_swap symmetric mirrored Dual-Bank layout", func(t *testing.T) {
		ctxSingle := testContext(t)
		ctxSingle.Chip.SlotCapabilities.ExecModel = "bank_swap"
		cfgSingle, err := resolveConfig(ctxSingle)
		if err != nil {
			t.Fatal(err)
		}
		if _, pErr := planLayout(ctxSingle.Device, ctxSingle.Hardware, cfgSingle); pErr == nil || !strings.Contains(pErr.Error(), "LAYOUT_007") {
			t.Fatalf("expected single-bank bank_swap layout to fail with LAYOUT_007, got %v", pErr)
		}

		for _, chip := range []string{"stm32f429", "stm32l476", "stm32h753"} {
			chipDir := filepath.Join("..", "..", "toob-infra", "registry", "packages", "chips", chip)
			hwPath := filepath.Join(chipDir, "hardware.json")
			cmPath := filepath.Join(chipDir, "chip_manifest.json")
			tmplPath := filepath.Join(chipDir, "template_device.toml")
			var dt *DeviceToml
			if _, stErr := os.Stat(tmplPath); stErr == nil {
				dt, err = ParseToml(tmplPath)
				if err != nil {
					t.Fatal(err)
				}
			} else {
				dt = testDevice()
				dt.Device.Chip = chip
				dt.Partitions.Stage0Size = 131072
				dt.Partitions.Stage1Size = 131072
				dt.Partitions.AppSize = 262144
				dt.Recovery.Crypto.Justification = "bank_swap test"
			}
			c, err := Load(Inputs{
				Device:           dt,
				HardwarePath:     hwPath,
				ChipManifestPath: cmPath,
				CoreDir:          testCoreDir(t),
				SourceDirs:       []string{t.TempDir()},
				OutDir:           filepath.Join(t.TempDir(), "generated"),
			}, NopLogger{})
			if err != nil {
				t.Fatalf("Load(%s): %v", chip, err)
			}
			c.Chip.SlotCapabilities.ExecModel = "bank_swap"
			cfg, layout := testLayout(t, c)
			if !layout.IsBankSwap {
				t.Fatalf("%s: expected IsBankSwap=true", chip)
			}
			appDelta := layout.App.Addr - layout.Bank1Base
			stgDelta := layout.Staging.Addr - layout.Bank2Base
			if appDelta != stgDelta {
				t.Fatalf("%s: App delta 0x%X != Staging delta 0x%X", chip, appDelta, stgDelta)
			}
			if layout.App.Budget != layout.Staging.Budget {
				t.Fatalf("%s: App budget %d != Staging budget %d", chip, layout.App.Budget, layout.Staging.Budget)
			}
			if layout.Wal.Addr == layout.Bank2Base {
				t.Fatalf("%s: WAL must never be placed at Bank 2 origin 0x%08X", chip, layout.Bank2Base)
			}
			asserts, err := renderLayoutAsserts(cfg, c.Hardware, layout).finish()
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(asserts), "CRIT-41: bank_swap requires mirrored intra-bank offset") {
				t.Errorf("%s: missing CRIT-41 _Static_assert", chip)
			}
		}
	})

	t.Run("CRIT-42 single-slot chip keeps non-zero Staging slot", func(t *testing.T) {
		ctx := testContext(t)
		ctx.Chip.SlotCapabilities = &SlotCapabilities{
			ExecModel:      "fixed",
			SlotCount:      1,
			HasScratch:     true,
			MaxEraseCycles: 100000,
		}
		ctx.Device.BootConfig.TransportProvider = "oneway"
		ctx.Device.BootConfig.BackupMode = "full"
		_, layout := testLayout(t, ctx)
		if layout.Staging.Budget == 0 {
			t.Fatal("CRIT-42: Staging.Budget must never be zeroed on 1-slot chips")
		}
	})

	t.Run("CRIT-43 & CRIT-44 Stage1B linker script and fixed-origin .noinit SRAM carve-out", func(t *testing.T) {
		ctx := testContext(t)
		ctx.Chip.Arch = "cortex-m"
		ctx.Arch.Name = "cortex-m"
		ctx.Hardware.Flash.VtorAlignment = 256
		ctx.Hardware.Flash.ImageHeaderOffset = 256
		ctx.Hardware.Memory.LpRamBase = ""
		ctx.Hardware.Memory.LpRamSize = ""
		ctx.Hardware.ReservedRamRegions = nil

		cfg, layout := testLayout(t, ctx)
		if (layout.Stage1A.Addr+256)%256 != 0 || (layout.Stage1B.Addr+256)%256 != 0 {
			t.Fatalf("Stage1A (0x%X) and Stage1B (0x%X) must satisfy VTOR alignment", layout.Stage1A.Addr, layout.Stage1B.Addr)
		}

		out, err := renderArtifacts(ctx, cfg, layout, []byte("# report"))
		if err != nil {
			t.Fatal(err)
		}
		byName := make(map[string]string, len(out.artifacts))
		for _, a := range out.artifacts {
			byName[a.name] = string(a.data)
		}
		if !strings.Contains(byName[fileFlashStage1BLD], "ORIGIN = __STAGE1B_ORIGIN, LENGTH = __STAGE1B_LENGTH") {
			t.Errorf("flash_layout_stage1b.ld missing __STAGE1B_ORIGIN:\n%s", byName[fileFlashStage1BLD])
		}
		if !strings.Contains(byName[fileMemoryLD], "__LP_RAM_LENGTH = 0x00000200;") {
			t.Errorf("generated_memory.ld missing 0x200 carved LP_RAM:\n%s", byName[fileMemoryLD])
		}
		for _, ldFile := range []string{fileStage0LD, fileFlashLD, fileFlashStage1BLD, fileRecoveryLD} {
			if !strings.Contains(strings.ToLower(byName[ldFile]), "} > lp_ram") {
				t.Errorf("%s did not place .noinit in LP_RAM:\n%s", ldFile, byName[ldFile])
			}
		}
		if !strings.Contains(byName[fileBootConfig], "CHIP_LP_RAM_BASE_ADDR") {
			t.Errorf("generated_boot_config.h missing CHIP_LP_RAM_BASE_ADDR")
		}
	})
}

func TestAuditRemediationsHighAndMedium(t *testing.T) {
	t.Run("HIGH-43 inherited unsigned recovery requires justification and exact lowercase", func(t *testing.T) {
		ctx := testContext(t)
		ctx.Chip.Recovery = &ChipRecovery{Crypto: &RecoveryCrypto{Backend: "none", Hash: "sha256_sw"}}
		if _, err := resolveConfig(ctx); err == nil || !strings.Contains(err.Error(), "REG-007") {
			t.Fatalf("expected inherited backend='none' without justification to fail REG-007, got %v", err)
		}
		ctx.Device.Recovery.Crypto.Justification = "ROM recovery verified externally"
		if _, err := resolveConfig(ctx); err != nil {
			t.Fatalf("expected justified inherited unsigned recovery to pass, got %v", err)
		}
		ctx.Device.Recovery.Crypto.Hash = "None"
		if _, err := resolveConfig(ctx); err == nil || !strings.Contains(err.Error(), "exact lowercase") {
			t.Fatalf("expected mixed-case 'None' with justification to fail lowercase check, got %v", err)
		}
	})

	t.Run("HIGH-44 swapmove allocates +1 spare sector in App and rejects heterogeneous sectors", func(t *testing.T) {
		ctx := testContext(t)
		ctx.Device.BootConfig.TransportProvider = "swapmove"
		cfg, layout := testLayout(t, ctx)
		if layout.App.Budget != layout.Staging.Budget+4096 {
			t.Fatalf("expected App.Budget (%d) == Staging.Budget (%d) + 4096", layout.App.Budget, layout.Staging.Budget)
		}
		asserts, err := renderLayoutAsserts(cfg, ctx.Hardware, layout).finish()
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(asserts), "HIGH-44: swapmove/swapoffset requires CHIP_APP_SLOT_SIZE") {
			t.Errorf("missing HIGH-44 _Static_assert:\n%s", asserts)
		}
	})

	t.Run("HIGH-45 flash_erased_byte != 0xFF and backoff overflow rejected", func(t *testing.T) {
		ctx := testContext(t)
		ctx.Hardware.Constants["flash_erased_byte"] = float64(0)
		if _, err := resolveConfig(ctx); err == nil || !strings.Contains(err.Error(), "0xFF") {
			t.Fatalf("expected flash_erased_byte=0 to fail, got %v", err)
		}

		ctx = testContext(t)
		ctx.Device.BootConfig.BackoffBaseS = math.MaxUint32/24 + 1
		if _, err := resolveConfig(ctx); err == nil || !strings.Contains(err.Error(), "backoff_base_s") {
			t.Fatalf("expected backoff_base_s overflow to fail, got %v", err)
		}
	})

	t.Run("HIGH-46 XIP 32-bit wrap and two-way overlap rejected", func(t *testing.T) {
		ctx := testContext(t)
		ctx.Hardware.Flash.XipBase = "0xFFF00000"
		if _, err := resolveConfig(ctx); err == nil || !strings.Contains(err.Error(), "32-bit address space") {
			t.Fatalf("expected XIP wrap to fail, got %v", err)
		}

		hj := validTestHardwareJSON(t)
		hj.Flash.Base = 0x08000000
		hj.Flash.Regions = []FlashRegion{
			{Type: "writable", Base: 0x08000000, SectorSize: 4096, Count: 1024, Provenance: hj.Provenance},
		}
		hj.Flash.XipBase = "0x07F00000" // overlaps [0x08000000..0x08400000) from below!
		if !HasVerificationFailures(VerifyHardwareProvenance(hj)) {
			t.Fatal("expected two-way XIP overlap to fail FLASH-004")
		}
	})

	t.Run("HIGH-47 chained symlink to directory link/junction escape blocked", func(t *testing.T) {
		root := t.TempDir()
		pkgDir := filepath.Join(root, "pkg")
		outsideDir := filepath.Join(root, "outside")
		for _, d := range []string{pkgDir, outsideDir} {
			if err := os.MkdirAll(d, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		writeTempFile(t, outsideDir, "secret.c", "/* secret */")
		juncInRoot := filepath.Join(root, "junc_to_outside")
		makeDirLink(t, outsideDir, juncInRoot)

		chained := filepath.Join(pkgDir, "chained_link")
		if err := os.Symlink(filepath.Join("..", "junc_to_outside"), chained); err != nil {
			makeDirLink(t, juncInRoot, chained)
		}
		if _, err := containPath(pkgDir, "chained_link/secret.c"); err == nil {
			t.Fatal("HIGH-47: containPath must block chained link -> junction escape")
		}
	})

	t.Run("HIGH-48 packBootromFlat pads < MinSize before CRC32 and blocks non-sentinel overwrite", func(t *testing.T) {
		tmp := t.TempDir()
		shortELF := filepath.Join(tmp, "short_boot2.elf")
		shortCode := make([]byte, 120)
		for i := range shortCode {
			shortCode[i] = 0xA5
		}
		if err := os.WriteFile(shortELF, buildMinimalELF32(0x10000001, 0x10000000, shortCode), 0o644); err != nil {
			t.Fatal(err)
		}
		var hw HardwareJson
		hw.ChipFamily = "rp2040"
		hw.Flash.XipBase = "0x10000000"
		hw.Flash.Size = 0x200000
		hw.BootromImage = &BootromImageSpec{
			Layout:  "flat",
			MinSize: 256,
			Patches: []BootromPatchSpec{{
				Op: "crc32", Offset: 252, Size: 4, Endian: "little",
				RangeStart: 0, RangeEnd: 252, Poly: 0x04C11DB7, Init: 0xFFFFFFFF,
			}},
		}
		packed, err := PackStage0ELF(shortELF, &hw)
		if err != nil {
			t.Fatalf("PackStage0ELF(<MinSize) failed: %v", err)
		}
		if len(packed) != 256 {
			t.Fatalf("expected padded length 256, got %d", len(packed))
		}
		wantCRC := computeGenericCRC32(packed[:252], 0x04C11DB7, 0xFFFFFFFF, 0, false)
		if gotCRC := binary.LittleEndian.Uint32(packed[252:256]); gotCRC != wantCRC {
			t.Fatalf("CRC mismatch after MinSize fill-pad: got 0x%08X want 0x%08X", gotCRC, wantCRC)
		}

		// Live non-sentinel bytes at [252..256) must fail fast.
		liveELF := filepath.Join(tmp, "live_boot2.elf")
		liveCode := make([]byte, 256)
		for i := range liveCode {
			liveCode[i] = 0x42
		}
		if err := os.WriteFile(liveELF, buildMinimalELF32(0x10000001, 0x10000000, liveCode), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := PackStage0ELF(liveELF, &hw); err == nil || !strings.Contains(err.Error(), "non-sentinel") {
			t.Fatalf("expected live SHT_PROGBITS overwrite to fail fast, got %v", err)
		}
	})

	t.Run("HIGH-53 non-contiguous Dual-Bank flash with unmapped gap succeeds", func(t *testing.T) {
		ctx := testContext(t)
		ctx.Hardware.Flash.Base = 0x08000000
		ctx.Hardware.Flash.XipBase = "0x0"
		ctx.Hardware.Flash.Size = 0x00100000 // 1 MiB physical flash across two 512 KB banks with 512 KB gap
		ctx.Hardware.Flash.Regions = []FlashRegion{
			{Type: "writable", Base: 0x08000000, SectorSize: 0x2000, Count: 64, Provenance: ctx.Hardware.Provenance},
			{Type: "writable", Base: 0x08100000, SectorSize: 0x2000, Count: 64, Provenance: ctx.Hardware.Provenance},
		}
		ctx.Chip.SlotCapabilities.ExecModel = "bank_swap"
		ctx.Device.Partitions.Stage0Size = 0x4000
		ctx.Device.Partitions.Stage1Size = 0x8000
		ctx.Device.Partitions.AppSize = 0x20000
		if HasVerificationFailures(VerifyHardwareProvenance(ctx.Hardware)) {
			t.Fatalf("non-contiguous Dual-Bank failed provenance: %s", FormatVerificationErrors(VerifyHardwareProvenance(ctx.Hardware)))
		}
		_, layout := testLayout(t, ctx)
		if layout.Staging.Addr-0x08100000 != layout.App.Addr-0x08000000 {
			t.Fatalf("expected mirrored Dual-Bank slots across unmapped gap")
		}
	})

	t.Run("HIGH-54 AllocateSector re-evaluates sector size after reserved blocker", func(t *testing.T) {
		alloc, err := NewAllocator([]FlashRegion{
			{Type: "writable", Base: 0x0000, SectorSize: 16384, Count: 1},
			{Type: "reserved", Base: 0x2000, Size: 0x2000}, // blocks second half of 16 KB sector!
			{Type: "writable", Base: 0x4000, SectorSize: 4096, Count: 4},
		})
		if err != nil {
			t.Fatal(err)
		}
		addr, size, err := alloc.AllocateSector("WAL 0", 0)
		if err != nil || addr != 0x4000 || size != 4096 {
			t.Fatalf("HIGH-54: expected single 4 KB sector at 0x4000, got addr=0x%X size=%d err=%v", addr, size, err)
		}
	})

	t.Run("HIGH-58 arena auto-scales for multi-MB slots and HIGH-60 Harvard RAM-exec _sidata", func(t *testing.T) {
		ctx := testContext(t)
		ctx.Device.Partitions.AppSize = 2 << 20 // 2 MiB -> 512 chunks * 32 = 16384 + 1600 = 17984
		ctx.Hardware.Flash.Size = 8 << 20
		ctx.Hardware.Flash.Regions[1].Count = 1900
		cfg, layout := testLayout(t, ctx)
		arena, err := resolveCryptoArenaSize(ctx.Device, ctx.Hardware, cfg, layout)
		if err != nil || arena < 17984 {
			t.Fatalf("expected arena >= 17984 for 2 MiB slot, got %d (err=%v)", arena, err)
		}

		// Harvard RAM-exec: flat uses LOADADDR(.data), segmented uses ADDR(.data).
		hwFlat := testHardware(t)
		hwFlat.Flash.Stage0ExecMode = "ram"
		hwFlat.Memory.IramBase = "0x40380000"
		hwFlat.Memory.IramSize = "0x20000"
		hwFlat.Memory.SramBase = "0x3FC80000"
		hwFlat.Memory.SramSize = "0x40000"
		hwFlat.BootromImage = &BootromImageSpec{Layout: "flat"}
		flatLD, err := renderStage0LD(hwFlat).finish()
		if err != nil || !strings.Contains(string(flatLD), "_sidata = LOADADDR(.data);") {
			t.Fatalf("expected _sidata = LOADADDR(.data) for flat Harvard RAM-exec, got:\n%s (err=%v)", flatLD, err)
		}

		hwSeg := *hwFlat
		hwSeg.BootromImage = &BootromImageSpec{Layout: "segmented"}
		segLD, err := renderStage0LD(&hwSeg).finish()
		if err != nil || !strings.Contains(string(segLD), "_sidata = ADDR(.data);") {
			t.Fatalf("expected _sidata = ADDR(.data) for segmented Harvard RAM-exec, got:\n%s (err=%v)", segLD, err)
		}
	})

	t.Run("MED-39, MED-41, MED-44, MED-46, MED-47 hardening checks", func(t *testing.T) {
		// MED-39: Windows reserved device names and trailing dots rejected.
		for _, bad := range []string{"CON", "prn", "COM1.c", "LPT9.h", "bad."} {
			if err := ValidateName("test", bad); err == nil {
				t.Errorf("ValidateName must reject %q", bad)
			}
		}

		// MED-41: Case-insensitive duplicate JSON keys rejected.
		if _, err := decodeJSONBytes[CryptoFootprint]("dup.json", []byte(`{"flash_bytes": 1024, "Flash_Bytes": 2048}`), true); err == nil {
			t.Fatal("expected case-folded duplicate JSON key to be rejected")
		}

		// MED-44: #if 0, #include <...>, ASM ; comment, and standalone #ifndef/#define fallback guard do NOT satisfy macro audit.
		srcDir := t.TempDir()
		outDir := filepath.Join(t.TempDir(), "out")
		writeTempFile(t, srcDir, "tricky.c", strings.Join([]string{
			"#include <CHIP_FAKE_HEADER.h>",
			"#if 0",
			"uint32_t dead = CHIP_DEAD_IF0;",
			"#endif",
			"#ifndef CHIP_FALLBACK_ONLY",
			"#define CHIP_FALLBACK_ONLY 1U",
			"#endif",
			"uint32_t live = CHIP_ACTUALLY_USED;",
		}, "\n")+"\n")
		writeTempFile(t, srcDir, "tricky.S", "    ; CHIP_ASM_COMMENT\n    @ CHIP_ARM_COMMENT\n")

		for _, unconsumed := range []string{"CHIP_FAKE_HEADER", "CHIP_DEAD_IF0", "CHIP_FALLBACK_ONLY", "CHIP_ASM_COMMENT", "CHIP_ARM_COMMENT"} {
			if err := auditMacroUsage([]string{unconsumed}, []string{srcDir}, outDir); err == nil {
				t.Errorf("MED-44: %s must NOT satisfy macro audit", unconsumed)
			}
		}
		if err := auditMacroUsage([]string{"CHIP_ACTUALLY_USED"}, []string{srcDir}, outDir); err != nil {
			t.Errorf("CHIP_ACTUALLY_USED should pass macro audit: %v", err)
		}

		// MED-46: usableRAMWindow trims both bottom and top reserved RAM regions.
		uBase, uLen, err := usableRAMWindow(0x20000000, 0x10000, []ReservedRamRegion{
			{Name: "rom_head", Base: "0x20000000", Size: 0x1000},
			{Name: "rom_tail", Base: "0x2000F000", Size: 0x1000},
		})
		if err != nil || uBase != 0x20001000 || uLen != 0xE000 {
			t.Fatalf("expected trimmed RAM [0x20001000, +0xE000), got base=0x%X len=0x%X err=%v", uBase, uLen, err)
		}

		// MED-47: renderResetCauses sorts crash ahead of 0-valued power reset.
		rcSrc, err := renderResetCauses(&ResetCauses{
			Codes: []ResetCauseCode{
				{Name: "por_zero", Value: 0, Class: "power"},
				{Name: "wdt_crash", Value: 2, Mask: 2, Class: "crash"},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		rcBytes, err := rcSrc.finish()
		if err != nil {
			t.Fatal(err)
		}
		rcText := string(rcBytes)
		if strings.Index(rcText, "wdt_crash") > strings.Index(rcText, "por_zero") {
			t.Errorf("expected crash reset cause ordered before 0-valued POR:\n%s", rcText)
		}
	})
}
