package build

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestParseU32Literal(t *testing.T) {
	valid := map[string]uint32{"0": 0, "4096": 4096, "0x1F": 0x1F, "0XFF": 0xFF, "0x0410": 0x410, "0xFFFFFFFF": 0xFFFFFFFF}
	for raw, want := range valid {
		if got, err := parseU32Literal(raw); err != nil || got != want {
			t.Errorf("parseU32Literal(%q) = %d, %v; want %d", raw, got, err, want)
		}
	}
	for _, raw := range []string{"", "0x", "0410", "-1", "+1", "0x1_0", "0b101", "0o17", "4294967296", "0x100000000", " 1", "0xG"} {
		if _, err := parseU32Literal(raw); err == nil {
			t.Errorf("parseU32Literal(%q) must fail", raw)
		}
	}
	if got, err := cU32Literal("0x1F"); err != nil || got != "0x1FU" {
		t.Errorf("cU32Literal must preserve notation, got %q (%v)", got, err)
	}
}

func TestCUnsigned(t *testing.T) {
	valid := []struct {
		in   any
		want string
	}{
		{float64(160000000), "160000000U"},
		{float64(0), "0U"},
		{int64(5), "5U"},
		{"0x10", "0x10U"},
	}
	for _, c := range valid {
		if got, err := cUnsigned(c.in); err != nil || got != c.want {
			t.Errorf("cUnsigned(%v) = %q, %v; want %q", c.in, got, err, c.want)
		}
	}
	for _, in := range []any{1.5, -1.0, 4294967296.0, int64(-1), int64(1) << 33, true, nil, "0x1_0"} {
		if _, err := cUnsigned(in); err == nil {
			t.Errorf("cUnsigned(%v) must fail", in)
		}
	}
}

func TestCSource(t *testing.T) {
	s := newCHeader("TEST_H")
	s.define("CHIP_A", "1U")
	s.defineList("TOOB_LIST", []string{"1U", "2U"})
	data, err := s.finish()
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{generatedBanner, "#ifndef TEST_H", "#define CHIP_A", "    1U, \\\n    2U \\\n}", "#endif /* TEST_H */"} {
		if !strings.Contains(text, want) {
			t.Errorf("rendered header missing %q:\n%s", want, text)
		}
	}
	if !slices.Equal(s.defines, []string{"CHIP_A", "TOOB_LIST"}) {
		t.Errorf("unexpected recorded defines %v", s.defines)
	}

	bad := newCFile()
	bad.define("CHIP_BAD-NAME", "1U")
	bad.define("ANOTHER BAD", "1U")
	if _, err := bad.finish(); err == nil || !strings.Contains(err.Error(), "CHIP_BAD-NAME") {
		t.Errorf("expected sticky error naming the first invalid macro, got %v", err)
	}

	dup := newCFile()
	dup.define("CHIP_A", "1U")
	dup.define("CHIP_A", "2U")
	if _, err := dup.finish(); err == nil || !strings.Contains(err.Error(), "CHIP_A is defined more than once") {
		t.Errorf("expected a duplicate macro error, got %v", err)
	}
}

func testLayout(t *testing.T, ctx *Context) (*ResolvedConfig, *PartitionLayout) {
	t.Helper()
	cfg, err := resolveConfig(ctx)
	if err != nil {
		t.Fatalf("resolveConfig: %v", err)
	}
	layout, err := planLayout(ctx.Device, ctx.Hardware, cfg)
	if err != nil {
		t.Fatalf("planLayout: %v", err)
	}
	return cfg, layout
}

func TestRegionsCoverEveryPartition(t *testing.T) {
	_, layout := testLayout(t, testContext(t))

	published := make(map[string]bool)
	for _, r := range layout.regions() {
		published[r.slot.Name] = true
	}
	v := reflect.ValueOf(*layout)
	for i := range v.NumField() {
		if slot, ok := v.Field(i).Interface().(PartitionSlot); ok && !published[slot.Name] {
			t.Errorf("PartitionLayout.%s (%q) is not published by regions()", v.Type().Field(i).Name, slot.Name)
		}
	}
}

func TestPlanLayout(t *testing.T) {
	ctx := testContext(t)
	_, layout := testLayout(t, ctx)

	if layout.Stage0.Addr != 0x40000 {
		t.Errorf("Stage 0 must start behind the reserved ROM region, got 0x%X", layout.Stage0.Addr)
	}
	if layout.App.Addr%layout.MaxSectorSize != 0 || layout.Scratch.Budget != 0 {
		t.Errorf("unexpected app/scratch placement: app=0x%X scratch=%d", layout.App.Addr, layout.Scratch.Budget)
	}
	if len(layout.WalSectors) != 4 || layout.Wal.Budget != 4*4096 || layout.Wal.Addr != layout.WalSectors[0].Addr {
		t.Errorf("unexpected WAL layout: %+v / %+v", layout.Wal, layout.WalSectors)
	}
	if layout.KDM.Budget != 3*layout.MaxSectorSize || layout.Mailbox.Budget != 2*layout.MaxSectorSize {
		t.Errorf("unexpected fixed partition sizes: kdm=%d mailbox=%d", layout.KDM.Budget, layout.Mailbox.Budget)
	}
	if len(layout.Reserved) != 1 || layout.Reserved[0].Kind != SlotReserved || layout.Reserved[0].Name != "Hardware Reserved" {
		t.Errorf("unexpected reserved slots %+v", layout.Reserved)
	}
	if len(layout.Gaps) == 0 || layout.Gaps[0].Partition != "Stage 0" {
		t.Errorf("expected the reserved-ROM skip to be reported as a gap, got %+v", layout.Gaps)
	}

	ctx.Device.BootConfig.TransportProvider = "swapscratch"
	ctx.Device.Partitions.ScratchSize = 0
	ctx.Chip.SlotCapabilities.HasScratch = true
	_, layout = testLayout(t, ctx)
	if layout.Scratch.Budget != 4*layout.MaxSectorSize {
		t.Errorf("default swapscratch scratch must be bounded to 4*maxSectorSize, got %d vs %d", layout.Scratch.Budget, 4*layout.MaxSectorSize)
	}

	// HIGH-17: oneway with slot_count >= 2 + backup_mode == "full" uses the 2nd slot without forcing a 3rd AppSize scratch slot.
	ctxOneway := testContext(t)
	ctxOneway.Chip.SlotCapabilities.ExecModel = "fixed"
	ctxOneway.Chip.SlotCapabilities.SlotCount = 2
	_, layoutOneway := testLayout(t, ctxOneway)
	if layoutOneway.Scratch.Budget != 0 || layoutOneway.Staging.Budget == 0 {
		t.Errorf("expected 2-slot oneway full backup to use Staging without 3rd Scratch slot, got staging=%d scratch=%d",
			layoutOneway.Staging.Budget, layoutOneway.Scratch.Budget)
	}

	// HIGH-17: explicit ScratchSize > 0 must always allocate scratch even when needsScratch == false.
	ctxExplicitScratch := testContext(t)
	ctxExplicitScratch.Device.Partitions.ScratchSize = 8192
	_, layoutExplicitScratch := testLayout(t, ctxExplicitScratch)
	if layoutExplicitScratch.Scratch.Budget != 8192 {
		t.Errorf("expected explicit ScratchSize=8192 to allocate scratch even for pointer transport, got %d", layoutExplicitScratch.Scratch.Budget)
	}

	ctx = testContext(t)
	ctx.Device.Partitions.AppSize = 4 << 20
	cfg, err := resolveConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := planLayout(ctx.Device, ctx.Hardware, cfg); err == nil {
		t.Error("expected an oversized layout to fail")
	}
}

func TestPlanWalRequiresContiguousSectors(t *testing.T) {
	alloc, err := NewAllocator([]FlashRegion{
		{Type: "writable", Base: 0, SectorSize: 4096, Count: 16},
		{Type: "reserved", Base: 0x2000, Size: 0x1000},
	})
	if err != nil {
		t.Fatal(err)
	}
	l := &PartitionLayout{}
	if err := planWal(alloc, l, 4); err == nil || !strings.Contains(err.Error(), "contiguous") {
		t.Fatalf("expected contiguity error, got %v", err)
	}
}

func TestRenderBootLayoutAndAsserts(t *testing.T) {
	ctx := testContext(t)
	cfg, layout := testLayout(t, ctx)

	data, err := renderBootLayout(layout).finish()
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{
		"CHIP_WAL_SECTOR_3_ADDR",
		"CHIP_MAILBOX_SLOT_SIZE",
		hex32(layout.Mailbox.Budget / 2),
		"CHIP_FORENSIC_SLOT_SIZE",
		"CHIP_FLASH_IMMUTABLE_BOOT_END",
		hex32(layout.Stage0.Addr + layout.Stage0.Budget),
	} {
		if !strings.Contains(text, want) {
			t.Errorf("boot_layout.h missing %q", want)
		}
	}

	noStage0 := *layout
	noStage0.Stage0 = PartitionSlot{}
	noStage0Data, err := renderBootLayout(&noStage0).finish()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(noStage0Data), hex32(uint32(noStage0.FlashBase))) {
		t.Errorf("expected CHIP_FLASH_IMMUTABLE_BOOT_END to fall back to FlashBase when Stage0.Budget == 0:\n%s", noStage0Data)
	}

	data, err = renderLayoutAsserts(cfg, ctx.Hardware, layout).finish()
	if err != nil {
		t.Fatal(err)
	}
	assertText := string(data)
	n := len(layout.regions())
	if got := strings.Count(assertText, "BOOT_CHECK_DISJOINT(CHIP_"); got != n*(n-1)/2 {
		t.Errorf("expected %d pairwise disjointness asserts, got %d", n*(n-1)/2, got)
	}
	if got := strings.Count(assertText, "address range wraps around"); got != n {
		t.Errorf("expected %d wrap-around asserts, got %d", n, got)
	}
	if !strings.Contains(assertText, "((uint64_t)CHIP_STAGE0_ABS_ADDR + (uint64_t)CHIP_STAGE0_SIZE)") {
		t.Errorf("expected uint64_t wrap-around casts in boot_layout_assert.h")
	}
	if !strings.Contains(assertText, "((uint64_t)CHIP_FLASH_IMMUTABLE_BOOT_END) >= ((uint64_t)CHIP_STAGE0_ABS_ADDR + (uint64_t)CHIP_STAGE0_SIZE)") {
		t.Errorf("expected CHIP_FLASH_IMMUTABLE_BOOT_END static assert in boot_layout_assert.h:\n%s", assertText)
	}

	// ARCH-T04: swapscratch emits CHIP_SCRATCH_SLOT_SIZE >= CHIP_FLASH_MAX_SECTOR_SIZE assert.
	ctxSwap := testContext(t)
	ctxSwap.Device.BootConfig.TransportProvider = "swapscratch"
	ctxSwap.Chip.SlotCapabilities.HasScratch = true
	cfgSwap, layoutSwap := testLayout(t, ctxSwap)
	swapAsserts, err := renderLayoutAsserts(cfgSwap, ctxSwap.Hardware, layoutSwap).finish()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(swapAsserts), "ARCH-T04: scratch_size must be >= max_sector_size for swapscratch") {
		t.Errorf("expected ARCH-T04 static assert for swapscratch:\n%s", swapAsserts)
	}
}

func TestRenderBootConfig(t *testing.T) {
	render := func(t *testing.T, ctx *Context) (string, error) {
		t.Helper()
		cfg, err := resolveConfig(ctx)
		if err != nil {
			return "", err
		}
		layout, err := planLayout(ctx.Device, ctx.Hardware, cfg)
		if err != nil {
			return "", err
		}
		src, err := renderBootConfig(ctx, cfg, layout)
		if err != nil {
			return "", err
		}
		data, err := src.finish()
		return string(data), err
	}

	t.Run("pointer", func(t *testing.T) {
		ctx := testContext(t)
		ctx.Device.DriverConfig = map[string]any{"uart_baudrate": int64(115200), "use_dma": true, "clock_src": "CLK_XTAL"}
		text, err := render(t, ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{
			"TOOB_TRANSPORT_POINTER", "CHIP_REG_SYSTIMER_BASE", "CHIP_FLASH_ERASED_BYTE", "255U",
			"TOOB_DRIVER_UART_BAUDRATE", "115200U", "CLK_XTAL", "CHIP_RST_BROWNOUT", "CHIP_LP_RAM_BASE",
			"(CHIP_REG_TIMG0_WDT_BASE + 0x48U)", "STORAGE SUMMARY",
			"TOOB_DEVICE_PRODUCT_ID", "0x0042U", "TOOB_DEVICE_VENDOR_ID", "0x0001U", "TOOB_DEVICE_HW_REV",
			"#ifdef CHIP_REG_CONFIRM_STORAGE_BASE", "ADDR_CONFIRM_RTC_RAM",
			"#define TOOB_FEATURE_CLOUD_COMMANDS              1",
			"#define TOOB_FEATURE_UART_PROVISIONING           1",
			"#define TOOB_FEATURE_MULTIIMAGE                  1",
			"#define TOOB_FEATURE_DELTA                       1",
			"#define TOOB_FEATURE_DECOMP                      1",
		} {
			if !strings.Contains(text, want) {
				t.Errorf("generated_boot_config.h missing %q", want)
			}
		}
		for _, banned := range []string{"#define REG_TIMG0_WDT_CONFIG0", "#define REG_LP_WDT_FEED", "#define REG_RESET_CAUSE"} {
			if strings.Contains(text, banned) {
				t.Errorf("HIGH-14: generated_boot_config.h must not hardcode ESP register alias %q", banned)
			}
		}
		if strings.Contains(text, "TOOB_ONEWAY_BACKUP_MODE") {
			t.Error("backup mode must only be emitted for the oneway transport")
		}
	})

	t.Run("oneway", func(t *testing.T) {
		ctx := testContext(t)
		ctx.Device.BootConfig.TransportProvider = "oneway"
		text, err := render(t, ctx)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(text, "TOOB_ONEWAY_BACKUP_FULL") {
			t.Error("expected the full backup macro for the oneway transport")
		}
	})

	t.Run("legacy registers", func(t *testing.T) {
		ctx := testContext(t)
		ctx.Hardware.Registers = map[string]any{"rng_data_reg": "0x60026000", "systimer_base": float64(0x6000A000)}
		text, err := render(t, ctx)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(text, "deprecated") {
			t.Error("legacy registers must be ignored while register_blocks/registers_flat exist")
		}

		ctx.Hardware.RegisterBlocks, ctx.Hardware.RegistersFlat = nil, nil
		ctx.Hardware.ResetCauses = nil // its aliases reference register blocks
		text, err = render(t, ctx)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(text, "deprecated") || !strings.Contains(text, "1610653696U") {
			t.Errorf("expected the legacy register section, got:\n%s", text)
		}
	})

	failures := []struct {
		name    string
		mutate  func(*Context)
		wantErr string
	}{
		{"float driver config", func(c *Context) { c.Device.DriverConfig = map[string]any{"ratio": 1.5} }, "driver_config.ratio"},
		{"multi-line driver config", func(c *Context) { c.Device.DriverConfig = map[string]any{"x": "A\nB"} }, "single-line"},
		{"empty driver config string", func(c *Context) { c.Device.DriverConfig = map[string]any{"x": ""} }, "non-empty"},
		{"block comment in driver config", func(c *Context) { c.Device.DriverConfig = map[string]any{"x": "A /* B"} }, "comment delimiters"},
		{"line comment in driver config", func(c *Context) { c.Device.DriverConfig = map[string]any{"x": "A // B"} }, "comment delimiters"},
		{"line continuation in driver config", func(c *Context) { c.Device.DriverConfig = map[string]any{"x": `A \`} }, "single-line"},
		{"colliding register names", func(c *Context) {
			block := RegisterBlock{Base: "0x60000000", Regs: map[string]string{}}
			c.Hardware.RegisterBlocks["uart"], c.Hardware.RegisterBlocks["UART"] = block, block
		}, "CHIP_REG_UART_BASE is defined more than once"},
		{"invalid driver config key", func(c *Context) { c.Device.DriverConfig = map[string]any{"bad-key": int64(1)} }, "TOOB_DRIVER_BAD-KEY"},
		{"bool constant", func(c *Context) { c.Hardware.Constants["flag"] = true }, "constants.flag"},
		{"register literal", func(c *Context) { c.Hardware.RegistersFlat["rng_data_reg"] = "0x6002_6000" }, "registers_flat.rng_data_reg"},
		{"register offset", func(c *Context) {
			c.Hardware.RegisterBlocks["uart0"] = RegisterBlock{Base: "0x60000000", Regs: map[string]string{"fifo": "16x"}}
		}, "regs.fifo"},
		{"crypto backend quote", func(c *Context) { c.Device.Crypto.Backend = `mono"cypher` }, "crypto.backend"},
		{"lp ram size missing", func(c *Context) { c.Hardware.Memory.LpRamSize = "" }, "memory.lp_ram_size"},
		{"reset mask", func(c *Context) { c.Hardware.ResetCauses.Mask = "mask" }, "reset_causes.mask"},
		{"arena override too small", func(c *Context) { c.Device.BootConfig.CryptoArenaSize = 1024 }, "crypto_arena_size"},
		{"arena override unaligned", func(c *Context) { c.Device.BootConfig.CryptoArenaSize = 4100 }, "crypto_arena_size"},
		{"reverse_delta with delta disabled", func(c *Context) {
			f := false
			c.Device.BootConfig.TransportProvider = "oneway"
			c.Device.BootConfig.BackupMode = "reverse_delta"
			c.Device.Features.Delta = &f
		}, "requires features.delta = true"},
	}
	for _, f := range failures {
		t.Run(f.name, func(t *testing.T) {
			ctx := testContext(t)
			f.mutate(ctx)
			if _, err := render(t, ctx); err == nil || !strings.Contains(err.Error(), f.wantErr) {
				t.Fatalf("expected error containing %q, got %v", f.wantErr, err)
			}
		})
	}

	t.Run("arena auto-sizing and feature flags", func(t *testing.T) {
		ctxSmall := testContext(t)
		ctxSmall.Hardware.CryptoCapabilities.ArenaSize = 8192
		ctxSmall.Device.Partitions.AppSize = 65536
		textSmall, err := render(t, ctxSmall)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(textSmall, "#define BOOT_CRYPTO_ARENA_SIZE                   4096U") {
			t.Errorf("expected 4096U arena for 64KB non-PQC app, got:\n%s", textSmall)
		}

		ctxLarge := testContext(t)
		ctxLarge.Hardware.CryptoCapabilities.ArenaSize = 8192
		ctxLarge.Device.Partitions.AppSize = 512 * 1024
		textLarge, err := render(t, ctxLarge)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(textLarge, "#define BOOT_CRYPTO_ARENA_SIZE                   8192U") {
			t.Errorf("expected 8192U arena for 512KB app, got:\n%s", textLarge)
		}

		ctxOverride := testContext(t)
		ctxOverride.Device.Partitions.AppSize = 65536
		ctxOverride.Device.BootConfig.CryptoArenaSize = 6144
		f := false
		ctxOverride.Device.Features.CloudCommands = &f
		ctxOverride.Device.Features.UartProvisioning = &f
		ctxOverride.Device.Features.MultiImage = &f
		ctxOverride.Device.Features.Delta = &f
		ctxOverride.Device.Features.Compression = &f
		textOverride, err := render(t, ctxOverride)
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{
			"#define BOOT_CRYPTO_ARENA_SIZE                   6144U",
			"#define TOOB_FEATURE_CLOUD_COMMANDS              0",
			"#define TOOB_FEATURE_UART_PROVISIONING           0",
			"#define TOOB_FEATURE_MULTIIMAGE                  0",
			"#define TOOB_FEATURE_DELTA                       0",
			"#define TOOB_FEATURE_DECOMP                      0",
		} {
			if !strings.Contains(textOverride, want) {
				t.Errorf("missing %q in:\n%s", want, textOverride)
			}
		}
	})
}

func TestRenderResetCauses(t *testing.T) {
	rc := testHardware(t).ResetCauses
	src, err := renderResetCauses(rc)
	if err != nil {
		t.Fatal(err)
	}
	data, err := src.finish()
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, "uint32_t hw_code") || !strings.Contains(text, "/* brownout */") || !strings.Contains(text, "CHIP_RST_CLASS_CRASH") {
		t.Errorf("reset table missing uint32_t hw_code or classified brownout entry:\n%s", data)
	}

	// CRIT-21: 32-bit hex bitmask priority evaluation.
	var bitmaskRC ResetCauses
	raw := `{
		"codes": [
			{"name": "bor", "value": "0x02000000", "mask": "0x02000000", "class": "crash"},
			{"name": "iwdg", "value": "0x20000000", "mask": "0x20000000", "class": "crash"},
			{"name": "por", "value": "0x08000000", "mask": "0x08000000", "class": "power"}
		]
	}`
	if uErr := json.Unmarshal([]byte(raw), &bitmaskRC); uErr != nil {
		t.Fatalf("unmarshal 32-bit bitmask reset causes failed: %v", uErr)
	}
	bmSrc, err := renderResetCauses(&bitmaskRC)
	if err != nil {
		t.Fatal(err)
	}
	bmData, err := bmSrc.finish()
	if err != nil {
		t.Fatal(err)
	}
	bmText := string(bmData)
	for _, want := range []string{"0x02000000U, 0x02000000U", "(hw_code & mask) == CHIP_RESET_CAUSE_TABLE[i].hw_code"} {
		if !strings.Contains(bmText, want) {
			t.Errorf("32-bit bitmask reset cause output missing %q:\n%s", want, bmText)
		}
	}

	rc.Codes[0].Class = "watchdog"
	if _, err := renderResetCauses(rc); err == nil || !strings.Contains(err.Error(), "unknown class 'watchdog'") {
		t.Errorf("expected unknown class error, got %v", err)
	}
}

func TestRenderPlatformWiring(t *testing.T) {
	t.Run("standard v3 declarative wiring", func(t *testing.T) {
		ctx := testContext(t)
		ctx.Hardware.Flash.EraseTimeUsMax = 55000
		ctx.Hardware.Flash.WriteTimeUsPage = 950
		data, required, err := renderPlatformWiring(ctx)
		if err != nil {
			t.Fatal(err)
		}
		code := string(data)
		for _, want := range []string{
			`#include "chip_config.h"`,
			`#include "generated_boot_config.h"`,
			`#include "boot_hal.h"`,
			`#include "boot_panic.h"`,
			`#include "boot_platform_bringup.h"`,
			`#include "arch_riscv.h"`,
			`#include "drivers/flash/tc_flash.h"`,
			`#include "drivers/keystore/tc_keystore.h"`,
			`#include "drivers/entropy/tc_entropy.h"`,
			`#include "drivers/slot/tc_slot/tc_slot.h"`,
			"#if !defined(TOOB_RECOVERY_CRYPTO_NONE) && !defined(TOOB_RECOVERY_CRYPTO_ROM)\n#include \"crypto_monocypher.h\"\n#endif",
			"#if !defined(TOOB_RECOVERY_HASH_NONE)\n#include \"crypto_sha256.h\"\n#endif",
			"static const flash_hal_t g_platform_flash_hal = {",
			".abi_version = TOOB_HAL_ABI_V2,",
			".init = tc_flash_init,",
			".get_last_vendor_error = tc_flash_get_vendor_error,",
			".max_erase_cycles = 100000U,",
			".erase_time_us_max = 55000U,",
			".write_time_us_page = 950U,",
			"static const crypto_hal_t g_platform_crypto_hal = {",
			".abi_version = TOOB_HAL_ABI_V3,",
			"#if !defined(TOOB_RECOVERY_CRYPTO_NONE) && !defined(TOOB_RECOVERY_CRYPTO_ROM)\n    .init = crypto_monocypher_init,",
			".verify_signature = crypto_monocypher_verify_signature,",
			"#if !defined(TOOB_RECOVERY_HASH_NONE)\n    .hash_init = crypto_sha256_init,",
			".has_hw_acceleration = false,",
			"arch_riscv_timer_init(CHIP_CPU_FREQ_HZ);",
			".get_reset_reason = tc_clock_get_reset_reason,",
			"static const entropy_hal_t g_platform_entropy_hal = {",
			".random = tc_entropy_random,",
			".is_hardware_trng = true,",
			"static const keystore_hal_t g_platform_keystore_hal = {",
			".read_pubkey = tc_keystore_read_pubkey,",
			".read_monotonic_counter = tc_keystore_read_monotonic,",
			".advance_monotonic_counter = tc_keystore_advance_monotonic,",
			"static const provisioning_hal_t g_platform_provisioning_hal = {",
			".burn_pubkey = tc_keystore_burn_pubkey,",
			".write_dslc = tc_keystore_write_dslc,",
			"#if !defined(TOOB_STAGE0_BUILD) && !defined(TOOB_RECOVERY_BUILD)\n    .slot_caps = &tc_slot_caps,\n#endif",
			"#if defined(TOOB_ENABLE_ED25519_PH) && !defined(TOOB_RECOVERY_CRYPTO_NONE) && !defined(TOOB_RECOVERY_CRYPTO_ROM)\n    .verify_signature_ph = crypto_monocypher_verify_signature_ph,",
			"#if !defined(TOOB_RECOVERY_CRYPTO_NONE) && !defined(TOOB_RECOVERY_CRYPTO_ROM)\n    { BOOT_HAL_KIND_CRYPTO, true, SITE_BRINGUP_CRYPTO },\n#endif",
			"arch_riscv_disable_interrupts();",
			"return &g_platform_instance;",
		} {
			if !strings.Contains(code, want) {
				t.Errorf("wiring missing %q:\n%s", want, code)
			}
		}
		for _, banned := range []string{
			"extern ",
			"TOOB_FLASH_HAL_V2",
			"TOOB_CRYPTO_HAL_V2",
			"TOOB_CRYPTO_HAL_V3",
			"TOOB_ENTROPY_HAL_V3",
			"TOOB_KEYSTORE_HAL_V3",
			"toob_crypto_hal_",
			"g_prov_write_dslc_wrapper",
			"test_chip_",
			".verify_pqc",
		} {
			if strings.Contains(code, banned) {
				t.Errorf("wiring must not contain %q:\n%s", banned, code)
			}
		}
		if slices.Contains(required, "CHIP_REG_SYSTIMER_BASE") || !slices.Contains(required, "CHIP_CPU_FREQ_HZ") || !slices.Contains(required, "CHIP_FLASH_ERASED_BYTE") {
			t.Errorf("unexpected required macros %v", required)
		}
	})

	t.Run("pqc bound and pqc missing required symbol", func(t *testing.T) {
		ctx := testContext(t)
		ctx.Crypto[0].HasHwAcceleration = true
		ctx.Crypto = append(ctx.Crypto, &CryptoManifest{
			Name:       "ml_dsa_65",
			Version:    "0.2.0",
			AbiVersion: "v3",
			Category:   []string{"pqc"},
			Headers:    []string{"crypto_pqc.h"},
			Symbols: map[string]string{
				"verify_pqc":      "crypto_ml_dsa_65_verify_pqc",
				"is_pqc_enforced": "crypto_ml_dsa_65_is_pqc_enforced",
			},
		})
		data, _, err := renderPlatformWiring(ctx)
		if err != nil {
			t.Fatalf("pqc wiring failed: %v", err)
		}
		code := string(data)
		for _, want := range []string{
			`#include "crypto_pqc.h"`,
			".verify_pqc = crypto_ml_dsa_65_verify_pqc,",
			".is_pqc_enforced = crypto_ml_dsa_65_is_pqc_enforced,",
			".has_hw_acceleration = true,",
		} {
			if !strings.Contains(code, want) {
				t.Errorf("pqc wiring missing %q:\n%s", want, code)
			}
		}

		delete(ctx.Crypto[2].Symbols, "verify_pqc")
		if _, _, err := renderPlatformWiring(ctx); err == nil || !strings.Contains(err.Error(), "verify_pqc") {
			t.Fatalf("expected missing pqc verify_pqc error, got %v", err)
		}
	})

	t.Run("arm and custom registered arch without codegen changes", func(t *testing.T) {
		ctx := testContext(t)
		ctx.Chip.Arch = "@partner/tricore"
		ctx.Chip.Name = "tc397"
		ctx.Drivers["entropy"].IsHardwareTRNG = false
		ctx.Arch = &ArchManifest{
			Name:    "@partner/tricore",
			Version: "1.0.0",
			Headers: []string{"arch_tricore.h"},
			Symbols: map[string]string{
				"disable_interrupts": "tricore_disable_irqs",
				"timer_init":         "tricore_stm_init",
				"get_tick_ms":        "tricore_stm_tick_ms",
				"delay_ms":           "tricore_stm_delay_ms",
			},
			RequiredMacros: []string{"CHIP_CPU_FREQ_HZ", "CHIP_STM_CLK_DIV"},
		}
		data, required, err := renderPlatformWiring(ctx)
		if err != nil {
			t.Fatalf("custom arch wiring failed: %v", err)
		}
		code := string(data)
		for _, want := range []string{
			`#include "arch_tricore.h"`,
			"tricore_stm_init(CHIP_CPU_FREQ_HZ);",
			".get_tick_ms = tricore_stm_tick_ms,",
			".delay_ms = tricore_stm_delay_ms,",
			"tricore_disable_irqs();",
			".is_hardware_trng = false,",
		} {
			if !strings.Contains(code, want) {
				t.Errorf("custom arch wiring missing %q:\n%s", want, code)
			}
		}
		if !slices.Contains(required, "CHIP_STM_CLK_DIV") {
			t.Errorf("expected custom arch required_macros in %v", required)
		}
	})

	t.Run("optional console soc slot_caps and property defaults", func(t *testing.T) {
		ctx := testContext(t)
		delete(ctx.Drivers, "console")
		delete(ctx.Drivers, "slot_caps")
		ctx.Chip.SlotCapabilities = nil
		ctx.Drivers["flash"].Symbols["lock_immutable_flash"] = "tc_flash_lock_boot"
		ctx.Drivers["soc"] = &DriverManifest{
			Name:       "tc_soc",
			Trait:      "soc",
			AbiVersion: "v2",
			Headers:    []string{"drivers/soc/tc_soc.h"},
			Symbols: map[string]string{
				"init":                         "tc_soc_init",
				"deinit":                       "tc_soc_deinit",
				"assert_secondary_cores_reset": "tc_soc_reset_cores",
				"flush_bus_matrix":             "tc_soc_flush",
				"battery_level_mv":             "tc_soc_bat",
			},
		}
		ctx.Drivers["keystore"].Symbols["init"] = "tc_keystore_init"
		ctx.Drivers["entropy"].Symbols["init"] = "tc_entropy_init"
		ctx.Hardware.Constants["min_battery_mv"] = float64(3300)

		data, _, consumed, err := renderPlatformWiringWithConsumed(ctx)
		if err != nil {
			t.Fatalf("optional traits wiring failed: %v", err)
		}
		code := string(data)
		for _, want := range []string{
			".console = NULL,",
			".slot_caps = NULL,",
			".soc = &g_platform_soc_hal,",
			".min_battery_mv = CHIP_MIN_BATTERY_MV,",
			".max_erase_cycles = 100000U,",
			".erase_time_us_max = 0U,",
			".write_time_us_page = 0U,",
			".lock_immutable_flash = tc_flash_lock_boot,",
			"BOOT_HAL_KIND_SOC",
			"BOOT_HAL_KIND_KEYSTORE",
			"BOOT_HAL_KIND_ENTROPY",
		} {
			if !strings.Contains(code, want) {
				t.Errorf("wiring missing %q:\n%s", want, code)
			}
		}
		if !slices.Contains(consumed, "CHIP_MIN_BATTERY_MV") {
			t.Errorf("expected CHIP_MIN_BATTERY_MV in consumed macros, got %v", consumed)
		}
	})

	t.Run("future-proof v4 contract in temp CoreDir generates v4 C without Go changes", func(t *testing.T) {
		root := t.TempDir()
		coreDir := filepath.Join(root, "core_v4")
		v4Contract := `{
  "schema_version": 1,
  "platform_struct_type": "boot_platform_v4_t",
  "platform_init_symbol": "boot_platform_v4_init",
  "bringup_function": "boot_platform_v4_bringup",
  "bringup_step_type": "bringup_step_v4_t",
  "core_headers": ["chip_config.h", "boot_hal_v4.h"],
  "arch": {
    "required_symbols": ["disable_interrupts"],
    "base_required_macros": ["CHIP_CPU_FREQ_HZ"],
    "entry_irq_disable_symbol": "disable_interrupts"
  },
  "traits": [
    {
      "name": "telemetry",
      "platform_field": "telemetry",
      "binding_mode": "struct",
      "struct_type": "telemetry_hal_t",
      "abi_version": "v4",
      "abi_constant": "TOOB_HAL_ABI_V4",
      "optional": false,
      "instantiate_when": "driver_bound",
      "driver_traits": ["telemetry"],
      "methods": [
        { "field": "init", "source": "driver", "key": "init", "required": true },
        { "field": "emit_metric", "source": "driver", "key": "emit_metric", "required": true }
      ],
      "properties": [
        { "field": "max_queue", "source": "hardware_uint", "hw_key": "telemetry_queue", "default": "16U" }
      ]
    }
  ],
  "bringup_steps": [
    { "trait": "telemetry", "kind_enum": "BOOT_HAL_KIND_TELEMETRY", "mandatory": true, "panic_site": "SITE_BRINGUP_TELEMETRY", "condition": "init_bound" }
  ]
}`
		writeTempFile(t, coreDir, halContractFile, v4Contract)

		archDir := filepath.Join(root, "arch")
		writeJSONFile(t, filepath.Join(archDir, archManifestFile), &ArchManifest{
			Name:    "riscv32",
			Version: "1.0.0",
			Headers: []string{"arch_riscv.h"},
			Symbols: map[string]string{"disable_interrupts": "arch_riscv_disable_interrupts"},
		})
		telDir := filepath.Join(root, "drivers", "telemetry")
		writeJSONFile(t, filepath.Join(telDir, driverManifestFile), &DriverManifest{
			Name:       "vendor_telemetry",
			Trait:      "telemetry",
			AbiVersion: "v4",
			Headers:    []string{"telemetry.h"},
			Symbols: map[string]string{
				"init":        "vendor_tel_init",
				"emit_metric": "vendor_tel_emit",
			},
		})
		srcDir := filepath.Join(root, "src")
		writeTempFile(t, srcDir, "placeholder.c", "/* v4 */\n")

		ctx, err := Load(Inputs{
			Device:           testDevice(),
			HardwarePath:     writeJSONFile(t, filepath.Join(root, "chip", "hardware.json"), testHardware(t)),
			ChipManifestPath: writeJSONFile(t, filepath.Join(root, "chip", "chip_manifest.json"), testChip()),
			CoreDir:          coreDir,
			ArchDir:          archDir,
			DriverDirs:       []string{telDir},
			SourceDirs:       []string{srcDir},
			OutDir:           filepath.Join(root, "out"),
		}, NopLogger{})
		if err != nil {
			t.Fatalf("Load(v4) failed: %v", err)
		}

		data, _, err := renderPlatformWiring(ctx)
		if err != nil {
			t.Fatalf("renderPlatformWiring(v4) failed: %v", err)
		}
		code := string(data)
		for _, want := range []string{
			`#include "boot_hal_v4.h"`,
			`#include "telemetry.h"`,
			"static const telemetry_hal_t g_platform_telemetry_hal = {",
			".abi_version = TOOB_HAL_ABI_V4,",
			".init = vendor_tel_init,",
			".emit_metric = vendor_tel_emit,",
			".max_queue = 16U,",
			"static const boot_platform_v4_t g_platform_instance = {",
			".telemetry = &g_platform_telemetry_hal,",
			"{ BOOT_HAL_KIND_TELEMETRY, true, SITE_BRINGUP_TELEMETRY },",
			"const boot_platform_v4_t *boot_platform_v4_init(void)",
			"(void)boot_platform_v4_bringup(&g_platform_instance, g_bringup_steps,",
		} {
			if !strings.Contains(code, want) {
				t.Errorf("v4 wiring missing %q:\n%s", want, code)
			}
		}
	})

	failures := []struct {
		name    string
		mutate  func(*Context)
		wantErr []string
	}{
		{"missing symbols", func(c *Context) {
			delete(c.Drivers["console"].Symbols, "init")
			delete(c.Drivers["console"].Symbols, "flush")
			delete(c.Drivers["flash"].Symbols, "read")
		}, []string{"console.init", "console.flush", "flash.read"}},
		{"invalid symbol", func(c *Context) { c.Drivers["wdt"].Symbols["kick"] = "bad-name" }, []string{"invalid C identifiers", "wdt.kick"}},
		{"slot caps without symbol", func(c *Context) { c.Drivers["slot_caps"].Symbols = nil }, []string{"slot_caps"}},
		{"missing driver headers", func(c *Context) { c.Drivers["flash"].Headers = nil }, []string{"at least one header"}},
		{"missing crypto headers", func(c *Context) { c.Crypto[0].Headers = nil }, []string{"at least one header"}},
		{"missing crypto manifests", func(c *Context) { c.Crypto = nil }, []string{"crypto[backend].init", "crypto[hash].hash_init"}},
		{"driver abi mismatch v2 on v3 trait", func(c *Context) { c.Drivers["keystore"].AbiVersion = "v2" }, []string{"abi_version", "v2", "v3"}},
		{"crypto abi mismatch v2 on v3 trait", func(c *Context) { c.Crypto[0].AbiVersion = "v2" }, []string{"abi_version", "v2", "v3"}},
		{"missing keystore driver", func(c *Context) { delete(c.Drivers, "keystore") }, []string{"driver:keystore"}},
		{"missing entropy driver", func(c *Context) { delete(c.Drivers, "entropy") }, []string{"driver:entropy"}},
		{"soc driver with zero methods", func(c *Context) {
			c.Drivers["soc"] = &DriverManifest{Name: "empty_soc", Trait: "soc", AbiVersion: "v2", Headers: []string{"soc.h"}}
		}, []string{"at least one method"}},
		{"invalid header", func(c *Context) { c.Drivers["slot_caps"].Headers = []string{`evil".h`} }, []string{"invalid header path"}},
		{"no chip manifest", func(c *Context) { c.Chip = nil }, []string{"requires a chip manifest"}},
		{"missing arch manifest", func(c *Context) { c.Arch = nil }, []string{"missing arch_manifest.json", "riscv32"}},
		{"mismatched arch manifest", func(c *Context) { c.Chip.Arch = "mips" }, []string{"does not match", "mips"}},
		{"empty arch", func(c *Context) { c.Chip.Arch = "" }, []string{"'arch' must not be empty"}},
		{"arch without headers", func(c *Context) { c.Arch.Headers = nil }, []string{"at least one header"}},
		{"arch missing symbol", func(c *Context) { delete(c.Arch.Symbols, "timer_init") }, []string{"arch.timer_init"}},
		{"arch invalid symbol", func(c *Context) { c.Arch.Symbols["delay_ms"] = "bad-sym" }, []string{"invalid C identifiers", "arch.delay_ms"}},
	}
	for _, f := range failures {
		t.Run(f.name, func(t *testing.T) {
			ctx := testContext(t)
			f.mutate(ctx)
			_, _, err := renderPlatformWiring(ctx)
			if err == nil {
				t.Fatal("expected an error")
			}
			for _, want := range f.wantErr {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("expected %q in error %v", want, err)
				}
			}
		})
	}
}

func TestCryptoFootprintUnmarshal(t *testing.T) {
	var fpEst CryptoFootprint
	if err := json.Unmarshal([]byte(`{"flash_estimate_bytes": 28000, "ram_estimate_bytes": 128}`), &fpEst); err != nil {
		t.Fatalf("unexpected error for estimate keys: %v", err)
	}
	if fpEst.FlashBytes != 28000 || fpEst.RamBytes != 128 {
		t.Fatalf("unexpected footprint %+v", fpEst)
	}

	var fpCanonical CryptoFootprint
	if err := json.Unmarshal([]byte(`{"flash_bytes": 4096, "ram_bytes": 64}`), &fpCanonical); err != nil {
		t.Fatalf("unexpected error for canonical keys: %v", err)
	}
	if fpCanonical.FlashBytes != 4096 || fpCanonical.RamBytes != 64 {
		t.Fatalf("unexpected footprint %+v", fpCanonical)
	}

	var fpBad CryptoFootprint
	if err := json.Unmarshal([]byte(`{"flash_bytes": 4096, "flash_estimate_bytes": 8192}`), &fpBad); err == nil {
		t.Fatal("expected conflicting flash footprint fields to fail")
	}
}

func TestForEachIdentifier(t *testing.T) {
	has := func(text, ident string) bool {
		found := false
		forEachIdentifier([]byte(text), func(id []byte) { found = found || string(id) == ident })
		return found
	}
	cases := []struct {
		text, ident string
		want        bool
	}{
		{"#define CHIP_FLASH_SIZE 1024", "CHIP_FLASH_SIZE", true},
		{"uint32_t x = CHIP_FLASH_SIZE;", "CHIP_FLASH_SIZE", true},
		{"/* CHIP_FLASH_SIZE_MAX */", "CHIP_FLASH_SIZE", false},
		{"MY_CHIP_FLASH_SIZE = 1", "CHIP_FLASH_SIZE", false},
		{"(CHIP_FLASH_SIZE)", "CHIP_FLASH_SIZE", true},
		{"CHIP_FLASH_SIZE", "CHIP_FLASH_SIZE", true},
		{"0x1FCHIP_A", "CHIP_A", false},
		{"10UCHIP_A + CHIP_B", "CHIP_B", true},
		{"nothing here", "CHIP_FLASH_SIZE", false},
		{"// CHIP_A\nCHIP_B", "CHIP_A", false},
		{"// CHIP_A\nCHIP_B", "CHIP_B", true},
		{"// note \\\n CHIP_A\nCHIP_B", "CHIP_A", false},
		{"// note \\\r\n CHIP_A\r\nCHIP_B", "CHIP_A", false},
		{"// note\r\nCHIP_A", "CHIP_A", true},
		{"// last line CHIP_A", "CHIP_A", false},
		{"/* a\n CHIP_A */ CHIP_B", "CHIP_A", false},
		{"/* a\n CHIP_A */ CHIP_B", "CHIP_B", true},
		{"/* unterminated CHIP_A", "CHIP_A", false},
		{"/* TODO CHIP_A */", "CHIP_A", false},
		{"a / b + CHIP_A", "CHIP_A", true},
		{`"CHIP_A"`, "CHIP_A", false},
		{`"say \"hi\" CHIP_A"`, "CHIP_A", false},
		{`'C' + CHIP_A`, "CHIP_A", true},
		{`'\'' CHIP_A`, "CHIP_A", true},
		{"\"open CHIP_A\nCHIP_B", "CHIP_A", false},
		{"\"open CHIP_A\nCHIP_B", "CHIP_B", true},
		{"it's CHIP_A\nCHIP_B", "CHIP_B", true},
		{"\"wrapped \\\nCHIP_A\"", "CHIP_A", false},
		{`"trailing escape \`, "CHIP_A", false},
	}
	for _, c := range cases {
		if got := has(c.text, c.ident); got != c.want {
			t.Errorf("identifier %q in %q = %v, want %v", c.ident, c.text, got, c.want)
		}
	}
}

func TestAuditMacroUsage(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "core")
	out := filepath.Join(src, "generated")
	macros := []string{"CHIP_FLASH_BASE_ADDR", "BOOT_WDT_TIMEOUT_MS"}

	writeTempFile(t, src, "main.c", "uint32_t base = CHIP_FLASH_BASE_ADDR;\n")
	writeTempFile(t, src, "notes.txt", "BOOT_WDT_TIMEOUT_MS\n") // not an audited file type
	writeTempFile(t, src, "dead.c", "// BOOT_WDT_TIMEOUT_MS\n/* BOOT_WDT_TIMEOUT_MS */\nconst char *s = \"BOOT_WDT_TIMEOUT_MS\";\n")
	writeTempFile(t, out, "self.h", "#define BOOT_WDT_TIMEOUT_MS 1U\n") // generated output is excluded

	err := auditMacroUsage(macros, []string{src}, out)
	if err == nil || !strings.Contains(err.Error(), "  - BOOT_WDT_TIMEOUT_MS") || strings.Contains(err.Error(), "  - CHIP_FLASH_BASE_ADDR") {
		t.Fatalf("expected only BOOT_WDT_TIMEOUT_MS to be reported, got %v", err)
	}

	writeTempFile(t, src, "start.S", "li t0, BOOT_WDT_TIMEOUT_MS\n")
	if err := auditMacroUsage(macros, []string{src}, out); err != nil {
		t.Fatalf("expected the upper-case .S file to satisfy the audit, got %v", err)
	}

	if err := auditMacroUsage(macros, []string{filepath.Join(root, "absent")}, out); err == nil || !strings.Contains(err.Error(), "scanning") {
		t.Errorf("expected walk errors to propagate, got %v", err)
	}

	got := auditableMacros([]string{"CHIP_A", "REG_TIMG0_WDT_FEED", "BOOT_B", "TOOB_C", "ADDR_CONFIRM_RTC_RAM"})
	if !slices.Equal(got, []string{"CHIP_A", "REG_TIMG0_WDT_FEED", "BOOT_B", "TOOB_C", "ADDR_CONFIRM_RTC_RAM"}) {
		t.Errorf("unexpected auditable macros %v", got)
	}

	// HIGH-14: defining a macro name (#define FOO 1) must not satisfy consumption, whereas
	// referencing it in another macro's expansion (#define BAR FOO) MUST satisfy consumption.
	defDir := filepath.Join(root, "defs")
	writeTempFile(t, defDir, "only_def.h", "#define CHIP_ONLY_DEFINED 1U\n")
	if err := auditMacroUsage([]string{"CHIP_ONLY_DEFINED"}, []string{defDir}, out); err == nil {
		t.Fatal("#define of the same name must not count as consuming the macro")
	}
	writeTempFile(t, defDir, "rhs_ref.h", "#define DRIVER_LOCAL_ALIAS CHIP_ONLY_DEFINED\n")
	if err := auditMacroUsage([]string{"CHIP_ONLY_DEFINED"}, []string{defDir}, out); err != nil {
		t.Fatalf("referencing macro on #define RHS must satisfy audit, got %v", err)
	}
}

func TestLinkerScriptsAnd64BitAddresses(t *testing.T) {
	ctx := testContext(t)
	ctx.Hardware.Flash.Base = 0x08000000
	ctx.Hardware.Flash.XipBase = "0x0"
	ctx.Hardware.Flash.Regions = []FlashRegion{
		{Type: "writable", Base: 0x08000000, SectorSize: 0x4000, Count: 64},
	}
	ctx.Hardware.Memory.SramBase = "0x20000000"
	ctx.Hardware.Memory.SramSize = "0x20000"
	ctx.Device.Partitions.RecoverySize = 0x10000
	ctx.Chip.Stage0ExecMode = "xip"
	ctx.Chip.EntrySymbol = "Reset_Handler"

	cfg, layout := testLayout(t, ctx)

	memLD, err := renderMemoryLD(ctx, cfg, layout).finish()
	if err != nil {
		t.Fatalf("renderMemoryLD: %v", err)
	}
	for _, want := range []string{
		"__STAGE0_ORIGIN = 0x08000000;", "__STAGE1A_ORIGIN", "__APP_SLOT_ORIGIN",
		"__RECOVERY_SLOT_ORIGIN", "__SRAM_ORIGIN = 0x20000000;",
	} {
		if !strings.Contains(string(memLD), want) {
			t.Errorf("generated_memory.ld missing %q:\n%s", want, memLD)
		}
	}

	s0LD, err := renderStage0LDForContext(ctx, ctx.Hardware).finish()
	if err != nil {
		t.Fatalf("renderStage0LDForContext: %v", err)
	}
	for _, want := range []string{
		"ENTRY(Reset_Handler)", "KEEP(*(.stage0_entry))", "KEEP(*(.isr_vector))", "KEEP(*(.vectors))",
		"_sidata = LOADADDR(.data);", "> S0_RAM AT > S0_ROM", "_sbss = .;", "_ebss = .;", "_stack_top",
	} {
		if !strings.Contains(string(s0LD), want) {
			t.Errorf("stage0_layout.ld missing %q:\n%s", want, s0LD)
		}
	}

	flashLD, err := renderFlashLD(ctx, cfg, layout).finish()
	if err != nil {
		t.Fatalf("renderFlashLD: %v", err)
	}
	if !strings.Contains(string(flashLD), "ORIGIN = __STAGE1A_ORIGIN") {
		t.Errorf("flash_layout.ld missing __STAGE1A_ORIGIN:\n%s", flashLD)
	}
	recLD, err := renderRecoveryLD(ctx, cfg, layout).finish()
	if err != nil {
		t.Fatalf("renderRecoveryLD: %v", err)
	}
	for _, want := range []string{
		"ORIGIN = __RECOVERY_SLOT_ORIGIN",
		"KEEP(*(.noinit.toob_handoff_state))",
		"KEEP(*(.noinit.toob_diag_state))",
		"KEEP(*(.noinit.toob_ota_resume_state))",
	} {
		if !strings.Contains(string(recLD), want) {
			t.Errorf("recovery_layout.ld missing %q:\n%s", want, recLD)
		}
	}

	// MED-16: 64-bit register address emits ULL while <= 32-bit stays U.
	lit64, val64, err := cAddrLiteral("0x100000000")
	if err != nil || lit64 != "0x100000000ULL" || val64 != 0x100000000 {
		t.Errorf("expected 64-bit ULL literal, got %q / 0x%X (%v)", lit64, val64, err)
	}
	lit32, _, err := cAddrLiteral("0x40000000")
	if err != nil || lit32 != "0x40000000U" {
		t.Errorf("expected 32-bit U literal, got %q (%v)", lit32, err)
	}
}

func TestRemoveStaleArtifacts(t *testing.T) {
	dir := t.TempDir()
	stale := []string{filePlatformWiring, fileResetCauses, "generated_platform_wiring.inc"}
	for _, name := range stale {
		writeTempFile(t, dir, name, "stale")
	}

	if err := removeStaleArtifacts(dir, []artifact{{fileResetCauses, nil}}); err != nil {
		t.Fatal(err)
	}
	for name, wantExists := range map[string]bool{filePlatformWiring: false, "generated_platform_wiring.inc": false, fileResetCauses: true} {
		_, err := os.Stat(filepath.Join(dir, name))
		if exists := err == nil; exists != wantExists {
			t.Errorf("%s: exists=%v, want %v", name, exists, wantExists)
		}
	}
	if err := removeStaleArtifacts(dir, nil); err != nil {
		t.Errorf("removing already-absent artifacts must succeed, got %v", err)
	}
}

func TestWriteFileAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.h")

	for _, content := range []string{"first", "second, longer content"} {
		if err := writeFileAtomic(path, []byte(content)); err != nil {
			t.Fatalf("writeFileAtomic: %v", err)
		}
		got, err := os.ReadFile(path)
		if err != nil || string(got) != content {
			t.Fatalf("expected %q, got %q (%v)", content, got, err)
		}
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 1 {
		t.Errorf("expected no leftover temporary files, got %v (%v)", entries, err)
	}

	if err := writeFileAtomic(filepath.Join(dir, "missing", "out.h"), nil); err == nil {
		t.Error("expected an error for a missing directory")
	}
}

func renderStage0LD(hw *HardwareJson) *cSource {
	return renderStage0LDForContext(nil, hw)
}

func renderPlatformWiring(ctx *Context) ([]byte, []string, error) {
	data, required, _, err := renderPlatformWiringWithConsumed(ctx)
	return data, required, err
}

func allocateLocalSectors(alloc *Allocator, slot *PartitionSlot, sectors uint32, equalSplit bool) error {
	_, err := allocateLocalSectorsWithSlots(alloc, slot, sectors, equalSplit)
	return err
}

func forEachIdentifier(src []byte, visit func(ident []byte)) {
	for i := 0; i < len(src); {
		c := src[i]
		switch {
		case isIdentStart(c):
			start := i
			for i < len(src) && isIdentPart(src[i]) {
				i++
			}
			visit(src[start:i])
		case c >= '0' && c <= '9':
			for i < len(src) && isIdentPart(src[i]) {
				i++
			}
		case c == '/' && hasPrefixAt(src, i, "//"):
			i = skipLineComment(src, i+2)
		case c == '/' && hasPrefixAt(src, i, "/*"):
			i = skipBlockComment(src, i+2)
		case c == '"' || c == '\'':
			i = skipQuoted(src, i)
		default:
			i++
		}
	}
}

func TestSecurityMacrosAndAuditPackageMacros(t *testing.T) {
	ctx := testContext(t)
	ctx.Device.Build.Profile = "production"
	cfg, layout := testLayout(t, ctx)

	src, err := renderBootConfig(ctx, cfg, layout)
	if err != nil {
		t.Fatalf("renderBootConfig: %v", err)
	}
	hdrBytes, err := src.finish()
	if err != nil {
		t.Fatalf("finish: %v", err)
	}
	hdr := string(hdrBytes)
	for _, want := range []string{
		"#define TOOB_PROFILE_PRODUCTION 1",
		"#define TOOB_DOUBLE_VERIFY 1",
		"#define TOOB_ALLOW_PUBLIC_JOURNAL_KEY_DEGRADATION 0",
		"TOOB_MOCK_TEST",
	} {
		if !strings.Contains(hdr, want) {
			t.Errorf("generated_boot_config.h missing %q:\n%s", want, hdr)
		}
	}

	// Production profile combined with mock list must fail validation.
	ctxMockProd := testContext(t)
	ctxMockProd.Device.Build.Profile = "production"
	ctxMockProd.Device.Build.Mock = []string{"flash"}
	if err := validateContext(ctxMockProd); err == nil {
		t.Fatal("expected production profile with build.mock to fail validation")
	}

	// AuditPackageMacros checks (#undef, protected macro override, header collisions).
	pkgA := filepath.Join(t.TempDir(), "pkgA")
	pkgB := filepath.Join(t.TempDir(), "pkgB")
	writeTempFile(t, pkgA, "a.h", "#ifndef PKG_A_H\n#define PKG_A_H\n#define SHARED_SYM 1\n#endif\n")
	writeTempFile(t, pkgB, "b.h", "#ifndef PKG_B_H\n#define PKG_B_H\n#define SHARED_SYM 1\n#endif\n")
	if err := AuditPackageMacros([]string{pkgA, pkgB}, nil); err == nil || !strings.Contains(err.Error(), "colliding header") {
		t.Fatalf("expected header collision error, got %v", err)
	}

	undefPkg := filepath.Join(t.TempDir(), "undefPkg")
	writeTempFile(t, undefPkg, "evil.c", "#undef BOOT_SECURE_REQUIRE\n#define BOOT_SECURE_REQUIRE(c,a)\n")
	if err := AuditPackageMacros([]string{undefPkg}, nil); err == nil || !strings.Contains(err.Error(), "#undef") {
		t.Fatalf("expected #undef error, got %v", err)
	}

	redefPkg := filepath.Join(t.TempDir(), "redefPkg")
	writeTempFile(t, redefPkg, "evil.c", "#ifndef BOOT_SECURE_REQUIRE\n#define BOOT_SECURE_REQUIRE(c,a)\n#endif\n")
	if err := AuditPackageMacros([]string{redefPkg}, nil); err == nil || !strings.Contains(err.Error(), "core security macro") {
		t.Fatalf("expected core security macro redefinition error, got %v", err)
	}
}
