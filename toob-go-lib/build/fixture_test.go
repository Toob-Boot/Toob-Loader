package build

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
)

// recordingLogger captures pipeline messages for assertions.
type recordingLogger struct {
	infos, warns []string
}

func (l *recordingLogger) Info(f string, a ...any) { l.infos = append(l.infos, fmt.Sprintf(f, a...)) }
func (l *recordingLogger) Success(string, ...any)  {}
func (l *recordingLogger) Warn(f string, a ...any) { l.warns = append(l.warns, fmt.Sprintf(f, a...)) }
func (l *recordingLogger) Step(string, ...any)     {}

func testCoreDir(t *testing.T) string {
	t.Helper()
	return filepath.Clean(filepath.Join("..", "..", "toobloader", "core"))
}

// testDevice returns a minimal valid device configuration for "test-chip".
func testDevice() *DeviceToml {
	dt := &DeviceToml{Name: "fixture-device", Version: "1.0.0"}
	dt.Device.Chip = "test-chip"
	dt.Identity.VendorID = 0x0001
	dt.Identity.ProductID = 0x0042
	dt.Identity.HwRev = 1
	dt.Partitions.Stage0Size = 16384
	dt.Partitions.Stage1Size = 65536
	dt.Partitions.AppSize = 262144
	dt.Partitions.WalSectors = 4
	dt.BootConfig.MaxRetries = 3
	dt.BootConfig.WdtTimeoutMs = 5000
	return dt
}

// testHardware extends the plausibility baseline with the macros the RISC-V
// platform wiring requires.
func testHardware(t *testing.T) *HardwareJson {
	t.Helper()
	hw := validTestHardwareJSON(t)
	hw.Constants["flash_erased_byte"] = float64(255)
	hw.RegisterBlocks["systimer"] = RegisterBlock{
		Base:       "0x6000A000",
		Regs:       map[string]string{},
		Provenance: &Provenance{Source: "trm", Ref: "Test TRM §21.4", Verified: "2026-01-15"},
	}
	return hw
}

func testChip() *ChipManifest {
	return &ChipManifest{
		Name:        "test-chip",
		Arch:        "riscv32",
		Version:     "1.0.0",
		MinCoreSDK:  "core/v0.1.0",
		MinCompiler: "14.2.0",
		SlotCapabilities: &SlotCapabilities{
			ExecModel:      "xip_remap",
			SlotCount:      2,
			MaxEraseCycles: 100000,
		},
	}
}

func testArch() *ArchManifest {
	return &ArchManifest{
		Name:    "riscv32",
		Version: "1.0.0",
		Headers: []string{"arch_riscv.h"},
		Symbols: map[string]string{
			"disable_interrupts": "arch_riscv_disable_interrupts",
			"enable_interrupts":  "arch_riscv_enable_interrupts",
			"timer_init":         "arch_riscv_timer_init",
			"get_tick_ms":        "arch_riscv_get_tick_ms",
			"delay_ms":           "arch_riscv_delay_ms",
			"trap_entry":         "arch_riscv_trap_entry",
		},
		RequiredMacros: []string{"CHIP_CPU_FREQ_HZ"},
	}
}

// testDrivers returns one complete driver per trait, keyed by trait.
func testDrivers() map[string]*DriverManifest {
	mk := func(trait, abi, header string, keys ...string) *DriverManifest {
		syms := make(map[string]string, len(keys))
		for _, k := range keys {
			syms[k] = "tc_" + trait + "_" + k
		}
		return &DriverManifest{
			Name:       "tc_" + trait,
			Trait:      trait,
			AbiVersion: abi,
			Headers:    []string{header},
			Symbols:    syms,
		}
	}
	drivers := map[string]*DriverManifest{
		"flash":    mk("flash", "v2", "drivers/flash/tc_flash.h", "init", "deinit", "read", "write", "erase_sector", "get_sector_size", "get_vendor_error"),
		"confirm":  mk("confirm", "v2", "drivers/rtc/tc_confirm.h", "init", "deinit", "check_ok", "clear"),
		"wdt":      mk("wdt", "v2", "drivers/wdt/tc_wdt.h", "init", "deinit", "kick", "suspend", "resume"),
		"clock":    mk("clock", "v2", "drivers/clock/tc_clock.h", "get_reset_reason"),
		"console":  mk("console", "v2", "drivers/uart/tc_console.h", "init", "deinit", "putchar", "getchar", "flush"),
		"keystore": mk("keystore", "v3", "drivers/keystore/tc_keystore.h", "read_pubkey", "read_chip_uid", "read_dslc", "write_dslc", "read_monotonic", "advance_monotonic", "burn_pubkey"),
	}
	ent := mk("entropy", "v3", "drivers/entropy/tc_entropy.h", "random")
	ent.IsHardwareTRNG = true
	drivers["entropy"] = ent
	drivers["slot_caps"] = &DriverManifest{
		Name:       "tc_slot",
		Trait:      "slot_caps",
		AbiVersion: "v2",
		Headers:    []string{"drivers/slot/tc_slot/tc_slot.h"},
		Symbols:    map[string]string{"slot_caps": "tc_slot_caps"},
	}
	return drivers
}

func testCrypto() []*CryptoManifest {
	return []*CryptoManifest{
		{
			Name:       "monocypher",
			Version:    "1.2.1",
			AbiVersion: "v3",
			Category:   []string{"backend"},
			Headers:    []string{"crypto_monocypher.h"},
			Symbols: map[string]string{
				"init":                "crypto_monocypher_init",
				"deinit":              "crypto_monocypher_deinit",
				"verify_signature":    "crypto_monocypher_verify_signature",
				"verify_signature_ph": "crypto_monocypher_verify_signature_ph",
			},
			Footprint: &CryptoFootprint{FlashBytes: 28000, RamBytes: 128},
		},
		{
			Name:       "sha256_sw",
			Version:    "1.1.0",
			AbiVersion: "v3",
			Category:   []string{"hash"},
			Headers:    []string{"crypto_sha256.h"},
			Symbols: map[string]string{
				"hash_init":         "crypto_sha256_init",
				"hash_update":       "crypto_sha256_update",
				"hash_finish":       "crypto_sha256_finish",
				"get_hash_ctx_size": "crypto_sha256_get_ctx_size",
			},
			Footprint: &CryptoFootprint{FlashBytes: 5600, RamBytes: 128},
		},
	}
}

// testContext builds a loaded context in memory, reading only hal_contract.json.
func testContext(t *testing.T) *Context {
	t.Helper()
	dir := t.TempDir()
	coreDir := testCoreDir(t)
	hc, err := loadHalContract(coreDir, nil)
	if err != nil {
		t.Fatalf("loadHalContract: %v", err)
	}
	return &Context{
		Inputs: Inputs{
			Device:     testDevice(),
			CoreDir:    coreDir,
			OutDir:     filepath.Join(dir, "generated"),
			SourceDirs: []string{dir},
		},
		Hardware:    testHardware(t),
		Chip:        testChip(),
		Arch:        testArch(),
		Drivers:     testDrivers(),
		Crypto:      testCrypto(),
		halContract: hc,
		Log:         NopLogger{},
	}
}

// writeFixtureInputs materializes the fixture on disk and returns Load inputs.
func writeFixtureInputs(t *testing.T, hw *HardwareJson) Inputs {
	t.Helper()
	root := t.TempDir()
	archDir := filepath.Join(root, "arch", "riscv32")
	writeJSONFile(t, filepath.Join(archDir, archManifestFile), testArch())
	in := Inputs{
		Device:           testDevice(),
		HardwarePath:     writeJSONFile(t, filepath.Join(root, "chip", "hardware.json"), hw),
		ChipManifestPath: writeJSONFile(t, filepath.Join(root, "chip", "chip_manifest.json"), testChip()),
		CoreDir:          testCoreDir(t),
		ArchDir:          archDir,
		SourceDirs:       []string{filepath.Join(root, "src")},
		OutDir:           filepath.Join(root, "generated"),
	}
	writeTempFile(t, in.SourceDirs[0], "placeholder.c", "/* fixture: CHIP_FLASH_IMMUTABLE_BOOT_END */\nunsigned long g_immutable_end_ref(void) { return CHIP_FLASH_IMMUTABLE_BOOT_END; }\n")
	for trait, dm := range testDrivers() {
		dir := filepath.Join(root, "drivers", trait)
		writeJSONFile(t, filepath.Join(dir, driverManifestFile), dm)
		in.DriverDirs = append(in.DriverDirs, dir)
	}
	for _, cm := range testCrypto() {
		dir := filepath.Join(root, "crypto", cm.Name)
		writeJSONFile(t, filepath.Join(dir, cryptoManifestFile), cm)
		in.CryptoDirs = append(in.CryptoDirs, dir)
	}
	return in
}

func writeJSONFile(t *testing.T, path string, v any) string {
	t.Helper()
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("marshal %s: %v", path, err)
	}
	return writeTempFile(t, filepath.Dir(path), filepath.Base(path), string(data))
}
