package build

import (
	"encoding/json"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func makeDirLink(t *testing.T, target, link string) {
	t.Helper()
	err := os.Symlink(target, link)
	if err == nil {
		return
	}
	if runtime.GOOS == "windows" {
		out, jErr := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput()
		if jErr == nil {
			return
		}
		t.Skipf("cannot create directory symlink (%v) or junction (%v: %s)", err, jErr, out)
	}
	t.Skipf("cannot create symlink: %v", err)
}

func makeFileLinkOrSkip(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("file symlinks require elevated privileges on this host: %v", err)
	}
}

func TestSecurityCodeInjectionBlocked(t *testing.T) {
	t.Run("driver_config rejects arbitrary C expressions and pragmas", func(t *testing.T) {
		payloads := []string{
			`1); system("compromise"`,
			`_Pragma("GCC error \"injected\"")`,
			`NULL`,
			`defined(FOO)`,
			`__builtin_trap()`,
			`0x10 + 0x20`,
			`foo(bar)`,
		}
		for _, payload := range payloads {
			ctx := testContext(t)
			ctx.Device.DriverConfig = map[string]any{"hook": payload}
			cfg, layout := testLayout(t, ctx)
			if _, err := renderBootConfig(ctx, cfg, layout); err == nil {
				t.Errorf("driver_config payload %q must be rejected", payload)
			}
		}
	})

	t.Run("crypto.backend rejects trigraphs and non-package characters", func(t *testing.T) {
		for _, bad := range []string{"mono??/cypher", "mono;cypher", "mono cypher", "../monocypher", "@bad scope/pkg"} {
			ctx := testContext(t)
			ctx.Device.Crypto.Backend = bad
			if _, err := resolveConfig(ctx); err == nil {
				t.Errorf("crypto.backend %q must be rejected by resolveConfig", bad)
			}
		}

		// Valid @scope/name package ref must succeed.
		ctx := testContext(t)
		ctx.Hardware.CryptoCapabilities.ArenaSize = 8192
		ctx.Device.Crypto.Backend = "@partner/ed25519_hw"
		ctx.Device.Crypto.Hash = "@community/sha256_fast"
		ctx.Device.Crypto.Pqc = "@toob/ml_dsa_65"
		ctx.Crypto = append(ctx.Crypto, &CryptoManifest{
			Name:       "@toob/ml_dsa_65",
			Version:    "1.0.0",
			AbiVersion: "v3",
			Category:   []string{"pqc"},
			Headers:    []string{"crypto_pqc.h"},
			Symbols: map[string]string{
				"verify_pqc":      "crypto_ml_dsa_65_verify_pqc",
				"is_pqc_enforced": "crypto_ml_dsa_65_is_pqc_enforced",
			},
		})
		cfg, layout := testLayout(t, ctx)
		src, err := renderBootConfig(ctx, cfg, layout)
		if err != nil {
			t.Fatalf("scoped crypto package ref must be accepted, got %v", err)
		}
		data, err := src.finish()
		if err != nil {
			t.Fatalf("finish failed: %v", err)
		}
		if !strings.Contains(string(data), `"@partner/ed25519_hw"`) {
			t.Fatalf("expected scoped backend macro in output:\n%s", data)
		}
	})

	t.Run("wiring rejects NULL, C keywords, builtins, and header traversal/injection", func(t *testing.T) {
		badSymbols := []string{"NULL", "return", "int", "_Pragma", "defined", "asm", "__asm__", "__builtin_unreachable", "func(); evil"}
		for _, sym := range badSymbols {
			ctx := testContext(t)
			ctx.Drivers["flash"].Symbols["init"] = sym
			if _, _, err := renderPlatformWiring(ctx); err == nil {
				t.Errorf("flash.init=%q must be rejected", sym)
			}

			ctx = testContext(t)
			ctx.Drivers["slot_caps"].Symbols["slot_caps"] = sym
			if _, _, err := renderPlatformWiring(ctx); err == nil {
				t.Errorf("slot_caps=%q must be rejected", sym)
			}

			ctx = testContext(t)
			ctx.Drivers["keystore"] = &DriverManifest{
				Name:       "@community/evil_ks",
				Trait:      "keystore",
				AbiVersion: "v3",
				Headers:    []string{"evil_ks.h"},
				Symbols: map[string]string{
					"read_pubkey":       sym,
					"read_dslc":         "valid_read_dslc",
					"write_dslc":        "valid_write_dslc",
					"read_monotonic":    "valid_read_monotonic",
					"advance_monotonic": "valid_advance_monotonic",
				},
			}
			if _, _, err := renderPlatformWiring(ctx); err == nil {
				t.Errorf("keystore.read_pubkey=%q must be rejected", sym)
			}

			ctx = testContext(t)
			ctx.Crypto[0].Symbols["verify_signature"] = sym
			if _, _, err := renderPlatformWiring(ctx); err == nil {
				t.Errorf("crypto.verify_signature=%q must be rejected", sym)
			}

			ctx = testContext(t)
			ctx.Arch.Symbols["disable_interrupts"] = sym
			if _, _, err := renderPlatformWiring(ctx); err == nil {
				t.Errorf("arch.disable_interrupts=%q must be rejected", sym)
			}
		}

		badHeaders := []string{
			`foo.h"` + "\n#pragma GCC poison main",
			`../../etc/passwd.h`,
			`/etc/passwd.h`,
			`drivers\slot\evil.h`,
			`foo.h */ #error injected /* .h`,
			`not_a_header.c`,
		}
		for _, hdr := range badHeaders {
			ctx := testContext(t)
			ctx.Drivers["slot_caps"].Headers = []string{hdr}
			if _, _, err := renderPlatformWiring(ctx); err == nil {
				t.Errorf("malicious header %q must be rejected", hdr)
			}

			ctx = testContext(t)
			ctx.Arch.Headers = []string{hdr}
			if _, _, err := renderPlatformWiring(ctx); err == nil {
				t.Errorf("malicious arch header %q must be rejected", hdr)
			}

			ctx = testContext(t)
			ctx.Crypto[0].Headers = []string{hdr}
			if _, _, err := renderPlatformWiring(ctx); err == nil {
				t.Errorf("malicious crypto header %q must be rejected", hdr)
			}
		}
	})

	t.Run("renderStage0LD rejects linker directive injection", func(t *testing.T) {
		hw := testHardware(t)
		hw.Memory.IramBase = "0x40800000, LENGTH = 0x1000 }\nSECTIONS { /DISCARD/ : { *(*) } } /*"
		if _, err := renderStage0LD(hw).finish(); err == nil {
			t.Fatal("expected linker injection in IramBase to fail")
		}
		hw = testHardware(t)
		hw.Memory.IramBase = "0xFFFF0000"
		hw.Memory.IramSize = "0x20000"
		if _, err := renderStage0LD(hw).finish(); err == nil {
			t.Fatal("expected 32-bit IRAM overflow in renderStage0LD to fail")
		}
	})

	t.Run("renderResetCauses rejects comment breakout and out-of-range codes", func(t *testing.T) {
		rc := &ResetCauses{
			Codes: []ResetCauseCode{
				{Name: "pwn */ }; extern int evil; /*", Value: 1, Class: "power"},
			},
		}
		if _, err := renderResetCauses(rc); err == nil {
			t.Fatal("expected comment breakout in reset cause name to fail")
		}

		var badCode ResetCauseCode
		if err := json.Unmarshal([]byte(`{"name":"neg","value":-1,"class":"crash"}`), &badCode); err == nil {
			t.Fatal("expected negative reset cause value in JSON to fail")
		}
	})

	t.Run("register block base + offset uint32 wraparound rejected", func(t *testing.T) {
		ctx := testContext(t)
		ctx.Hardware.RegisterBlocks["wrap"] = RegisterBlock{
			Base: "0xFFFFF000",
			Regs: map[string]string{"overflow": "0x2000"},
		}
		cfg, layout := testLayout(t, ctx)
		if _, err := renderBootConfig(ctx, cfg, layout); err == nil {
			t.Fatal("expected register base + offset uint32 overflow to fail")
		}
	})
}

func TestSecurityPathContainmentAndSymlinks(t *testing.T) {
	t.Run("containPath blocks lexical and symlink escapes", func(t *testing.T) {
		root := t.TempDir()
		pkgDir := filepath.Join(root, "pkg")
		outsideDir := filepath.Join(root, "outside")
		if err := os.MkdirAll(pkgDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(outsideDir, 0o755); err != nil {
			t.Fatal(err)
		}
		writeTempFile(t, outsideDir, "secret.c", "/* secret */")

		for _, rel := range []string{"../outside/secret.c", "sub/../../outside/secret.c", "/abs/secret.c", `\abs\secret.c`, "C:secret.c", "file.c:ads"} {
			if _, err := containPath(pkgDir, rel); err == nil {
				t.Errorf("containPath must reject %q", rel)
			}
		}

		makeDirLink(t, outsideDir, filepath.Join(pkgDir, "escape_dir"))
		if _, err := containPath(pkgDir, "escape_dir/secret.c"); err == nil {
			t.Fatal("containPath must reject directory symlink/junction escaping package root")
		}
	})

	t.Run("Load rejects escaping paths in chip_manifest.json and driver_manifest.json", func(t *testing.T) {
		in := writeFixtureInputs(t, testHardware(t))
		writeTempFile(t, filepath.Dir(in.ChipManifestPath), filepath.Base(in.ChipManifestPath), `{
			"name": "test-chip",
			"arch": "riscv32",
			"sources": {"startup": "../escape.S"}
		}`)
		if _, err := Load(in, NopLogger{}); err == nil {
			t.Fatal("Load must reject ../escape.S in chip_manifest.json")
		}

		in = writeFixtureInputs(t, testHardware(t))
		drvDir := t.TempDir()
		writeTempFile(t, drvDir, driverManifestFile, `{
			"name": "@community/evil",
			"trait": "entropy",
			"sources": ["../../escape.c"]
		}`)
		in.DriverDirs = append(in.DriverDirs, drvDir)
		if _, err := Load(in, NopLogger{}); err == nil {
			t.Fatal("Load must reject ../../escape.c in driver_manifest.json")
		}
	})

	t.Run("auditMacroUsage blocks escaping symlinks and symlinks into outDir", func(t *testing.T) {
		root := t.TempDir()
		srcDir := filepath.Join(root, "src")
		outDir := filepath.Join(root, "out")
		outsideDir := filepath.Join(root, "outside")
		for _, d := range []string{srcDir, outDir, outsideDir} {
			if err := os.MkdirAll(d, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		writeTempFile(t, outsideDir, "fake_consumer.c", "uint32_t x = CHIP_SECRET_MACRO;\n")
		makeDirLink(t, outsideDir, filepath.Join(srcDir, "linked_outside"))

		if err := auditMacroUsage([]string{"CHIP_SECRET_MACRO"}, []string{srcDir}, outDir); err == nil || !strings.Contains(err.Error(), "escapes") {
			t.Fatalf("expected symlink escape error in auditMacroUsage, got %v", err)
		}

		if err := os.Remove(filepath.Join(srcDir, "linked_outside")); err != nil {
			t.Fatal(err)
		}
		inTreeOut := filepath.Join(srcDir, "generated")
		writeTempFile(t, inTreeOut, "generated_boot_config.h", "#define CHIP_SELF_SATISFIED 1U\n")
		makeDirLink(t, inTreeOut, filepath.Join(srcDir, "alias_to_generated"))
		if err := auditMacroUsage([]string{"CHIP_SELF_SATISFIED"}, []string{srcDir}, inTreeOut); err == nil || !strings.Contains(err.Error(), "NEVER referenced") {
			t.Fatalf("symlink to outDir must not satisfy macro consumption audit, got %v", err)
		}
	})

	t.Run("writeFileIfChanged replaces pre-planted symlink without overwriting target", func(t *testing.T) {
		root := t.TempDir()
		victim := filepath.Join(root, "victim.h")
		if err := os.WriteFile(victim, []byte("DO_NOT_TOUCH"), 0o644); err != nil {
			t.Fatal(err)
		}
		outDir := filepath.Join(root, "out")
		if err := os.MkdirAll(outDir, 0o755); err != nil {
			t.Fatal(err)
		}
		outLink := filepath.Join(outDir, "generated_boot_config.h")
		makeFileLinkOrSkip(t, victim, outLink)

		if err := writeFileIfChanged(outLink, []byte("SAFE_GENERATED")); err != nil {
			t.Fatalf("writeFileIfChanged failed: %v", err)
		}
		gotVictim, err := os.ReadFile(victim)
		if err != nil {
			t.Fatal(err)
		}
		if string(gotVictim) != "DO_NOT_TOUCH" {
			t.Fatalf("victim file was overwritten through symlink: %q", gotVictim)
		}
	})
}

func TestSecurityOverflowsDoSAndMemorySafety(t *testing.T) {
	t.Run("excessive wal_sectors rejected before allocation", func(t *testing.T) {
		ctx := testContext(t)
		ctx.Device.Partitions.WalSectors = math.MaxUint32
		if _, err := resolveConfig(ctx); err == nil || !strings.Contains(err.Error(), "wal_sectors") {
			t.Fatalf("expected wal_sectors upper-bound rejection, got %v", err)
		}

		alloc, err := NewAllocator([]FlashRegion{{Type: "writable", Base: 0, SectorSize: 4096, Count: 16}})
		if err != nil {
			t.Fatal(err)
		}
		if err := planWal(alloc, &PartitionLayout{}, math.MaxUint32); err == nil {
			t.Fatal("planWal must reject excessive sector counts before slice allocation")
		}
	})

	t.Run("NewAllocator rejects non-power-of-two sectors, unaligned base, unknown type, and writable overlaps", func(t *testing.T) {
		badRegions := [][]FlashRegion{
			{{Type: "bogus", Base: 0, Size: 4096}},
			{{Type: "writable", Base: 0, SectorSize: 3000, Count: 4}},
			{{Type: "writable", Base: 2048, SectorSize: 4096, Count: 4}},
			{{Type: "writable", Base: 0xFFFFF000, SectorSize: 4096, Count: 4}},
			{
				{Type: "writable", Base: 0, SectorSize: 4096, Count: 4},
				{Type: "writable", Base: 0x2000, SectorSize: 4096, Count: 4},
			},
		}
		for i, regs := range badRegions {
			if _, err := NewAllocator(regs); err == nil {
				t.Errorf("case %d: expected NewAllocator(%+v) to fail", i, regs)
			}
		}

		alloc, err := NewAllocator([]FlashRegion{
			{Type: "reserved", Base: 0, Size: 0x4000},
			{Type: "writable", Base: 0x4000, SectorSize: 4096, Count: 4},
		})
		if err != nil {
			t.Fatal(err)
		}
		for _, badAlign := range []uint32{3, 5000} {
			if _, _, err := alloc.AllocateSector("test", badAlign); err == nil {
				t.Fatalf("AllocateSector(%d) must fail without advancing cursor", badAlign)
			}
			if alloc.offset != 0 {
				t.Fatalf("failed AllocateSector(%d) mutated offset to 0x%X", badAlign, alloc.offset)
			}
		}
	})

	t.Run("PartitionLayout.validate catches overlapping partitions and 32-bit wraparounds", func(t *testing.T) {
		_, layout := testLayout(t, testContext(t))
		dup := *layout
		dup.KDM.Addr = dup.Mailbox.Addr // aligned to MaxSectorSize, passes LAYOUT_001..004, overlaps Mailbox
		if err := dup.validate(); err == nil || !strings.Contains(err.Error(), "LAYOUT_005") {
			t.Fatalf("expected LAYOUT_005 overlap failure, got %v", err)
		}

		wrap := *layout
		wrap.Forensic.Addr = 0xFFFFF000
		wrap.Forensic.Budget = 0x2000
		if err := wrap.validate(); err == nil || !strings.Contains(err.Error(), "LAYOUT_005") {
			t.Fatalf("expected LAYOUT_005 bounds/wraparound failure, got %v", err)
		}
	})

	t.Run("FLASH-001 and FLASH-002 catch 32-bit uint32 wraparounds", func(t *testing.T) {
		hj := validTestHardwareJSON(t)
		prov := &Provenance{Source: "trm", Ref: "TRM", Verified: "2026-01-15"}
		hj.Flash.Regions = []FlashRegion{
			{Type: "reserved", Base: 0xFFFF0000, Size: 0x20000, Provenance: prov}, // wraps uint32 to 0x10000
		}
		results := VerifyHardwareProvenance(hj)
		for _, r := range results {
			if r.Check == "FLASH-001" && r.Passed {
				t.Fatal("FLASH-001 failed to detect Base + Size uint32 wraparound")
			}
		}

		hj = validTestHardwareJSON(t)
		hj.Flash.Regions = []FlashRegion{
			{Type: "writable", Base: 0, SectorSize: 65536, Count: 65537, Size: 65536, Provenance: prov}, // 65536*65537 wraps uint32 to 65536
		}
		results = VerifyHardwareProvenance(hj)
		for _, r := range results {
			if r.Check == "FLASH-002" && r.Passed {
				t.Fatal("FLASH-002 failed to detect SectorSize * Count uint32 wraparound")
			}
		}
	})
}

func TestSecurityProvenanceJSONAndESP32C6Regression(t *testing.T) {
	t.Run("duplicate JSON keys rejected in hardware.json", func(t *testing.T) {
		dir := t.TempDir()
		hwPath := filepath.Join(dir, "hardware.json")
		dupJSON := `{"chip_family":"esp32-c6","flash":{"size":4194304,"size":8388608}}`
		if err := os.WriteFile(hwPath, []byte(dupJSON), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := ParseHardwareJSON(hwPath); err == nil || !strings.Contains(err.Error(), "duplicate JSON key") {
			t.Fatalf("expected duplicate JSON key rejection, got %v", err)
		}
	})

	t.Run("empty provenance object and decimal/hex parser differential caught", func(t *testing.T) {
		hj := validTestHardwareJSON(t)
		hj.Provenance = &Provenance{} // non-nil empty object previously bypassed PROV-001 & PROV-003
		results := VerifyHardwareProvenance(hj)
		var prov001, prov003 bool
		for _, r := range results {
			if r.Check == "PROV-001" {
				prov001 = !r.Passed
			}
			if r.Check == "PROV-003" {
				prov003 = !r.Passed
			}
		}
		if !prov001 || !prov003 {
			t.Fatalf("empty Provenance{} must fail PROV-001 (%v) and PROV-003 (%v)", prov001, prov003)
		}

		// Decimal "40000010" is 0x02625A0A in C (unaligned and below 0x40000000 MMIO),
		// whereas hex parsing previously misread it as 0x40000010.
		hj = validTestHardwareJSON(t)
		hj.RegisterBlocks["bad_dec"] = RegisterBlock{
			Base:       "40000010",
			Regs:       map[string]string{},
			Provenance: &Provenance{Source: "trm", Ref: "TRM", Verified: "2026-01-15"},
		}
		results = VerifyHardwareProvenance(hj)
		var addr001, addr003Warn bool
		for _, r := range results {
			if r.Check == "ADDR-001" {
				addr001 = !r.Passed
			}
			if r.Check == "ADDR-003" {
				addr003Warn = r.Passed && r.Warning
			}
		}
		if !addr001 || !addr003Warn {
			t.Fatalf("decimal address without 0x prefix must fail ADDR-001 (%v) and warn ADDR-003 (%v)", addr001, addr003Warn)
		}
	})

	t.Run("Markdown injection sanitized in provenance_report.md", func(t *testing.T) {
		hj := validTestHardwareJSON(t)
		hj.Provenance.Ref = "TRM | **PASS** |\n| `forged` | Fake | `0` | `trm` | Ref | 2026-01-15 | **SELF_ATTESTED (trm)**"
		items := AuditProvenance(hj)
		results := VerifyHardwareProvenance(hj)
		report, err := renderProvenanceReportWithRaw(hj, nil, items, results)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(report), "\n| `forged` |") {
			t.Fatalf("untrusted provenance ref forged a new Markdown table row:\n%s", report)
		}
	})

	t.Run("real ESP32-C6 manifests validate cleanly", func(t *testing.T) {
		espDir := filepath.Clean(filepath.Join("..", "..", "toob-infra", "registry", "packages", "chips", "esp32c6"))
		hwPath := filepath.Join(espDir, "hardware.json")
		cmPath := filepath.Join(espDir, "chip_manifest.json")
		if _, err := os.Stat(hwPath); err != nil {
			t.Skipf("ESP32-C6 registry files not present at %s: %v", espDir, err)
		}

		hj, err := ParseHardwareJSON(hwPath)
		if err != nil {
			t.Fatalf("ParseHardwareJSON(esp32c6): %v", err)
		}
		results := VerifyHardwareProvenance(hj)
		if HasVerificationFailures(results) {
			t.Fatalf("ESP32-C6 hardware.json failed provenance verification:\n%s", FormatVerificationErrors(results))
		}

		srcDir := t.TempDir()
		outDir := filepath.Join(t.TempDir(), "generated")
		dev := &DeviceToml{}
		dev.Device.Chip = "esp32-c6"
		dev.Identity.VendorID = 0x1234
		dev.Identity.ProductID = 0x5678
		dev.Identity.HwRev = 1
		dev.Partitions.Stage0Size = 32768
		dev.Partitions.Stage1Size = 65536
		dev.Partitions.AppSize = 1048576
		dev.BootConfig.MaxRetries = 3
		dev.Crypto.Backend = "monocypher"
		dev.Crypto.Hash = "sha256_sw"
		dev.Recovery.Crypto.Justification = "Lab bringup security test"
		dev.Drivers = map[string]string{
			"keystore": "@partner/atecc608",
		}

		ctx, err := Load(Inputs{
			Device:           dev,
			HardwarePath:     hwPath,
			ChipManifestPath: cmPath,
			CoreDir:          testCoreDir(t),
			SourceDirs:       []string{srcDir},
			OutDir:           outDir,
		}, NopLogger{})
		if err != nil {
			t.Fatalf("Load(ESP32-C6) failed: %v", err)
		}
		cfg, err := resolveConfig(ctx)
		if err != nil {
			t.Fatalf("resolveConfig(ESP32-C6) failed: %v", err)
		}
		if _, err := planLayout(ctx.Device, ctx.Hardware, cfg); err != nil {
			t.Fatalf("planLayout(ESP32-C6) failed: %v", err)
		}
	})
}
