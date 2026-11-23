package resolve

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/toob-boot/toob/internal/lockfile"
	"github.com/toob-boot/toob/internal/registry"
)

func TestResolve(t *testing.T) {
	fx := newFixture(t)
	plan, err := fx.resolve()
	requireNoErr(t, err)

	if plan.Chip.Name != testChip || plan.Chip.Local {
		t.Errorf("unexpected chip %+v", plan.Chip)
	}
	if plan.CoreSDK.Version != "core/v1.2.0" || plan.CoreSDK.Origin != originAuto {
		t.Errorf("unexpected Core SDK %+v", plan.CoreSDK)
	}
	if plan.Compiler != "latest" {
		t.Errorf("Compiler = %q, want latest", plan.Compiler)
	}
	if plan.Arch.Name != "riscv" {
		t.Errorf("unexpected arch %+v", plan.Arch)
	}
	if plan.Toolchain.Name != testToolchain || plan.Toolchain.ExpectedVersion != "1.2.3" {
		t.Errorf("unexpected toolchain %+v", plan.Toolchain)
	}
	if len(plan.Drivers) != 2 {
		t.Errorf("driver directories must be deduplicated, got %v", plan.Drivers)
	}
	if len(plan.Crypto) != 3 || plan.Crypto[0].Name != "monocypher" || plan.Crypto[1].Name != "sha256_sw" {
		t.Errorf("unexpected crypto %+v", plan.Crypto)
	}
	if plan.PQCEnabled() {
		t.Error("PQC must be disabled by default")
	}
	if !plan.Recovery.Declared || len(plan.Recovery.Drivers) != 2 {
		t.Errorf("unexpected recovery %+v", plan.Recovery)
	}
	if plan.SoCDir != "" {
		t.Errorf("SoCDir = %q, want none without a soc package", plan.SoCDir)
	}
}

func TestResolveSoCIsOptional(t *testing.T) {
	t.Run("resolves matching SoC package from index", func(t *testing.T) {
		fx := newFixture(t)
		fx.reg.socOK = true
		fx.index.SoCs = map[string]registry.SoCInfo{
			"stm32": {Name: "stm32", Path: "soc/stm32", Chips: []string{"stm32u5"}},
			"soc":   {Name: "soc", Path: "soc", Chips: []string{testChip}},
		}
		plan, err := fx.resolve()
		requireNoErr(t, err)
		if want := filepath.Join(fx.reg.base, "soc", "soc"); plan.SoCDir != want {
			t.Fatalf("SoCDir = %q, want %q", plan.SoCDir, want)
		}
	})

	t.Run("skips SoC packages that do not match target chip", func(t *testing.T) {
		fx := newFixture(t)
		fx.reg.socOK = true
		fx.index.SoCs = map[string]registry.SoCInfo{
			"stm32": {Name: "stm32", Path: "soc/stm32", Chips: []string{"stm32u5"}},
		}
		plan, err := fx.resolve()
		requireNoErr(t, err)
		if plan.SoCDir != "" {
			t.Fatalf("SoCDir = %q, want empty for non-matching chip", plan.SoCDir)
		}
	})

	t.Run("missing SoC source on disk propagates error fail-fast (HIGH-89)", func(t *testing.T) {
		fx := newFixture(t)
		fx.reg.socOK = false
		fx.index.SoCs = map[string]registry.SoCInfo{
			"soc": {Name: "soc", Path: "soc", Chips: []string{testChip}},
		}
		_, err := fx.resolve()
		requireErr(t, err, "failed to resolve SoC package")
	})

	t.Run("local SoC override resolves without registry", func(t *testing.T) {
		fx := newFixture(t)
		localSoCDir := filepath.Join(fx.root, localHalDir, "soc", "esp")
		fx.writeJSON(filepath.Join(localSoCDir, socManifestFile), map[string]any{
			"name":    "esp",
			"version": "1.0.0",
			"chips":   []string{testChip},
		})
		plan, err := fx.resolve()
		requireNoErr(t, err)
		if plan.SoCDir != localSoCDir || plan.SoCName != "esp" || plan.SoCSource != "local" {
			t.Fatalf("unexpected local SoC resolution: dir=%q name=%q source=%q", plan.SoCDir, plan.SoCName, plan.SoCSource)
		}
	})
}

func TestResolveFailsOnEachStage(t *testing.T) {
	tests := []struct {
		name  string
		setup func(fx *fixture)
		want  string
	}{
		{"chip", func(fx *fixture) { fx.dev.Device.Chip = "" }, "must define [device]"},
		{"core sdk", func(fx *fixture) { fx.dev.Build.CoreSDK = "core/../x" }, "Core SDK version"},
		{"compiler", func(fx *fixture) { fx.dev.Build.Compiler = "a b" }, "compiler version"},
		{"arch", func(fx *fixture) { fx.reg.fail["arch:riscv"] = true }, "architecture"},
		{"toolchain", func(fx *fixture) { fx.reg.fail["toolchains:"+testToolchain] = true }, "toolchain"},
		{"drivers", func(fx *fixture) { fx.reg.fail["drivers:drivers/flash/esp_flash"] = true }, "driver"},
		{"crypto", func(fx *fixture) { fx.dev.Crypto.Backend = "nope" }, "crypto package"},
		{"recovery", func(fx *fixture) { fx.dev.Recovery.Console = "../x" }, "recovery driver"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fx := newFixture(t)
			tc.setup(fx)
			plan, err := fx.resolve()
			requireErr(t, err, tc.want)
			if plan != nil {
				t.Fatalf("a failed resolution must not return a plan, got %+v", plan)
			}
		})
	}
}

func TestPQCEnabled(t *testing.T) {
	plan := &Plan{Crypto: []CryptoSlot{{Slot: slotBackend, Name: "a"}, {Slot: slotPQC}}}
	if plan.PQCEnabled() {
		t.Fatal("a disabled pqc slot must not enable PQC")
	}
	plan.Crypto[1].Name = "mldsa"
	if !plan.PQCEnabled() {
		t.Fatal("an enabled pqc slot must enable PQC")
	}
	if (&Plan{}).PQCEnabled() {
		t.Fatal("a plan without slots must not enable PQC")
	}
}

func TestCryptoDirs(t *testing.T) {
	var nilPlan *Plan
	if got := nilPlan.CryptoDirs(); len(got) != 0 {
		t.Fatalf("nil Plan.CryptoDirs() = %v, want empty", got)
	}

	plan := &Plan{
		Crypto: []CryptoSlot{
			{Slot: slotBackend, Name: "monocypher", Dir: "/pkg/crypto/backend/monocypher"},
			{Slot: slotHash, Name: "sha256_sw", Dir: "/pkg/crypto/hash/sha256_sw"},
			{Slot: slotPQC}, // disabled
		},
	}
	want := []string{"/pkg/crypto/backend/monocypher", "/pkg/crypto/hash/sha256_sw"}
	if got := plan.CryptoDirs(); !slices.Equal(got, want) {
		t.Fatalf("CryptoDirs() = %v, want %v", got, want)
	}

	// Deduplicates reused packages while preserving deterministic backend -> hash -> pqc order.
	planWithReuseAndPQC := &Plan{
		Crypto: []CryptoSlot{
			{Slot: slotBackend, Name: "unified_crypto", Dir: "/pkg/crypto/unified"},
			{Slot: slotHash, Name: "unified_crypto", Dir: "/pkg/crypto/unified", Reused: true},
			{Slot: slotPQC, Name: "ml_dsa_65", Dir: "/pkg/crypto/pqc/ml_dsa_65"},
		},
	}
	wantDedup := []string{"/pkg/crypto/unified", "/pkg/crypto/pqc/ml_dsa_65"}
	if got := planWithReuseAndPQC.CryptoDirs(); !slices.Equal(got, wantDedup) {
		t.Fatalf("CryptoDirs() with reuse/pqc = %v, want %v", got, wantDedup)
	}

	// Stage-1 CryptoDirs MUST isolate out Recovery crypto slots (CRIT-62).
	isolated := &Plan{
		Crypto: []CryptoSlot{
			{Slot: slotBackend, Name: "monocypher", Dir: "/pkg/crypto/backend/monocypher"},
			{Slot: slotHash, Name: "sha256_sw", Dir: "/pkg/crypto/hash/sha256_sw"},
		},
		Recovery: Recovery{
			Backend:     "rec_crypto",
			Hash:        "rec_hash",
			BackendSlot: &CryptoSlot{Slot: "recovery_backend", Name: "rec_crypto", Dir: "/pkg/crypto/rec_crypto"},
			HashSlot:    &CryptoSlot{Slot: "recovery_hash", Name: "rec_hash", Dir: "/pkg/crypto/rec_hash"},
			Drivers:     []string{"/pkg/drivers/rec_uart", "/pkg/drivers/rec_flash"},
		},
	}
	if got := isolated.CryptoDirs(); !slices.Equal(got, want) {
		t.Fatalf("Stage-1 CryptoDirs() leaked recovery crypto: got %v, want %v", got, want)
	}
	wantRecCrypto := []string{"/pkg/crypto/rec_crypto", "/pkg/crypto/rec_hash"}
	if got := isolated.RecoveryCryptoDirs(); !slices.Equal(got, wantRecCrypto) {
		t.Fatalf("RecoveryCryptoDirs() = %v, want %v", got, wantRecCrypto)
	}
	wantRecDrv := []string{"/pkg/drivers/rec_uart", "/pkg/drivers/rec_flash"}
	if got := isolated.RecoveryDriverDirs(); !slices.Equal(got, wantRecDrv) {
		t.Fatalf("RecoveryDriverDirs() = %v, want %v", got, wantRecDrv)
	}
}

func TestToLockfileV2AndStrictLockedMode(t *testing.T) {
	fx := newFixture(t)
	shaChip := strings.Repeat("a", 64)
	shaArch := strings.Repeat("b", 64)
	shaUart := strings.Repeat("c", 64)
	shaFlash := strings.Repeat("d", 64)
	shaMono := strings.Repeat("e", 64)
	shaHash := strings.Repeat("f", 64)
	shaSDK := strings.Repeat("1", 64)
	shaTC := strings.Repeat("2", 64)

	fx.index.Chips[testChip] = registry.ChipInfo{Name: testChip, Version: "2.0.0", SHA256: shaChip}
	fx.index.Archs = map[string]registry.ArchInfo{
		"riscv": {Name: "riscv", Version: "1.1.0", SHA256: shaArch},
	}
	fx.index.Drivers = map[string]registry.DriverInfo{
		"esp_uart_v1": {Name: "esp_uart_v1", Trait: "console", Version: "1.0.0", SHA256: shaUart},
		"esp_flash":   {Name: "esp_flash", Trait: "flash", Version: "1.0.0", SHA256: shaFlash},
	}
	fx.index.Toolchains[testToolchain] = registry.ToolchainInfo{
		Version: "1.2.3",
		Sha256:  map[string]string{"linux_amd64": shaTC},
	}
	fx.setCrypto("monocypher", func(c *registry.CryptoInfo) { c.SHA256 = shaMono })
	fx.setCrypto("sha256_sw", func(c *registry.CryptoInfo) { c.SHA256 = shaHash })

	plan, err := fx.resolve()
	requireNoErr(t, err)

	lf, err := plan.ToLockfile(nil, nil, "https://registry.example.com", "42", strings.Repeat("9", 64), shaSDK, "sha256:"+strings.Repeat("8", 64))
	requireNoErr(t, err)
	if lf.FormatVersion != lockfile.FormatVersionV2 {
		t.Fatalf("FormatVersion = %d, want 2", lf.FormatVersion)
	}
	if _, ok := lf.Targets[testChip]; !ok {
		t.Fatalf("missing [targets.%s] in generated lockfile", testChip)
	}

	// Strict --locked round-trip succeeds against the generated Lockfile v2.
	in := fx.input()
	in.Lock = lf
	in.Locked = true
	lockedPlan, err := Resolve(in)
	requireNoErr(t, err)
	if lockedPlan.Chip.Version != "2.0.0" {
		t.Fatalf("locked Chip.Version = %q, want 2.0.0", lockedPlan.Chip.Version)
	}

	// Reject unlocked [build] compiler override in device.toml.
	in.Device.Build.Compiler = "v9.9.9"
	_, err = Resolve(in)
	requireErr(t, err, "rejects unlocked")
	in.Device.Build.Compiler = ""

	// Reject toolchain per-platform SHA256 drift.
	fx.index.Toolchains[testToolchain] = registry.ToolchainInfo{
		Version: "1.2.3",
		Sha256:  map[string]string{"linux_amd64": strings.Repeat("0", 64)},
	}
	_, err = Resolve(in)
	requireErr(t, err, "sha256")
}

func TestEnforceLockedChip(t *testing.T) {
	fx := newFixture(t)
	fx.lock.Chips = []lockfile.ChipEntry{
		{Name: testChip, Version: "9.9.9", Arch: "riscv"},
	}
	if _, err := fx.resolve(); err == nil {
		t.Fatal("expected locked chip version mismatch to fail")
	}

	fx.lock.Chips = []lockfile.ChipEntry{
		{Name: testChip, Version: "2.0.0", Arch: "riscv", CryptoBackend: "monocypher", CryptoHash: "sha256_sw"},
	}
	if _, err := fx.resolve(); err != nil {
		t.Fatalf("matching locked chip entry failed: %v", err)
	}
}
