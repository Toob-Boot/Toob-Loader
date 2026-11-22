package resolve

import (
	"path/filepath"
	"slices"
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

	t.Run("missing SoC source on disk does not fail resolution", func(t *testing.T) {
		fx := newFixture(t)
		fx.reg.socOK = false
		fx.index.SoCs = map[string]registry.SoCInfo{
			"soc": {Name: "soc", Path: "soc", Chips: []string{testChip}},
		}
		plan, err := fx.resolve()
		requireNoErr(t, err)
		if plan.SoCDir != "" {
			t.Fatalf("SoCDir = %q, want empty when unavailable", plan.SoCDir)
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
