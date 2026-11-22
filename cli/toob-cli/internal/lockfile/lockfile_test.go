package lockfile_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/toob-boot/toob/internal/lockfile"
)

func TestLockfileRoundTripAndQuotedToolchains(t *testing.T) {
	dir := t.TempDir()
	lfPath := filepath.Join(dir, "toob.lock")

	lf := &lockfile.Lockfile{
		Chips: []lockfile.ChipEntry{
			{
				Name:             "esp32c6",
				Version:          "1.3.2",
				Arch:             "riscv32",
				ArchVersion:      "1.0.0",
				Toolchain:        "riscv32-esp-elf",
				ToolchainVersion: "esp-14.2.0_20251107",
				CryptoBackend:    "@partner/ed25519_hw",
				CryptoHash:       "sha256_sw",
				Spawned:          false,
			},
		},
		Toolchains: map[string]lockfile.ToolchainEntry{
			"riscv32-esp-elf": {Version: "esp-14.2.0_20251107"},
			"arm.gnu.v14":     {Version: "14.2.rel1"},
		},
	}
	lf.Registry.Version = "v1.2.2"
	lf.Registry.Commit = "42"
	lf.Environment.Compiler = "v1.1.16"
	lf.Environment.CoreSDK = "core/v0.1.0"

	if err := lf.Save(lfPath); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	raw, err := os.ReadFile(lfPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `[toolchains."arm.gnu.v14"]`) {
		t.Fatalf("expected quoted [toolchains.%%q] table header, got:\n%s", string(raw))
	}

	loaded, err := lockfile.Load(lfPath)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if loaded.Toolchains["arm.gnu.v14"].Version != "14.2.rel1" {
		t.Fatalf("round-trip lost dotted toolchain key: %+v", loaded.Toolchains)
	}
	if loaded.GetChip("esp32c6") == nil || loaded.GetChip("esp32c6").CryptoBackend != "@partner/ed25519_hw" {
		t.Fatalf("unexpected chip round-trip: %+v", loaded.Chips)
	}
}

func TestLockfileRejectsTraversalAndInjection(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{
			name: "registry commit traversal",
			raw:  "[registry]\ncommit = \"../../../../evil\"\n",
		},
		{
			name: "toolchain version traversal",
			raw:  "[registry]\ncommit = \"42\"\n[toolchains.\"riscv32-esp-elf\"]\nversion = \"../../../../../workspace/local_tc\"\n",
		},
		{
			name: "toolchain key leading dash",
			raw:  "[registry]\ncommit = \"42\"\n[toolchains.\"-evil\"]\nversion = \"1.0.0\"\n",
		},
		{
			name: "chip version semicolon",
			raw:  "[registry]\ncommit = \"42\"\n[[chip]]\nname = \"esp32c6\"\nversion = \"1.0;evil\"\narch = \"riscv32\"\n",
		},
		{
			name: "chip name windows drive colon",
			raw:  "[registry]\ncommit = \"42\"\n[[chip]]\nname = \"C:evil\"\nversion = \"1.0.0\"\narch = \"riscv32\"\n",
		},
		{
			name: "unknown key rejected",
			raw:  "[registry]\ncommit = \"42\"\nevil_extra = \"bad\"\n",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "toob.lock")
			if err := os.WriteFile(p, []byte(tc.raw), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := lockfile.Load(p); err == nil {
				t.Fatalf("expected Load to reject %s, but it succeeded", tc.name)
			}
		})
	}
}

func TestLockfileV2_RoundTripScopedPackagesTargetsAndNonMutatingSave(t *testing.T) {
	dir := t.TempDir()
	lfPath := filepath.Join(dir, "toob.lock")

	shaA := strings.Repeat("a", 64)
	shaB := strings.Repeat("b", 64)
	shaC := strings.Repeat("c", 64)
	shaD := strings.Repeat("d", 64)

	lf := lockfile.NewV2()
	lf.Registry = lockfile.RegistryLock{
		URL:         "https://registry.the-toob.com",
		Revision:    "42",
		IndexSHA256: shaA,
	}
	lf.Environment = lockfile.EnvironmentLock{
		CoreSDK:        "core/v0.1.0",
		CoreSDKSHA256:  shaB,
		Compiler:       "v1.2.0",
		CompilerDigest: "sha256:" + shaC,
	}
	// Deliberately unsorted order to verify Save does NOT mutate caller slice in place.
	lf.Packages = []lockfile.LockedPackage{
		{
			Category: "driver",
			Name:     "@acme/spi_flash",
			Version:  "1.2.0",
			Source:   "registry",
			SHA256:   shaD,
			Trait:    "flash",
		},
		{
			Category:    "chip",
			Name:        "esp32c6",
			Version:     "1.3.2",
			Source:      "spawned",
			BaseVersion: "1.3.0",
			BaseSHA256:  shaA,
		},
		{
			Category: "arch",
			Name:     "riscv32",
			Version:  "1.0.0",
			Source:   "registry",
			SHA256:   shaB,
		},
	}
	lf.Toolchains["@espressif/riscv32-esp-elf"] = lockfile.ToolchainEntry{
		Version: "14.2.0",
		SHA256: map[string]string{
			"linux_amd64":   shaA,
			"windows_amd64": shaB,
		},
	}
	lf.Targets["esp32c6"] = lockfile.TargetLock{
		Chip:        "esp32c6@1.3.2",
		Arch:        "riscv32@1.0.0",
		Toolchain:   "@espressif/riscv32-esp-elf@14.2.0",
		SoC:         "local:vendor/esp_soc",
		Integration: "none",
		Drivers: map[string]string{
			"flash": "@acme/spi_flash@1.2.0",
			"wdt":   "none",
		},
		Crypto: map[string]string{
			"hash":    "sha256_sw@1.0.0",
			"signing": "none",
		},
	}

	if err := lf.Save(lfPath); err != nil {
		t.Fatalf("v2 Save failed: %v", err)
	}
	if lf.Packages[0].Category != "driver" {
		t.Fatalf("Save mutated caller lf.Packages order in place: %+v", lf.Packages)
	}

	loaded, err := lockfile.Load(lfPath)
	if err != nil {
		t.Fatalf("v2 Load failed: %v", err)
	}
	if loaded.FormatVersion != lockfile.FormatVersionV2 {
		t.Fatalf("FormatVersion = %d, want %d", loaded.FormatVersion, lockfile.FormatVersionV2)
	}
	// On-disk output must be sorted deterministically (arch before chip before driver).
	if len(loaded.Packages) != 3 || loaded.Packages[0].Category != "arch" || loaded.Packages[2].Name != "@acme/spi_flash" {
		t.Fatalf("unexpected sorted Packages after Load: %+v", loaded.Packages)
	}
	if loaded.Toolchains["@espressif/riscv32-esp-elf"].SHA256["windows_amd64"] != shaB {
		t.Fatalf("lost per-platform toolchain sha256: %+v", loaded.Toolchains)
	}
	if loaded.Targets["esp32c6"].Drivers["flash"] != "@acme/spi_flash@1.2.0" {
		t.Fatalf("lost target driver binding: %+v", loaded.Targets["esp32c6"])
	}
	// Compatibility GetChip synthesis on v2 Targets.
	synth := loaded.GetChip("esp32c6")
	if synth == nil || !synth.Spawned || synth.Arch != "riscv32" || synth.Toolchain != "@espressif/riscv32-esp-elf" {
		t.Fatalf("unexpected synthesized ChipEntry from v2 target: %+v", synth)
	}
}

func TestLockfileV1MigrationAndSharedPackagePruning(t *testing.T) {
	p := filepath.Join(t.TempDir(), "toob.lock")
	v1Raw := `[registry]
version = "v1.2.2"
commit = "42"

[[chip]]
name = "esp32c6"
version = "1.3.2"
arch = "riscv32"
arch_version = "1.0.0"
toolchain = "riscv32-esp-elf"
toolchain_version = "14.2.0"
crypto_backend = "ed25519_sw"
crypto_hash = "sha256_sw"
spawned = true

[[chip]]
name = "esp32h2"
version = "1.0.0"
arch = "riscv32"
arch_version = "1.0.0"
toolchain = "riscv32-esp-elf"
toolchain_version = "14.2.0"
spawned = false
`
	if err := os.WriteFile(p, []byte(v1Raw), 0o600); err != nil {
		t.Fatal(err)
	}
	lf, err := lockfile.Load(p)
	if err != nil {
		t.Fatalf("loading legacy v1 lockfile failed: %v", err)
	}
	if lf.Registry.Revision != "42" {
		t.Fatalf("expected legacy commit migrated to Revision=42, got %q", lf.Registry.Revision)
	}
	if len(lf.Targets) != 2 {
		t.Fatalf("expected 2 migrated Targets, got %d", len(lf.Targets))
	}
	if !lf.IsSpawnedPackageShared("arch", "riscv32", "esp32c6") {
		t.Fatal("expected riscv32 arch to be reported shared with esp32h2")
	}
	if !lf.RemoveTarget("esp32c6") {
		t.Fatal("expected RemoveTarget(esp32c6) to return true")
	}
	if lf.IsSpawnedPackageShared("arch", "riscv32", "esp32h2") {
		t.Fatal("expected riscv32 arch to no longer be shared once esp32c6 is removed")
	}
	if lf.FindPackage("chip", "esp32c6", "") != nil {
		t.Fatal("expected unreferenced esp32c6 package to be pruned")
	}
	if lf.FindPackage("arch", "riscv32", "") == nil {
		t.Fatal("expected riscv32 arch still referenced by esp32h2 to survive")
	}
}

func TestLockfileV2_RejectsUnknownVersionDuplicatesAndMissingSHA(t *testing.T) {
	goodSHA := strings.Repeat("1", 64)
	cases := []struct {
		name string
		raw  string
	}{
		{
			name: "unsupported future format_version 3",
			raw:  "format_version = 3\n[registry]\nrevision = \"1\"\n",
		},
		{
			name: "registry source missing sha256 in v2",
			raw:  "format_version = 2\n[[package]]\ncategory = \"driver\"\nname = \"wdt\"\nversion = \"1.0.0\"\nsource = \"registry\"\n",
		},
		{
			name: "uppercase scoped package rejected in strict v2",
			raw:  "format_version = 2\n[[package]]\ncategory = \"driver\"\nname = \"@BadScope/wdt\"\nversion = \"1.0.0\"\nsource = \"registry\"\nsha256 = \"" + goodSHA + "\"\n",
		},
		{
			name: "case-insensitive duplicate package entries",
			raw: "format_version = 2\n" +
				"[[package]]\ncategory = \"driver\"\nname = \"wdt\"\nversion = \"1.0.0\"\nsource = \"local\"\n" +
				"[[package]]\ncategory = \"driver\"\nname = \"WDT\"\nversion = \"1.0.0\"\nsource = \"local\"\n",
		},
		{
			name: "case-colliding targets tables in raw TOML",
			raw: "format_version = 2\n" +
				"[targets.\"esp32c6\"]\nchip = \"esp32c6@1.0.0\"\n" +
				"[targets.\"ESP32C6\"]\nchip = \"esp32c6@1.0.0\"\n",
		},
		{
			name: "local target ref escaping workspace",
			raw:  "format_version = 2\n[targets.\"esp32c6\"]\nchip = \"local:../../outside\"\n",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "toob.lock")
			if err := os.WriteFile(p, []byte(tc.raw), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := lockfile.Load(p); err == nil {
				t.Fatalf("expected Load to reject %s", tc.name)
			}
		})
	}
}
