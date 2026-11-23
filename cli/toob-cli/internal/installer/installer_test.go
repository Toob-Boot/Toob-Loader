package installer

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/toob-boot/toob/internal/lockfile"
	manifestpkg "github.com/toob-boot/toob/internal/manifest"
	"github.com/toob-boot/toob/internal/paths"
	"github.com/toob-boot/toob/internal/registry"
)

func setupTestEnv(t *testing.T) (projectRoot, regDir, homeDir string, cache *registry.Cache) {
	t.Helper()
	homeDir = filepath.Join(t.TempDir(), "toob-home")
	regDir = filepath.Join(t.TempDir(), "registry")
	projectRoot = filepath.Join(t.TempDir(), "project")

	if err := os.MkdirAll(homeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(regDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(projectRoot, 0o755); err != nil {
		t.Fatal(err)
	}

	t.Setenv("TOOB_HOME", homeDir)
	t.Setenv("TOOB_REGISTRY_DIR", regDir)
	t.Setenv("TOOB_DEV", "1")

	writeRegFile := func(rel, content string) {
		t.Helper()
		full := filepath.Join(regDir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	shaA := strings.Repeat("a", 64)
	shaB := strings.Repeat("b", 64)
	shaC := strings.Repeat("c", 64)
	shaD := strings.Repeat("d", 64)
	shaE := strings.Repeat("e", 64)
	shaF := strings.Repeat("f", 64)
	sha1 := strings.Repeat("1", 64)
	sha2 := strings.Repeat("2", 64)

	idx := registry.Index{
		FormatVersion:   1,
		RegistryVersion: "2026.11.0",
		Chips: map[string]registry.ChipInfo{
			"esp32c6": {
				Name:           "esp32c6",
				Arch:           "riscv32",
				CompilerPrefix: "riscv32-esp-elf-",
				Path:           "chips/esp32c6",
				Version:        "1.2.0",
				SHA256:         shaA,
				Verified:       true,
				HalBindings: map[string]string{
					"console": "esp_uart",
				},
				Includes: []string{"soc/esp/include"},
				Crypto:   &registry.ChipCrypto{Backend: "monocypher", Hash: "sha256_sw"},
			},
			"esp32c3": {
				Name:           "esp32c3",
				Arch:           "riscv32",
				CompilerPrefix: "riscv32-esp-elf-",
				Path:           "chips/esp32c3",
				Version:        "1.1.0",
				SHA256:         shaA,
				Verified:       true,
				Includes:       []string{"soc/esp/include"},
			},
		},
		Archs: map[string]registry.ArchInfo{
			"riscv32": {Name: "riscv32", Path: "arch/riscv32", Version: "1.0.0", SHA256: shaB, Description: "RISC-V 32"},
		},
		Toolchains: map[string]registry.ToolchainInfo{
			"riscv32-esp-elf": {
				Path:            "toolchains/riscv32-esp-elf",
				Version:         "14.2.0",
				UpstreamVersion: "esp-14.2.0",
				TarballSHA:      sha1,
				CompilerBinary:  "riscv32-esp-elf-gcc",
				Sha256:          map[string]string{"linux_amd64": sha2},
			},
		},
		Drivers: map[string]registry.DriverInfo{
			"esp_uart": {
				Name: "esp_uart", Trait: "console", Path: "drivers/uart/esp_uart", Version: "1.0.0", SHA256: shaC,
			},
			"@partner/drv": {
				Name: "@partner/drv", Author: "partner", Tier: "partner", Trait: "keystore",
				Path: "drivers/@partner/drv", Version: "2.3.4", SHA256: shaD,
			},
		},
		Crypto: map[string]registry.CryptoInfo{
			"monocypher": {
				Name: "monocypher", Path: "crypto/backend/monocypher", Version: "4.0.1",
				Category: []string{"backend"}, SHA256: shaE,
			},
			"sha256_sw": {
				Name: "sha256_sw", Path: "crypto/hash/sha256_sw", Version: "1.0.0",
				Category: []string{"hash"}, SHA256: shaF,
			},
		},
		SoCs: map[string]registry.SoCInfo{
			"soc": {
				Name: "soc", Path: "soc", Version: "1.0.0", SHA256: sha1, Chips: []string{"esp32c6", "esp32c3"},
			},
		},
		Integrations: map[string]registry.IntegrationInfo{
			"esp-idf": {Name: "esp-idf", Path: "integrations/esp-idf", Version: "5.3.0", SHA256: sha2, Description: "ESP-IDF"},
		},
		Ports: map[string]registry.PortInfo{
			"linux-sim": {Name: "linux-sim", Path: "ports/linux-sim", Version: "0.9.0", SHA256: sha1, Description: "Host sim"},
		},
	}

	rawIdx, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	writeRegFile("registry.json", string(rawIdx))
	writeRegFile("chips/esp32c6/chip_manifest.json", `{"name":"esp32c6","arch":"riscv32","compiler_prefix":"riscv32-esp-elf-","version":"1.2.0"}`)
	writeRegFile("chips/esp32c6/hardware.json", `{}`)
	writeRegFile("chips/esp32c3/chip_manifest.json", `{"name":"esp32c3","arch":"riscv32","compiler_prefix":"riscv32-esp-elf-","version":"1.1.0"}`)
	writeRegFile("chips/esp32c3/hardware.json", `{}`)
	writeRegFile("arch/riscv32/arch_manifest.json", `{"name":"riscv32","version":"1.0.0"}`)
	writeRegFile("drivers/uart/esp_uart/uart.c", "void uart_init(void) {}\n")
	writeRegFile("drivers/@partner/drv/drv.c", "void drv_init(void) {}\n")
	writeRegFile("crypto/backend/monocypher/monocypher.c", "void mc_init(void) {}\n")
	writeRegFile("crypto/hash/sha256_sw/sha256.c", "void sha_init(void) {}\n")
	writeRegFile("soc/soc_manifest.json", `{"name":"soc","version":"1.0.0","chips":["esp32c6","esp32c3"]}`)
	writeRegFile("soc/esp/include/esp_soc.h", "#pragma once\n")
	writeRegFile("integrations/esp-idf/CMakeLists.txt", "# esp-idf\n")
	writeRegFile("toolchains/riscv32-esp-elf/toolchain.cmake", "# toolchain\n")
	writeRegFile("ports/linux-sim/port.c", "int main(void) { return 0; }\n")

	cache = registry.NewCache("")
	return projectRoot, regDir, homeDir, cache
}

func TestNewPropagatesLockfileErrors(t *testing.T) {
	root, _, _, cache := setupTestEnv(t)
	if err := os.WriteFile(paths.LockfilePath(root), []byte("not = [valid toml"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := New(root, cache); err == nil {
		t.Fatal("expected New to fail fast on malformed lockfile (CRIT-60)")
	}
}

func TestParsePackageRef(t *testing.T) {
	tests := []struct {
		arg     string
		wantN   string
		wantV   string
		wantErr bool
	}{
		{"esp32c6", "esp32c6", "", false},
		{"esp32c6@1.2.0", "esp32c6", "1.2.0", false},
		{"@partner/drv", "@partner/drv", "", false},
		{"@partner/drv@2.3.4", "@partner/drv", "2.3.4", false},
		{"uart/esp_uart", "uart/esp_uart", "", false},
		{"", "", "", true},
		{"@partner", "", "", true},
		{"@partner/drv@", "", "", true},
		{"esp32c6@notsemver", "", "", true},
		{"../evil", "", "", true},
	}
	for _, tc := range tests {
		n, v, err := ParsePackageRef(tc.arg)
		if (err != nil) != tc.wantErr {
			t.Fatalf("ParsePackageRef(%q) err=%v wantErr=%v", tc.arg, err, tc.wantErr)
		}
		if !tc.wantErr && (n != tc.wantN || v != tc.wantV) {
			t.Fatalf("ParsePackageRef(%q) = (%q, %q), want (%q, %q)", tc.arg, n, v, tc.wantN, tc.wantV)
		}
	}
}

func TestInstaller_AllCategoriesAddSpawnInfoListRemove(t *testing.T) {
	root, _, _, cache := setupTestEnv(t)

	inst, err := New(root, cache)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Wrong version must fail cleanly without calling SwitchVersion.
	if addErr := inst.Add(CategoryDriver, "@partner/drv@9.9.9"); addErr == nil {
		t.Fatal("expected error for missing package version")
	}

	// Exercise Add / Spawn / Info / List / Remove across all remaining categories cleanly.
	if err = inst.Add(CategoryArch, "riscv32@1.0.0"); err != nil {
		t.Fatalf("Add arch: %v", err)
	}
	if err = inst.Spawn(CategoryDriver, "@partner/drv@2.3.4"); err != nil {
		t.Fatalf("Spawn scoped driver: %v", err)
	}
	if err = inst.Add(CategoryIntegration, "esp-idf"); err != nil {
		t.Fatalf("Add integration: %v", err)
	}
	if err = inst.Add(CategoryToolchain, "riscv32-esp-elf@14.2.0"); err != nil {
		t.Fatalf("Add toolchain: %v", err)
	}
	if err = inst.Spawn(CategoryPort, "linux-sim"); err != nil {
		t.Fatalf("Spawn port: %v", err)
	}
	if err = inst.Add(CategorySoC, "soc"); err != nil {
		t.Fatalf("Add soc: %v", err)
	}
	if err = inst.Add(CategoryCrypto, "monocypher"); err != nil {
		t.Fatalf("Add crypto: %v", err)
	}

	info, err := inst.Info(CategoryDriver, "@partner/drv")
	if err != nil {
		t.Fatalf("Info driver: %v", err)
	}
	if !info.Locked || info.Source != "spawned" || info.Tier != "partner" || info.SpawnedPath == "" {
		t.Fatalf("unexpected Info: %+v", info)
	}

	listed, err := inst.List("")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(listed) < 7 {
		t.Fatalf("expected all installed categories in List, got %d (%+v)", len(listed), listed)
	}

	if err = inst.Remove(CategoryDriver, "@partner/drv"); err != nil {
		t.Fatalf("Remove spawned driver: %v", err)
	}
	if _, statErr := os.Stat(info.SpawnedPath); !os.IsNotExist(statErr) {
		t.Fatalf("expected spawned driver directory moved to trash, still exists at %s", info.SpawnedPath)
	}
}

func TestInstaller_SpawnChipSoCLayoutNoGitignoreNoHardlinksExternalTrash(t *testing.T) {
	root, regDir, homeDir, cache := setupTestEnv(t)

	// Pre-populate .gitignore to ensure installer never mutates it.
	gitignorePath := filepath.Join(root, ".gitignore")
	if err := os.WriteFile(gitignorePath, []byte("build/\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	inst, err := New(root, cache)
	if err != nil {
		t.Fatal(err)
	}
	if err = inst.SpawnChip("esp32c6@1.2.0"); err != nil {
		t.Fatalf("SpawnChip: %v", err)
	}

	// Verify .gitignore and cmake/toolchain.cmake were NOT mutated/written.
	rawGitignore, _ := os.ReadFile(gitignorePath)
	if strings.Contains(string(rawGitignore), "toobloader/hal/") {
		t.Fatalf("installer must never mutate .gitignore, got %q", string(rawGitignore))
	}
	if _, statErr := os.Stat(filepath.Join(root, "cmake", "toolchain.cmake")); !os.IsNotExist(statErr) {
		t.Fatal("installer must never write cmake/toolchain.cmake")
	}

	// Verify HIGH-81: SoC package root copied with soc_manifest.json and nested esp/include intact.
	socManifest := filepath.Join(root, "toobloader", "hal", "soc", "soc_manifest.json")
	if _, statErr := os.Stat(socManifest); statErr != nil {
		t.Fatalf("expected full SoC package root with soc_manifest.json at %s: %v", socManifest, statErr)
	}
	if _, statErr := os.Stat(filepath.Join(root, "toobloader", "hal", "soc", "esp", "include", "esp_soc.h")); statErr != nil {
		t.Fatalf("expected nested SoC header intact: %v", statErr)
	}

	// Verify NO hardlinks into editable workspace: editing workspace copy must not alter registry cache.
	spawnedChipJSON := filepath.Join(root, "toobloader", "hal", "chips", "esp32c6", "chip_manifest.json")
	if err = os.WriteFile(spawnedChipJSON, []byte(`{"modified":true}`), 0o644); err != nil {
		t.Fatal(err)
	}
	regChipJSON, _ := os.ReadFile(filepath.Join(regDir, "chips", "esp32c6", "chip_manifest.json"))
	if strings.Contains(string(regChipJSON), `"modified"`) {
		t.Fatal("spawned file appears hard-linked to registry cache")
	}

	// Verify Lockfile v2 target + spawned base_version / base_sha256.
	lf, err := lockfile.Load(paths.LockfilePath(root))
	if err != nil {
		t.Fatalf("reload lockfile: %v", err)
	}
	if lf.FormatVersion != lockfile.FormatVersionV2 {
		t.Fatalf("FormatVersion = %d, want 2", lf.FormatVersion)
	}
	lp := lf.FindPackage(CategoryChip, "esp32c6", "1.2.0")
	if lp == nil || lp.Source != "spawned" || lp.BaseVersion != "1.2.0" || lp.BaseSHA256 == "" {
		t.Fatalf("unexpected chip lock entry: %+v", lp)
	}
	if _, ok := lf.Targets["esp32c6"]; !ok {
		t.Fatalf("missing [targets.esp32c6] in Lockfile v2: %+v", lf.Targets)
	}

	// Add second chip sharing riscv32/soc; removing esp32c6 must preserve shared arch and soc!
	if err := inst.AddChip("esp32c3"); err != nil {
		t.Fatalf("AddChip esp32c3: %v", err)
	}
	if err := inst.RemoveChip("esp32c6"); err != nil {
		t.Fatalf("RemoveChip esp32c6: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "toobloader", "hal", "chips", "esp32c6")); !os.IsNotExist(err) {
		t.Fatal("expected removed chip dir moved out of hal")
	}
	if _, err := os.Stat(filepath.Join(root, "toobloader", "hal", "arch", "riscv32")); err != nil {
		t.Fatalf("shared arch must not be removed while esp32c3 remains: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "toobloader", "hal", ".trash")); !os.IsNotExist(err) {
		t.Fatal("trash must never be stored inside toobloader/hal/.trash")
	}
	if entries, err := os.ReadDir(filepath.Join(homeDir, "trash")); err != nil || len(entries) == 0 {
		t.Fatalf("expected removed dir under %s/trash, got err=%v entries=%v", homeDir, err, entries)
	}
}

func TestInstaller_UseCryptoAndDeviceTomlAtomicUpdate(t *testing.T) {
	root, _, _, cache := setupTestEnv(t)
	deviceToml := filepath.Join(root, "device.toml")
	orig := `[identity]
vendor_id = 0x0001
product_id = 0x0042
hw_rev = 1

[device]
chip = "esp32c6"
`
	if err := os.WriteFile(deviceToml, []byte(orig), 0o644); err != nil {
		t.Fatal(err)
	}

	inst, err := New(root, cache)
	if err != nil {
		t.Fatal(err)
	}

	// Category mismatch must fail before mutating device.toml.
	if useErr := inst.UseCrypto("backend", "sha256_sw"); useErr == nil {
		t.Fatal("expected category mismatch error binding hash package to backend slot")
	}

	if err = inst.UseCrypto("backend", "monocypher@4.0.1"); err != nil {
		t.Fatalf("UseCrypto backend: %v", err)
	}
	if err = inst.UseCrypto("hash", "sha256_sw"); err != nil {
		t.Fatalf("UseCrypto hash: %v", err)
	}

	updated, err := os.ReadFile(deviceToml)
	if err != nil {
		t.Fatal(err)
	}
	dt, err := manifestpkg.ParseToml(deviceToml)
	if err != nil {
		t.Fatalf("updated device.toml failed ParseToml: %v\n%s", err, string(updated))
	}
	if dt.Crypto.Backend != "monocypher" || dt.Crypto.Hash != "sha256_sw" {
		t.Fatalf("unexpected device.toml crypto section: %+v", dt.Crypto)
	}
}

func TestInstaller_MatrixSkippedInDevAndBoundedOffline(t *testing.T) {
	root, regDir, homeDir, _ := setupTestEnv(t)

	slowSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
	}))
	defer slowSrv.Close()

	// Disable dev mode so local cache hits slow remote matrix URL; verify 2s bound holds.
	t.Setenv("TOOB_DEV", "0")
	t.Setenv("TOOB_REGISTRY_DIR", "")
	cache := registry.NewCache(slowSrv.URL)
	homeRegistry := filepath.Join(homeDir, "registry")
	_ = os.RemoveAll(homeRegistry)
	if copyErr := copyTree(regDir, homeDir, "registry"); copyErr != nil {
		t.Fatal(copyErr)
	}

	inst, err := New(root, cache)
	if err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	err = inst.AddChip("esp32c6")
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("AddChip: %v", err)
	}
	if elapsed > 3500*time.Millisecond {
		t.Fatalf("matrix fetch was not bounded by 2s timeout (elapsed=%v)", elapsed)
	}
	if err = inst.RemoveChip("esp32c6"); err != nil {
		t.Fatal(err)
	}

	// Verify list ordering helper sanity.
	listed, err := inst.List("")
	if err != nil || !slices.Equal(listed, []InstalledPackage(nil)) && len(listed) != 0 {
		t.Fatalf("expected empty list after removing chip, got %+v (err=%v)", listed, err)
	}
}
