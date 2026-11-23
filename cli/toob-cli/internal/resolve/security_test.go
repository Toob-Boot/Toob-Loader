package resolve

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/toob-boot/toob/internal/lockfile"
	manifestpkg "github.com/toob-boot/toob/internal/manifest"
	"github.com/toob-boot/toob/internal/registry"
)

func makeDirLink(t *testing.T, target, link string) {
	t.Helper()
	err := os.Symlink(target, link)
	if err == nil {
		return
	}
	if runtime.GOOS != "windows" {
		t.Skipf("cannot create symlink: %v", err)
	}
	out, jErr := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput()
	if jErr != nil {
		t.Skipf("cannot create directory symlink (%v) or junction (%v: %s)", err, jErr, out)
	}
}

func TestSecurityCMakeInjectionBlocked(t *testing.T) {
	plan := testPlan()
	plan.Chip.Dir = `c:\Users\dev\Toob-Loader\hal\chips\esp32c6`
	plan.Crypto = []CryptoSlot{
		{
			Slot:    "BACKEND)\nexecute_process(COMMAND calc)\nset(FOO",
			Name:    "mono\nexecute_process(COMMAND calc)",
			Dir:     `c:\Users\dev\crypto\mono`,
			Sources: []string{`c:\Users\dev\crypto\mono\monocypher.c`},
		},
		{
			Slot:   slotHash,
			Name:   "mono\nexecute_process(COMMAND calc)",
			Dir:    `c:\Users\dev\crypto\mono`,
			Reused: true,
		},
	}

	out := plan.RenderConfig(SDKPaths{
		Bootloader: `c:\Users\dev\Toob-Loader\toobloader`,
		Core:       `c:\Users\dev\Toob-Loader\toobloader\core`,
		Stage0:     `c:\Users\dev\Toob-Loader\toobloader\stage0`,
		SDK:        `c:\Users\dev\Toob-Loader\sdk`,
	}, `c:\Users\dev\bin\toob.exe`)

	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "execute_process") {
			t.Fatalf("CMake command injection succeeded on standalone line:\n%s", out)
		}
	}
	if !strings.Contains(out, `set(TOOB_HAL_CHIP_DIR "c:/Users/dev/Toob-Loader/hal/chips/esp32c6")`) {
		t.Fatalf("Windows path normalization broken in RenderConfig:\n%s", out)
	}
}

func TestSecurityCryptoCflagsAllowlist(t *testing.T) {
	allowed := [][]string{
		{"-Os"},
		{"-O3", "-fno-strict-aliasing"},
		{"-O2", "-Wall", "-Wextra", "-Wno-unused-parameter", "-std=c11", "-DMONOCYPHER_CPP_NAMESPACE=mc"},
	}
	for _, flags := range allowed {
		fx := newFixture(t)
		fx.setCrypto("monocypher", func(c *registry.CryptoInfo) { c.Cflags = flags })
		if _, err := resolveCrypto(fx.input(), fx.chip(), "core/v1.0.0"); err != nil {
			t.Errorf("legitimate cflags %v rejected: %v", flags, err)
		}
	}

	malicious := []string{
		"-fplugin=/tmp/evil.so",
		"-include/etc/passwd",
		"-I/outside/include",
		"@/tmp/evil.rsp",
		"-Wp,-include,/etc/passwd",
		"-Wl,--defsym,main=evil",
		"-Wa,-I/outside",
		"-DTOOB_MOCK_HW=1",
		"-DBOOT_STAGE1_SVN=0",
		"-DCHIP_FLASH_TOTAL_SIZE=0",
		"-D__STDC__=0",
		"-Dif=while",
		"-DX=system(1)",
		"source.c",
	}
	for _, bad := range malicious {
		fx := newFixture(t)
		fx.setCrypto("monocypher", func(c *registry.CryptoInfo) { c.Cflags = []string{bad} })
		if _, err := resolveCrypto(fx.input(), fx.chip(), "core/v1.0.0"); err == nil {
			t.Errorf("malicious cflag %q must be rejected", bad)
		}
	}
}

func TestSecurityTraversalAndSymlinkEscapes(t *testing.T) {
	t.Run("Contain blocks symlink/junction escape", func(t *testing.T) {
		root := t.TempDir()
		pkgDir := filepath.Join(root, "pkg")
		outsideDir := filepath.Join(root, "outside")
		for _, d := range []string{pkgDir, outsideDir} {
			if err := os.MkdirAll(d, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		makeDirLink(t, outsideDir, filepath.Join(pkgDir, "link_out"))
		if _, err := Contain(pkgDir, "link_out/evil.c"); err == nil {
			t.Fatal("Contain must reject symlink/junction escaping base directory")
		}
	})

	t.Run("chip_manifest.json hal_bindings trait traversal rejected", func(t *testing.T) {
		fx := newFixture(t)
		fx.setSpec(func(s *manifestpkg.ChipManifest) {
			s.HalBindings = map[string]string{"../../outside": "esp_uart_v1"}
		})
		if _, err := fx.resolve(); err == nil {
			t.Fatal("expected traversal in hal_bindings trait key to be rejected")
		}
	})

	t.Run("registry index driver path traversal out of localHalDir rejected", func(t *testing.T) {
		fx := newFixture(t)
		fx.index.Drivers = map[string]registry.DriverInfo{
			"esp_efuse": {Name: "esp_efuse", Path: "../../../outside", Trait: "keystore"},
		}
		fx.setSpec(func(s *manifestpkg.ChipManifest) {
			s.HalBindings = map[string]string{"keystore": "esp_efuse"}
		})
		if _, err := fx.resolve(); err == nil {
			t.Fatal("expected escaping index driver path to be rejected")
		}
	})

	t.Run("chip_manifest.json startup/linker/extra traversal rejected", func(t *testing.T) {
		for _, mutate := range []func(*manifestpkg.ChipManifest){
			func(s *manifestpkg.ChipManifest) { s.Sources = &manifestpkg.ChipSources{Startup: "../escape.S"} },
			func(s *manifestpkg.ChipManifest) { s.Sources = &manifestpkg.ChipSources{Linker: "../escape.ld"} },
			func(s *manifestpkg.ChipManifest) { s.Sources = &manifestpkg.ChipSources{Hardware: "../escape.json"} },
			func(s *manifestpkg.ChipManifest) {
				s.Sources = &manifestpkg.ChipSources{Extra: []string{"../escape.c"}}
			},
		} {
			fx := newFixture(t)
			fx.setSpec(mutate)
			if _, err := resolveChip(fx.input()); err == nil {
				t.Fatal("expected escaping path in chip_manifest.json sources to fail")
			}
		}
	})

	t.Run("driver_manifest.json duplicate keys and invalid headers rejected", func(t *testing.T) {
		fx := newFixture(t)
		drvDir := filepath.Join(fx.reg.base, "drivers", "esp_efuse")
		if err := os.MkdirAll(drvDir, 0o755); err != nil {
			t.Fatal(err)
		}
		dupManifest := `{"name":"esp_efuse","trait":"keystore","trait":"console","sources":["a.c"]}`
		if err := os.WriteFile(filepath.Join(drvDir, "driver_manifest.json"), []byte(dupManifest), 0o644); err != nil {
			t.Fatal(err)
		}
		fx.setSpec(func(s *manifestpkg.ChipManifest) {
			s.HalBindings = map[string]string{"keystore": "esp_efuse"}
		})
		if _, err := fx.resolve(); err == nil || !strings.Contains(err.Error(), "duplicate JSON key") {
			t.Fatalf("expected duplicate JSON key rejection in driver_manifest.json, got %v", err)
		}

		badHeaderManifest := `{"name":"esp_efuse","trait":"keystore","headers":["../evil.h"],"sources":["a.c"]}`
		if err := os.WriteFile(filepath.Join(drvDir, "driver_manifest.json"), []byte(badHeaderManifest), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := fx.resolve(); err == nil {
			t.Fatal("expected escaping header in driver_manifest.json to fail")
		}
	})

	t.Run("nil Lockfile or nil Device does not panic", func(t *testing.T) {
		if _, err := Resolve(Input{}); err == nil {
			t.Fatal("expected clean error on empty Input")
		}
		fx := newFixture(t)
		in := fx.input()
		in.Lock = nil
		if _, err := Resolve(in); err != nil {
			t.Fatalf("Resolve with nil Lockfile must succeed without panic, got %v", err)
		}
	})
}

func TestSecurityScopedPackagesAndRealESP32C6Plan(t *testing.T) {
	regJSONPath := filepath.Clean(filepath.Join("..", "..", "..", "..", "toob-infra", "registry", "packages", "registry.json"))
	espChipDir := filepath.Clean(filepath.Join("..", "..", "..", "..", "toob-infra", "registry", "packages", "chips", "esp32c6"))
	if _, err := os.Stat(regJSONPath); err != nil {
		t.Skipf("registry.json not present at %s: %v", regJSONPath, err)
	}

	rawIdx, err := os.ReadFile(regJSONPath)
	if err != nil {
		t.Fatal(err)
	}
	var idx registry.Index
	if idxErr := json.Unmarshal(rawIdx, &idx); idxErr != nil {
		t.Fatalf("json.Unmarshal(registry.json) failed: %v", idxErr)
	}

	// Add scoped partner/community crypto & driver packages to verify @scope/name support end-to-end.
	if idx.Crypto == nil {
		idx.Crypto = map[string]registry.CryptoInfo{}
	}
	idx.Crypto["@partner/ed25519_hw"] = registry.CryptoInfo{
		Name:            "@partner/ed25519_hw",
		Tier:            "partner",
		Category:        []string{"backend"},
		UpstreamSources: []string{"ed25519_hw.c"},
		Cflags:          []string{"-O2"},
	}

	fake := &fakeSource{base: t.TempDir(), socOK: true, fail: map[string]bool{}}
	// Copy real ESP32-C6 chip manifest & hardware.json into fake registry chip dir alongside dummy TUs.
	targetChipDir := filepath.Join(fake.base, "chips", "esp32c6")
	if mkErr := os.MkdirAll(filepath.Join(targetChipDir, "recovery"), 0o755); mkErr != nil {
		t.Fatal(mkErr)
	}
	for _, fn := range []string{"hardware.json", "chip_manifest.json"} {
		raw, readErr := os.ReadFile(filepath.Join(espChipDir, fn))
		if readErr != nil {
			t.Fatal(readErr)
		}
		if wrErr := os.WriteFile(filepath.Join(targetChipDir, fn), raw, 0o644); wrErr != nil {
			t.Fatal(wrErr)
		}
	}
	if tcMkErr := os.MkdirAll(filepath.Join(fake.base, "toolchains", "riscv32-esp-elf"), 0o755); tcMkErr != nil {
		t.Fatal(tcMkErr)
	}
	if tcWrErr := os.WriteFile(filepath.Join(fake.base, "toolchains", "riscv32-esp-elf", "toolchain.cmake"), []byte("# ok\n"), 0o644); tcWrErr != nil {
		t.Fatal(tcWrErr)
	}

	dev := &manifestpkg.DeviceToml{}
	dev.Device.Chip = "esp32c6"
	dev.Build.CoreSDK = "core/v0.1.0"
	dev.Crypto.Backend = "@partner/ed25519_hw"
	dev.Recovery.Crypto.Backend = "@partner/ed25519_hw"

	plan, err := Resolve(Input{
		Root:     t.TempDir(),
		Device:   dev,
		Lock:     &lockfile.Lockfile{},
		Index:    &idx,
		Registry: fake,
	})
	if err != nil {
		t.Fatalf("ESP32-C6 Resolve with scoped package failed: %v", err)
	}
	cmakeOut := plan.RenderConfig(SDKPaths{
		Bootloader: "c:/Users/robin/Desktop/Toob-Loader/toobloader",
		Core:       "c:/Users/robin/Desktop/Toob-Loader/toobloader/core",
		Stage0:     "c:/Users/robin/Desktop/Toob-Loader/toobloader/stage0",
		SDK:        "c:/Users/robin/Desktop/Toob-Loader/sdk",
	}, "c:/Users/robin/Desktop/Toob-Loader/bin/toob.exe")

	if !strings.Contains(cmakeOut, `set(TOOB_CRYPTO_BACKEND_NAME "@partner/ed25519_hw")`) {
		t.Fatalf("missing scoped crypto backend in rendered CMake config:\n%s", cmakeOut)
	}
	if !strings.Contains(cmakeOut, `set(TOOB_RECOVERY_CRYPTO_BACKEND "@partner/ed25519_hw")`) {
		t.Fatalf("missing scoped recovery crypto backend in rendered CMake config:\n%s", cmakeOut)
	}
}
