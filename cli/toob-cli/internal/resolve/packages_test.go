package resolve

import (
	"path/filepath"
	"slices"
	"testing"

	manifestpkg "github.com/toob-boot/toob/internal/manifest"
	"github.com/toob-boot/toob/internal/registry"
)

func TestResolveDrivers(t *testing.T) {
	contract, err := loadHALContract("")
	requireNoErr(t, err)
	mode := buildMode{profile: ProfileProduction}
	t.Run("one directory per driver", func(t *testing.T) {
		fx := newFixture(t)
		dirs, _, _, err := resolveDriverPackages(fx.input(), fx.chip(), mode, contract)
		requireNoErr(t, err)
		want := []string{
			filepath.Join(fx.reg.base, "drivers", "drivers", "uart", "esp_uart_v1"),
			filepath.Join(fx.reg.base, "drivers", "drivers", "flash", "esp_flash"),
		}
		if !slices.Equal(dirs, want) {
			t.Fatalf("got %v, want %v", dirs, want)
		}
	})

	t.Run("no drivers", func(t *testing.T) {
		fx := newFixture(t)
		fx.setSpec(func(s *manifestpkg.ChipManifest) { s.Sources = nil })
		dirs, _, _, err := resolveDriverPackages(fx.input(), fx.chip(), mode, contract)
		requireNoErr(t, err)
		if len(dirs) != 0 {
			t.Fatalf("got %v, want none", dirs)
		}
	})

	t.Run("filters bound and none traits before legacy sources.drivers", func(t *testing.T) {
		fx := newFixture(t)
		fx.index.Drivers = map[string]registry.DriverInfo{
			"esp_uart_v1": {Name: "esp_uart_v1", Trait: "console", Version: "1.0.0"},
			"esp_flash":   {Name: "esp_flash", Trait: "flash", Version: "1.0.0"},
		}
		// Disable console ("none"): legacy uart/esp_uart_v1 must be skipped before resolving.
		fx.reg.fail["drivers:drivers/uart/esp_uart_v1"] = true
		fx.dev.Drivers = map[string]string{"console": "none"}
		dirs, pkgs, _, err := resolveDriverPackages(fx.input(), fx.chip(), mode, contract)
		requireNoErr(t, err)
		if len(pkgs) != 1 || pkgs[0].Name != "esp_flash" {
			t.Fatalf("expected only esp_flash after filtering 'none' console trait, got %+v (%v)", pkgs, dirs)
		}
	})

	errs := []struct{ name, file, want string }{
		{"file without directory", "console.c", "inside a driver directory"},
		{"traversal", "../x/f.c", "invalid driver name"},
		{"absolute", "/abs/f.c", "invalid driver name"},
		{"unsafe character", "drivers/a b/f.c", "invalid driver name"},
	}
	for _, tc := range errs {
		t.Run(tc.name, func(t *testing.T) {
			fx := newFixture(t)
			chip := fx.chip()
			chip.driverFiles = []string{tc.file}
			_, _, _, err := resolveDriverPackages(fx.input(), chip, mode, contract)
			requireErr(t, err, tc.want)
		})
	}

	t.Run("unresolvable", func(t *testing.T) {
		fx := newFixture(t)
		fx.reg.fail["drivers:drivers/flash/esp_flash"] = true
		_, _, _, err := resolveDriverPackages(fx.input(), fx.chip(), mode, contract)
		requireErr(t, err, "failed to resolve driver")
	})
}

func TestResolveCrypto(t *testing.T) {
	t.Run("chip defaults", func(t *testing.T) {
		fx := newFixture(t)
		slots, err := resolveCrypto(fx.input(), fx.chip(), "core/v1.0.0")
		requireNoErr(t, err)
		if len(slots) != 3 {
			t.Fatalf("expected 3 slots, got %d", len(slots))
		}
		for i, slot := range []string{slotBackend, slotHash, slotPQC} {
			if slots[i].Slot != slot {
				t.Fatalf("slot %d = %q, want %q", i, slots[i].Slot, slot)
			}
		}

		dir := filepath.Join(fx.reg.base, "crypto", "monocypher")
		backend := slots[0]
		if backend.Name != "monocypher" || backend.Dir != dir || backend.Reused {
			t.Fatalf("unexpected backend slot %+v", backend)
		}
		if want := []string{filepath.Join(dir, "src", "a.c"), filepath.Join(dir, "src", "b.c")}; !slices.Equal(backend.Sources, want) {
			t.Fatalf("Sources = %v, want %v", backend.Sources, want)
		}
		if want := []string{filepath.Join(dir, "inc")}; !slices.Equal(backend.Includes, want) {
			t.Fatalf("Includes = %v, want %v", backend.Includes, want)
		}
		if backend.Wrapper != filepath.Join(dir, "wrap", "w.c") || !slices.Equal(backend.Cflags, []string{"-DX=1"}) {
			t.Fatalf("unexpected wrapper/cflags in %+v", backend)
		}
		if slots[1].Name != "sha256_sw" || slots[1].Wrapper != "" {
			t.Fatalf("unexpected hash slot %+v", slots[1])
		}
		if slots[2].Enabled() {
			t.Fatalf("pqc slot must be disabled, got %+v", slots[2])
		}
	})

	t.Run("no chip crypto section", func(t *testing.T) {
		fx := newFixture(t)
		fx.setSpec(func(s *manifestpkg.ChipManifest) { s.Crypto = nil })
		slots, err := resolveCrypto(fx.input(), fx.chip(), "main")
		requireNoErr(t, err)
		for _, s := range slots {
			if s.Enabled() {
				t.Fatalf("slot %+v must be disabled", s)
			}
		}
	})

	t.Run("case-insensitive none disables slots", func(t *testing.T) {
		fx := newFixture(t)
		fx.dev.Crypto.Backend = "NONE"
		fx.dev.Crypto.Hash = "None"
		fx.dev.Crypto.Pqc = "none"
		slots, err := resolveCrypto(fx.input(), fx.chip(), "core/v1.0.0")
		requireNoErr(t, err)
		for _, s := range slots {
			if s.Enabled() {
				t.Fatalf("slot %+v must be disabled for none", s)
			}
		}
	})

	t.Run("device overrides chip and marks reuse", func(t *testing.T) {
		fx := newFixture(t)
		fx.index.Crypto["unified_crypto"] = registry.CryptoInfo{
			Version:         "1.0.0",
			Category:        []string{"backend", "hash", "pqc"},
			UpstreamSources: []string{"all.c"},
		}
		fx.dev.Crypto.Backend = "unified_crypto"
		fx.dev.Crypto.Hash = "unified_crypto"
		fx.dev.Crypto.Pqc = "unified_crypto"
		slots, err := resolveCrypto(fx.input(), fx.chip(), "core/v1.0.0")
		requireNoErr(t, err)
		if slots[0].Name != "unified_crypto" || slots[0].Reused {
			t.Fatalf("first use must be emitted: %+v", slots[0])
		}
		if !slots[1].Reused || !slots[2].Reused {
			t.Fatalf("later uses must be marked reused: %+v, %+v", slots[1], slots[2])
		}
		if !(&Plan{Crypto: slots}).PQCEnabled() {
			t.Fatal("PQCEnabled must be true when the pqc slot selects a package")
		}
	})

	t.Run("slot category mismatch rejected", func(t *testing.T) {
		fx := newFixture(t)
		fx.dev.Crypto.Backend = "sha256_sw"
		_, err := resolveCrypto(fx.input(), fx.chip(), "core/v1.0.0")
		requireErr(t, err, "cannot satisfy slot")
	})

	t.Run("chip_binding StringOrSlice array supported", func(t *testing.T) {
		fx := newFixture(t)
		cDir := filepath.Join(fx.reg.base, "crypto", "monocypher")
		fx.writeJSON(filepath.Join(cDir, cryptoManifestFile), map[string]any{
			"name":         "monocypher",
			"version":      "1.0.0",
			"category":     []string{"backend"},
			"chip_binding": []string{"esp32c3", testChip},
		})
		_, err := resolveCrypto(fx.input(), fx.chip(), "core/v1.0.0")
		requireNoErr(t, err)
	})

	errs := []struct {
		name  string
		setup func(fx *fixture)
		want  string
	}{
		{"unknown package", func(fx *fixture) { fx.dev.Crypto.Backend = "nope" }, "not found in the registry index"},
		{"unsafe name", func(fx *fixture) { fx.dev.Crypto.Backend = "a b" }, "invalid crypto package name"},
		{"newer Core SDK required", func(fx *fixture) {
			fx.setCrypto("monocypher", func(c *registry.CryptoInfo) { c.MinCoreSdk = "v9.0.0" })
		}, "requires Core SDK >= v9.0.0"},
		{"chip binding mismatch", func(fx *fixture) {
			fx.setCrypto("monocypher", func(c *registry.CryptoInfo) { c.ChipBinding = []string{"other"} })
		}, "chip-bound"},
		{"package not fetchable", func(fx *fixture) { fx.reg.fail["crypto:monocypher"] = true }, "is not available"},
		{"source escapes package", func(fx *fixture) {
			fx.setCrypto("monocypher", func(c *registry.CryptoInfo) { c.UpstreamSources = []string{"../x.c"} })
		}, "upstream_sources"},
		{"absolute include", func(fx *fixture) {
			fx.setCrypto("monocypher", func(c *registry.CryptoInfo) { c.Includes = []string{"/abs"} })
		}, "includes"},
		{"wrapper escapes package", func(fx *fixture) {
			fx.setCrypto("monocypher", func(c *registry.CryptoInfo) { w := "../w.c"; c.Wrapper = &w })
		}, "wrapper"},
	}
	for _, tc := range errs {
		t.Run(tc.name, func(t *testing.T) {
			fx := newFixture(t)
			tc.setup(fx)
			_, err := resolveCrypto(fx.input(), fx.chip(), "core/v1.0.0")
			requireErr(t, err, tc.want)
		})
	}

	t.Run("chip binding match", func(t *testing.T) {
		fx := newFixture(t)
		fx.setCrypto("monocypher", func(c *registry.CryptoInfo) { c.ChipBinding = []string{testChip} })
		_, err := resolveCrypto(fx.input(), fx.chip(), "core/v1.0.0")
		requireNoErr(t, err)
	})

	t.Run("empty wrapper is none", func(t *testing.T) {
		fx := newFixture(t)
		fx.setCrypto("monocypher", func(c *registry.CryptoInfo) { w := ""; c.Wrapper = &w })
		slots, err := resolveCrypto(fx.input(), fx.chip(), "core/v1.0.0")
		requireNoErr(t, err)
		if slots[0].Wrapper != "" {
			t.Fatalf("Wrapper = %q, want none", slots[0].Wrapper)
		}
	})

	t.Run("disk crypto_manifest.json overrides index fields and falls back to index author/tier", func(t *testing.T) {
		fx := newFixture(t)
		fx.setCrypto("monocypher", func(c *registry.CryptoInfo) {
			c.Author = "toob-core-team"
			c.Tier = "official"
		})
		monoDir := filepath.Join(fx.reg.base, "crypto", "monocypher")
		diskJSON := `{
			"name": "monocypher",
			"version": "1.3.0",
			"abi_version": "v3",
			"category": ["backend"],
			"min_core_sdk": "core/v1.0.0",
			"wrapper": "crypto_monocypher.c",
			"upstream_sources": ["monocypher.c"],
			"headers": ["crypto_monocypher.h"],
			"includes": ["include"],
			"symbols": {
				"init": "crypto_monocypher_init",
				"deinit": "crypto_monocypher_deinit",
				"verify_signature": "crypto_monocypher_verify_signature"
			},
			"cflags": ["-Os"],
			"footprint": {
				"flash_estimate_bytes": 28000,
				"ram_estimate_bytes": 128
			}
		}`
		fx.touch(filepath.Join(monoDir, "crypto_monocypher.c"))
		fx.touch(filepath.Join(monoDir, "monocypher.c"))
		fx.touch(filepath.Join(monoDir, "crypto_monocypher.h"))
		if err := fx.writeRaw(filepath.Join(monoDir, "crypto_manifest.json"), diskJSON); err != nil {
			t.Fatal(err)
		}

		slots, err := resolveCrypto(fx.input(), fx.chip(), "core/v1.0.0")
		requireNoErr(t, err)
		got := slots[0]
		if got.Tier != "official" || got.Local {
			t.Fatalf("expected official non-local tier fallback from index, got %+v", got)
		}
		if got.Wrapper != filepath.Join(monoDir, "crypto_monocypher.c") {
			t.Fatalf("Wrapper = %q, want disk manifest wrapper", got.Wrapper)
		}
		if want := []string{filepath.Join(monoDir, "monocypher.c")}; !slices.Equal(got.Sources, want) {
			t.Fatalf("Sources = %v, want %v", got.Sources, want)
		}
		if want := []string{filepath.Join(monoDir, "include")}; !slices.Equal(got.Includes, want) {
			t.Fatalf("Includes = %v, want %v", got.Includes, want)
		}
		if !slices.Equal(got.Cflags, []string{"-Os"}) {
			t.Fatalf("Cflags = %v, want [-Os]", got.Cflags)
		}
	})

	t.Run("local override crypto package without registry.json entry", func(t *testing.T) {
		fx := newFixture(t)
		localDir := filepath.Join(fx.root, localHalDir, "crypto", "custom_ed25519")
		fx.touch(filepath.Join(localDir, "wrap.c"))
		fx.touch(filepath.Join(localDir, "ed.c"))
		fx.touch(filepath.Join(localDir, "custom_ed25519.h"))
		localManifest := `{
			"name": "custom_ed25519",
			"version": "0.1.0",
			"abi_version": "v3",
			"category": ["backend"],
			"wrapper": "wrap.c",
			"upstream_sources": ["ed.c"],
			"headers": ["custom_ed25519.h"],
			"symbols": {
				"init": "custom_ed_init",
				"deinit": "custom_ed_deinit",
				"verify_signature": "custom_ed_verify"
			},
			"cflags": ["-O2"]
		}`
		if err := fx.writeRaw(filepath.Join(localDir, "crypto_manifest.json"), localManifest); err != nil {
			t.Fatal(err)
		}
		fx.dev.Crypto.Backend = "custom_ed25519"

		slots, err := resolveCrypto(fx.input(), fx.chip(), "core/v1.0.0")
		requireNoErr(t, err)
		got := slots[0]
		if !got.Local || got.Tier != "local" || got.Dir != localDir {
			t.Fatalf("expected local crypto override at %s, got %+v", localDir, got)
		}
		if got.Wrapper != filepath.Join(localDir, "wrap.c") {
			t.Fatalf("Wrapper = %q, want %q", got.Wrapper, filepath.Join(localDir, "wrap.c"))
		}
	})

	t.Run("crypto_manifest.json rejects invalid symbols and escaping headers", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			raw  string
			want string
		}{
			{
				name: "invalid C symbol",
				raw:  `{"name":"monocypher","headers":["ok.h"],"symbols":{"init":"evil;sym()"}}`,
				want: "invalid C symbol",
			},
			{
				name: "C keyword symbol",
				raw:  `{"name":"monocypher","headers":["ok.h"],"symbols":{"init":"static"}}`,
				want: "invalid C symbol",
			},
			{
				name: "escaping header",
				raw:  `{"name":"monocypher","headers":["../evil.h"],"symbols":{"init":"ok_init"}}`,
				want: "header",
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				fx := newFixture(t)
				monoDir := filepath.Join(fx.reg.base, "crypto", "monocypher")
				if err := fx.writeRaw(filepath.Join(monoDir, "crypto_manifest.json"), tc.raw); err != nil {
					t.Fatal(err)
				}
				_, err := resolveCrypto(fx.input(), fx.chip(), "core/v1.0.0")
				requireErr(t, err, tc.want)
			})
		}
	})
}

func resolveRecovery(in Input, chip *Chip) (Recovery, error) {
	contract, err := loadHALContract(in.CoreDir)
	if err != nil {
		return Recovery{}, err
	}
	mode, err := resolveBuildMode(in, contract)
	if err != nil {
		return Recovery{}, err
	}
	return resolveRecoveryWithMode(in, chip, mode, "", "", contract)
}

func chipIncludes(in Input, chip *Chip) ([]string, error) {
	return chipIncludesWithFallback(in, chip, "", "")
}

func TestResolveRecovery(t *testing.T) {
	t.Run("chip mapping", func(t *testing.T) {
		fx := newFixture(t)
		chip := fx.chip()
		rec, err := resolveRecovery(fx.input(), chip)
		requireNoErr(t, err)

		if !rec.Declared || rec.Backend != "none" || rec.Hash != "sha256_sw" {
			t.Fatalf("unexpected recovery %+v", rec)
		}
		drivers := filepath.Join(fx.reg.base, "drivers")
		if want := []string{filepath.Join(drivers, "uart", "esp_uart_v1"), filepath.Join(drivers, "flash", "esp_flash")}; !slices.Equal(rec.Drivers, want) {
			t.Fatalf("Drivers = %v, want %v", rec.Drivers, want)
		}
		if want := []string{filepath.Join(chip.Dir, "recovery", "main.c")}; !slices.Equal(rec.Sources, want) {
			t.Fatalf("Sources = %v, want %v", rec.Sources, want)
		}
		want := []string{
			filepath.Join(fx.reg.base, "soc", "esp", "include"),
			filepath.Join(chip.Dir, "include"),
			filepath.Join(chip.Dir, "recovery", "inc"),
		}
		if !slices.Equal(rec.Includes, want) {
			t.Fatalf("Includes = %v, want %v", rec.Includes, want)
		}
	})

	t.Run("optional drivers keep role order", func(t *testing.T) {
		fx := newFixture(t)
		fx.setSpec(func(s *manifestpkg.ChipManifest) {
			s.Recovery.WDT, s.Recovery.Clock, s.Recovery.RTC = "wdt/a", "clk/b", "rtc/c"
		})
		fx.dev.Recovery.Console = "uart/override"
		rec, err := resolveRecovery(fx.input(), fx.chip())
		requireNoErr(t, err)

		var names []string
		for _, d := range rec.Drivers {
			names = append(names, filepath.ToSlash(d[len(filepath.Join(fx.reg.base, "drivers"))+1:]))
		}
		if want := []string{"uart/override", "flash/esp_flash", "wdt/a", "clk/b", "rtc/c"}; !slices.Equal(names, want) {
			t.Fatalf("driver order = %v, want %v", names, want)
		}
	})

	t.Run("project sources and includes", func(t *testing.T) {
		fx := newFixture(t)
		fx.dev.Recovery.Sources = []string{"src/hook.c"}
		fx.dev.Recovery.Includes = []string{"inc"}
		rec, err := resolveRecovery(fx.input(), fx.chip())
		requireNoErr(t, err)
		if got := rec.Sources[len(rec.Sources)-1]; got != filepath.Join(fx.root, "src", "hook.c") {
			t.Fatalf("project source = %q", got)
		}
		if got := rec.Includes[len(rec.Includes)-1]; got != filepath.Join(fx.root, "inc") {
			t.Fatalf("project include = %q", got)
		}
	})

	t.Run("chip without recovery mapping", func(t *testing.T) {
		fx := newFixture(t)
		fx.setSpec(func(s *manifestpkg.ChipManifest) { s.Recovery = nil })
		rec, err := resolveRecovery(fx.input(), fx.chip())
		requireNoErr(t, err)
		if rec.Declared || len(rec.Drivers) != 0 || rec.Backend != "monocypher" || rec.Hash != "sha256_sw" {
			t.Fatalf("unexpected recovery %+v", rec)
		}
	})

	t.Run("device.toml recovery populated when chip.recovery is nil (MED-72)", func(t *testing.T) {
		fx := newFixture(t)
		fx.setSpec(func(s *manifestpkg.ChipManifest) { s.Recovery = nil })
		rtcDir := filepath.Join(fx.reg.base, "drivers", "rtc_c")
		fx.writeJSON(filepath.Join(rtcDir, driverManifestFile), manifestpkg.DriverManifest{
			Name: "rtc_c", Trait: "confirm",
		})
		fx.dev.Recovery.Console = "uart/esp_uart_v1"
		fx.dev.Recovery.Flash = "flash/esp_flash"
		fx.dev.Recovery.RTC = "rtc_c"
		rec, err := resolveRecovery(fx.input(), fx.chip())
		requireNoErr(t, err)
		if !rec.Declared || len(rec.Drivers) != 3 {
			t.Fatalf("expected recovery declared with 3 drivers when chip.recovery==nil and device.toml [recovery] populated, got %+v", rec)
		}
	})

	t.Run("recovery validates driver_manifest trait", func(t *testing.T) {
		fx := newFixture(t)
		badDir := filepath.Join(fx.reg.base, "drivers", "uart", "esp_uart_v1")
		fx.writeJSON(filepath.Join(badDir, driverManifestFile), manifestpkg.DriverManifest{
			Name: "esp_uart_v1", Trait: "wdt",
		})
		_, err := resolveRecovery(fx.input(), fx.chip())
		requireErr(t, err, "cannot bind to recovery trait")
	})

	precedence := []struct {
		name  string
		setup func(fx *fixture)
		want  [2]string
	}{
		{"chip recovery crypto", func(fx *fixture) {}, [2]string{"none", "sha256_sw"}},
		{"device recovery crypto wins", func(fx *fixture) {
			fx.dev.Recovery.Crypto.Backend, fx.dev.Recovery.Crypto.Hash = "ROM", "h1"
		}, [2]string{"rom", "h1"}},
		{"device crypto beats chip crypto", func(fx *fixture) {
			fx.setSpec(func(s *manifestpkg.ChipManifest) { s.Recovery.Crypto = nil })
			fx.dev.Crypto.Backend, fx.dev.Crypto.Hash = "foo", "bar"
		}, [2]string{"foo", "bar"}},
		{"chip crypto is the last resort", func(fx *fixture) {
			fx.setSpec(func(s *manifestpkg.ChipManifest) { s.Recovery.Crypto = nil })
		}, [2]string{"monocypher", "sha256_sw"}},
	}
	for _, tc := range precedence {
		t.Run(tc.name, func(t *testing.T) {
			fx := newFixture(t)
			tc.setup(fx)
			rec, err := resolveRecovery(fx.input(), fx.chip())
			requireNoErr(t, err)
			if got := [2]string{rec.Backend, rec.Hash}; got != tc.want {
				t.Fatalf("backend/hash = %v, want %v", got, tc.want)
			}
		})
	}

	errs := []struct {
		name  string
		setup func(fx *fixture)
		want  string
	}{
		{"missing console", func(fx *fixture) { fx.setSpec(func(s *manifestpkg.ChipManifest) { s.Recovery.Console = "" }) }, "'console'"},
		{"missing flash", func(fx *fixture) { fx.setSpec(func(s *manifestpkg.ChipManifest) { s.Recovery.Flash = "" }) }, "'flash'"},
		{"unsafe driver", func(fx *fixture) { fx.dev.Recovery.Console = "../x" }, "invalid recovery driver name"},
		{"unresolvable driver", func(fx *fixture) { fx.reg.fail["drivers:flash/esp_flash"] = true }, "failed to resolve recovery driver"},
		{"unsafe crypto backend", func(fx *fixture) { fx.dev.Recovery.Crypto.Backend = "a b" }, "invalid recovery crypto backend name"},
		{"unsafe crypto hash", func(fx *fixture) { fx.dev.Recovery.Crypto.Hash = "a;b" }, "invalid recovery crypto hash name"},
		{"chip source escapes package", func(fx *fixture) {
			fx.setSpec(func(s *manifestpkg.ChipManifest) { s.Recovery.Sources = []string{"../x.c"} })
		}, "recovery sources of chip"},
		{"chip include escapes package", func(fx *fixture) {
			fx.setSpec(func(s *manifestpkg.ChipManifest) { s.Recovery.Includes = []string{"../x"} })
		}, "recovery includes of chip"},
		{"chip-wide include escapes", func(fx *fixture) {
			fx.setSpec(func(s *manifestpkg.ChipManifest) { s.Includes = []string{"soc/../../x"} })
		}, "includes of chip"},
		{"project source escapes root", func(fx *fixture) { fx.dev.Recovery.Sources = []string{"../x.c"} }, "[recovery] sources"},
		{"project include is absolute", func(fx *fixture) { fx.dev.Recovery.Includes = []string{"/abs"} }, "[recovery] includes"},
	}
	for _, tc := range errs {
		t.Run(tc.name, func(t *testing.T) {
			fx := newFixture(t)
			tc.setup(fx)
			_, err := resolveRecovery(fx.input(), fx.chip())
			requireErr(t, err, tc.want)
		})
	}
}

func TestChipIncludesBase(t *testing.T) {
	fx := newFixture(t)
	fx.setSpec(func(s *manifestpkg.ChipManifest) {
		s.Includes = []string{"soc/s", "arch/a", "drivers/d", "plain", "sub/dir"}
	})
	chip := fx.chip()
	got, err := chipIncludes(fx.input(), chip)
	requireNoErr(t, err)

	want := []string{
		filepath.Join(fx.reg.base, "soc", "s"),
		filepath.Join(fx.reg.base, "arch", "a"),
		filepath.Join(fx.reg.base, "drivers", "d"),
		filepath.Join(chip.Dir, "plain"),
		filepath.Join(chip.Dir, "sub", "dir"),
	}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}

	// Without explicit HalRoot/Registry, shared includes fail rather than guessing '..'.
	if _, err := chipIncludes(Input{}, chip); err == nil {
		t.Fatal("expected missing HAL root error for shared include without HalRoot or Registry")
	}
}

func TestResolveHalBindingsMockAndTiers(t *testing.T) {
	fx := newFixture(t)
	fx.index.Drivers = map[string]registry.DriverInfo{
		"esp_efuse":         {Name: "esp_efuse", Path: "drivers/keystore/esp_efuse", Version: "1.0.0", Trait: "keystore", Tier: "official"},
		"@partner/atecc608": {Name: "@partner/atecc608", Path: "drivers/keystore/atecc608", Version: "2.1.0", Trait: "keystore", Tier: "partner"},
		"@community/jtag":   {Name: "@community/jtag", Path: "drivers/uart/jtag", Version: "0.3.0", Trait: "console"},
	}

	efuseDir := filepath.Join(fx.reg.base, "drivers", "esp_efuse")
	fx.touch(filepath.Join(efuseDir, "efuse_real.c"))
	fx.touch(filepath.Join(efuseDir, "efuse_mock.c"))
	fx.writeJSON(filepath.Join(efuseDir, "driver_manifest.json"), manifestpkg.DriverManifest{
		Name: "esp_efuse", Trait: "keystore", Tier: "official",
		Sources: []string{"efuse_real.c"}, MockSources: []string{"efuse_mock.c"},
	})

	fx.setSpec(func(s *manifestpkg.ChipManifest) {
		s.HalBindings = map[string]string{"keystore": "esp_efuse"}
		s.Sources = &manifestpkg.ChipSources{
			Startup: "startup.c",
			Drivers: []string{"drivers/keystore/esp_efuse/efuse_real.c"},
		}
	})

	t.Run("dev profile selects mock_sources by default for keystore and provisioning", func(t *testing.T) {
		plan, err := Resolve(fx.input())
		requireNoErr(t, err)
		if plan.Profile != ProfileDev || !plan.MockHW {
			t.Fatalf("expected dev profile with MockHW=true, got profile=%q mockHW=%v", plan.Profile, plan.MockHW)
		}
		wantSrc := []string{filepath.Join(efuseDir, "efuse_mock.c")}
		if !slices.Equal(plan.DriverSources, wantSrc) {
			t.Fatalf("DriverSources = %v, want %v", plan.DriverSources, wantSrc)
		}
		if len(plan.DriverPackages) != 1 || plan.DriverPackages[0].Tier != "official" || !plan.DriverPackages[0].Mocked {
			t.Fatalf("unexpected DriverPackages: %+v", plan.DriverPackages)
		}

		// Verify contract-derived security mocks include keystore, otp, and provisioning (HIGH-93).
		contract, cErr := loadHALContract("")
		requireNoErr(t, cErr)
		bm, bErr := resolveBuildMode(fx.input(), contract)
		requireNoErr(t, bErr)
		for _, trait := range []string{"keystore", "otp", "provisioning"} {
			if !bm.shouldMock(trait) {
				t.Errorf("expected contract-derived dev mock for security trait %q", trait)
			}
		}
	})

	t.Run("production profile selects real sources and forbids mock override", func(t *testing.T) {
		in := fx.input()
		in.Profile = ProfileProduction
		plan, err := Resolve(in)
		requireNoErr(t, err)
		if plan.Profile != ProfileProduction || plan.MockHW {
			t.Fatalf("expected production profile with MockHW=false, got profile=%q mockHW=%v", plan.Profile, plan.MockHW)
		}
		wantSrc := []string{filepath.Join(efuseDir, "efuse_real.c")}
		if !slices.Equal(plan.DriverSources, wantSrc) {
			t.Fatalf("DriverSources = %v, want %v", plan.DriverSources, wantSrc)
		}

		in.MockSet = true
		in.MockOverrides = []string{"keystore"}
		if _, err := Resolve(in); err == nil {
			t.Fatal("expected error when enabling mocks in production profile")
		}
	})

	t.Run("device.toml [drivers] overrides default binding and classifies partner/community/local tiers", func(t *testing.T) {
		partnerDir := filepath.Join(fx.reg.base, "drivers", "@partner", "atecc608")
		fx.touch(filepath.Join(partnerDir, "atecc608.c"))
		fx.writeJSON(filepath.Join(partnerDir, "driver_manifest.json"), manifestpkg.DriverManifest{
			Name: "@partner/atecc608", Trait: "keystore", Tier: "partner",
			Sources: []string{"atecc608.c"},
		})

		commDir := filepath.Join(fx.reg.base, "drivers", "@community", "jtag")
		fx.touch(filepath.Join(commDir, "jtag_real.c"))
		fx.touch(filepath.Join(commDir, "jtag_mock.c"))

		localFlashDir := filepath.Join(fx.root, localHalDir, "drivers", "flash", "my_flash")
		fx.touch(filepath.Join(localFlashDir, "my_flash.c"))

		fx.dev.Drivers = map[string]string{
			"keystore": "@partner/atecc608",
			"console":  "@community/jtag",
			"flash":    "my_flash",
		}
		in := fx.input()
		in.Profile = ProfileProduction
		plan, err := Resolve(in)
		requireNoErr(t, err)

		tiers := make(map[string]string)
		for _, dp := range plan.DriverPackages {
			tiers[dp.Trait] = dp.Tier
		}
		if tiers["keystore"] != "partner" || tiers["console"] != "community" || tiers["flash"] != "local" {
			t.Fatalf("unexpected driver tiers: %v (packages: %+v)", tiers, plan.DriverPackages)
		}
		for _, src := range plan.DriverSources {
			if filepath.Base(src) == "efuse_real.c" || filepath.Base(src) == "jtag_mock.c" {
				t.Fatalf("unexpected source %s in production DriverSources: %v", src, plan.DriverSources)
			}
		}
	})
}
