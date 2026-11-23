package resolve

import (
	"strings"
	"testing"

	manifestpkg "github.com/toob-boot/toob/internal/manifest"
)

func testPlan() *Plan {
	return &Plan{
		HalRoot: "/hal",
		Chip: Chip{
			Name: "chip", Arch: "riscv", Prefix: "riscv32-esp-elf-", Dir: "/hal/chips/chip",
			Spec: &manifestpkg.ChipManifest{
				CompilerFlags: &manifestpkg.CompilerFlags{
					CFlags: []string{"-march=rv32imac"},
				},
			},
		},
		Arch:         Arch{Name: "riscv", Dir: "/hal/arch/riscv"},
		Toolchain:    Toolchain{Name: "riscv32-esp-elf", CompilerBinary: "riscv32-esp-elf-gcc"},
		SoCDir:       "/hal/soc/esp",
		ArchFlags:    []string{"-mabi=ilp32", "-march=rv32imac"},
		ChipCFlags:   []string{"-mabi=ilp32", "-march=rv32imac"},
		ChipAsmFlags: []string{"-mabi=ilp32"},
		ChipLDFlags:  []string{"-nostdlib"},
		ChipStartup:  "/hal/chips/chip/startup.c",
		ChipLinker:   "/hal/chips/chip/link.ld",
		Drivers:      []string{"/hal/drivers/a", "/hal/drivers/b"},
		Crypto: []CryptoSlot{
			{
				Slot: slotBackend, Name: "mono", Dir: "/crypto/mono",
				Sources:  []string{"/crypto/mono/a.c", "/crypto/mono/b.c"},
				Includes: []string{"/crypto/mono/inc"},
				Wrapper:  "/crypto/mono/w.c",
				Cflags:   []string{"-DX=1"},
			},
			{
				Slot: slotHash, Name: "mono", Dir: "/crypto/mono",
				Wrapper:  "/crypto/mono/w.c",
				Includes: []string{"/crypto/mono/inc"},
				Sources:  []string{"/crypto/mono/a.c"},
				Cflags:   []string{"-DX=1"},
				Reused:   true,
			},
			{Slot: slotPQC},
		},
		Recovery: Recovery{
			Backend: "none", Hash: "sha256_sw",
			Drivers:  []string{"/hal/drivers/uart"},
			Sources:  []string{"/hal/chips/chip/recovery.c"},
			Includes: []string{"/hal/soc/include", "/hal/chips/chip/inc"},
		},
	}
}

func render(plan *Plan) string {
	return plan.RenderConfig(SDKPaths{
		Bootloader: "/sdk/toobloader", Core: "/sdk/toobloader/core",
		Stage0: "/sdk/toobloader/stage0", SDK: "/sdk/sdk",
	}, "/bin/toob")
}

func TestRenderConfig(t *testing.T) {
	out := render(testPlan())
	want := []string{
		`set(TOOB_ARCH "riscv")`,
		`set(TOOB_CHIP "chip")`,
		`set(TOOLCHAIN_PREFIX "riscv32-esp-elf-")`,
		`set(TOOB_CORE_DIR "/sdk/toobloader/core")`,
		`set(TOOB_STAGE0_DIR "/sdk/toobloader/stage0")`,
		`set(TOOB_HAL_ROOT "/hal")`,
		`set(TOOB_HAL_CHIP_DIR "/hal/chips/chip")`,
		`set(TOOB_HAL_ARCH_DIR "/hal/arch/riscv")`,
		`set(TOOB_SOC_DIR "/hal/soc/esp")`,
		`set(TOOB_COMPILER_BINARY "riscv32-esp-elf-gcc")`,
		`set(TOOB_CHIP_ARCH_FLAGS "-mabi=ilp32;-march=rv32imac")`,
		`set(TOOB_CHIP_C_FLAGS "-mabi=ilp32;-march=rv32imac")`,
		`set(TOOB_CHIP_ASM_FLAGS "-mabi=ilp32")`,
		`set(TOOB_CHIP_LD_FLAGS "-nostdlib")`,
		`set(TOOB_CHIP_STARTUP "/hal/chips/chip/startup.c")`,
		`set(TOOB_CHIP_LINKER "/hal/chips/chip/link.ld")`,
		`set(TOOB_SDK_DIR "/sdk/sdk")`,
		`set(TOOB_CLI_PATH "/bin/toob")`,
		`set(TOOB_FEATURE_PQC_HYBRID OFF)`,
		"list(APPEND TOOB_DRIVERS \"/hal/drivers/a\")\nlist(APPEND TOOB_DRIVERS \"/hal/drivers/b\")\n",
		`set(TOOB_CRYPTO_BACKEND_ENABLED ON)`,
		`set(TOOB_CRYPTO_BACKEND_NAME "mono")`,
		`set(TOOB_CRYPTO_BACKEND_SOURCES "/crypto/mono/a.c;/crypto/mono/b.c")`,
		`set(TOOB_CRYPTO_BACKEND_WRAPPER "/crypto/mono/w.c")`,
		`set(TOOB_CRYPTO_BACKEND_CFLAGS "-DX=1")`,
		`set(TOOB_CRYPTO_BACKEND_INCLUDES "/crypto/mono/inc")`,
		`set(TOOB_CRYPTO_HASH_ENABLED ON)`,
		`set(TOOB_CRYPTO_HASH_DIR "/crypto/mono")`,
		`set(TOOB_CRYPTO_HASH_WRAPPER "/crypto/mono/w.c")`,
		`set(TOOB_CRYPTO_HASH_INCLUDES "/crypto/mono/inc")`,
		`# HASH slot reuses package 'mono'`,
		`set(TOOB_CRYPTO_PQC_ENABLED OFF)`,
		`set(TOOB_RECOVERY_CRYPTO_BACKEND "none")`,
		`set(TOOB_RECOVERY_CRYPTO_HASH "sha256_sw")`,
		`set(TOOB_RECOVERY_DRIVERS "/hal/drivers/uart")`,
		`set(TOOB_RECOVERY_SOURCES "/hal/chips/chip/recovery.c")`,
		`set(TOOB_RECOVERY_INCLUDES "/hal/soc/include;/hal/chips/chip/inc")`,
	}
	for _, line := range want {
		if !strings.Contains(out, line) {
			t.Errorf("output lacks %q\n%s", line, out)
		}
	}

	absent := []string{"TOOB_CRYPTO_DIR", "TOOB_CRYPTO_HASH_SOURCES", "TOOB_CRYPTO_PQC_NAME", "TOOB_CRYPTO_PQC_DIR"}
	for _, name := range absent {
		if strings.Contains(out, name) {
			t.Errorf("output must not contain %q\n%s", name, out)
		}
	}
}

func TestRenderConfigSlotOrder(t *testing.T) {
	out := render(testPlan())
	backend := strings.Index(out, "TOOB_CRYPTO_BACKEND_ENABLED")
	hash := strings.Index(out, "TOOB_CRYPTO_HASH_ENABLED")
	pqc := strings.Index(out, "TOOB_CRYPTO_PQC_ENABLED")
	if backend < 0 || backend >= hash || hash >= pqc {
		t.Fatalf("slots must be rendered backend, hash, pqc; positions %d, %d, %d", backend, hash, pqc)
	}
}

func TestRenderConfigPQC(t *testing.T) {
	plan := testPlan()
	plan.Crypto[2] = CryptoSlot{Slot: slotPQC, Name: "mldsa", Dir: "/crypto/mldsa", Sources: []string{"/crypto/mldsa/m.c"}}
	out := render(plan)
	for _, line := range []string{
		`set(TOOB_FEATURE_PQC_HYBRID ON)`,
		`set(TOOB_CRYPTO_PQC_ENABLED ON)`,
		`set(TOOB_CRYPTO_PQC_NAME "mldsa")`,
		`set(TOOB_CRYPTO_PQC_SOURCES "/crypto/mldsa/m.c")`,
	} {
		if !strings.Contains(out, line) {
			t.Errorf("output lacks %q\n%s", line, out)
		}
	}
}

func TestRenderConfigOmitsEmptyRecoveryLists(t *testing.T) {
	plan := testPlan()
	plan.Recovery = Recovery{Backend: "none", Hash: "sha256_sw"}
	out := render(plan)
	for _, name := range []string{"TOOB_RECOVERY_DRIVERS", "TOOB_RECOVERY_SOURCES", "TOOB_RECOVERY_INCLUDES"} {
		if strings.Contains(out, name) {
			t.Errorf("output must not contain %q for an empty list", name)
		}
	}
}

func TestRenderConfigEscapes(t *testing.T) {
	plan := testPlan()
	plan.Chip.Name = `x"y\z`
	plan.Drivers = []string{`/d/a$b;c`}
	plan.Crypto[0].Cflags = []string{`-DNAME="v"`, "-DA=$B"}
	out := plan.RenderConfig(SDKPaths{}, "/bin/to\nob")

	for _, line := range []string{
		`set(TOOB_CHIP "x\"y\\z")`,
		`list(APPEND TOOB_DRIVERS "/d/a\$b\;c")`,
		`set(TOOB_CRYPTO_BACKEND_CFLAGS "-DNAME=\"v\";-DA=\$B")`,
		`set(TOOB_CLI_PATH "/bin/to\nob")`,
	} {
		if !strings.Contains(out, line) {
			t.Errorf("output lacks %q\n%s", line, out)
		}
	}
	if strings.Contains(out, "to\nob") {
		t.Error("a raw line break leaked into the CMake file")
	}
}

func TestRenderConfigProfileAndDriverSources(t *testing.T) {
	plan := testPlan()
	plan.Profile = ProfileProduction
	plan.MockHW = false
	plan.Arch.Sources = []string{"/hal/arch/riscv/arch_timer.c", "/hal/arch/riscv/arch_trap.c"}
	plan.ChipSources = []string{"/hal/chips/chip/startup.c"}
	plan.ChipIncludes = []string{"/hal/soc/esp/include"}
	plan.DriverSources = []string{"/hal/drivers/keystore/esp_efuse/efuse_real.c"}
	plan.Recovery.DriverSources = []string{"/hal/drivers/uart/console.c"}

	out := render(plan)
	for _, line := range []string{
		`set(TOOB_PROFILE "production")`,
		`set(TOOB_MOCK_HW OFF)`,
		`set(TOOB_ARCH_SOURCES "/hal/arch/riscv/arch_timer.c;/hal/arch/riscv/arch_trap.c")`,
		`set(TOOB_CHIP_SOURCES "/hal/chips/chip/startup.c")`,
		`set(TOOB_CHIP_INCLUDES "/hal/soc/esp/include")`,
		`set(TOOB_DRIVER_SOURCES "/hal/drivers/keystore/esp_efuse/efuse_real.c")`,
		`set(TOOB_RECOVERY_DRIVER_SOURCES "/hal/drivers/uart/console.c")`,
	} {
		if !strings.Contains(out, line) {
			t.Errorf("output lacks %q\n%s", line, out)
		}
	}
}
