package scaffold

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type BaremetalGenerator struct{}

func (g *BaremetalGenerator) Generate(ctx Context) error {
	// 1. Generate device.toml
	if err := GenerateDeviceToml(ctx); err != nil {
		return err
	}

	// 2. Generate CMakeLists.txt
	cmakeLists := fmt.Sprintf(`cmake_minimum_required(VERSION 3.20)
project(%s C CXX ASM)

# ==============================================================================
# OS & Framework Integration (Baremetal)
# ==============================================================================
include(FetchContent)
FetchContent_Declare(
  toob_sdk
  GIT_REPOSITORY "%s"
  GIT_TAG        "%s"
)
FetchContent_MakeAvailable(toob_sdk)

# Include libtoob headers
target_include_directories(${PROJECT_NAME} PRIVATE ${toob_sdk_SOURCE_DIR}/sdk/libtoob/include)

add_executable(${PROJECT_NAME} src/main.c src/toob_zero_bloat_hooks.c)
`, ctx.ProjectName, ctx.SdkUrl, ctx.SdkRevision)
	if err := os.WriteFile(filepath.Join(ctx.ProjectDir, "CMakeLists.txt"), []byte(cmakeLists), 0o644); err != nil {
		return err
	}

	// 3. Generate src/main.c & src/toob_zero_bloat_hooks.c
	if err := os.MkdirAll(filepath.Join(ctx.ProjectDir, "src"), 0o755); err != nil {
		return err
	}
	
	mainC := `#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

// Toob-Boot Interface (Zero-Bloat API)
#include "libtoob.h"

/**
 * @brief Demonstrates how to extract and print the CRA-compliant diagnostic data.
 */
static void print_toob_diagnostics(void) {
    toob_boot_diag_t diag = {0};
    if (toob_get_boot_diag(&diag) == TOOB_OK) {
        printf("\n--- Toob-Loader Diagnostics ---\n");
        printf("Boot Duration : %u ms\n", diag.boot_duration_ms);
        printf("Verify Time   : %u ms\n", diag.verify_time_ms);
        printf("Last Error    : 0x%08X\n", diag.last_error_code);
        printf("Edge Recovery : %u attempts\n", diag.edge_recovery_events);
        
        printf("SBOM Digest   : ");
        for (int i = 0; i < 32; i++) {
            printf("%02X", diag.sbom_digest[i]);
        }
        printf("\n-------------------------------\n\n");
    } else {
        printf("Failed to retrieve Toob-Loader diagnostics!\n");
    }
}

/**
 * @brief Application Entrypoint
 */
int main(void) {
    /* 1. FATAL HANDOFF VALIDATION
     * This MUST be the very first call in your application!
     */
    TOOB_OS_INIT_OR_PANIC();
    // IMPORTANT: Ensure your RTOS feeds or disables the hardware watchdog passed by Toob-Boot!

    printf("Toob-Loader Baremetal App Booted Successfully!\n");

    /* 2. Print System Diagnostics */
    print_toob_diagnostics();

    /* 3. ASYNC UPDATE CONFIRMATION */
    toob_status_t status = toob_confirm_boot();
    if (status == TOOB_OK) {
        printf("Update committed (or no update pending).\n");
    } else {
        printf("Failed to confirm boot (Status: 0x%X)\n", status);
    }

    while (1) {
    }

    return 0;
}
`
	if err := os.WriteFile(filepath.Join(ctx.ProjectDir, "src", "main.c"), []byte(mainC), 0o644); err != nil {
		return err
	}

	hooksC := `/**
 * ==============================================================================
 * Toob-Loader "Zero-Bloat" Linker Hooks
 * ==============================================================================
 */

#include "libtoob.h"
#include <stdio.h>

toob_status_t toob_os_flash_read(uint32_t addr, uint8_t* buf, uint32_t len) {
    printf("[toob_hooks] WARN: toob_os_flash_read not implemented!\n");
    return TOOB_ERR_NOT_SUPPORTED;
}

toob_status_t toob_os_flash_write(uint32_t addr, const uint8_t* buf, uint32_t len) {
    printf("[toob_hooks] WARN: toob_os_flash_write not implemented!\n");
    return TOOB_ERR_NOT_SUPPORTED;
}

toob_status_t toob_os_flash_erase(uint32_t addr, uint32_t len) {
    printf("[toob_hooks] WARN: toob_os_flash_erase not implemented!\n");
    return TOOB_ERR_NOT_SUPPORTED;
}

toob_status_t toob_os_sha256_init(toob_os_sha256_ctx_t* ctx) { 
    printf("[toob_hooks] CRITICAL: toob_os_sha256_init not implemented. Secure boot/OTA will fail!\n");
    return TOOB_ERR_NOT_SUPPORTED; 
}
toob_status_t toob_os_sha256_update(toob_os_sha256_ctx_t* ctx, const uint8_t* data, uint32_t len) { return TOOB_ERR_NOT_SUPPORTED; }
toob_status_t toob_os_sha256_finalize(toob_os_sha256_ctx_t* ctx, uint8_t out_hash[32]) { return TOOB_ERR_NOT_SUPPORTED; }
`
	if err := os.WriteFile(filepath.Join(ctx.ProjectDir, "src", "toob_zero_bloat_hooks.c"), []byte(hooksC), 0o644); err != nil {
		return err
	}

	// 4. Generate CMakePresets.json
	presets := `{
  "version": 3,
  "configurePresets": [
    {
      "name": "baremetal",
      "displayName": "Baremetal Build",
      "generator": "Ninja",
      "binaryDir": "${sourceDir}/build"
    }
  ],
  "buildPresets": [
    {
      "name": "baremetal",
      "configurePreset": "baremetal"
    }
  ]
}`
	if err := os.WriteFile(filepath.Join(ctx.ProjectDir, "CMakePresets.json"), []byte(presets), 0o644); err != nil {
		return err
	}

	// 5. Generate .gitignore
	gitignore := `# CMake
build/
CMakeCache.txt
CMakeFiles/

# Toob-Loader
toobloader/
.toob/
`
	if err := os.WriteFile(filepath.Join(ctx.ProjectDir, ".gitignore"), []byte(gitignore), 0o644); err != nil {
		return err
	}

	// 5. VS Code Integration
	if !ctx.NoVSCode {
		if err := os.MkdirAll(filepath.Join(ctx.ProjectDir, ".vscode"), 0o755); err != nil {
			return err
		}
		
		var includePaths []string
		chipSrc := filepath.Join(ctx.RegistryDir, "chips", ctx.ChipInfo.Name)
		archSrc := filepath.Join(ctx.RegistryDir, "arch", ctx.ChipInfo.Arch)
		vendorSrc := filepath.Join(ctx.RegistryDir, "vendor", ctx.ChipInfo.Vendor)
		includePaths = append(includePaths,
			filepath.Join(chipSrc, "include"),
			filepath.Join(archSrc, "include"),
			filepath.Join(vendorSrc, "include"),
		)
		
		rootLibtoob := filepath.Join(ctx.RegistryDir, "..", "sdk", "libtoob", "include")
		includePaths = append(includePaths, rootLibtoob)
		includePaths = append(includePaths, "${workspaceFolder}/**")

		cCppProps := map[string]interface{}{
			"configurations": []map[string]interface{}{
				{
					"name": "Toob-Loader (Baremetal)",
					"includePath": includePaths,
					"compilerPath": "",
					"cStandard": "c17",
					"intelliSenseMode": "gcc-arm",
				},
			},
			"version": 4,
		}
		
		propsData, _ := json.MarshalIndent(cCppProps, "", "    ")
		os.WriteFile(filepath.Join(ctx.ProjectDir, ".vscode", "c_cpp_properties.json"), propsData, 0o644)
	}

	return nil
}
