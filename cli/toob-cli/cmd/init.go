package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/toob-boot/toob/internal/installer"
	"github.com/toob-boot/toob/internal/paths"
	"github.com/toob-boot/toob/internal/registry"
)

var (
	initChip     string
	initNoVSCode bool
)

var initCmd = &cobra.Command{
	Use:   "init [project-name]",
	Short: "Initialize a new Toob-Loader IoT project (Zero-Bloat Scaffold)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		projectName := args[0]
		if initChip == "" {
			return fmt.Errorf("please specify a chip using the --chip flag (e.g., --chip esp32c6)")
		}

		// 1. Create project directory
		projectDir := filepath.Join(".", projectName)
		if _, err := os.Stat(projectDir); err == nil {
			return fmt.Errorf("directory %s already exists", projectDir)
		}
		if err := os.MkdirAll(projectDir, 0o755); err != nil {
			return err
		}

		fmt.Printf("[toob] Initializing Zero-Bloat project '%s' for chip '%s'...\n", projectName, initChip)

		// 2. Generate device.toml
		deviceToml := fmt.Sprintf(`name = "%s"
version = "0.1.0"
`, projectName)
		if err := os.WriteFile(filepath.Join(projectDir, "device.toml"), []byte(deviceToml), 0o644); err != nil {
			return err
		}

		// 3. Generate CMakeLists.txt
		cmakeLists := fmt.Sprintf(`cmake_minimum_required(VERSION 3.20)
project(%s C CXX ASM)

# ==============================================================================
# OS & Framework Integration
# ==============================================================================
# If using Zephyr OS:
#   find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
#   zephyr_library()
#   zephyr_library_sources(src/main.c src/toob_zero_bloat_hooks.c)
# 
# If using ESP-IDF:
#   include($ENV{IDF_PATH}/tools/cmake/project.cmake)
#   idf_component_register(SRCS "src/main.c" "src/toob_zero_bloat_hooks.c" INCLUDE_DIRS "src")

# For Generic/Baremetal Builds (via Toob-Loader CLI):
include(cmake/toob_paths.cmake OPTIONAL)
add_executable(${PROJECT_NAME} src/main.c src/toob_zero_bloat_hooks.c)

# If integrating libtoob directly, ensure its headers are in the include path.
# target_include_directories(${PROJECT_NAME} PRIVATE ${TOOB_CORE_DIR}/sdk/libtoob/include)
`, projectName)
		if err := os.WriteFile(filepath.Join(projectDir, "CMakeLists.txt"), []byte(cmakeLists), 0o644); err != nil {
			return err
		}

		// 4. Generate src/main.c & src/toob_zero_bloat_hooks.c
		if err := os.MkdirAll(filepath.Join(projectDir, "src"), 0o755); err != nil {
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
 * 
 * If using ESP-IDF, rename this to app_main(void).
 * If using Zephyr, int main(void) is correct.
 */
int main(void) {
    /* 1. FATAL HANDOFF VALIDATION
     * This MUST be the very first call in your application!
     * It validates the CRC of the .noinit RAM boundary to prevent 
     * rogue pointer propagation if the Bootloader was bypassed (e.g. WDT reset).
     * If validation fails, the system halts (Hardware Trap).
     */
    TOOB_OS_INIT_OR_PANIC();

    printf("Toob-Loader IoT App Booted Successfully!\n");

    /* 2. Print System Diagnostics */
    print_toob_diagnostics();

    /* 3. ASYNC UPDATE CONFIRMATION
     * If this boot was triggered by a new OTA update, the update is "TENTATIVE".
     * You MUST call toob_confirm_boot() after your network/cloud connection 
     * is stable to mark the update as "COMMITTED". If you do not call this before
     * the Network Watchdog TTL expires, the system will automatically rollback!
     */
    toob_status_t status = toob_confirm_boot();
    if (status == TOOB_OK) {
        printf("Update committed (or no update pending).\n");
    } else {
        printf("Failed to confirm boot (Status: 0x%X)\n", status);
    }

    // Your Application Logic Here...
    while (1) {
        // do_work();
    }

    return 0;
}
`
		if err := os.WriteFile(filepath.Join(projectDir, "src", "main.c"), []byte(mainC), 0o644); err != nil {
			return err
		}

		hooksC := `/**
 * ==============================================================================
 * Toob-Loader "Zero-Bloat" Linker Hooks
 * ==============================================================================
 * 
 * Toob-Loader refuses to compile massive Vendor SDK SPI drivers into the Bootloader
 * API (libtoob). Instead, it requires your OS to provide these hardware capabilities
 * at link-time.
 * 
 * You MUST implement these functions using your OS's native APIs (Zephyr / ESP-IDF)
 * to enable OTA updates and WAL (Write-Ahead-Log) persistence.
 * 
 * - Zephyr: Use flash_read(), flash_write(), flash_erase() from <zephyr/drivers/flash.h>
 * - ESP-IDF: Use esp_flash_read(), esp_flash_write(), esp_flash_erase() from <esp_flash.h>
 */

#include "libtoob.h"
#include <stdio.h>

/**
 * @brief Physical Flash Read Access
 * @param addr Absolute byte address in SPI Flash
 * @param buf Data buffer in local OS SRAM
 * @param len Length of data to read
 */
toob_status_t toob_os_flash_read(uint32_t addr, uint8_t* buf, uint32_t len) {
    // TODO: Implement using your framework's flash API
    printf("[toob_hooks] WARN: toob_os_flash_read not implemented!\n");
    return TOOB_ERR_NOT_SUPPORTED;
}

/**
 * @brief Physical Flash Write Access
 * @param addr Absolute byte address in SPI Flash (must be page-aligned)
 * @param buf Constant data buffer to write
 * @param len Length of data to write
 */
toob_status_t toob_os_flash_write(uint32_t addr, const uint8_t* buf, uint32_t len) {
    // TODO: Implement using your framework's flash API
    printf("[toob_hooks] WARN: toob_os_flash_write not implemented!\n");
    return TOOB_ERR_NOT_SUPPORTED;
}

/**
 * @brief Physical Flash Erase Access
 * @param addr Absolute byte address in SPI Flash (must be sector-aligned)
 * @param len Length to erase (must be sector-aligned)
 */
toob_status_t toob_os_flash_erase(uint32_t addr, uint32_t len) {
    // TODO: Implement using your framework's flash API
    printf("[toob_hooks] WARN: toob_os_flash_erase not implemented!\n");
    return TOOB_ERR_NOT_SUPPORTED;
}

/* ==============================================================================
 * Hardware Accelerated Cryptography (Optional for Zero-Bloat Streams)
 * ==============================================================================
 * If your hardware has cryptographic accelerators, route these functions to your
 * OS's hardware-backed crypto API (e.g. mbedTLS hardware engine).
 * This enables ultra-fast, zero-buffer OTA streaming verification.
 */

toob_status_t toob_os_sha256_init(toob_os_sha256_ctx_t* ctx) {
    return TOOB_ERR_NOT_SUPPORTED;
}

toob_status_t toob_os_sha256_update(toob_os_sha256_ctx_t* ctx, const uint8_t* data, uint32_t len) {
    return TOOB_ERR_NOT_SUPPORTED;
}

toob_status_t toob_os_sha256_finalize(toob_os_sha256_ctx_t* ctx, uint8_t out_hash[32]) {
    return TOOB_ERR_NOT_SUPPORTED;
}
`
		if err := os.WriteFile(filepath.Join(projectDir, "src", "toob_zero_bloat_hooks.c"), []byte(hooksC), 0o644); err != nil {
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
		if err := os.WriteFile(filepath.Join(projectDir, ".gitignore"), []byte(gitignore), 0o644); err != nil {
			return err
		}

		// 6. Run installer.Add (True IKEA Mode)
		cwd, _ := os.Getwd()
		os.Chdir(projectDir)
		defer os.Chdir(cwd)

		regDir, err := paths.RegistryDir()
		if err != nil {
			return err
		}
		cache := registry.NewCache(regDir)
		if err := cache.Sync(); err != nil {
			return err
		}
		inst := installer.New(".", cache)
		if err := inst.Add(initChip); err != nil {
			return fmt.Errorf("failed to add chip '%s': %w", initChip, err)
		}

		// 7. VS Code Integration
		if !initNoVSCode {
			if err := os.MkdirAll(filepath.Join(projectDir, ".vscode"), 0o755); err != nil {
				return err
			}
			
			ci, err := cache.GetChip(initChip)
			var includePaths []string
			if err == nil {
				chipSrc, _ := cache.ChipSourcePath(ci.Name)
				archSrc := cache.ArchSourcePath(ci.Arch)
				vendorSrc := cache.VendorSourcePath(ci.Vendor)
				includePaths = append(includePaths,
					filepath.Join(chipSrc, "include"),
					filepath.Join(archSrc, "include"),
					filepath.Join(vendorSrc, "include"),
				)
			}
			
			// Absolutly critical: Ensure libtoob and common APIs are available to intellisense!
			// Find Toob-Loader root directory from paths context to inject the libtoob header
			rootLibtoob := filepath.Join(regDir, "..", "..", "sdk", "libtoob", "include")
			includePaths = append(includePaths, rootLibtoob)
			includePaths = append(includePaths, "${workspaceFolder}/**")

			cCppProps := map[string]interface{}{
				"configurations": []map[string]interface{}{
					{
						"name": "Toob-Loader",
						"includePath": includePaths,
						"compilerPath": "",
						"cStandard": "c11",
						"intelliSenseMode": "gcc-arm",
					},
				},
				"version": 4,
			}
			
			propsData, _ := json.MarshalIndent(cCppProps, "", "    ")
			os.WriteFile(filepath.Join(projectDir, ".vscode", "c_cpp_properties.json"), propsData, 0o644)
		}

		fmt.Println("\n[toob] Project initialized successfully!")
		fmt.Printf("Run `cd %s` then `toob build` to compile.\n", projectName)
		return nil
	},
}

func init() {
	initCmd.Flags().StringVarP(&initChip, "chip", "c", "", "Target chip for the project (e.g., esp32c6)")
	initCmd.Flags().BoolVar(&initNoVSCode, "no-vscode", false, "Disable generation of VS Code IntelliSense configurations")
}
