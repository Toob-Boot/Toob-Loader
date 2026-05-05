package scaffold

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type EspIdfGenerator struct{}

func (g *EspIdfGenerator) Generate(ctx Context) error {
	// 1. Generate Root CMakeLists.txt
	rootCmake := fmt.Sprintf(`cmake_minimum_required(VERSION 3.16)
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(%s)
`, ctx.ProjectName)
	if err := os.WriteFile(filepath.Join(ctx.ProjectDir, "CMakeLists.txt"), []byte(rootCmake), 0o644); err != nil {
		return err
	}

	// 2. Generate sdkconfig.defaults (Custom Partition Table)
	sdkconfig := `# Ensure Toob-Loader offset configuration
CONFIG_PARTITION_TABLE_CUSTOM=y
CONFIG_PARTITION_TABLE_CUSTOM_FILENAME="partitions.csv"
CONFIG_PARTITION_TABLE_OFFSET=0x8000

# Toob-Loader Network Client
CONFIG_ESP_HTTP_CLIENT_ENABLE_HTTPS=y
CONFIG_MBEDTLS_CERTIFICATE_BUNDLE=y
CONFIG_MBEDTLS_CERTIFICATE_BUNDLE_DEFAULT_FULL=y
`
	if err := os.WriteFile(filepath.Join(ctx.ProjectDir, "sdkconfig.defaults"), []byte(sdkconfig), 0o644); err != nil {
		return err
	}

	// 3. Generate partitions.csv (Flash Offset)
	partitions := `# ESP-IDF Partition Table
# Name,   Type, SubType, Offset,  Size, Flags
# Note: Toob-Boot (Stage 0/1) resides at 0x0000.
nvs,      data, nvs,     0x9000,  0x4000,
otadata,  data, ota,     0xd000,  0x2000,
phy_init, data, phy,     0xf000,  0x1000,
factory,  app,  factory, 0x10000, 2M,
`
	if err := os.WriteFile(filepath.Join(ctx.ProjectDir, "partitions.csv"), []byte(partitions), 0o644); err != nil {
		return err
	}

	// 4. Generate main/ directory
	mainDir := filepath.Join(ctx.ProjectDir, "main")
	if err := os.MkdirAll(mainDir, 0o755); err != nil {
		return err
	}

	// 5. Generate main/CMakeLists.txt
	mainCmake := `idf_component_register(
    SRCS "main.c" "toob_zero_bloat_hooks.c"
    INCLUDE_DIRS "."
    REQUIRES os_client
)
`
	if err := os.WriteFile(filepath.Join(mainDir, "CMakeLists.txt"), []byte(mainCmake), 0o644); err != nil {
		return err
	}

	// 6. Generate main/idf_component.yml (GitHub Dependency)
	idfComponent := fmt.Sprintf(`dependencies:
  idf: ">=5.0"
  os_client:
    git: %s
    version: %s
    path: sdk/os_client
`, ctx.SdkUrl, ctx.SdkRevision)
	if err := os.WriteFile(filepath.Join(mainDir, "idf_component.yml"), []byte(idfComponent), 0o644); err != nil {
		return err
	}

	// 7. Generate main/main.c & main/toob_zero_bloat_hooks.c
	mainC := `#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"

// Toob-Boot Interface (Zero-Bloat API)
#include "libtoob.h"

static const char* TAG = "APP";

/**
 * @brief Demonstrates how to extract and print the CRA-compliant diagnostic data.
 */
static void print_toob_diagnostics(void) {
    toob_boot_diag_t diag = {0};
    if (toob_get_boot_diag(&diag) == TOOB_OK) {
        ESP_LOGI(TAG, "--- Toob-Loader Diagnostics ---");
        ESP_LOGI(TAG, "Boot Duration : %lu ms", diag.boot_duration_ms);
        ESP_LOGI(TAG, "Verify Time   : %lu ms", diag.verify_time_ms);
        ESP_LOGI(TAG, "Last Error    : 0x%08lX", diag.last_error_code);
        ESP_LOGI(TAG, "Edge Recovery : %lu attempts", diag.edge_recovery_events);
        
        printf("SBOM Digest   : ");
        for (int i = 0; i < 32; i++) {
            printf("%02X", diag.sbom_digest[i]);
        }
        printf("\n-------------------------------\n\n");
    } else {
        ESP_LOGE(TAG, "Failed to retrieve Toob-Loader diagnostics!");
    }
}

/**
 * @brief ESP-IDF Application Entrypoint
 */
void app_main(void) {
    /* 1. FATAL HANDOFF VALIDATION
     * This MUST be the very first call in your application!
     */
    TOOB_OS_INIT_OR_PANIC();
    // IMPORTANT: Ensure your RTOS feeds or disables the hardware watchdog passed by Toob-Boot!

    ESP_LOGI(TAG, "Toob-Loader ESP-IDF App Booted Successfully!");

    /* 2. Print System Diagnostics */
    print_toob_diagnostics();

    /* 3. ASYNC UPDATE CONFIRMATION */
    toob_status_t status = toob_confirm_boot();
    if (status == TOOB_OK) {
        ESP_LOGI(TAG, "Update committed (or no update pending).");
    } else {
        ESP_LOGE(TAG, "Failed to confirm boot (Status: 0x%X)", status);
    }

    while (1) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}
`
	if err := os.WriteFile(filepath.Join(mainDir, "main.c"), []byte(mainC), 0o644); err != nil {
		return err
	}

	hooksC := `/**
 * ==============================================================================
 * Toob-Loader "Zero-Bloat" Linker Hooks for ESP-IDF
 * ==============================================================================
 */

#include "libtoob.h"
#include "esp_flash.h"
#include "esp_log.h"

toob_status_t toob_os_flash_read(uint32_t addr, uint8_t* buf, uint32_t len) {
    if (esp_flash_read(NULL, buf, addr, len) == ESP_OK) {
        return TOOB_OK;
    }
    return TOOB_ERR_FLASH;
}

toob_status_t toob_os_flash_write(uint32_t addr, const uint8_t* buf, uint32_t len) {
    if (esp_flash_write(NULL, buf, addr, len) == ESP_OK) {
        return TOOB_OK;
    }
    return TOOB_ERR_FLASH;
}

toob_status_t toob_os_flash_erase(uint32_t addr, uint32_t len) {
    if (esp_flash_erase_region(NULL, addr, len) == ESP_OK) {
        return TOOB_OK;
    }
    return TOOB_ERR_FLASH;
}

toob_status_t toob_os_sha256_init(toob_os_sha256_ctx_t* ctx) { 
    ESP_LOGE("HOOK", "CRITICAL: toob_os_sha256_init not implemented. Secure boot/OTA will fail!");
    return TOOB_ERR_NOT_SUPPORTED; 
}
toob_status_t toob_os_sha256_update(toob_os_sha256_ctx_t* ctx, const uint8_t* data, uint32_t len) { return TOOB_ERR_NOT_SUPPORTED; }
toob_status_t toob_os_sha256_finalize(toob_os_sha256_ctx_t* ctx, uint8_t out_hash[32]) { return TOOB_ERR_NOT_SUPPORTED; }
`
	if err := os.WriteFile(filepath.Join(mainDir, "toob_zero_bloat_hooks.c"), []byte(hooksC), 0o644); err != nil {
		return err
	}

	// 8. Generate CMakePresets.json
	presets := `{
  "version": 3,
  "configurePresets": [
    {
      "name": "espidf",
      "displayName": "ESP-IDF Build",
      "generator": "Ninja",
      "binaryDir": "${sourceDir}/build"
    }
  ],
  "buildPresets": [
    {
      "name": "espidf",
      "configurePreset": "espidf"
    }
  ]
}`
	if err := os.WriteFile(filepath.Join(ctx.ProjectDir, "CMakePresets.json"), []byte(presets), 0o644); err != nil {
		return err
	}

	// 9. Generate .gitignore
	gitignore := `# ESP-IDF Build
build/
sdkconfig
managed_components/
`
	if ctx.UseDevContainer {
		gitignore += `
# DevContainer cache
.devcontainer/.cache/
`
	}
	if err := os.WriteFile(filepath.Join(ctx.ProjectDir, ".gitignore"), []byte(gitignore), 0o644); err != nil {
		return err
	}

	// 9. Generate DevContainer configuration
	if ctx.UseDevContainer {
		if err := os.MkdirAll(filepath.Join(ctx.ProjectDir, ".devcontainer"), 0o755); err != nil {
			return err
		}

		devcontainer := `{
    "name": "Toob-Loader ESP-IDF SDK",
    "image": "espressif/idf:release-v5.3",
    
    // Install the C/C++ Extension & ESP-IDF Extension
    "customizations": {
        "vscode": {
            "extensions": [
                "ms-vscode.cpptools",
                "espressif.esp-idf-extension"
            ]
        }
    },

    "remoteUser": "esp"
}
`
		if err := os.WriteFile(filepath.Join(ctx.ProjectDir, ".devcontainer", "devcontainer.json"), []byte(devcontainer), 0o644); err != nil {
			return err
		}
	}

	// 10. VS Code Integration (Bare minimum, usually handled by ESP-IDF extension)
	if !ctx.NoVSCode {
		if err := os.MkdirAll(filepath.Join(ctx.ProjectDir, ".vscode"), 0o755); err != nil {
			return err
		}
		
		rootLibtoob := filepath.Join(ctx.RegistryDir, "..", "sdk", "libtoob", "include")
		cCppProps := map[string]interface{}{
			"configurations": []map[string]interface{}{
				{
					"name": "ESP-IDF",
					"includePath": []string{
						rootLibtoob,
						"${workspaceFolder}/**",
					},
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
