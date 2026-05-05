package scaffold

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type ZephyrGenerator struct{}

func (g *ZephyrGenerator) Generate(ctx Context) error {
	cmakeLists := fmt.Sprintf(`cmake_minimum_required(VERSION 3.20.0)

# The Toob-Loader SDK is automatically pulled via west.yml and 
# registered as a Zephyr module. No manual paths needed!
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(%s)

target_sources(app PRIVATE 
    src/main.c 
    src/toob_zero_bloat_hooks.c
)
`, ctx.ProjectName)
	if err := os.WriteFile(filepath.Join(ctx.ProjectDir, "CMakeLists.txt"), []byte(cmakeLists), 0o644); err != nil {
		return err
	}

	// 2. Generate prj.conf
	prjConf := `# Zephyr Application Configuration
# Tells Zephyr to compile as a chain-loaded payload
CONFIG_BOOTLOADER_MCUBOOT=y

# Network / OTA requirements
CONFIG_NETWORKING=y
CONFIG_HTTP_CLIENT=y
CONFIG_FLASH=y
CONFIG_FLASH_MAP=y
CONFIG_FLASH_PAGE_LAYOUT=y

# Toob-Loader Network Client
CONFIG_TOOB_NETWORK_CLIENT=y
`
	if err := os.WriteFile(filepath.Join(ctx.ProjectDir, "prj.conf"), []byte(prjConf), 0o644); err != nil {
		return err
	}

	// 3. Generate app.overlay (DeviceTree Layout)
	appOverlay := `/* 
 * Zephyr DeviceTree Overlay for Toob-Boot
 * This shifts the Zephyr boot vector to 0x10000, allowing Toob-Boot to reside at 0x0.
 * Adjust the flash boundaries according to your specific chip!
 */
/ {
	chosen {
		zephyr,code-partition = &slot0_partition;
	};
};

&flash0 {
	partitions {
		compatible = "fixed-partitions";
		#address-cells = <1>;
		#size-cells = <1>;

		boot_partition: partition@0 {
			label = "toob-boot";
			reg = <0x00000000 0x00010000>;
		};
		slot0_partition: partition@10000 {
			label = "image-0";
			reg = <0x00010000 0x00040000>;
		};
		slot1_partition: partition@50000 {
			label = "image-1";
			reg = <0x00050000 0x00040000>;
		};
	};
};
`
	if err := os.WriteFile(filepath.Join(ctx.ProjectDir, "app.overlay"), []byte(appOverlay), 0o644); err != nil {
		return err
	}

	// 4. Generate west.yml (Dependency Management)
	westYml := fmt.Sprintf(`manifest:
  remotes:
    - name: toob-boot
      url-base: https://github.com/Toob-Boot
  projects:
    - name: Toob-Loader
      remote: toob-boot
      revision: main
      path: modules/toob-loader
  self:
    path: %s
`, ctx.ProjectName)
	if err := os.WriteFile(filepath.Join(ctx.ProjectDir, "west.yml"), []byte(westYml), 0o644); err != nil {
		return err
	}

	// 5. Generate src/main.c & src/toob_zero_bloat_hooks.c
	if err := os.MkdirAll(filepath.Join(ctx.ProjectDir, "src"), 0o755); err != nil {
		return err
	}
	
	mainC := `#include <zephyr/kernel.h>
#include <stdio.h>

// Toob-Boot Interface (Zero-Bloat API)
#include "libtoob.h"

/**
 * @brief Demonstrates how to extract and print the CRA-compliant diagnostic data.
 */
static void print_toob_diagnostics(void) {
    toob_boot_diag_t diag = {0};
    if (toob_get_boot_diag(&diag) == TOOB_OK) {
        printk("\n--- Toob-Loader Diagnostics ---\n");
        printk("Boot Duration : %u ms\n", diag.boot_duration_ms);
        printk("Verify Time   : %u ms\n", diag.verify_time_ms);
        printk("Last Error    : 0x%08X\n", diag.last_error_code);
        printk("Edge Recovery : %u attempts\n", diag.edge_recovery_events);
        
        printk("SBOM Digest   : ");
        for (int i = 0; i < 32; i++) {
            printk("%02X", diag.sbom_digest[i]);
        }
        printk("\n-------------------------------\n\n");
    } else {
        printk("Failed to retrieve Toob-Loader diagnostics!\n");
    }
}

/**
 * @brief Zephyr Application Entrypoint
 */
int main(void) {
    /* 1. FATAL HANDOFF VALIDATION
     * This MUST be the very first call in your application!
     */
    TOOB_OS_INIT_OR_PANIC();

    printk("Toob-Loader Zephyr App Booted Successfully!\n");

    /* 2. Print System Diagnostics */
    print_toob_diagnostics();

    /* 3. ASYNC UPDATE CONFIRMATION */
    toob_status_t status = toob_confirm_boot();
    if (status == TOOB_OK) {
        printk("Update committed (or no update pending).\n");
    } else {
        printk("Failed to confirm boot (Status: 0x%X)\n", status);
    }

    while (1) {
        k_msleep(1000);
    }

    return 0;
}
`
	if err := os.WriteFile(filepath.Join(ctx.ProjectDir, "src", "main.c"), []byte(mainC), 0o644); err != nil {
		return err
	}

	hooksC := `/**
 * ==============================================================================
 * Toob-Loader "Zero-Bloat" Linker Hooks for Zephyr OS
 * ==============================================================================
 */

#include "libtoob.h"
#include <zephyr/kernel.h>
#include <zephyr/drivers/flash.h>
#include <zephyr/storage/flash_map.h>

// Helper to get the primary flash device
static const struct device *flash_dev = DEVICE_DT_GET(DT_CHOSEN(zephyr_flash_controller));

toob_status_t toob_os_flash_read(uint32_t addr, uint8_t* buf, uint32_t len) {
    if (!device_is_ready(flash_dev)) return TOOB_ERR_FLASH;
    if (flash_read(flash_dev, addr, buf, len) != 0) {
        return TOOB_ERR_FLASH;
    }
    return TOOB_OK;
}

toob_status_t toob_os_flash_write(uint32_t addr, const uint8_t* buf, uint32_t len) {
    if (!device_is_ready(flash_dev)) return TOOB_ERR_FLASH;
    if (flash_write(flash_dev, addr, buf, len) != 0) {
        return TOOB_ERR_FLASH;
    }
    return TOOB_OK;
}

toob_status_t toob_os_flash_erase(uint32_t addr, uint32_t len) {
    if (!device_is_ready(flash_dev)) return TOOB_ERR_FLASH;
    if (flash_erase(flash_dev, addr, len) != 0) {
        return TOOB_ERR_FLASH;
    }
    return TOOB_OK;
}

toob_status_t toob_os_sha256_init(toob_os_sha256_ctx_t* ctx) { return TOOB_ERR_NOT_SUPPORTED; }
toob_status_t toob_os_sha256_update(toob_os_sha256_ctx_t* ctx, const uint8_t* data, uint32_t len) { return TOOB_ERR_NOT_SUPPORTED; }
toob_status_t toob_os_sha256_finalize(toob_os_sha256_ctx_t* ctx, uint8_t out_hash[32]) { return TOOB_ERR_NOT_SUPPORTED; }
`
	if err := os.WriteFile(filepath.Join(ctx.ProjectDir, "src", "toob_zero_bloat_hooks.c"), []byte(hooksC), 0o644); err != nil {
		return err
	}

	// 5. Generate .gitignore
	gitignore := `# CMake
build/
CMakeCache.txt
CMakeFiles/
`
	if ctx.UseDevContainer {
		gitignore += `
# Zephyr DevContainer Workspace (Keeps PC clean)
.west/
zephyr/
modules/
tools/
bootloader/
`
	}
	if err := os.WriteFile(filepath.Join(ctx.ProjectDir, ".gitignore"), []byte(gitignore), 0o644); err != nil {
		return err
	}

	// 6. Generate DevContainer configuration (Modern & Clean PC)
	if ctx.UseDevContainer {
		if err := os.MkdirAll(filepath.Join(ctx.ProjectDir, ".devcontainer"), 0o755); err != nil {
			return err
		}

		devcontainer := `{
    "name": "Toob-Loader Zephyr SDK",
    "image": "zephyrprojectrtos/zephyr-build:latest",
    
    // Install the C/C++ Extension for Autocompletion
    "customizations": {
        "vscode": {
            "extensions": [
                "ms-vscode.cpptools",
                "ms-vscode.cmake-tools"
            ]
        }
    },

    // This command keeps your workspace up to date automatically!
    // It downloads the OS source code ONLY inside the container context.
    "postCreateCommand": "west init && west update",
    
    // Map Zephyr Base automatically
    "remoteEnv": {
        "ZEPHYR_BASE": "${containerWorkspaceFolder}/zephyr"
    },

    "remoteUser": "user"
}
`
		if err := os.WriteFile(filepath.Join(ctx.ProjectDir, ".devcontainer", "devcontainer.json"), []byte(devcontainer), 0o644); err != nil {
			return err
		}
	}

	// 7. VS Code Integration
	if !ctx.NoVSCode {
		if err := os.MkdirAll(filepath.Join(ctx.ProjectDir, ".vscode"), 0o755); err != nil {
			return err
		}
		
		var includePaths []string
		
		// For Zephyr, Intellisense mostly depends on the Zephyr SDK and west build output.
		// However, we explicitly include libtoob headers.
		rootLibtoob := filepath.Join(ctx.RegistryDir, "..", "sdk", "libtoob", "include")
		includePaths = append(includePaths, rootLibtoob)
		includePaths = append(includePaths, "${workspaceFolder}/**")

		cCppProps := map[string]interface{}{
			"configurations": []map[string]interface{}{
				{
					"name": "Zephyr",
					"includePath": includePaths,
					"compilerPath": "",
					"cStandard": "c11",
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
