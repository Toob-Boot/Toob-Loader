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
	Short: "Initialize a new Toob-Loader IoT project",
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

		fmt.Printf("[toob] Initializing project '%s' for chip '%s'...\n", projectName, initChip)

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

# TODO: Connect to Zephyr or ESP-IDF if needed.
# We haven't fully tested ESP-IDF or Zephyr integration yet.
# For now, we integrate standard toob_hal directly.

# The CLI will generate toob_paths.cmake during the build.
include(cmake/toob_paths.cmake OPTIONAL)

add_executable(${PROJECT_NAME} src/main.c)

# TODO: Link against libtoob or common APIs
# target_link_libraries(${PROJECT_NAME} PRIVATE toob_hal)
`, projectName)
		if err := os.WriteFile(filepath.Join(projectDir, "CMakeLists.txt"), []byte(cmakeLists), 0o644); err != nil {
			return err
		}

		// 4. Generate src/main.c
		if err := os.MkdirAll(filepath.Join(projectDir, "src"), 0o755); err != nil {
			return err
		}
		mainC := `#include <stdio.h>

// TODO: Include specific Repowatt/Toob-Loader headers here
// E.g., from common/include/boot_hal.h or libtoob
// #include "boot_hal.h"

// TODO: Define the correct entrypoint depending on the underlying framework.
// E.g., app_main() for ESP-IDF, main() for Zephyr/Baremetal.
int main(void) {
    printf("Hello from Toob-Loader IoT App!\n");
    return 0;
}
`
		if err := os.WriteFile(filepath.Join(projectDir, "src", "main.c"), []byte(mainC), 0o644); err != nil {
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
		inst := installer.New(projectDir, cache)
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
