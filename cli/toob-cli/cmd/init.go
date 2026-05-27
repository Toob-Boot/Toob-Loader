package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
	"github.com/toob-boot/toob/internal/apiclient"
	"github.com/toob-boot/toob/internal/installer"
	"github.com/toob-boot/toob/internal/paths"
	"github.com/toob-boot/toob/internal/registry"
	"github.com/toob-boot/toob/internal/scaffold"
	"github.com/toob-boot/toob/internal/ui"
)

var (
	initChip         string
	initNoVSCode     bool
	initFramework    string
	initDevContainer bool
	initSdkUrl       string
	initSdkRevision  string
	initPackage      bool
)

var initCmd = &cobra.Command{
	Use:   "init [project-name]",
	Short: "Initialize a new Toob-Loader IoT project (Zero-Bloat Scaffold)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		projectName := args[0]

		var validNamePattern *regexp.Regexp
		if initPackage {
			validNamePattern = regexp.MustCompile(`^(@[a-zA-Z0-9_-]+/)?[a-zA-Z0-9_-]+$`)
		} else {
			validNamePattern = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
		}
		if !validNamePattern.MatchString(projectName) {
			if initPackage {
				return fmt.Errorf("invalid package name '%s'. Allowed: unscoped 'name' or scoped '@scope/name' containing alphanumeric, dashes, and underscores", projectName)
			}
			return fmt.Errorf("invalid project name '%s'. Only alphanumeric characters, dashes, and underscores are allowed", projectName)
		}

		if initChip == "" {
			return fmt.Errorf("please specify a chip using the --chip flag (e.g., --chip esp32c6)")
		}

		// 1. Create project directory
		projectDir := fmt.Sprintf("./%s", projectName)
		if _, err := os.Stat(projectDir); err == nil {
			return fmt.Errorf("directory %s already exists", projectDir)
		}
		if err := os.MkdirAll(projectDir, 0o755); err != nil {
			return err
		}

		// Rollback on failure
		var initErr error
		defer func() {
			if initErr != nil {
				ui.Error("Scaffolding failed: %v", initErr)
				ui.Step("Rolling back... removing %s", projectDir)
				os.RemoveAll(projectDir)
			}
		}()

		ui.Header("Project Init")
		ui.Step("Creating '%s' for chip '%s' (Framework: %s)", projectName, ui.Bold(initChip), ui.Cyan(initFramework))

		// 2. Fetch Registry Context
		_, err := paths.RegistryDir()
		if err != nil {
			initErr = err
			return err
		}
		cache := registry.NewCache("")
		if err := cache.Sync(false, false); err != nil {
			initErr = err
			return err
		}
		ci, err := cache.GetChip(initChip)
		if err != nil {
			initErr = fmt.Errorf("chip %s not found in registry", initChip)
			return initErr
		}

		if initPackage {
			ui.Step("Scaffolding publishable package project '%s'...", projectName)
			// Get author login
			author := apiclient.GetLogin()
			if author == "" {
				author = "unregistered"
			}

			// Determine core/toolchain versions from matrix
			tcVersion := "12.2.0"
			coreVersion := "1.0.0"
			if matrix, err := cache.FetchLiveMatrix(); err == nil && matrix != nil {
				if chipMatrix, ok := (*matrix)[initChip]; ok {
					for _, v := range chipMatrix.Versions {
						if v.Dependencies.Toolchain != "" {
							tcVersion = v.Dependencies.Toolchain
						}
						if v.Dependencies.CoreSDK != "" {
							coreVersion = v.Dependencies.CoreSDK
						}
						break
					}
				}
			}

			// Clean base name for files (remove scope if present)
			baseName := projectName
			if _, after, ok := strings.Cut(projectName, "/"); ok {
				baseName = after
			}

			// 1. Create folders: src, include
			if err := os.MkdirAll(filepath.Join(projectDir, "src"), 0o755); err != nil {
				initErr = err
				return err
			}
			if err := os.MkdirAll(filepath.Join(projectDir, "include"), 0o755); err != nil {
				initErr = err
				return err
			}

			// 2. Write driver_manifest.json
			manifestPath := filepath.Join(projectDir, "driver_manifest.json")
			manifestJSON := fmt.Sprintf(`{
  "name": %q,
  "author": %q,
  "version": "0.1.0",
  "description": "Scaffolded driver for %s",
  "reference_build_context": {
    "chip": %q,
    "core_sdk_version": %q,
    "toolchain_version": %q,
    "target_architecture": %q
  },
  "dependencies": {
    "core": "^%s"
  },
  "sources": [
    "src/%s.c"
  ],
  "includes": [
    "include"
  ]
}
`, projectName, author, initChip, initChip, coreVersion, tcVersion, ci.Arch, coreVersion, baseName)
			if err := os.WriteFile(manifestPath, []byte(manifestJSON), 0o644); err != nil {
				initErr = err
				return err
			}

			// 3. Write src/<baseName>.c
			cPath := filepath.Join(projectDir, "src", baseName+".c")
			funcName := strings.ReplaceAll(baseName, "-", "_")
			cCode := fmt.Sprintf(`#include "%s.h"

// TODO: Implement your driver initialization function here
void %s_init(void) {
    // Hardware initialization
}
`, baseName, funcName)
			if err := os.WriteFile(cPath, []byte(cCode), 0o644); err != nil {
				initErr = err
				return err
			}

			// 4. Write include/<baseName>.h
			hPath := filepath.Join(projectDir, "include", baseName+".h")
			hCode := fmt.Sprintf(`#ifndef %s_H
#define %s_H

void %s_init(void);

#endif // %s_H
`, strings.ToUpper(funcName), strings.ToUpper(funcName), funcName, strings.ToUpper(funcName))
			if err := os.WriteFile(hPath, []byte(hCode), 0o644); err != nil {
				initErr = err
				return err
			}

			// 5. Write .toobignore and .gitignore
			ignoreList := ".toob/\nbuild/\ncredentials.json\n*.tar.gz\n"
			if err := os.WriteFile(filepath.Join(projectDir, ".toobignore"), []byte(ignoreList), 0o644); err != nil {
				initErr = err
				return err
			}
			if err := os.WriteFile(filepath.Join(projectDir, ".gitignore"), []byte(ignoreList), 0o644); err != nil {
				initErr = err
				return err
			}

			// Initialize git repo
			gitCmd := exec.Command("git", "init")
			_ = gitCmd.Run()

			ui.Divider()
			ui.KeyValue("Package Name", ui.Bold(projectName))
			ui.KeyValue("Chip", ui.BoldBrand(initChip))
			ui.KeyValue("Architecture", ui.Cyan(ci.Arch))
			ui.Divider()
			ui.Success("Package initialized successfully!")
			ui.Tip("Run `cd %s` and check out `driver_manifest.json`.", projectName)
			return nil
		}

		if initFramework == "" {
			idx, _ := cache.LoadIndex()
			liveIntegrations, liveErr := cache.FetchLiveIntegrations()
			var frameworks []string
			var frameworkKeys []string

			if liveErr == nil && len(liveIntegrations) > 0 {
				// We have live data!
				for _, key := range liveIntegrations {
					displayName := key
					// Try to enrich with local description if available
					if idx != nil {
						if info, ok := idx.Integrations[key]; ok && info.Description != "" {
							displayName = fmt.Sprintf("%s (%s)", info.Name, info.Description)
						}
					}
					frameworks = append(frameworks, displayName)
					frameworkKeys = append(frameworkKeys, key)
				}
			} else {
				// Fallback to local cache
				if idx == nil || len(idx.Integrations) == 0 {
					initErr = fmt.Errorf("no integrations found in registry")
					return initErr
				}
				for key, info := range idx.Integrations {
					displayName := info.Name
					if info.Description != "" {
						displayName = fmt.Sprintf("%s (%s)", info.Name, info.Description)
					}
					frameworks = append(frameworks, displayName)
					frameworkKeys = append(frameworkKeys, key)
				}
			}

			choiceIdx, err := ui.Select("Select Target Framework", frameworks)
			if err != nil {
				return err
			}
			initFramework = frameworkKeys[choiceIdx]
		}

		// Auto-sync if the chosen framework does not exist locally
		idx, _ := cache.LoadIndex()
		_, exists := idx.Integrations[initFramework]
		if idx == nil || !exists {
			ui.Step("Framework '%s' is new! Auto-syncing registry to download files...", initFramework)
			if err := cache.Sync(false, false); err != nil {
				return fmt.Errorf("failed to sync registry to download new framework: %w", err)
			}
			// Reload index after sync
			if _, err := cache.LoadIndex(); err != nil {
				return fmt.Errorf("failed to load registry index after sync: %w", err)
			}
		}

		ctx := scaffold.Context{
			ProjectName:     projectName,
			ProjectDir:      projectDir,
			ChipName:        initChip,
			ChipInfo:        ci,
			RegistryDir:     cache.Dir(),
			NoVSCode:        initNoVSCode,
			UseDevContainer: initDevContainer,
			SdkUrl:          initSdkUrl,
			SdkRevision:     initSdkRevision,
		}

		// 3. Delegate to Integration Generator
		generator := &scaffold.IntegrationGenerator{Framework: initFramework}

		if err := generator.Generate(ctx); err != nil {
			initErr = fmt.Errorf("scaffolding failed: %w", err)
			return initErr
		}

		// 4. Run installer.Add (True IKEA Mode)
		// Change directory to the project directory before running installer
		cwd, _ := os.Getwd()
		os.Chdir(projectDir)
		defer os.Chdir(cwd)

		inst := installer.New(".", cache)
		if err := inst.Add(initChip); err != nil {
			initErr = fmt.Errorf("failed to add chip '%s': %w", initChip, err)
			return initErr
		}

		// 5. Initialize Git Repository
		gitCmd := exec.Command("git", "init")
		gitCmd.Stdout = os.Stdout
		gitCmd.Stderr = os.Stderr
		if err := gitCmd.Run(); err != nil {
			ui.Warn("Failed to initialize git repository: %v", err)
		}

		ui.Divider()
		ui.KeyValue("Project", ui.Bold(projectName))
		ui.KeyValue("Chip", ui.BoldBrand(initChip))
		ui.KeyValue("Framework", ui.Cyan(initFramework))
		ui.Divider()
		ui.Success("Project initialized successfully!")
		ui.Tip("Run `cd %s` and check out the `toob_integration/INTEGRATION_GUIDE.md` to finish the setup.", projectName)
		return nil
	},
}

func init() {
	initCmd.Flags().StringVarP(&initChip, "chip", "c", "", "Target chip for the project (e.g., esp32c6)")
	initCmd.Flags().BoolVar(&initNoVSCode, "no-vscode", false, "Disable generation of VS Code IntelliSense configurations")
	initCmd.Flags().StringVar(&initFramework, "framework", "", "Target RTOS framework (baremetal, zephyr, espidf)")
	initCmd.Flags().BoolVar(&initDevContainer, "devcontainer", false, "Generate VS Code DevContainer configuration for isolated builds")
	initCmd.Flags().StringVar(&initSdkUrl, "sdk-url", "https://github.com/Toob-Boot/Toob-Loader.git", "URL to fetch the Toob-Loader SDK from")
	initCmd.Flags().StringVar(&initSdkRevision, "sdk-version", "main", "Git branch or tag to use for the Toob-Loader SDK")
	// TODO (Gap 10): Scaffold a publishable package project with manifest template.
	initCmd.Flags().BoolVar(&initPackage, "package", false, "Initialize as a publishable package project instead of a firmware application")
}
