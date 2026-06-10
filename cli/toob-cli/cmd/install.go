package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/toob-boot/toob/internal/lockfile"
	"github.com/toob-boot/toob/internal/paths"
	"github.com/toob-boot/toob/internal/registry"
	"github.com/toob-boot/toob/internal/toolchain"
	"github.com/toob-boot/toob/internal/ui"
)

var installCmd = &cobra.Command{
	Use:   "install",
	Short: "Install all toolchains and dependencies defined in toob.lock",
	RunE: func(cmd *cobra.Command, args []string) error {
		root, err := paths.FindProjectRoot("")
		if err != nil {
			return fmt.Errorf("not in a Toob project: %w", err)
		}

		lfPath := paths.LockfilePath(root)
		lf, err := lockfile.Load(lfPath)
		if err != nil || len(lf.Chips) == 0 {
			ui.Info("No dependencies found in toob.lock. Try 'toob chip add' first.")
			return nil
		}

		ui.Header("Install")

		cache := registry.NewCache("")
		if !cache.IsInitialized() {
			ui.Step("Registry not initialized. Auto-syncing...")
			if err := cache.Sync(false, false); err != nil {
				return fmt.Errorf("registry sync failed: %w", err)
			}
		}

		// Ensure we are using the registry version defined in lockfile
		if lf.Registry.Commit != "" {
			if err := cache.SwitchVersion(lf.Registry.Commit); err != nil {
				return fmt.Errorf("failed to checkout locked registry commit %s: %w", lf.Registry.Commit, err)
			}
		}

		installedCount := 0
		for _, chip := range lf.Chips {
			// 1. Pre-fetch Chip Package
			ui.Step("Pre-fetching chip package '%s'...", chip.Name)
			chipDir, err := cache.ChipSourcePath(chip.Name)
			if err != nil {
				return fmt.Errorf("failed to pre-fetch chip package '%s': %w", chip.Name, err)
			}

			// 2. Parse chip_manifest.json to resolve drivers & other dependencies
			var chipManifest struct {
				Drivers    []string `json:"drivers"`
				Arch       string   `json:"arch"`
				Toolchain  string   `json:"toolchain"`
				MinCoreSDK string   `json:"min_core_sdk"`
				Includes   []string `json:"includes"`
			}
			manifestPath := filepath.Join(chipDir, "chip_manifest.json")
			if manifestData, err := os.ReadFile(manifestPath); err == nil {
				if err := json.Unmarshal(manifestData, &chipManifest); err == nil {
					// Pre-fetch Architecture
					if chipManifest.Arch != "" {
						ui.Step("Pre-fetching architecture '%s'...", chipManifest.Arch)
						if _, err := cache.ArchSourcePath(chipManifest.Arch); err != nil {
							ui.Warn("Failed to pre-fetch architecture '%s': %v", chipManifest.Arch, err)
						}
					}
					// Pre-fetch Drivers
					for _, drv := range chipManifest.Drivers {
						ui.Step("Pre-fetching driver '%s'...", drv)
						if _, err := cache.DriverSourcePath(drv); err != nil {
							ui.Warn("Failed to pre-fetch driver '%s': %v", drv, err)
						}
					}
					// Pre-fetch SoC package if needed
					if len(chipManifest.Includes) > 0 {
						ui.Step("Pre-fetching SoC includes...")
						if _, err := cache.SoCSourcePath("soc"); err != nil {
							ui.Warn("Failed to pre-fetch SoC package: %v", err)
						}
					}
				}
			}

			// 3. Pre-fetch Crypto Packages
			for _, cryptoPkg := range []string{chip.CryptoBackend, chip.CryptoHash, chip.CryptoPqc} {
				if cryptoPkg != "" {
					ui.Step("Pre-fetching crypto package '%s'...", cryptoPkg)
					if _, err := cache.CryptoSourcePath(cryptoPkg); err != nil {
						ui.Warn("Failed to pre-fetch crypto package '%s': %v", cryptoPkg, err)
					}
				}
			}

			if chip.Toolchain == "" {
				continue
			}

			// 4. Pre-fetch Toolchain configuration (toolchain.cmake)
			tcName := strings.TrimSuffix(chip.Toolchain, "-")
			ui.Step("Pre-fetching toolchain config for '%s'...", tcName)
			if _, err := cache.ToolchainConfigPath(tcName); err != nil {
				ui.Warn("Failed to pre-fetch toolchain config '%s': %v", tcName, err)
			}

			// Resolve expected version. Fallback to registry if lockfile is missing it.
			expectedVersion := chip.ToolchainVersion
			if expectedVersion == "" {
				expectedVersion = toolchain.GetExpectedVersion(chip.Toolchain, cache.Dir())
			}

			ui.Step("Ensuring toolchain %s (v%s) for chip %s", chip.Toolchain, expectedVersion, chip.Name)

			_, err = toolchain.EnsureAvailable(chip.Toolchain, expectedVersion, cache.Dir())
			if err != nil {
				return fmt.Errorf("failed to install toolchain %s: %w", chip.Toolchain, err)
			}
			installedCount++
		}

		if installedCount > 0 {
			ui.Success("Successfully installed %d toolchain(s). Native builds are ready!", installedCount)
		} else {
			ui.Info("All dependencies are already satisfied.")
		}

		return nil
	},
}
