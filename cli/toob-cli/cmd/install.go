package cmd

import (
	"fmt"

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
			if chip.Toolchain == "" {
				continue
			}

			// Resolve expected version. Fallback to registry if lockfile is missing it.
			expectedVersion := chip.ToolchainVersion
			if expectedVersion == "" {
				expectedVersion = toolchain.GetExpectedVersion(chip.Toolchain, cache.Dir())
			}

			ui.Step("Ensuring toolchain %s (v%s) for chip %s", chip.Toolchain, expectedVersion, chip.Name)

			_, err := toolchain.EnsureAvailable(chip.Toolchain, expectedVersion, cache.Dir())
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
