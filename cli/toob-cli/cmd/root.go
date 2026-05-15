package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/toob-boot/toob/internal/regcheck"
	"github.com/toob-boot/toob/internal/ui"
	"github.com/toob-boot/toob/internal/updater"
)

var (
	Version        = "dev"
	updateResult   chan *updater.CheckResult
	registryResult <-chan *regcheck.Result
)

var rootCmd = &cobra.Command{
	Use:   "toob",
	Short: "Hardware Package Manager for the Toob-Boot ecosystem",
	Long: `Toob manages chip HAL packages, registry synchronization,
and orchestrates the full build pipeline for Toob-Boot firmware.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		ui.Init()
		if cmd.Name() == "update" || cmd.Name() == "sync" {
			return
		}
		// CLI update check (async, zero-blocking)
		res, _ := updater.CheckForUpdate(Version, false, false)
		if res != nil {
			updateResult = make(chan *updater.CheckResult, 1)
			updateResult <- res
		}
		// Registry freshness check (async, zero-blocking)
		registryResult = regcheck.CheckAsync()
	},
	PersistentPostRun: func(cmd *cobra.Command, args []string) {
		// CLI update banner
		if updateResult != nil {
			select {
			case res := <-updateResult:
				if res != nil && res.Available {
					ui.UpdateBanner(Version, res.Version)
				}
			default:
			}
		}
		// Registry freshness banner
		if registryResult != nil {
			select {
			case res := <-registryResult:
				if res != nil && res.Outdated {
					ui.RegistryBanner(res.CurrentVersion, res.LatestVersion, res.ChipWarnings)
				}
			default:
			}
		}
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.Version = Version
	rootCmd.CompletionOptions.DisableDefaultCmd = true

	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(registryCmd)
	rootCmd.AddCommand(chipCmd)
	rootCmd.AddCommand(buildCmd)
	rootCmd.AddCommand(cleanCmd)
	rootCmd.AddCommand(doctorCmd)
	rootCmd.AddCommand(abiCmd)
	rootCmd.AddCommand(installCmd)
}
