package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/toob-boot/toob/internal/updater"
)

var (
	Version      = "1.0.0"
	updateResult chan *updater.CheckResult
)

var rootCmd = &cobra.Command{
	Use:   "toob",
	Short: "Hardware Package Manager for the Toob-Boot ecosystem",
	Long: `Toob manages chip HAL packages, registry synchronization,
and orchestrates the full build pipeline for Toob-Boot firmware.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		if cmd.Name() == "update" {
			return
		}
		updateResult = make(chan *updater.CheckResult, 1)
		go func() {
			res, _ := updater.CheckForUpdate(Version)
			updateResult <- res
		}()
	},
	PersistentPostRun: func(cmd *cobra.Command, args []string) {
		if updateResult == nil {
			return
		}
		select {
		case res := <-updateResult:
			if res != nil && res.Available {
				fmt.Printf("\n\033[36m╭──────────────────────────────────────────────────────────╮\033[0m\n")
				fmt.Printf("\033[36m│\033[0m                                                          \033[36m│\033[0m\n")
				fmt.Printf("\033[36m│\033[0m   Update available! %-6s \u2192 %-25s \033[36m│\033[0m\n", Version, res.Version)
				fmt.Printf("\033[36m│\033[0m   Run 'toob update' to install the newest version.       \033[36m│\033[0m\n")
				fmt.Printf("\033[36m│\033[0m                                                          \033[36m│\033[0m\n")
				fmt.Printf("\033[36m╰──────────────────────────────────────────────────────────╯\033[0m\n\n")
			}
		case <-time.After(150 * time.Millisecond):
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
}
