package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

const version = "1.0.0"

var rootCmd = &cobra.Command{
	Use:   "toob",
	Short: "Hardware Package Manager for the Toob-Boot ecosystem",
	Long: `Toob manages chip HAL packages, registry synchronization,
and orchestrates the full build pipeline for Toob-Boot firmware.`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.Version = version
	rootCmd.CompletionOptions.DisableDefaultCmd = true

	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(registryCmd)
	rootCmd.AddCommand(chipCmd)
	rootCmd.AddCommand(buildCmd)
	rootCmd.AddCommand(cleanCmd)
	rootCmd.AddCommand(doctorCmd)
}
