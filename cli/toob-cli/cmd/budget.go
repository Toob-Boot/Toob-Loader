package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/toob-boot/toob/internal/manifest"
)

var (
	budgetToml  string
	budgetBin   string
	budgetStage string
)

var budgetCmd = &cobra.Command{
	Use:    "budget",
	Short:  "Check if a compiled binary fits into its TOML budget",
	Hidden: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		err := manifest.CheckBudget(budgetToml, budgetBin, budgetStage)
		if err != nil {
			return fmt.Errorf("budget check failed: %w", err)
		}
		return nil
	},
}

func init() {
	budgetCmd.Flags().StringVar(&budgetToml, "toml", "device.toml", "Path to device.toml")
	budgetCmd.Flags().StringVar(&budgetBin, "bin", "", "Path to compiled .bin")
	budgetCmd.Flags().StringVar(&budgetStage, "stage", "", "Which stage to check (stage0 or stage1)")
	budgetCmd.MarkFlagRequired("bin")
	budgetCmd.MarkFlagRequired("stage")

	rootCmd.AddCommand(budgetCmd)
}
