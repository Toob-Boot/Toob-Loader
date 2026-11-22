package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/toob-boot/toob/internal/manifest"
	"github.com/toob-boot/toob/internal/ui"
)

type budgetOptions struct {
	toml  string
	bin   string
	stage string
}

func newBudgetCmd() *cobra.Command {
	var opts budgetOptions
	c := &cobra.Command{
		Use:    "budget",
		Short:  "Check if a compiled binary fits into its TOML budget",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			rep, err := manifest.CheckBudget(opts.toml, opts.bin, opts.stage)
			if err != nil {
				return fmt.Errorf("budget check failed: %w", err)
			}
			ui.Success("BUDGET SUCCESS: %s (%d bytes) fits into budget (%d bytes).", rep.Stage, rep.Size, rep.Budget)
			return nil
		},
	}
	c.Flags().StringVar(&opts.toml, "toml", "device.toml", "Path to device.toml")
	c.Flags().StringVar(&opts.bin, "bin", "", "Path to compiled .bin")
	c.Flags().StringVar(&opts.stage, "stage", "", "Which stage to check (stage0, stage1, recovery, app, or netcore)")
	_ = c.MarkFlagRequired("bin")
	_ = c.MarkFlagRequired("stage")
	return c
}

var budgetCmd = newBudgetCmd()

func init() {
	rootCmd.AddCommand(budgetCmd)
}
