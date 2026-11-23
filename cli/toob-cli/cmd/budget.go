package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/toob-boot/toob/internal/manifest"
	"github.com/toob-boot/toob/internal/ui"
)

func newBudgetCmd() *cobra.Command {
	var (
		tomlPath string
		binPath  string
		stage    string
	)

	c := &cobra.Command{
		Use:    "budget",
		Short:  "Verify binary footprint fits within the declarative flash budget for a stage",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			report, err := manifest.CheckBudget(tomlPath, binPath, stage)
			if err != nil {
				return fmt.Errorf("budget check (%s): %w", sanitizeDisplay(stage), err)
			}
			pct := 0.0
			if report.Budget > 0 {
				pct = (float64(report.Size) / float64(report.Budget)) * 100.0
			}
			ui.Success("Flash budget OK [%s]: %d / %d bytes (%.1f%%)",
				sanitizeDisplay(stage), report.Size, report.Budget, pct)
			return nil
		},
	}

	c.Flags().StringVar(&tomlPath, "toml", "", "Path to device.toml (required)")
	c.Flags().StringVar(&binPath, "bin", "", "Path to compiled binary image (required)")
	c.Flags().StringVar(&stage, "stage", "", "Target bootloader stage (stage0, stage1, stage1b, recovery) (required)")
	_ = c.MarkFlagRequired("toml")
	_ = c.MarkFlagRequired("bin")
	_ = c.MarkFlagRequired("stage")
	return c
}
