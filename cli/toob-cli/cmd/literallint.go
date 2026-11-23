package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/toob-boot/toob/internal/literallint"
	"github.com/toob-boot/toob/internal/ui"
)

func newLiteralLintCmd() *cobra.Command {
	var (
		jsonPath string
		deepMode bool
	)

	c := &cobra.Command{
		Use:   "literallint [dir]",
		Short: "Scan C HAL sources for REG-040 literal safety violations",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			targetDir := "."
			if len(args) == 1 {
				targetDir = args[0]
			}
			absDir, err := filepath.Abs(targetDir)
			if err != nil {
				return fmt.Errorf("resolve directory %q: %w", targetDir, err)
			}

			cfg := literallint.DefaultConfig(absDir)
			cfg.DeepMode = deepMode

			report, err := literallint.RunLint(cfg)
			if err != nil {
				return fmt.Errorf("literallint scan failed: %w", err)
			}

			if jsonPath != "" {
				data, encErr := json.MarshalIndent(report, "", "  ")
				if encErr != nil {
					return fmt.Errorf("marshal literallint report: %w", encErr)
				}
				if writeErr := os.WriteFile(filepath.Clean(jsonPath), data, 0o600); writeErr != nil {
					return fmt.Errorf("write literallint report %s: %w", jsonPath, writeErr)
				}
			}

			for _, v := range report.Violations {
				ui.Warn("%s:%d:%d: [%s] banned literal %q",
					sanitizeDisplay(v.File), v.Line, v.Column, sanitizeDisplay(v.Source), sanitizeDisplay(v.Literal))
			}

			if !report.Passed || len(report.Violations) > 0 {
				return fmt.Errorf("literallint failed: %d violation(s)", len(report.Violations))
			}

			ui.Success("literallint passed (%d files scanned, 0 violations)", report.Stats.FilesScanned)
			return nil
		},
	}

	c.Flags().StringVar(&jsonPath, "json", "", "Write JSON lint report to path")
	c.Flags().BoolVar(&deepMode, "deep", false, "Enable clang-query AST literal inspection")
	return c
}
