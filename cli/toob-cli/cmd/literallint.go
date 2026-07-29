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

var (
	literallintDeep     bool
	literallintIncludes []string
	literallintJSON     string
)

var literallintCmd = &cobra.Command{
	Use:   "literallint [paths...]",
	Short: "Literal-Bann-Lint for chips/ and drivers/ codebases",
	Long: `Audits C/H source files for unallowed numeric literals (hardcoded addresses, register offsets, magic numbers).
Every hardware constant must originate from generated_boot_config.h or chip_config.h.

Uses a regex scanner by default, and optional AST inspection via clang-query when --deep is specified.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		paths := args
		if len(paths) == 0 {
			// Default paths
			paths = []string{
				"toob-registry/registry/chips",
				"toob-registry/registry/drivers",
			}
		}

		var absPaths []string
		for _, p := range paths {
			abs, err := filepath.Abs(p)
			if err != nil {
				return fmt.Errorf("invalid path %s: %w", p, err)
			}
			if _, err := os.Stat(abs); err == nil {
				absPaths = append(absPaths, abs)
			}
		}

		if len(absPaths) == 0 {
			return fmt.Errorf("no valid scanning paths found among: %v", paths)
		}

		cfg := literallint.LintConfig{
			Paths:        absPaths,
			Extensions:   []string{".c", ".h"},
			IncludePaths: literallintIncludes,
			DeepMode:     literallintDeep,
		}

		ui.Header(fmt.Sprintf("Literal-Bann-Lint: Scanning %d path(s)", len(absPaths)))

		report, err := literallint.RunLint(cfg)
		if err != nil {
			return fmt.Errorf("literal lint failed: %w", err)
		}

		ui.Info("Mode: %s", report.Mode)
		ui.Info("Files scanned: %d, Lines scanned: %d, Suppressed: %d",
			report.Stats.FilesScanned, report.Stats.LinesScanned, report.Stats.Suppressed)

		if len(report.Violations) > 0 {
			ui.Error("Found %d numeric literal violation(s):", len(report.Violations))
			for _, v := range report.Violations {
				relPath, _ := filepath.Rel(".", v.File)
				if relPath == "" {
					relPath = v.File
				}
				ui.Error("  %s:%d:%d: literal '%s' [%s]\n    Line: %s",
					relPath, v.Line, v.Column, v.Literal, v.Source, v.Context)
			}
		}

		if literallintJSON != "" {
			data, _ := json.MarshalIndent(report, "", "  ")
			if err := os.WriteFile(literallintJSON, data, 0o644); err != nil {
				ui.Error("Failed to write JSON report to %s: %v", literallintJSON, err)
			} else {
				ui.Success("Exported JSON report to %s", literallintJSON)
			}
		}

		if !report.Passed {
			return fmt.Errorf("FATAL [LITERAL_LINT_FAIL]: Found %d banned numeric literal(s)!", len(report.Violations))
		}

		ui.Success("Literal-Bann-Lint PASSED cleanly. No unauthorized numeric literals found.")
		return nil
	},
}

func init() {
	literallintCmd.Flags().BoolVar(&literallintDeep, "deep", false, "Enable clang-query AST hybrid scanning")
	literallintCmd.Flags().StringSliceVar(&literallintIncludes, "include", nil, "Header include paths for clang-query")
	literallintCmd.Flags().StringVar(&literallintJSON, "json", "", "Export report as JSON to specified file path")
	rootCmd.AddCommand(literallintCmd)
}
