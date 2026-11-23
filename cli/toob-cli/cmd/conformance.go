package cmd

import (
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/toob-boot/toob/internal/conformance"
	"github.com/toob-boot/toob/internal/ui"
)

func newConformanceCmd() *cobra.Command {
	var (
		jsonPath     string
		mdPath       string
		contractPath string
	)

	c := &cobra.Command{
		Use:   "conformance [package-dir]",
		Short: "Run HAL & package conformance audit on a local package directory",
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

			var report *conformance.ConformanceReport
			if contractPath != "" {
				report, err = conformance.AuditPackageWithOptions(absDir, conformance.AuditOptions{ContractPath: contractPath})
			} else {
				report, err = conformance.AuditPackage(absDir)
			}
			if err != nil {
				return fmt.Errorf("conformance audit failed: %w", err)
			}

			if jsonPath != "" {
				if expErr := conformance.ExportReportJSON(report, jsonPath); expErr != nil {
					return fmt.Errorf("export conformance JSON report: %w", expErr)
				}
			}
			if mdPath != "" {
				if expErr := conformance.ExportReportMarkdown(report, mdPath); expErr != nil {
					return fmt.Errorf("export conformance Markdown report: %w", expErr)
				}
			}

			if !report.Passed {
				return fmt.Errorf("conformance audit failed with %d failed check(s)", countFailedConformanceChecks(report))
			}

			ui.Success("Conformance audit passed for %s", absDir)
			return nil
		},
	}

	c.Flags().StringVar(&jsonPath, "json", "", "Write JSON conformance report to path")
	c.Flags().StringVar(&mdPath, "md", "", "Write Markdown conformance report to path")
	c.Flags().StringVar(&contractPath, "contract", "", "Optional override path to hal_contract.json")
	return c
}

func countFailedConformanceChecks(report *conformance.ConformanceReport) int {
	if report == nil {
		return 1
	}
	failed := 0
	for _, chk := range report.Checks {
		if !chk.Passed {
			failed++
		}
	}
	if failed == 0 && !report.Passed {
		return 1
	}
	return failed
}
