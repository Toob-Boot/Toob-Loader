package cmd

import (
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/toob-boot/toob/internal/conformance"
	"github.com/toob-boot/toob/internal/ui"
)

var conformanceCmd = &cobra.Command{
	Use:   "conformance [path]",
	Short: "Audit a package for HAL trait conformance and Mock/Real equivalence",
	Long: `Audits a driver or chip package directory against HAL trait contracts and Mock vs Real implementation parity.

Generates conformance_report.json and conformance_report.md (CRA Annex-I Evidence).`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		pkgPath := "."
		if len(args) > 0 {
			pkgPath = args[0]
		}
		absDir, err := filepath.Abs(pkgPath)
		if err != nil {
			return fmt.Errorf("invalid path: %w", err)
		}

		ui.Header(fmt.Sprintf("HAL Conformance Harness: %s", filepath.Base(absDir)))

		report, err := conformance.AuditPackage(absDir)
		if err != nil {
			return fmt.Errorf("conformance audit failed: %w", err)
		}

		jsonPath := filepath.Join(absDir, "conformance_report.json")
		mdPath := filepath.Join(absDir, "conformance_report.md")

		_ = conformance.ExportReportJSON(report, jsonPath)
		_ = conformance.ExportReportMarkdown(report, mdPath)

		for _, chk := range report.Checks {
			if chk.Passed {
				ui.Success("%s: %s", chk.Name, chk.Details)
			} else {
				ui.Error("%s: %s", chk.Name, chk.Details)
			}
		}

		if !report.Passed {
			return fmt.Errorf("FATAL [CONFORMANCE_FAIL]: Package failed HAL conformance audit!")
		}

		ui.Success("HAL Conformance audit PASSED cleanly. Exported reports to %s and %s", jsonPath, mdPath)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(conformanceCmd)
}
