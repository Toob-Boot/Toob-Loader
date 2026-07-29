package conformance

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ExportReportJSON writes the ConformanceReport to a JSON file.
func ExportReportJSON(report *ConformanceReport, outPath string) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal conformance report: %w", err)
	}
	return os.WriteFile(outPath, data, 0o644)
}

// ExportReportMarkdown writes a Markdown summary of the ConformanceReport for CRA evidence documentation.
func ExportReportMarkdown(report *ConformanceReport, outPath string) error {
	var b strings.Builder

	statusEmoji := "✅ PASS"
	if !report.Passed {
		statusEmoji = "❌ FAIL"
	}

	b.WriteString(fmt.Sprintf("# HAL Conformance & Verification Report — %s\n\n", report.PackageName))
	b.WriteString(fmt.Sprintf("**Package Path:** `%s`  \n", report.PackagePath))
	b.WriteString(fmt.Sprintf("**Trait:** `%s`  \n", report.Trait))
	b.WriteString(fmt.Sprintf("**ABI Version:** `%s`  \n", report.AbiVersion))
	b.WriteString(fmt.Sprintf("**Audit Timestamp:** `%s`  \n", report.Timestamp.Format("2006-01-02 15:04:05 UTC")))
	b.WriteString(fmt.Sprintf("**Overall Status:** **%s**\n\n", statusEmoji))

	b.WriteString("## 1. Trait Contract & Metadata Checks\n\n")
	b.WriteString("| Check Name | Status | Details |\n")
	b.WriteString("| --- | --- | --- |\n")

	for _, check := range report.Checks {
		chkStatus := "PASS"
		if !check.Passed {
			chkStatus = "FAIL"
		}
		b.WriteString(fmt.Sprintf("| %s | %s | %s |\n", check.Name, chkStatus, check.Details))
	}

	b.WriteString("\n## 2. Mock / Real Implementation Equivalence\n\n")
	if report.MockEquivalence != nil {
		if report.MockEquivalence.Passed {
			b.WriteString("> [!NOTE]\n> Mock and Real implementation files adhere to identical symbol signatures and contract semantics.\n\n")
		} else {
			b.WriteString("> [!CAUTION]\n> Mock/Real contract divergence detected:\n")
			for _, d := range report.MockEquivalence.Divergences {
				b.WriteString(fmt.Sprintf("- %s\n", d))
			}
			b.WriteString("\n")
		}
	} else {
		b.WriteString("No Mock implementation file found — single production compilation target audited.\n\n")
	}

	b.WriteString("---\n*Generated automatically by TOOB HAL Conformance Engine (CRA Annex-I Evidence)*\n")

	dir := filepath.Dir(outPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	return os.WriteFile(outPath, []byte(b.String()), 0o644)
}
