package conformance

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func escapeMarkdownCell(s string) string {
	replaced := strings.ReplaceAll(s, "\r\n", "<br>")
	replaced = strings.ReplaceAll(replaced, "\n", "<br>")
	replaced = strings.ReplaceAll(replaced, "\r", "<br>")
	return strings.ReplaceAll(replaced, "|", `\|`)
}

func escapeMarkdownInline(s string) string {
	replaced := strings.ReplaceAll(s, "\r\n", " ")
	replaced = strings.ReplaceAll(replaced, "\n", " ")
	replaced = strings.ReplaceAll(replaced, "\r", " ")
	return strings.ReplaceAll(replaced, "`", "'")
}

// ExportReportJSON writes the ConformanceReport to a JSON file.
func ExportReportJSON(report *ConformanceReport, outPath string) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal conformance report: %w", err)
	}
	dir := filepath.Dir(outPath)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return err
		}
	}
	return os.WriteFile(outPath, data, 0o600)
}

// ExportReportMarkdown writes a Markdown summary of the ConformanceReport for CRA evidence documentation.
func ExportReportMarkdown(report *ConformanceReport, outPath string) error {
	var b strings.Builder

	statusEmoji := "✅ PASS"
	if !report.Passed {
		statusEmoji = "❌ FAIL"
	}

	fmt.Fprintf(&b, "# HAL Conformance & Verification Report — %s\n\n", escapeMarkdownInline(report.PackageName))
	fmt.Fprintf(&b, "**Package Path:** `%s`  \n", escapeMarkdownInline(report.PackagePath))
	fmt.Fprintf(&b, "**Trait:** `%s`  \n", escapeMarkdownInline(report.Trait))
	fmt.Fprintf(&b, "**ABI Version:** `%s`  \n", escapeMarkdownInline(report.AbiVersion))
	fmt.Fprintf(&b, "**Audit Timestamp:** `%s`  \n", report.Timestamp.Format("2006-01-02 15:04:05 UTC"))
	fmt.Fprintf(&b, "**Overall Status:** **%s**\n\n", statusEmoji)

	b.WriteString("## 1. Trait Contract & Metadata Checks\n\n")
	b.WriteString("| Check Name | Status | Details |\n")
	b.WriteString("| --- | --- | --- |\n")

	for _, check := range report.Checks {
		chkStatus := "PASS"
		if !check.Passed {
			chkStatus = "FAIL"
		}
		fmt.Fprintf(&b, "| %s | %s | %s |\n",
			escapeMarkdownCell(check.Name), chkStatus, escapeMarkdownCell(check.Details))
	}

	b.WriteString("\n## 2. Mock / Real Implementation Equivalence\n\n")
	if report.MockEquivalence != nil {
		if report.MockEquivalence.Passed {
			b.WriteString("> [!NOTE]\n> Mock and Real implementation files adhere to identical symbol signatures and contract semantics.\n\n")
		} else {
			b.WriteString("> [!CAUTION]\n> Mock/Real contract divergence detected:\n")
			for _, d := range report.MockEquivalence.Divergences {
				fmt.Fprintf(&b, "- %s\n", escapeMarkdownInline(d))
			}
			b.WriteString("\n")
		}
	} else {
		b.WriteString("No Mock implementation file found — single production compilation target audited.\n\n")
	}

	b.WriteString("---\n*Generated automatically by TOOB HAL Conformance Engine (CRA Annex-I Evidence)*\n")

	dir := filepath.Dir(outPath)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return err
		}
	}

	return os.WriteFile(outPath, []byte(b.String()), 0o600)
}
