package ui

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// parseMarkdown applies lightweight formatting, e.g. turning `text` into Cyan text.
func parseMarkdown(s string) string {
	parts := strings.Split(s, "`")
	// Every odd index is inside backticks (if properly paired)
	for i := 1; i < len(parts); i += 2 {
		parts[i] = Cyan(parts[i])
	}
	return strings.Join(parts, "")
}

// --- Semantic Output Primitives ---
// Inspired by Turborepo's task-scoped logging and Docker's clean progress output.

// Step prints a primary action being performed.
//
//	▸ Configuring CMake ...
func Step(msg string, args ...any) {
	fmt.Fprintf(os.Stderr, "  %s %s\n", Brand("▸"), fmt.Sprintf(msg, args...))
}

// Success prints a completed action.
//
//	✓ Build complete
func Success(msg string, args ...any) {
	fmt.Fprintf(os.Stderr, "  %s %s\n", Green("✓"), fmt.Sprintf(msg, args...))
}

// Warn prints a non-fatal warning.
//
//	⚠ Registry index could not be loaded
func Warn(msg string, args ...any) {
	fmt.Fprintf(os.Stderr, "  %s %s\n", Yellow("⚠"), fmt.Sprintf(msg, args...))
}

// Error prints a fatal error or failure.
//
//	✗ Manifest not found
func Error(msg string, args ...any) {
	formatted := parseMarkdown(fmt.Sprintf(msg, args...))
	fmt.Fprintf(os.Stderr, "  %s %s\n", Red("✗"), formatted)
}

// Info prints a secondary detail line.
//
//   - Target: espressif/esp32c6
func Info(msg string, args ...any) {
	fmt.Fprintf(os.Stderr, "  %s %s\n", Brand("•"), fmt.Sprintf(msg, args...))
}

// Muted prints a de-emphasized, informational line.
//
//	(skipped — already up to date)
func Muted(msg string, args ...any) {
	fmt.Fprintf(os.Stderr, "    %s\n", Gray(fmt.Sprintf(msg, args...)))
}

// Tip prints a helpful suggestion after a completed operation.
//
//	💡 Run 'toob build --native' for faster builds.
func Tip(msg string, args ...any) {
	formatted := parseMarkdown(fmt.Sprintf(msg, args...))
	fmt.Fprintf(os.Stderr, "  %s %s\n", Brand("›"), Gray(formatted))
}

// --- Structured Components ---

// Header prints a prominent section title with a brand-colored underline.
//
//	TOOB BUILD
//	──────────
func Header(title string) {
	upper := strings.ToUpper(title)
	fmt.Fprintf(os.Stderr, "\n  %s\n", BoldBrand(upper))
	fmt.Fprintf(os.Stderr, "  %s\n", Brand(strings.Repeat("─", len(upper))))
}

// Divider prints a subtle horizontal separator.
func Divider() {
	fmt.Fprintln(os.Stderr)
}

// KeyValue prints a label-value pair with consistent alignment.
//
//	Vendor:         espressif
func KeyValue(key, val string) {
	gap := 16 - len(key)
	if gap < 1 {
		gap = 1
	}
	fmt.Fprintf(os.Stderr, "  %s%s%s\n", Gray(key+":"), strings.Repeat(" ", gap), val)
}

// UpdateBanner prints a prominent update notification, styled like Turborepo
// but with the Toob toggle-switch logo integrated into the border.
func UpdateBanner(current, latest string) {
	width := 50

	// Logo in the border: " TツOB "
	logoText := " TツOB "
	logoVisualLen := 7 // " TツOB " has 7 visual characters
	leftDash := (width - 2 - logoVisualLen) / 2
	rightDash := width - 2 - logoVisualLen - leftDash

	topBorder := Brand("╭"+strings.Repeat("─", leftDash)) + BoldBrand(logoText) + Brand(strings.Repeat("─", rightDash)+"╮")
	bottomBorder := Brand("╰" + strings.Repeat("─", width-2) + "╯")
	emptyLine := Brand("│") + strings.Repeat(" ", width-2) + Brand("│")

	// Visual length of "Update available " + current + " → " + latest
	line1 := fmt.Sprintf("Update available %s %s %s", Gray(current), Gray("→"), BoldBrand(latest))
	visualLen1 := 17 + len(current) + 3 + len(latest) // "Update available " (17) + current + " → " (3) + latest
	pad1 := width - 2 - visualLen1
	if pad1 < 0 {
		pad1 = 0
	}
	left1 := pad1 / 2
	right1 := pad1 - left1

	// Visual length of "Run toob update to update"
	line2 := fmt.Sprintf("Run %s to update", Cyan("toob update"))
	visualLen2 := 25 // "Run " (4) + "toob update" (11) + " to update" (10)
	pad2 := width - 2 - visualLen2
	if pad2 < 0 {
		pad2 = 0
	}
	left2 := pad2 / 2
	right2 := pad2 - left2

	fmt.Fprintf(os.Stderr, "\n  %s\n", topBorder)
	fmt.Fprintf(os.Stderr, "  %s\n", emptyLine)
	fmt.Fprintf(os.Stderr, "  %s%s%s%s%s\n", Brand("│"), strings.Repeat(" ", left1), line1, strings.Repeat(" ", right1), Brand("│"))
	fmt.Fprintf(os.Stderr, "  %s%s%s%s%s\n", Brand("│"), strings.Repeat(" ", left2), line2, strings.Repeat(" ", right2), Brand("│"))
	fmt.Fprintf(os.Stderr, "  %s\n", emptyLine)
	fmt.Fprintf(os.Stderr, "  %s\n\n", bottomBorder)
}

// RegistryBanner prints a notification when the locked registry is outdated.
func RegistryBanner(current, latest string, chipWarnings []string) {
	width := 50

	logoText := " TツOB "
	logoVisualLen := 7
	leftDash := (width - 2 - logoVisualLen) / 2
	rightDash := width - 2 - logoVisualLen - leftDash

	topBorder := Cyan("╭"+strings.Repeat("─", leftDash)) + BoldCyan(logoText) + Cyan(strings.Repeat("─", rightDash)+"╮")
	bottomBorder := Cyan("╰" + strings.Repeat("─", width-2) + "╯")
	emptyLine := Cyan("│") + strings.Repeat(" ", width-2) + Cyan("│")

	// Line 1: "Registry v1.0.10 → v1.2.0"
	line1 := fmt.Sprintf("Registry %s %s %s", Gray(current), Gray("→"), BoldCyan(latest))
	visualLen1 := 9 + len(current) + 3 + len(latest) // "Registry " (9) + current + " → " (3) + latest
	pad1 := width - 2 - visualLen1
	if pad1 < 0 {
		pad1 = 0
	}
	left1 := pad1 / 2
	right1 := pad1 - left1

	// Line 2: "Run toob registry sync to update"
	line2 := fmt.Sprintf("Run %s to update", Cyan("toob registry sync"))
	visualLen2 := 32 // "Run " (4) + "toob registry sync" (18) + " to update" (10)
	pad2 := width - 2 - visualLen2
	if pad2 < 0 {
		pad2 = 0
	}
	left2 := pad2 / 2
	right2 := pad2 - left2

	fmt.Fprintf(os.Stderr, "\n  %s\n", topBorder)
	fmt.Fprintf(os.Stderr, "  %s\n", emptyLine)
	fmt.Fprintf(os.Stderr, "  %s%s%s%s%s\n", Cyan("│"), strings.Repeat(" ", left1), line1, strings.Repeat(" ", right1), Cyan("│"))
	fmt.Fprintf(os.Stderr, "  %s%s%s%s%s\n", Cyan("│"), strings.Repeat(" ", left2), line2, strings.Repeat(" ", right2), Cyan("│"))

	if len(chipWarnings) > 0 {
		fmt.Fprintf(os.Stderr, "  %s\n", emptyLine)
		warnLine := fmt.Sprintf("%s Chips not found: %s", Yellow("⚠"), Yellow(strings.Join(chipWarnings, ", ")))
		warnVisual := 18 + len(strings.Join(chipWarnings, ", ")) // "⚠ Chips not found: " = 20 visually but ⚠ is 1 char
		warnPad := width - 2 - warnVisual
		if warnPad < 0 {
			warnPad = 0
		}
		wLeft := warnPad / 2
		wRight := warnPad - wLeft
		fmt.Fprintf(os.Stderr, "  %s%s%s%s%s\n", Cyan("│"), strings.Repeat(" ", wLeft), warnLine, strings.Repeat(" ", wRight), Cyan("│"))
	}

	fmt.Fprintf(os.Stderr, "  %s\n", emptyLine)
	fmt.Fprintf(os.Stderr, "  %s\n\n", bottomBorder)
}

// TableOptions defines configurable settings for Table rendering.
type TableOptions struct {
	ColumnPadding   int   // Number of spaces between columns (default 2)
	MinColumnWidths []int // Minimum width for specific columns, matched by index
}

// Table prints a formatted table with default settings (2 spaces padding).
func Table(headers []string, rows [][]string) {
	TableWithOptions(headers, rows, TableOptions{ColumnPadding: 2})
}

// TableWithOptions prints a formatted table with configurable settings.
// Automatically calculates column widths, ignoring ANSI colors for alignment.
func TableWithOptions(headers []string, rows [][]string, opts TableOptions) {
	if opts.ColumnPadding <= 0 {
		opts.ColumnPadding = 2
	}
	padStr := strings.Repeat(" ", opts.ColumnPadding)

	colWidths := make([]int, len(headers))
	for i, h := range headers {
		w := len(Strip(h))
		if i < len(opts.MinColumnWidths) && opts.MinColumnWidths[i] > w {
			w = opts.MinColumnWidths[i]
		}
		colWidths[i] = w
	}
	
	for _, row := range rows {
		for i, cell := range row {
			if i < len(colWidths) {
				w := len(Strip(cell))
				if w > colWidths[i] {
					colWidths[i] = w
				}
			}
		}
	}

	// Header row
	var hdr strings.Builder
	for i, h := range headers {
		if i > 0 {
			hdr.WriteString(padStr)
		}
		
		visualLen := len(Strip(h))
		padding := colWidths[i] - visualLen
		if padding < 0 {
			padding = 0
		}
		hdr.WriteString(h + strings.Repeat(" ", padding))
	}
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "  %s\n", Bold(hdr.String()))

	// Separator (directly below column headers, no gap)
	var sep strings.Builder
	for i, w := range colWidths {
		if i > 0 {
			sep.WriteString(padStr)
		}
		sep.WriteString(strings.Repeat("─", w))
	}
	fmt.Fprintf(os.Stderr, "  %s\n", Gray(sep.String()))

	// Data rows
	for _, row := range rows {
		var line strings.Builder
		for i, cell := range row {
			if i > 0 {
				line.WriteString(padStr)
			}
			w := 0
			if i < len(colWidths) {
				w = colWidths[i]
			}
			
			visualLen := len(Strip(cell))
			padding := w - visualLen
			if padding < 0 {
				padding = 0
			}
			
			line.WriteString(cell + strings.Repeat(" ", padding))
		}
		fmt.Fprintf(os.Stderr, "  %s\n", line.String())
	}
}

// TimingEntry represents a single phase in a timing summary.
type TimingEntry struct {
	Name     string
	Duration time.Duration
}

// TimingSummary prints a Turborepo-style timing breakdown.
//
//	TIMINGS
//	───────
//	Manifest Compiler ······· 12ms
//	CMake Configure ········· 340ms
//	Ninja Build ············· 1.2s
//	─────────────────────────────
//	Total ··················· 1.56s
func TimingSummary(phases []TimingEntry, total time.Duration) {
	Header("Timings")
	padWidth := 28
	for _, p := range phases {
		fmt.Fprintf(os.Stderr, "  %s %s\n",
			Pad(p.Name, padWidth),
			Bold(p.Duration.Round(time.Millisecond).String()))
	}
	fmt.Fprintf(os.Stderr, "  %s\n", Gray(strings.Repeat("─", padWidth+15)))
	fmt.Fprintf(os.Stderr, "  %s %s\n\n",
		Pad(BoldBrand("Total"), padWidth),
		Bold(total.Round(time.Millisecond).String()))
}

// ErrorBanner prints a prominent error classification block.
// Replaces the raw ANSI "BUILD ERROR CLASSIFIER" banner.
func ErrorBanner(category, detail, hint string) {
	width := 72
	bar := strings.Repeat("━", width)

	fmt.Fprintf(os.Stderr, "\n  %s\n", Red(bar))
	fmt.Fprintf(os.Stderr, "  %s  %s\n", Red("✗"), BoldRed(category))
	fmt.Fprintf(os.Stderr, "  %s\n", Red(bar))
	fmt.Fprintf(os.Stderr, "  %s\n", detail)
	if hint != "" {
		fmt.Fprintf(os.Stderr, "  %s %s\n", Brand("›"), Gray(hint))
	}
	fmt.Fprintf(os.Stderr, "  %s\n\n", Red(bar))
}

// CheckItem prints a doctor-style check result.
func CheckItem(ok bool, optional bool, name, detail string) {
	if ok {
		fmt.Fprintf(os.Stderr, "  %s %s  %s\n", Green("✓"), Bold(name), Gray(detail))
	} else if optional {
		fmt.Fprintf(os.Stderr, "  %s %s  %s\n", Gray("○"), name, Gray(detail))
	} else {
		fmt.Fprintf(os.Stderr, "  %s %s  %s\n", Red("✗"), Bold(name), detail)
	}
}
