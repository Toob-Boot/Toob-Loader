package ui

import (
	"fmt"
	"strings"
	"time"
)

func formatMsg(msg string, args ...any) string {
	if len(args) == 0 {
		return msg
	}
	return fmt.Sprintf(msg, args...)
}

// parseMarkdown highlights paired `code` spans in Cyan while optionally re-applying outerCode
// after each closing backtick so nested color wrappers (such as Gray in Tip) never drop midway.
func parseMarkdownWithOuter(s, outerCode string) string {
	parts := strings.Split(s, "`")
	if len(parts) < 3 {
		if outerCode != "" {
			return Color(outerCode, s)
		}
		return s
	}

	if !ColorEnabled() {
		var plain strings.Builder
		for i, p := range parts {
			if i%2 == 1 && i == len(parts)-1 {
				plain.WriteByte('`')
			}
			plain.WriteString(p)
		}
		return plain.String()
	}

	var b strings.Builder
	if outerCode != "" {
		b.WriteString(outerCode)
	}
	for i := range parts {
		if i%2 == 1 {
			if i == len(parts)-1 {
				// Unmatched trailing backtick: preserve literal text.
				b.WriteByte('`')
				b.WriteString(parts[i])
			} else {
				b.WriteString("\033[36m")
				b.WriteString(parts[i])
				b.WriteString("\033[0m")
				if outerCode != "" {
					b.WriteString(outerCode)
				}
			}
		} else {
			b.WriteString(parts[i])
		}
	}
	if outerCode != "" {
		b.WriteString("\033[0m")
	}
	return b.String()
}

// Step prints a primary action being performed.
func Step(msg string, args ...any) {
	_, _ = fmt.Fprintf(Output(), "  %s %s\n", Brand("▸"), formatMsg(msg, args...))
}

// Success prints a completed action.
func Success(msg string, args ...any) {
	_, _ = fmt.Fprintf(Output(), "  %s %s\n", Green("✓"), formatMsg(msg, args...))
}

// Warn prints a non-fatal warning.
func Warn(msg string, args ...any) {
	_, _ = fmt.Fprintf(Output(), "  %s %s\n", Yellow("⚠"), formatMsg(msg, args...))
}

// Error prints a fatal error or failure.
func Error(msg string, args ...any) {
	formatted := parseMarkdownWithOuter(formatMsg(msg, args...), "")
	_, _ = fmt.Fprintf(Output(), "  %s %s\n", Red("✗"), formatted)
}

// Info prints a secondary detail line.
func Info(msg string, args ...any) {
	_, _ = fmt.Fprintf(Output(), "  %s %s\n", Brand("•"), formatMsg(msg, args...))
}

// Muted prints a de-emphasized informational line.
func Muted(msg string, args ...any) {
	_, _ = fmt.Fprintf(Output(), "    %s\n", Gray(formatMsg(msg, args...)))
}

// Tip prints a helpful suggestion after a completed operation, preserving Gray outside `code` spans.
func Tip(msg string, args ...any) {
	formatted := parseMarkdownWithOuter(formatMsg(msg, args...), "\033[90m")
	_, _ = fmt.Fprintf(Output(), "  %s %s\n", Brand("›"), formatted)
}

// Header prints a prominent section title with a brand-colored underline matching visual width.
func Header(title string) {
	upper := strings.ToUpper(title)
	out := Output()
	_, _ = fmt.Fprintf(out, "\n  %s\n", BoldBrand(upper))
	_, _ = fmt.Fprintf(out, "  %s\n", Brand(strings.Repeat("─", max(VisualWidth(upper), 1))))
}

// Divider prints a subtle horizontal separator.
func Divider() {
	_, _ = fmt.Fprintln(Output())
}

// KeyValue prints a label-value pair with consistent visual column alignment.
func KeyValue(key string, val any) {
	var valStr string
	if s, ok := val.(string); ok {
		valStr = s
	} else {
		valStr = fmt.Sprint(val)
	}
	gap := max(16-VisualWidth(key), 1)
	_, _ = fmt.Fprintf(Output(), "  %s%s%s\n", Gray(key+":"), strings.Repeat(" ", gap), valStr)
}

// UpdateBanner prints a prominent CLI update notification with exact East-Asian-aware border alignment.
func UpdateBanner(current, latest string) {
	logoText := " TツOB "
	line1 := fmt.Sprintf("Update available %s %s %s", Gray(current), Gray("→"), BoldBrand(latest))
	line2 := fmt.Sprintf("Run %s to update", Cyan("toob update"))

	visualLen1 := VisualWidth(line1)
	visualLen2 := VisualWidth(line2)
	logoVisualLen := VisualWidth(logoText)

	width := max(50, visualLen1+6, visualLen2+6, logoVisualLen+6)
	innerWidth := width - 2

	leftDash := (innerWidth - logoVisualLen) / 2
	rightDash := innerWidth - logoVisualLen - leftDash

	topBorder := Brand("╭"+strings.Repeat("─", leftDash)) + BoldBrand(logoText) + Brand(strings.Repeat("─", rightDash)+"╮")
	bottomBorder := Brand("╰" + strings.Repeat("─", innerWidth) + "╯")
	emptyLine := Brand("│") + strings.Repeat(" ", innerWidth) + Brand("│")

	pad1 := max(innerWidth-visualLen1, 0)
	left1 := pad1 / 2
	right1 := pad1 - left1

	pad2 := max(innerWidth-visualLen2, 0)
	left2 := pad2 / 2
	right2 := pad2 - left2

	out := Output()
	_, _ = fmt.Fprintf(out, "\n  %s\n", topBorder)
	_, _ = fmt.Fprintf(out, "  %s\n", emptyLine)
	_, _ = fmt.Fprintf(out, "  %s%s%s%s%s\n", Brand("│"), strings.Repeat(" ", left1), line1, strings.Repeat(" ", right1), Brand("│"))
	_, _ = fmt.Fprintf(out, "  %s%s%s%s%s\n", Brand("│"), strings.Repeat(" ", left2), line2, strings.Repeat(" ", right2), Brand("│"))
	_, _ = fmt.Fprintf(out, "  %s\n", emptyLine)
	_, _ = fmt.Fprintf(out, "  %s\n\n", bottomBorder)
}

// RegistryBanner prints a notification when the locked registry revision is outdated.
func RegistryBanner(current, latest string, chipWarnings []string) {
	logoText := " TツOB "
	line1 := fmt.Sprintf("Registry %s %s %s", Gray(current), Gray("→"), BoldCyan(latest))
	line2 := fmt.Sprintf("Run %s to update", Cyan("toob registry sync"))

	visualLen1 := VisualWidth(line1)
	visualLen2 := VisualWidth(line2)
	logoVisualLen := VisualWidth(logoText)

	var warnLine string
	warnVisual := 0
	if len(chipWarnings) > 0 {
		warnLine = fmt.Sprintf("%s Chips not found: %s", Yellow("⚠"), Yellow(strings.Join(chipWarnings, ", ")))
		warnVisual = VisualWidth(warnLine)
	}

	width := max(50, visualLen1+6, visualLen2+6, warnVisual+6, logoVisualLen+6)
	innerWidth := width - 2

	leftDash := (innerWidth - logoVisualLen) / 2
	rightDash := innerWidth - logoVisualLen - leftDash

	topBorder := Cyan("╭"+strings.Repeat("─", leftDash)) + BoldCyan(logoText) + Cyan(strings.Repeat("─", rightDash)+"╮")
	bottomBorder := Cyan("╰" + strings.Repeat("─", innerWidth) + "╯")
	emptyLine := Cyan("│") + strings.Repeat(" ", innerWidth) + Cyan("│")

	pad1 := max(innerWidth-visualLen1, 0)
	left1 := pad1 / 2
	right1 := pad1 - left1

	pad2 := max(innerWidth-visualLen2, 0)
	left2 := pad2 / 2
	right2 := pad2 - left2

	out := Output()
	_, _ = fmt.Fprintf(out, "\n  %s\n", topBorder)
	_, _ = fmt.Fprintf(out, "  %s\n", emptyLine)
	_, _ = fmt.Fprintf(out, "  %s%s%s%s%s\n", Cyan("│"), strings.Repeat(" ", left1), line1, strings.Repeat(" ", right1), Cyan("│"))
	_, _ = fmt.Fprintf(out, "  %s%s%s%s%s\n", Cyan("│"), strings.Repeat(" ", left2), line2, strings.Repeat(" ", right2), Cyan("│"))

	if warnLine != "" {
		_, _ = fmt.Fprintf(out, "  %s\n", emptyLine)
		warnPad := max(innerWidth-warnVisual, 0)
		wLeft := warnPad / 2
		wRight := warnPad - wLeft
		_, _ = fmt.Fprintf(out, "  %s%s%s%s%s\n", Cyan("│"), strings.Repeat(" ", wLeft), warnLine, strings.Repeat(" ", wRight), Cyan("│"))
	}

	_, _ = fmt.Fprintf(out, "  %s\n", emptyLine)
	_, _ = fmt.Fprintf(out, "  %s\n\n", bottomBorder)
}

// TableOptions defines configurable settings for Table rendering.
type TableOptions struct {
	ColumnPadding   int
	MinColumnWidths []int
}

// Table prints a formatted table with default settings (2 spaces padding).
func Table(headers []string, rows [][]string) {
	TableWithOptions(headers, rows, TableOptions{ColumnPadding: 2})
}

// TableWithOptions prints a formatted table using visual display widths for column alignment.
func TableWithOptions(headers []string, rows [][]string, opts TableOptions) {
	if opts.ColumnPadding <= 0 {
		opts.ColumnPadding = 2
	}
	padStr := strings.Repeat(" ", opts.ColumnPadding)

	colWidths := make([]int, len(headers))
	for i, h := range headers {
		w := VisualWidth(h)
		if i < len(opts.MinColumnWidths) && opts.MinColumnWidths[i] > w {
			w = opts.MinColumnWidths[i]
		}
		colWidths[i] = w
	}

	for _, row := range rows {
		for i, cell := range row {
			if i < len(colWidths) {
				if w := VisualWidth(cell); w > colWidths[i] {
					colWidths[i] = w
				}
			}
		}
	}

	var hdr strings.Builder
	for i, h := range headers {
		if i > 0 {
			hdr.WriteString(padStr)
		}
		padding := max(colWidths[i]-VisualWidth(h), 0)
		hdr.WriteString(h)
		hdr.WriteString(strings.Repeat(" ", padding))
	}

	out := Output()
	_, _ = fmt.Fprintln(out)
	_, _ = fmt.Fprintf(out, "  %s\n", Bold(hdr.String()))

	var sep strings.Builder
	for i, w := range colWidths {
		if i > 0 {
			sep.WriteString(padStr)
		}
		sep.WriteString(strings.Repeat("─", w))
	}
	_, _ = fmt.Fprintf(out, "  %s\n", Gray(sep.String()))

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
			padding := max(w-VisualWidth(cell), 0)
			line.WriteString(cell)
			line.WriteString(strings.Repeat(" ", padding))
		}
		_, _ = fmt.Fprintf(out, "  %s\n", line.String())
	}
}

// TimingEntry represents a single phase in a timing summary.
type TimingEntry struct {
	Name     string
	Duration time.Duration
}

// TimingSummary prints a Turborepo-style timing breakdown.
func TimingSummary(phases []TimingEntry, total time.Duration) {
	Header("Timings")
	const padWidth = 28
	out := Output()
	for _, p := range phases {
		_, _ = fmt.Fprintf(out, "  %s %s\n",
			Pad(p.Name, padWidth),
			Bold(p.Duration.Round(time.Millisecond).String()))
	}
	_, _ = fmt.Fprintf(out, "  %s\n", Gray(strings.Repeat("─", padWidth+15)))
	_, _ = fmt.Fprintf(out, "  %s %s\n\n",
		Pad(BoldBrand("Total"), padWidth),
		Bold(total.Round(time.Millisecond).String()))
}

// ErrorBanner prints a prominent error classification block.
func ErrorBanner(category, detail, hint string) {
	const width = 72
	bar := strings.Repeat("━", width)
	out := Output()

	_, _ = fmt.Fprintf(out, "\n  %s\n", Red(bar))
	_, _ = fmt.Fprintf(out, "  %s  %s\n", Red("✗"), BoldRed(category))
	_, _ = fmt.Fprintf(out, "  %s\n", Red(bar))
	_, _ = fmt.Fprintf(out, "  %s\n", detail)
	if hint != "" {
		_, _ = fmt.Fprintf(out, "  %s %s\n", Brand("›"), Gray(hint))
	}
	_, _ = fmt.Fprintf(out, "  %s\n\n", Red(bar))
}

// CheckItem prints a doctor-style check result.
func CheckItem(ok, optional bool, name, detail string) {
	out := Output()
	switch {
	case ok:
		_, _ = fmt.Fprintf(out, "  %s %s  %s\n", Green("✓"), Bold(name), Gray(detail))
	case optional:
		_, _ = fmt.Fprintf(out, "  %s %s  %s\n", Gray("○"), name, Gray(detail))
	default:
		_, _ = fmt.Fprintf(out, "  %s %s  %s\n", Red("✗"), Bold(name), detail)
	}
}
