package ui

import (
	"fmt"
	"os"
	"strings"
)

// colorEnabled is set once at init time via Init().
var colorEnabled = true

// Init detects the terminal environment and disables color if needed.
// Must be called once from root.go PersistentPreRun before any output.
func Init() {
	// NO_COLOR standard: https://no-color.org
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		colorEnabled = false
		return
	}

	// Dumb terminals
	if os.Getenv("TERM") == "dumb" {
		colorEnabled = false
		return
	}

	// Piped stdout (not a TTY)
	if stat, err := os.Stdout.Stat(); err == nil {
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			colorEnabled = false
		}
	}
}

// Color applies an ANSI color code to a string. Returns uncolored string
// when color is disabled.
func Color(code, s string) string {
	if !colorEnabled {
		return s
	}
	return code + s + "\033[0m"
}

// --- Brand Palette ---
// Soft Mint Green (from Toob Logo) mapped to ANSI 256-color 120.
// Falls back to standard bright green (\033[92m) on limited terminals.

func Brand(s string) string  { return Color("\033[38;5;120m", s) }
func Green(s string) string  { return Color("\033[32m", s) }
func Yellow(s string) string { return Color("\033[33m", s) }
func Red(s string) string    { return Color("\033[31m", s) }
func Cyan(s string) string   { return Color("\033[36m", s) }
func Gray(s string) string   { return Color("\033[90m", s) }
func Bold(s string) string   { return Color("\033[1m", s) }

// BoldBrand combines bold + mint for high-impact headings.
func BoldBrand(s string) string { return Color("\033[1;38;5;120m", s) }
func BoldGreen(s string) string { return Color("\033[1;32m", s) }
func BoldRed(s string) string   { return Color("\033[1;31m", s) }

// Strip removes all ANSI escape sequences from a string.
func Strip(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	inEsc := false
	for i := 0; i < len(s); i++ {
		if s[i] == '\033' {
			inEsc = true
			continue
		}
		if inEsc {
			if (s[i] >= 'a' && s[i] <= 'z') || (s[i] >= 'A' && s[i] <= 'Z') {
				inEsc = false
			}
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// Pad returns a string padded with dots to a target width, used for timing tables.
func Pad(label string, width int) string {
	stripped := Strip(label)
	gap := width - len(stripped)
	if gap < 2 {
		gap = 2
	}
	return fmt.Sprintf("%s %s", label, strings.Repeat("·", gap))
}
