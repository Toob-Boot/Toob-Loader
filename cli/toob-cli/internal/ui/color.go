package ui

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
)

var (
	colorEnabled   atomic.Bool
	interactiveTTY atomic.Bool

	outputMu     sync.RWMutex
	outputWriter io.Writer = os.Stderr
)

func init() {
	Init()
}

// SetOutput configures the destination io.Writer for UI output (defaulting to os.Stderr).
func SetOutput(w io.Writer) {
	outputMu.Lock()
	if w == nil {
		outputWriter = os.Stderr
	} else {
		outputWriter = w
	}
	outputMu.Unlock()
	Init()
}

// Output returns the active destination io.Writer for UI output.
func Output() io.Writer {
	outputMu.RLock()
	w := outputWriter
	outputMu.RUnlock()
	return w
}

// SetColorEnabled explicitly enables or disables ANSI color output (useful in tests).
func SetColorEnabled(enabled bool) {
	colorEnabled.Store(enabled)
}

// ColorEnabled reports whether ANSI color output is currently active.
func ColorEnabled() bool {
	return colorEnabled.Load()
}

// IsInteractive reports whether the active output stream supports live cursor
// animations (TTY on Stderr, not dumb terminal, and CI environment unset).
func IsInteractive() bool {
	if strings.TrimSpace(os.Getenv("CI")) != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	return interactiveTTY.Load()
}

// Init detects the terminal environment on the active output stream (os.Stderr by default),
// enables Windows virtual terminal processing when available, and configures color/TTY flags.
func Init() {
	w := Output()
	outFile, isOSFile := w.(*os.File)
	tty := isOSFile && isFileTerminal(outFile)
	if tty {
		tty = enableVTOutput(outFile)
	}
	interactiveTTY.Store(tty && strings.TrimSpace(os.Getenv("CI")) == "" && os.Getenv("TERM") != "dumb")

	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		colorEnabled.Store(false)
		return
	}
	if os.Getenv("TERM") == "dumb" {
		colorEnabled.Store(false)
		return
	}
	if !tty {
		colorEnabled.Store(false)
		return
	}
	colorEnabled.Store(true)
}

// Color applies an ANSI color code to a string when color output is enabled.
func Color(code, s string) string {
	if !colorEnabled.Load() {
		return s
	}
	return code + s + "\033[0m"
}

func Brand(s string) string  { return Color("\033[38;5;120m", s) }
func Green(s string) string  { return Color("\033[32m", s) }
func Yellow(s string) string { return Color("\033[33m", s) }
func Red(s string) string    { return Color("\033[31m", s) }
func Cyan(s string) string   { return Color("\033[36m", s) }
func Gray(s string) string   { return Color("\033[90m", s) }
func Bold(s string) string   { return Color("\033[1m", s) }

func BoldBrand(s string) string { return Color("\033[1;38;5;120m", s) }
func BoldGreen(s string) string { return Color("\033[1;32m", s) }
func BoldRed(s string) string   { return Color("\033[1;31m", s) }
func BoldCyan(s string) string  { return Color("\033[1;36m", s) }

// Strip removes ANSI CSI and OSC escape sequences from s.
func Strip(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '\033' {
			b.WriteByte(s[i])
			continue
		}
		if i+1 >= len(s) {
			break
		}
		switch s[i+1] {
		case '[': // CSI: ESC [ ... <final byte 0x40..0x7E>
			i += 2
			for i < len(s) && (s[i] < 0x40 || s[i] > 0x7e) {
				i++
			}
		case ']': // OSC: ESC ] ... (BEL or ESC \)
			i += 2
			for i < len(s) {
				if s[i] == '\a' {
					break
				}
				if s[i] == '\033' && i+1 < len(s) && s[i+1] == '\\' {
					i++
					break
				}
				i++
			}
		default:
			i++
		}
	}
	return b.String()
}

// VisualWidth computes the terminal display column width of s after stripping ANSI escapes,
// accounting for 2-column East-Asian Wide / Fullwidth runes (such as 'ツ' in " TツOB ").
func VisualWidth(s string) int {
	stripped := Strip(s)
	cols := 0
	for _, r := range stripped {
		cols += runeWidth(r)
	}
	return cols
}

func runeWidth(r rune) int {
	if r < 0x20 || (r >= 0x7f && r < 0xa0) {
		return 0
	}
	if (r >= 0x0300 && r <= 0x036f) || (r >= 0x200b && r <= 0x200d) || (r >= 0xfe00 && r <= 0xfe0f) {
		return 0
	}
	if isWideRune(r) {
		return 2
	}
	return 1
}

func isWideRune(r rune) bool {
	return (r >= 0x1100 && r <= 0x115f) ||
		r == 0x2329 || r == 0x232a ||
		(r >= 0x2e80 && r <= 0x303e) ||
		(r >= 0x3040 && r <= 0x33bf) || // Hiragana, Katakana ('ツ' = U+30C4), Bopomofo, CJK compatibility
		(r >= 0x3400 && r <= 0x4dbf) ||
		(r >= 0x4e00 && r <= 0xa4cf) ||
		(r >= 0xac00 && r <= 0xd7a3) ||
		(r >= 0xf900 && r <= 0xfaff) ||
		(r >= 0xfe10 && r <= 0xfe19) ||
		(r >= 0xfe30 && r <= 0xfe6f) ||
		(r >= 0xff01 && r <= 0xff60) ||
		(r >= 0xffe0 && r <= 0xffe6) ||
		(r >= 0x1f300 && r <= 0x1faff) ||
		(r >= 0x20000 && r <= 0x3fffd)
}

// Pad returns a string padded with dots to a target visual column width.
func Pad(label string, width int) string {
	gap := max(width-VisualWidth(label), 2)
	return fmt.Sprintf("%s %s", label, strings.Repeat("·", gap))
}
