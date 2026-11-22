package ui_test

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/toob-boot/toob/internal/ui"
)

func TestVisualWidth_AndBannerAlignment(t *testing.T) {
	var buf bytes.Buffer
	ui.SetOutput(&buf)
	t.Cleanup(func() {
		ui.SetOutput(os.Stderr)
	})
	ui.SetColorEnabled(true)

	// " TツOB ": ' ' (1) + 'T' (1) + 'ツ' (2) + 'O' (1) + 'B' (1) + ' ' (1) = 7 display columns.
	if got := ui.VisualWidth(" TツOB "); got != 7 {
		t.Fatalf("VisualWidth(\" TツOB \") = %d, want 7", got)
	}

	assertUniformBox := func(t *testing.T, rendered string) {
		t.Helper()
		var widths []int
		for _, line := range strings.Split(rendered, "\n") {
			plain := strings.TrimRight(ui.Strip(line), "\r")
			if strings.TrimSpace(plain) == "" {
				continue
			}
			widths = append(widths, ui.VisualWidth(plain))
		}
		if len(widths) < 4 {
			t.Fatalf("expected multi-line box banner, got:\n%s", rendered)
		}
		for i, w := range widths {
			if w != widths[0] {
				t.Fatalf("banner line %d has visual width %d, want %d:\n%s", i, w, widths[0], ui.Strip(rendered))
			}
		}
	}

	buf.Reset()
	ui.UpdateBanner("v0.6.0", "v0.7.0")
	assertUniformBox(t, buf.String())

	buf.Reset()
	ui.RegistryBanner("41", "42", []string{"esp32c6", "stm32h7_experimental_long_chip_identifier"})
	assertUniformBox(t, buf.String())
}

func TestFormatMsg_NoPrintfManglingAndTipPreservesOuterGray(t *testing.T) {
	var buf bytes.Buffer
	ui.SetOutput(&buf)
	t.Cleanup(func() {
		ui.SetOutput(os.Stderr)
	})

	ui.SetColorEnabled(false)
	stepFn := ui.Step
	stepFn("Downloading https://registry.the-toob.com/pkg/%40toob%2Fesp32c6")
	if got := buf.String(); !strings.Contains(got, "%40toob%2Fesp32c6") || strings.Contains(got, "%!o(MISSING)") {
		t.Fatalf("zero-arg Step mangled URL percent escapes: %q", got)
	}

	buf.Reset()
	ui.SetColorEnabled(true)
	ui.Tip("Run `toob sync` before `toob build` now")
	out := buf.String()
	// After closing `toob sync`, outer Gray (\033[90m) must be re-applied for " before ".
	if !strings.Contains(out, "\033[36mtoob sync\033[0m\033[90m before ") {
		t.Fatalf("expected Tip to restore Gray ANSI code after backtick span, got %q", out)
	}

	buf.Reset()
	ui.SetColorEnabled(false)
	ui.KeyValue("Job ID", int64(9876543210))
	if !strings.Contains(buf.String(), "9876543210") {
		t.Fatalf("expected int64 KeyValue output, got %q", buf.String())
	}
}

func TestLiveSpinner_NonTTYDegradationAndDetailSanitization(t *testing.T) {
	var buf bytes.Buffer
	ui.SetOutput(&buf)
	t.Cleanup(func() {
		ui.SetOutput(os.Stderr)
	})

	s := ui.NewSpinner("Building\r\n\033[31mfirmware")
	// Calling Start twice must be idempotent via sync.Once.
	s.Start()
	s.Start()
	s.UpdateDetail("compiling \033[2J\r\n" + strings.Repeat("verylongpath/", 10))
	if _, err := s.Write([]byte("chunk")); err != nil {
		t.Fatalf("spinner Write failed: %v", err)
	}
	s.Stop()
	s.Stop()

	got := buf.String()
	if strings.Count(got, "\n") != 1 {
		t.Fatalf("expected single clean log line in non-TTY spinner mode, got %q", got)
	}
	if strings.Contains(got, "\033[31m") {
		t.Fatalf("expected control/ANSI injection stripped from spinner message, got %q", got)
	}
}

func TestPrompts_FailFastWhenNotTTY(t *testing.T) {
	if _, err := ui.Select("Pick target", []string{"esp32c6", "stm32u5"}); err == nil {
		t.Fatal("expected Select to fail immediately when stdin/stderr is not a TTY")
	}
	if _, err := ui.Confirm("Proceed?", false); err == nil {
		t.Fatal("expected Confirm to fail immediately when stdin/stderr is not a TTY")
	}
}
