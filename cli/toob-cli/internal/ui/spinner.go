package ui

import (
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"strings"
	"sync"
	"time"
)

// LiveSpinner represents a terminal progress spinner that automatically degrades
// to clean single-line status logging in CI or non-TTY environments.
type LiveSpinner struct {
	mu           sync.Mutex
	startOnce    sync.Once
	stopOnce     sync.Once
	message      string
	detail       string
	stopChan     chan struct{}
	wg           sync.WaitGroup
	startTime    time.Time
	easterEggIdx int

	total   int
	current int
}

// NewSpinner creates a new LiveSpinner instance.
func NewSpinner(message string) *LiveSpinner {
	return &LiveSpinner{
		message:      sanitizeControlChars(message),
		stopChan:     make(chan struct{}),
		easterEggIdx: -1,
	}
}

// Start begins the spinner animation once in a background goroutine on interactive
// terminals, or logs a single status line in CI / redirected streams.
func (s *LiveSpinner) Start() {
	s.startOnce.Do(func() {
		s.mu.Lock()
		s.startTime = time.Now()
		msg := s.message
		s.mu.Unlock()

		if !IsInteractive() {
			if msg != "" {
				_, _ = fmt.Fprintf(Output(), "  %s %s\n", Brand("▸"), msg)
			}
			return
		}

		s.wg.Add(1)
		go s.run()
	})
}

func (s *LiveSpinner) run() {
	defer s.wg.Done()

	const (
		clearTwoLines = "\r\033[2K\033[1A\033[2K"
		clearOneLine  = "\r\033[2K"
	)

	frames := []string{
		"[●   ]",
		"[ ●  ]",
		"[  ● ]",
		"[   ●]",
		"[  ● ]",
		"[ ●  ]",
	}
	easterEggs := []string{"[ツ]", "[-_-]", "[o_o]", "[~_~]", "[>_<]", "[^.^]"}

	ticker := time.NewTicker(400 * time.Millisecond)
	defer ticker.Stop()

	frameIdx := 0
	firstDraw := true
	linesDrawn := 0

	for {
		select {
		case <-s.stopChan:
			s.clearLines(Output(), linesDrawn, clearOneLine, clearTwoLines)
			return
		case t := <-ticker.C:
			s.mu.Lock()
			msg := s.message
			det := s.detail
			cur := s.current
			tot := s.total
			start := s.startTime
			s.mu.Unlock()

			out := Output()
			elapsed := t.Sub(start).Seconds()
			showEasterEgg := false
			if int(elapsed)%10 == 0 && elapsed > 5 {
				showEasterEgg = true
				if s.easterEggIdx == -1 {
					//nolint:gosec // G404: cosmetic non-security easter-egg frame selection.
					s.easterEggIdx = rand.IntN(len(easterEggs))
				}
			} else {
				s.easterEggIdx = -1
			}

			var activeFrame string
			if showEasterEgg && s.easterEggIdx >= 0 {
				activeFrame = easterEggs[s.easterEggIdx]
			} else {
				activeFrame = frames[frameIdx%len(frames)]
			}

			if !firstDraw {
				s.clearLines(out, linesDrawn, clearOneLine, clearTwoLines)
			}

			coloredFrame := BoldBrand(activeFrame)
			var progressStr string
			if tot > 0 {
				if cur > tot {
					cur = tot
				}
				percent := int((float64(cur) / float64(tot)) * 100)
				const barWidth = 25
				filled := int((float64(cur) / float64(tot)) * float64(barWidth))
				empty := max(barWidth-filled, 0)
				bar := Brand(strings.Repeat("█", filled)) + Gray(strings.Repeat("░", empty))

				timeStr := ""
				if elapsed > 1 {
					timeStr = Gray(fmt.Sprintf(" (%ds)", int(elapsed)))
				}
				progressStr = fmt.Sprintf(" [%s] %3d%%%s", bar, percent, timeStr)
			}

			if det != "" {
				maxCols := 72
				if f, ok := out.(*os.File); ok {
					maxCols = max(terminalWidth(f)-8, 20)
				}
				clampedDet := clampVisualWidth(det, maxCols)
				_, _ = fmt.Fprintf(out, "  %s %s%s\n    %s %s", coloredFrame, msg, progressStr, Brand("❯"), Gray(clampedDet))
				linesDrawn = 2
			} else {
				_, _ = fmt.Fprintf(out, "  %s %s%s", coloredFrame, msg, progressStr)
				linesDrawn = 1
			}

			firstDraw = false
			frameIdx++
		}
	}
}

func (s *LiveSpinner) clearLines(out io.Writer, count int, clearOne, clearTwo string) {
	switch count {
	case 2:
		_, _ = fmt.Fprint(out, clearTwo)
	case 1:
		_, _ = fmt.Fprint(out, clearOne)
	}
}

// UpdateDetail strips ANSI/control sequences, clamps column width, and updates the spinner's detail line.
func (s *LiveSpinner) UpdateDetail(detail string) {
	cleaned := sanitizeControlChars(Strip(detail))
	maxCols := 72
	if f, ok := Output().(*os.File); ok && isFileTerminal(f) {
		maxCols = max(terminalWidth(f)-8, 20)
	}
	clamped := clampVisualWidth(cleaned, maxCols)

	s.mu.Lock()
	s.detail = clamped
	s.mu.Unlock()
}

func sanitizeControlChars(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r == '\t' || r == '\r' || r == '\n' {
			b.WriteByte(' ')
			continue
		}
		if r < 0x20 || (r >= 0x7f && r < 0xa0) {
			continue
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}

func clampVisualWidth(s string, maxCols int) string {
	if maxCols <= 3 || VisualWidth(s) <= maxCols {
		return s
	}
	var b strings.Builder
	cols := 0
	for _, r := range s {
		w := runeWidth(r)
		if cols+w > maxCols-1 {
			b.WriteRune('…')
			break
		}
		b.WriteRune(r)
		cols += w
	}
	return b.String()
}

// SetProgress enables the progress bar mode on the spinner.
func (s *LiveSpinner) SetProgress(current, total int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.current = current
	s.total = total
}

// AddProgress increments the current progress count.
func (s *LiveSpinner) AddProgress(amount int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.current += amount
}

// Write implements io.Writer so LiveSpinner can track streaming progress directly in io.Copy.
func (s *LiveSpinner) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.current += len(p)
	return len(p), nil
}

// Stop cleanly terminates the spinner goroutine and wipes its visual footprint.
func (s *LiveSpinner) Stop() {
	s.stopOnce.Do(func() {
		close(s.stopChan)
	})
	s.wg.Wait()
}
