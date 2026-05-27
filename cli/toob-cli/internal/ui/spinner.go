package ui

import (
	"fmt"
	"math/rand"
	"os"
	"strings"
	"sync"
	"time"
)

// LiveSpinner represents a highly performant, lag-free terminal spinner.
// It supports a primary status message and an optional dynamic detail line,
// automatically handling terminal cursor manipulation for in-place updates.
type LiveSpinner struct {
	mu           sync.Mutex
	message      string
	detail       string
	stopChan     chan struct{}
	wg           sync.WaitGroup
	startTime    time.Time
	easterEggIdx int

	// Progress Tracking
	total   int
	current int
}

// NewSpinner creates a new LiveSpinner instance.
func NewSpinner(message string) *LiveSpinner {
	return &LiveSpinner{
		message:      message,
		stopChan:     make(chan struct{}),
		easterEggIdx: -1,
	}
}

// Start begins the spinner animation in a background goroutine.
func (s *LiveSpinner) Start() {
	s.startTime = time.Now()
	s.wg.Add(1)

	// ANSI Cursor Manipulation Primitives
	// \033[1A : Move cursor up 1 line
	// \033[2K : Clear entire line
	// \r      : Move cursor to start of line
	clearTwoLines := "\r\033[2K\033[1A\033[2K"
	clearOneLine := "\r\033[2K"

	go func() {
		defer s.wg.Done()

		// Primary animation frames (Bouncing Dot)
		frames := []string{
			"[●   ]",
			"[ ●  ]",
			"[  ● ]",
			"[   ●]",
			"[  ● ]",
			"[ ●  ]",
		}

		// Easter Egg frames (Kawaii faces)
		easterEggs := []string{"[ツ]", "[-_-]", "[o_o]", "[~_~]", "[>_<]", "[^.^]"}

		ticker := time.NewTicker(400 * time.Millisecond) // Smooth toggle interval
		defer ticker.Stop()

		frameIdx := 0
		firstDraw := true
		linesDrawn := 0

		for {
			select {
			case <-s.stopChan:
				// Clean up the spinner output before exiting
				s.clearLines(linesDrawn, clearOneLine, clearTwoLines)
				return
			case t := <-ticker.C:
				s.mu.Lock()
				msg := s.message
				det := s.detail
				s.mu.Unlock()

				// Determine if we should show an Easter Egg (every ~10 seconds)
				elapsed := t.Sub(s.startTime).Seconds()
				showEasterEgg := false

				// 10s interval, active for 1.2 seconds (3 frames)
				intervalMod := int(elapsed) % 10
				if intervalMod == 0 && elapsed > 5 {
					showEasterEgg = true
					if s.easterEggIdx == -1 {
						s.easterEggIdx = rand.Intn(len(easterEggs))
					}
				} else {
					s.easterEggIdx = -1 // Reset
				}

				// Select the active frame
				var activeFrame string
				if showEasterEgg && s.easterEggIdx >= 0 {
					activeFrame = easterEggs[s.easterEggIdx]
				} else {
					activeFrame = frames[frameIdx%len(frames)]
				}

				// Erase previous draw to prevent terminal artifacts
				if !firstDraw {
					s.clearLines(linesDrawn, clearOneLine, clearTwoLines)
				}

				// Render Frame
				// Primary Line:   [■ ] Building... [████░░░] 50%
				// Detail Line:      ❯ [45/120] Compiling main.c

				// Apply Brand color to the spinner frame
				coloredFrame := BoldBrand(activeFrame)

				// Calculate optional progress bar
				var progressStr string
				s.mu.Lock()
				cur := s.current
				tot := s.total
				s.mu.Unlock()

				if tot > 0 {
					if cur > tot {
						cur = tot
					}
					percent := int((float64(cur) / float64(tot)) * 100)
					width := 25
					filled := int((float64(cur) / float64(tot)) * float64(width))
					empty := max(width-filled, 0)
					bar := Brand(strings.Repeat("█", filled)) + Gray(strings.Repeat("░", empty))

					timeStr := ""
					if elapsed > 1 {
						timeStr = Gray(fmt.Sprintf(" (%ds)", int(elapsed)))
					}
					progressStr = fmt.Sprintf(" [%s] %3d%%%s", bar, percent, timeStr)
				}

				// Determine how many lines we are drawing
				if det != "" {
					fmt.Fprintf(os.Stderr, "  %s %s%s\n    %s %s", coloredFrame, msg, progressStr, Brand("❯"), Gray(det))
					linesDrawn = 2
				} else {
					fmt.Fprintf(os.Stderr, "  %s %s%s", coloredFrame, msg, progressStr)
					linesDrawn = 1
				}

				firstDraw = false
				frameIdx++
			}
		}
	}()
}

// clearLines encapsulates the mathematical logic for wiping the correct terminal geometry.
func (s *LiveSpinner) clearLines(count int, clearOne, clearTwo string) {
	if count == 2 {
		fmt.Fprint(os.Stderr, clearTwo)
	} else if count == 1 {
		fmt.Fprint(os.Stderr, clearOne)
	}
}

// UpdateDetail safely updates the secondary detail line of the spinner.
// This is heavily optimized for zero-allocation where possible, allowing
// thousands of updates per second without lagging the terminal.
func (s *LiveSpinner) UpdateDetail(detail string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Pre-strip whitespace/newlines from raw compiler output
	s.detail = strings.TrimSpace(detail)
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

// Write implements io.Writer so the LiveSpinner can be used directly in io.Copy
// to track download or streaming progress automatically.
func (s *LiveSpinner) Write(p []byte) (n int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.current += len(p)
	return len(p), nil
}

// Stop cleanly terminates the spinner goroutine and wipes its visual footprint.
func (s *LiveSpinner) Stop() {
	close(s.stopChan)
	s.wg.Wait()
}
