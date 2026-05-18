package ui

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// ProgressBar represents a minimalist, Docker-style progress bar.
// Example: [██████░░░] 75%
type ProgressBar struct {
	mu        sync.Mutex
	label     string
	total     int
	current   int
	width     int
	startTime time.Time
}

// NewProgressBar initializes a new progress bar.
// label is the text shown before the bar.
// total is the maximum value for the progress.
func NewProgressBar(label string, total int) *ProgressBar {
	return &ProgressBar{
		label:     label,
		total:     total,
		width:     30, // 30 characters wide
		startTime: time.Now(),
	}
}

// Update sets the current progress and redraws the bar in-place.
func (p *ProgressBar) Update(current int) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if current > p.total {
		current = p.total
	}
	if current < 0 {
		current = 0
	}
	p.current = current

	percent := 0
	if p.total > 0 {
		percent = int((float64(p.current) / float64(p.total)) * 100)
	}

	filled := 0
	if p.total > 0 {
		filled = int((float64(p.current) / float64(p.total)) * float64(p.width))
	}
	empty := p.width - filled
	if empty < 0 {
		empty = 0
	}

	bar := Brand(strings.Repeat("█", filled)) + Gray(strings.Repeat("░", empty))

	elapsed := time.Since(p.startTime).Round(time.Second)
	timeStr := ""
	if elapsed > 0 {
		timeStr = Gray(fmt.Sprintf(" (%s)", elapsed))
	}

	// \r returns to start of line, \033[K clears the line
	fmt.Fprintf(os.Stderr, "\r\033[K  %s %s %s %3d%%%s", Brand("▸"), Bold(p.label), bar, percent, timeStr)
}

// Finish completes the progress bar, reaching 100% and printing a success mark on a new line.
func (p *ProgressBar) Finish() {
	p.Update(p.total) // ensure it reaches 100%
	// Overwrite the progress bar with a final success message
	fmt.Fprintf(os.Stderr, "\r\033[K  %s %s %s\n", Green("✓"), Bold(p.label), Gray("done"))
}
