package buildrunner

import (
	"bytes"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/toob-boot/toob/internal/ui"
)

const (
	defaultRingBufferBytes = 64 * 1024
	maxSpinnerLineBytes    = 4096
)

// RingBuffer stores the trailing N bytes written to it using slice copies.
type RingBuffer struct {
	mu   sync.Mutex
	buf  []byte
	pos  int
	full bool
}

// NewRingBuffer creates a bounded circular byte buffer.
func NewRingBuffer(maxBytes int) *RingBuffer {
	if maxBytes <= 0 {
		maxBytes = defaultRingBufferBytes
	}
	return &RingBuffer{
		buf: make([]byte, maxBytes),
	}
}

// Write appends p to the ring buffer, retaining only the most recent maxBytes.
func (rb *RingBuffer) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	rb.mu.Lock()
	defer rb.mu.Unlock()

	capLen := len(rb.buf)
	if len(p) >= capLen {
		copy(rb.buf, p[len(p)-capLen:])
		rb.pos = 0
		rb.full = true
		return len(p), nil
	}

	first := capLen - rb.pos
	if len(p) <= first {
		copy(rb.buf[rb.pos:], p)
		rb.pos += len(p)
		if rb.pos == capLen {
			rb.pos = 0
			rb.full = true
		}
		return len(p), nil
	}

	copy(rb.buf[rb.pos:], p[:first])
	rem := len(p) - first
	copy(rb.buf, p[first:])
	rb.pos = rem
	rb.full = true
	return len(p), nil
}

// String returns the buffered bytes in chronological order.
func (rb *RingBuffer) String() string {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	if !rb.full {
		return string(rb.buf[:rb.pos])
	}

	out := make([]byte, len(rb.buf))
	n := copy(out, rb.buf[rb.pos:])
	copy(out[n:], rb.buf[:rb.pos])
	return string(out)
}

// SanitizeTerminalOutput strips ANSI/ECMA-48 escape sequences (CSI, OSC, DCS,
// SOS, PM, APC, and single ESC sequences), C0 controls (except \n, \r, \t),
// DEL (0x7F), and C1 controls (0x80..0x9F), while preserving valid UTF-8.
func SanitizeTerminalOutput(s string) string {
	if s == "" {
		return ""
	}

	var b strings.Builder
	b.Grow(len(s))

	for i := 0; i < len(s); {
		ch := s[i]
		if ch == 0x1B {
			i = skipEscape7Bit(s, i+1)
			continue
		}

		if ch < 0x80 {
			if isAllowedASCII(ch) {
				b.WriteByte(ch)
			}
			i++
			continue
		}

		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			// Drop malformed single raw bytes so raw C1 bytes (e.g. 0x9B) cannot leak.
			i++
			continue
		}

		if r >= 0x80 && r <= 0x9F {
			i = skipC1Sequence(s, r, i+size)
			continue
		}

		b.WriteRune(r)
		i += size
	}

	return b.String()
}

func isAllowedASCII(ch byte) bool {
	if ch == '\n' || ch == '\r' || ch == '\t' {
		return true
	}
	return ch >= 0x20 && ch != 0x7F
}

func skipEscape7Bit(s string, i int) int {
	if i >= len(s) {
		return len(s)
	}
	switch s[i] {
	case '[':
		return skipCSISequence(s, i+1)
	case ']', 'P', 'X', '^', '_':
		return skipStringSequence(s, i+1)
	default:
		// Consume optional intermediate bytes (0x20..0x2F) followed by final byte (0x30..0x7E).
		for i < len(s) && s[i] >= 0x20 && s[i] <= 0x2F {
			i++
		}
		if i < len(s) && s[i] >= 0x30 && s[i] <= 0x7E {
			return i + 1
		}
		return i
	}
}

func skipC1Sequence(s string, r rune, i int) int {
	switch r {
	case 0x9B: // 8-bit CSI
		return skipCSISequence(s, i)
	case 0x90, 0x98, 0x9D, 0x9E, 0x9F: // DCS, SOS, OSC, PM, APC
		return skipStringSequence(s, i)
	default:
		return i
	}
}

func skipCSISequence(s string, i int) int {
	for i < len(s) {
		ch := s[i]
		if ch >= 0x40 && ch <= 0x7E {
			return i + 1
		}
		if ch < 0x20 || ch > 0x3F {
			return i
		}
		i++
	}
	return len(s)
}

func skipStringSequence(s string, i int) int {
	for i < len(s) {
		ch := s[i]
		if ch == 0x07 {
			return i + 1
		}
		if ch == '\n' {
			// Unterminated control string: stop before newline so following lines remain visible.
			return i
		}
		if ch == 0x1B && i+1 < len(s) && s[i+1] == '\\' {
			return i + 2
		}
		if ch == 0x9C {
			return i + 1
		}
		if ch >= 0x80 {
			r, size := utf8.DecodeRuneInString(s[i:])
			if r == 0x9C {
				return i + size
			}
			i += size
			continue
		}
		i++
	}
	return len(s)
}

// SpinnerWriter forwards sanitized lines from subprocess output to a LiveSpinner.
type SpinnerWriter struct {
	mu      sync.Mutex
	spinner *ui.LiveSpinner
	buf     []byte
}

// NewSpinnerWriter creates a line-buffered writer targeting spinner detail updates.
func NewSpinnerWriter(spinner *ui.LiveSpinner) *SpinnerWriter {
	return &SpinnerWriter{
		spinner: spinner,
	}
}

// Write buffers p and emits complete CR/LF-delimited lines to the spinner.
func (sw *SpinnerWriter) Write(p []byte) (int, error) {
	if sw == nil || sw.spinner == nil || len(p) == 0 {
		return len(p), nil
	}

	sw.mu.Lock()
	defer sw.mu.Unlock()

	sw.buf = append(sw.buf, p...)
	sw.drainLinesLocked()

	if len(sw.buf) > maxSpinnerLineBytes {
		cut := trimIncompleteUTF8Tail(sw.buf)
		sw.emitLineLocked(sw.buf[:cut])
		sw.buf = append(sw.buf[:0], sw.buf[cut:]...)
	}

	return len(p), nil
}

// Flush emits any remaining partial line buffered in SpinnerWriter.
func (sw *SpinnerWriter) Flush() {
	if sw == nil || sw.spinner == nil {
		return
	}

	sw.mu.Lock()
	defer sw.mu.Unlock()

	if len(sw.buf) == 0 {
		return
	}
	sw.emitLineLocked(sw.buf)
	sw.buf = sw.buf[:0]
}

func (sw *SpinnerWriter) drainLinesLocked() {
	for {
		idx := bytes.IndexAny(sw.buf, "\r\n")
		if idx < 0 {
			return
		}
		sw.emitLineLocked(sw.buf[:idx])
		next := idx + 1
		if sw.buf[idx] == '\r' && next < len(sw.buf) && sw.buf[next] == '\n' {
			next++
		}
		sw.buf = append(sw.buf[:0], sw.buf[next:]...)
	}
}

func (sw *SpinnerWriter) emitLineLocked(raw []byte) {
	clean := strings.TrimSpace(SanitizeTerminalOutput(string(raw)))
	if clean != "" {
		sw.spinner.UpdateDetail(clean)
	}
}

func trimIncompleteUTF8Tail(buf []byte) int {
	cut := len(buf)
	for start := cut - 1; start >= 0 && start >= cut-utf8.UTFMax; start-- {
		if utf8.RuneStart(buf[start]) {
			if !utf8.FullRune(buf[start:cut]) {
				return start
			}
			return cut
		}
	}
	return cut
}
