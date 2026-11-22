package ui

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// ErrPromptAborted indicates that the user cancelled an interactive prompt (Ctrl+C / Ctrl+D).
var ErrPromptAborted = errors.New("aborted")

// Select presents an interactive, single-choice menu to the user.
// Returns the index of the selected option, or fails fast when stdin/stderr is not a TTY.
func Select(label string, options []string) (int, error) {
	if len(options) == 0 {
		return -1, errors.New("no options provided")
	}
	if !isFileTerminal(os.Stdin) || !isFileTerminal(os.Stderr) {
		return -1, errors.New("interactive selection requires a terminal (TTY) on stdin and stderr")
	}

	restore, err := makeRawTerminal(os.Stdin)
	if err != nil {
		return -1, err
	}
	defer restore()

	out := Output()
	selected := 0
	clearLine := "\r\033[K"

	draw := func() {
		_, _ = fmt.Fprintf(out, "\r\033[K  %s %s\r\n", Brand("?"), Bold(label))
		for i, opt := range options {
			if i == selected {
				_, _ = fmt.Fprintf(out, "\r\033[K    %s %s\r\n", Brand("❯"), Cyan(opt))
			} else {
				_, _ = fmt.Fprintf(out, "\r\033[K      %s\r\n", Gray(opt))
			}
		}
	}

	moveUp := func(n int) {
		_, _ = fmt.Fprintf(out, "\033[%dA", n)
	}

	draw()

	buf := make([]byte, 3)
	for {
		n, readErr := os.Stdin.Read(buf)
		if readErr != nil {
			return -1, fmt.Errorf("reading prompt input: %w", readErr)
		}
		if n == 0 {
			return -1, io.EOF
		}

		if n == 1 {
			switch buf[0] {
			case 3, 4: // Ctrl+C, Ctrl+D
				_, _ = fmt.Fprint(out, "\r\n")
				return -1, ErrPromptAborted
			case 13, 10: // CR, LF
				moveUp(len(options) + 1)
				for range len(options) + 1 {
					_, _ = fmt.Fprint(out, clearLine+"\r\n")
				}
				moveUp(len(options) + 1)

				_, _ = fmt.Fprintf(out, "\r\033[K  %s %s %s %s\r\n", Green("✓"), Bold(label), Gray("·"), Brand(options[selected]))
				return selected, nil
			}
		} else if n == 3 && buf[0] == 27 && (buf[1] == '[' || buf[1] == 'O') {
			switch buf[2] {
			case 'A': // Up
				selected--
				if selected < 0 {
					selected = len(options) - 1
				}
			case 'B': // Down
				selected++
				if selected >= len(options) {
					selected = 0
				}
			}

			moveUp(len(options) + 1)
			draw()
		}
	}
}

// Confirm presents an interactive Yes/No prompt and fails fast if stdin/stderr is not a TTY.
func Confirm(label string, defaultYes bool) (bool, error) {
	if !isFileTerminal(os.Stdin) || !isFileTerminal(os.Stderr) {
		return false, errors.New("interactive confirmation requires a terminal (TTY) on stdin and stderr")
	}

	restore, err := makeRawTerminal(os.Stdin)
	if err != nil {
		return false, err
	}
	defer restore()

	out := Output()
	yes := defaultYes

	yStr, nStr := "y", "N"
	if defaultYes {
		yStr, nStr = "Y", "n"
	}
	_, _ = fmt.Fprintf(out, "\r\033[K  %s %s %s\r", Brand("?"), Bold(label), Gray(fmt.Sprintf("[%s/%s]", yStr, nStr)))

	buf := make([]byte, 1)
	for {
		n, readErr := os.Stdin.Read(buf)
		if readErr != nil {
			return false, fmt.Errorf("reading confirmation input: %w", readErr)
		}
		if n == 0 {
			return false, io.EOF
		}

		switch buf[0] {
		case 3, 4: // Ctrl+C, Ctrl+D
			_, _ = fmt.Fprint(out, "\r\n")
			return false, ErrPromptAborted
		case 13, 10: // CR, LF
			ansStr := "No"
			if yes {
				ansStr = "Yes"
			}
			_, _ = fmt.Fprintf(out, "\r\033[K  %s %s %s %s\r\n", Green("✓"), Bold(label), Gray("·"), Brand(ansStr))
			return yes, nil
		case 'y', 'Y':
			_, _ = fmt.Fprintf(out, "\r\033[K  %s %s %s %s\r\n", Green("✓"), Bold(label), Gray("·"), Brand("Yes"))
			return true, nil
		case 'n', 'N':
			_, _ = fmt.Fprintf(out, "\r\033[K  %s %s %s %s\r\n", Green("✓"), Bold(label), Gray("·"), Brand("No"))
			return false, nil
		}
	}
}
