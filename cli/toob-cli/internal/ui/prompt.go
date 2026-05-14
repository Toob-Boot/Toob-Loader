package ui

import (
	"fmt"
	"os"

	"golang.org/x/term"
)

// Select presents an interactive, single-choice menu to the user.
// Returns the index of the selected option.
func Select(label string, options []string) (int, error) {
	if len(options) == 0 {
		return -1, fmt.Errorf("no options provided")
	}

	// Put terminal in raw mode
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return -1, err
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)

	selected := 0
	clearLines := "\r\033[K" // clear current line

	// Helper to draw the menu
	draw := func() {
		// Move cursor up if not the first draw
		fmt.Fprintf(os.Stderr, "\r\033[K  %s %s\r\n", Brand("?"), Bold(label))
		for i, opt := range options {
			if i == selected {
				fmt.Fprintf(os.Stderr, "\r\033[K    %s %s\r\n", Brand("❯"), Cyan(opt))
			} else {
				fmt.Fprintf(os.Stderr, "\r\033[K      %s\r\n", Gray(opt))
			}
		}
	}

	// Move cursor up N lines
	moveUp := func(n int) {
		fmt.Fprintf(os.Stderr, "\033[%dA", n)
	}

	draw()

	buf := make([]byte, 3)
	for {
		n, err := os.Stdin.Read(buf)
		if err != nil || n == 0 {
			continue
		}

		// Parse key presses
		if n == 1 {
			switch buf[0] {
			case 3: // Ctrl+C
				return -1, fmt.Errorf("aborted")
			case 13: // Enter
				// Redraw final state (clean)
				moveUp(len(options) + 1)
				for i := 0; i <= len(options); i++ {
					fmt.Fprint(os.Stderr, clearLines+"\r\n")
				}
				moveUp(len(options) + 1)

				fmt.Fprintf(os.Stderr, "\r\033[K  %s %s %s %s\r\n", Green("✓"), Bold(label), Gray("·"), Brand(options[selected]))
				return selected, nil
			}
		} else if n == 3 && buf[0] == 27 && buf[1] == 91 { // Escape sequence (Arrows)
			switch buf[2] {
			case 65: // Up
				selected--
				if selected < 0 {
					selected = len(options) - 1
				}
			case 66: // Down
				selected++
				if selected >= len(options) {
					selected = 0
				}
			}

			// Redraw
			moveUp(len(options) + 1)
			draw()
		}
	}
}

// Confirm presents an interactive Yes/No prompt.
func Confirm(label string, defaultYes bool) (bool, error) {
	// Put terminal in raw mode
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return false, err
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)

	yes := defaultYes

	draw := func() {
		yStr, nStr := "y", "N"
		if defaultYes {
			yStr, nStr = "Y", "n"
		}

		fmt.Fprintf(os.Stderr, "\r\033[K  %s %s %s\r", Brand("?"), Bold(label), Gray(fmt.Sprintf("[%s/%s]", yStr, nStr)))
	}

	draw()

	buf := make([]byte, 1)
	for {
		n, err := os.Stdin.Read(buf)
		if err != nil || n == 0 {
			continue
		}

		switch buf[0] {
		case 3: // Ctrl+C
			return false, fmt.Errorf("aborted")
		case 13: // Enter
			ansStr := "No"
			if yes {
				ansStr = "Yes"
			}
			fmt.Fprintf(os.Stderr, "\r\033[K  %s %s %s %s\r\n", Green("✓"), Bold(label), Gray("·"), Brand(ansStr))
			return yes, nil
		case 'y', 'Y':
			yes = true
			fmt.Fprintf(os.Stderr, "\r\033[K  %s %s %s %s\r\n", Green("✓"), Bold(label), Gray("·"), Brand("Yes"))
			return true, nil
		case 'n', 'N':
			yes = false
			fmt.Fprintf(os.Stderr, "\r\033[K  %s %s %s %s\r\n", Green("✓"), Bold(label), Gray("·"), Brand("No"))
			return false, nil
		}
	}
}

// MultiSelect presents an interactive, multi-choice menu to the user.
// Returns a slice of indices of the selected options.
func MultiSelect(label string, options []string) ([]int, error) {
	if len(options) == 0 {
		return nil, fmt.Errorf("no options provided")
	}

	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return nil, err
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)

	selected := 0
	clearLines := "\r\033[K"
	checked := make([]bool, len(options))

	draw := func() {
		fmt.Fprintf(os.Stderr, "\r\033[K  %s %s %s\r\n", Brand("?"), Bold(label), Gray("(Space to toggle, Enter to confirm)"))
		for i, opt := range options {
			box := "[ ]"
			if checked[i] {
				box = Brand("[x]")
			} else {
				box = Gray("[ ]")
			}

			if i == selected {
				fmt.Fprintf(os.Stderr, "\r\033[K    %s %s %s\r\n", Brand("❯"), box, Cyan(opt))
			} else {
				fmt.Fprintf(os.Stderr, "\r\033[K      %s %s\r\n", box, Gray(opt))
			}
		}
	}

	moveUp := func(n int) {
		fmt.Fprintf(os.Stderr, "\033[%dA", n)
	}

	draw()

	buf := make([]byte, 3)
	for {
		n, err := os.Stdin.Read(buf)
		if err != nil || n == 0 {
			continue
		}

		if n == 1 {
			switch buf[0] {
			case 3: // Ctrl+C
				return nil, fmt.Errorf("aborted")
			case 13: // Enter
				moveUp(len(options) + 1)
				for i := 0; i <= len(options); i++ {
					fmt.Fprint(os.Stderr, clearLines+"\r\n")
				}
				moveUp(len(options) + 1)

				var chosen []string
				var result []int
				for i, c := range checked {
					if c {
						chosen = append(chosen, options[i])
						result = append(result, i)
					}
				}

				summary := "none"
				if len(chosen) > 0 {
					summary = chosen[0]
					for i := 1; i < len(chosen); i++ {
						summary += ", " + chosen[i]
					}
				}

				fmt.Fprintf(os.Stderr, "\r\033[K  %s %s %s %s\r\n", Green("✓"), Bold(label), Gray("·"), Brand(summary))
				return result, nil
			case ' ': // Space
				checked[selected] = !checked[selected]
				moveUp(len(options) + 1)
				draw()
			}
		} else if n == 3 && buf[0] == 27 && buf[1] == 91 {
			switch buf[2] {
			case 65: // Up
				selected--
				if selected < 0 {
					selected = len(options) - 1
				}
			case 66: // Down
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
