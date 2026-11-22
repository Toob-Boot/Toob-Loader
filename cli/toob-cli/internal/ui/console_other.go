//go:build !windows

package ui

import (
	"fmt"
	"math"
	"os"

	"golang.org/x/term"
)

func fdInt(f *os.File) (int, bool) {
	if f == nil {
		return 0, false
	}
	fd := f.Fd()
	if fd > uintptr(math.MaxInt) {
		return 0, false
	}
	return int(fd), true
}

func enableVTOutput(f *os.File) bool {
	return isFileTerminal(f)
}

func isFileTerminal(f *os.File) bool {
	fd, ok := fdInt(f)
	return ok && term.IsTerminal(fd)
}

func terminalWidth(f *os.File) int {
	fd, ok := fdInt(f)
	if !ok {
		return 80
	}
	w, _, err := term.GetSize(fd)
	if err != nil || w <= 0 {
		return 80
	}
	return w
}

func makeRawTerminal(f *os.File) (func(), error) {
	fd, ok := fdInt(f)
	if !ok {
		return nil, fmt.Errorf("invalid terminal file descriptor")
	}
	oldState, err := term.MakeRaw(fd)
	if err != nil {
		return nil, err
	}
	return func() {
		_ = term.Restore(fd, oldState)
	}, nil
}
