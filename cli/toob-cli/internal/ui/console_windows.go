//go:build windows

package ui

import (
	"os"

	"golang.org/x/sys/windows"
	"golang.org/x/term"
)

func enableVTOutput(f *os.File) bool {
	if f == nil {
		return false
	}
	handle := windows.Handle(f.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(handle, &mode); err != nil {
		return false
	}
	if mode&windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0 {
		return true
	}
	return windows.SetConsoleMode(handle, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING) == nil
}

func enableVTInput(f *os.File) func() {
	if f == nil {
		return func() {}
	}
	handle := windows.Handle(f.Fd())
	var origMode uint32
	if err := windows.GetConsoleMode(handle, &origMode); err != nil {
		return func() {}
	}
	if origMode&windows.ENABLE_VIRTUAL_TERMINAL_INPUT != 0 {
		return func() {}
	}
	if err := windows.SetConsoleMode(handle, origMode|windows.ENABLE_VIRTUAL_TERMINAL_INPUT); err != nil {
		return func() {}
	}
	return func() {
		_ = windows.SetConsoleMode(handle, origMode)
	}
}

func isFileTerminal(f *os.File) bool {
	if f == nil {
		return false
	}
	return term.IsTerminal(int(f.Fd()))
}

func terminalWidth(f *os.File) int {
	if f == nil {
		return 80
	}
	w, _, err := term.GetSize(int(f.Fd()))
	if err != nil || w <= 0 {
		return 80
	}
	return w
}

func makeRawTerminal(f *os.File) (func(), error) {
	fd := int(f.Fd())
	oldState, err := term.MakeRaw(fd)
	if err != nil {
		return nil, err
	}
	restoreVT := enableVTInput(f)
	return func() {
		restoreVT()
		_ = term.Restore(fd, oldState)
	}, nil
}
