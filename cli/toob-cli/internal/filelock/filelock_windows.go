//go:build windows

package filelock

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

const (
	initialPollInterval = 10 * time.Millisecond
	maxPollInterval     = 100 * time.Millisecond
)

func lockFile(ctx context.Context, f *os.File) error {
	handle := windows.Handle(f.Fd())
	flags := uint32(windows.LOCKFILE_EXCLUSIVE_LOCK | windows.LOCKFILE_FAIL_IMMEDIATELY)

	interval := initialPollInterval
	var timer *time.Timer
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()

	for {
		var ol windows.Overlapped
		err := windows.LockFileEx(handle, flags, 0, 1, 0, &ol)
		if err == nil {
			return nil
		}
		if !errors.Is(err, windows.ERROR_LOCK_VIOLATION) && !errors.Is(err, windows.ERROR_IO_PENDING) {
			return fmt.Errorf("filelock: LockFileEx %s: %w", f.Name(), err)
		}

		if timer == nil {
			timer = time.NewTimer(interval)
		} else {
			timer.Reset(interval)
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("filelock: waiting for %s: %w", f.Name(), ctx.Err())
		case <-timer.C:
		}

		if interval < maxPollInterval {
			interval = min(interval*2, maxPollInterval)
		}
	}
}

func unlockFile(f *os.File) error {
	var ol windows.Overlapped
	if err := windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, &ol); err != nil {
		return fmt.Errorf("filelock: UnlockFileEx %s: %w", f.Name(), err)
	}
	return nil
}
