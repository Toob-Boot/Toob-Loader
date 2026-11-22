//go:build !windows

package filelock

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

const (
	initialPollInterval = 10 * time.Millisecond
	maxPollInterval     = 100 * time.Millisecond
)

func fileDescriptor(f *os.File) (int, error) {
	fd := f.Fd()
	if fd > uintptr(math.MaxInt) {
		return 0, fmt.Errorf("filelock: file descriptor %d overflows int", fd)
	}
	return int(fd), nil
}

func lockFile(ctx context.Context, f *os.File) error {
	fd, err := fileDescriptor(f)
	if err != nil {
		return err
	}

	interval := initialPollInterval
	var timer *time.Timer
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()

	for {
		err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return nil
		}
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			return fmt.Errorf("filelock: flock %s: %w", f.Name(), err)
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
	fd, err := fileDescriptor(f)
	if err != nil {
		return err
	}
	if err := unix.Flock(fd, unix.LOCK_UN); err != nil {
		return fmt.Errorf("filelock: flock unlock %s: %w", f.Name(), err)
	}
	return nil
}
