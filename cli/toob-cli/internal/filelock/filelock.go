// Package filelock provides cross-platform kernel advisory file locking.
//
// Unlike PID-file directory locks, advisory kernel locks (LockFileEx on Windows
// and flock on Unix) are automatically released by the operating system if a
// process crashes or is killed.
package filelock

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Lock acquires an exclusive advisory lock on lockFilePath, blocking until the
// lock becomes available or ctx is cancelled. The returned unlock function is
// idempotent and releases both the OS lock and the underlying file descriptor.
func Lock(ctx context.Context, lockFilePath string) (func() error, error) {
	if strings.TrimSpace(lockFilePath) == "" {
		return nil, errors.New("filelock: lock file path must not be empty")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	absPath, err := filepath.Abs(lockFilePath)
	if err != nil {
		return nil, fmt.Errorf("filelock: resolve path %q: %w", lockFilePath, err)
	}
	if mkErr := os.MkdirAll(filepath.Dir(absPath), 0o700); mkErr != nil {
		return nil, fmt.Errorf("filelock: create lock directory: %w", mkErr)
	}

	f, err := os.OpenFile(absPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("filelock: open %s: %w", absPath, err)
	}

	if err := lockFile(ctx, f); err != nil {
		_ = f.Close()
		return nil, err
	}

	unlock := sync.OnceValue(func() error {
		unlockErr := unlockFile(f)
		closeErr := f.Close()
		return errors.Join(unlockErr, closeErr)
	})
	return unlock, nil
}
