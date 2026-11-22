package filelock_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/toob-boot/toob/internal/filelock"
)

func TestLock_ExclusiveAcrossGoroutinesAndIdempotentUnlock(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), "nested", "registry.lock")

	var active atomic.Int32
	var maxActive atomic.Int32
	var wg sync.WaitGroup

	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()

			unlock, err := filelock.Lock(ctx, lockPath)
			if err != nil {
				t.Errorf("Lock failed: %v", err)
				return
			}
			cur := active.Add(1)
			for {
				prev := maxActive.Load()
				if cur <= prev || maxActive.CompareAndSwap(prev, cur) {
					break
				}
			}
			time.Sleep(15 * time.Millisecond)
			active.Add(-1)

			if err := unlock(); err != nil {
				t.Errorf("first unlock failed: %v", err)
			}
			if err := unlock(); err != nil {
				t.Errorf("idempotent second unlock failed: %v", err)
			}
		}()
	}

	wg.Wait()
	if got := maxActive.Load(); got != 1 {
		t.Fatalf("expected mutual exclusion (maxActive=1), got %d", got)
	}
}

func TestLock_SubprocessContentionAndCrashAutoRelease(t *testing.T) {
	if os.Getenv("TOOB_FILELOCK_HELPER") == "1" {
		lockPath := os.Getenv("TOOB_FILELOCK_PATH")
		readyPath := os.Getenv("TOOB_FILELOCK_READY")
		unlock, err := filelock.Lock(t.Context(), lockPath)
		if err != nil {
			t.Fatalf("helper Lock failed: %v", err)
		}
		defer func() { _ = unlock() }()
		_ = os.WriteFile(readyPath, []byte("locked"), 0o600)
		time.Sleep(30 * time.Second)
		return
	}

	dir := t.TempDir()
	lockPath := filepath.Join(dir, "toolchain.lock")
	readyPath := filepath.Join(dir, "ready")

	cmd := exec.Command(os.Args[0], "-test.run=^TestLock_SubprocessContentionAndCrashAutoRelease$")
	cmd.Env = append(os.Environ(),
		"TOOB_FILELOCK_HELPER=1",
		"TOOB_FILELOCK_PATH="+lockPath,
		"TOOB_FILELOCK_READY="+readyPath,
	)
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting helper process: %v", err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})

	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(readyPath); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for helper process to acquire lock")
		}
		time.Sleep(15 * time.Millisecond)
	}

	// Contending Lock must time out while helper holds the kernel lock.
	shortCtx, shortCancel := context.WithTimeout(t.Context(), 80*time.Millisecond)
	defer shortCancel()
	if _, err := filelock.Lock(shortCtx, lockPath); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected DeadlineExceeded while helper holds lock, got %v", err)
	}

	// Kill helper abruptly to simulate process crash; OS kernel must release the lock automatically.
	if err := cmd.Process.Kill(); err != nil {
		t.Fatalf("killing helper process: %v", err)
	}
	_ = cmd.Wait()

	acquireCtx, acquireCancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer acquireCancel()
	unlock, err := filelock.Lock(acquireCtx, lockPath)
	if err != nil {
		t.Fatalf("expected kernel to auto-release lock after process crash, got: %v", err)
	}
	if err := unlock(); err != nil {
		t.Fatalf("unlock failed: %v", err)
	}
}
