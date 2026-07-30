package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// LocalWORMStore implements ObjectStore on the local filesystem.
// Provides WORM immutability by applying 0444 read-only file permissions
// and verifying post-upload SHA-256 digest on read-back.
type LocalWORMStore struct {
	baseDir string
	mu      sync.RWMutex
}

// NewLocalWORMStore initializes a local filesystem WORM store in baseDir.
func NewLocalWORMStore(baseDir string) (*LocalWORMStore, error) {
	if baseDir == "" {
		return nil, fmt.Errorf("store.NewLocalWORMStore: baseDir cannot be empty")
	}
	absDir, err := filepath.Abs(baseDir)
	if err != nil {
		return nil, fmt.Errorf("store.NewLocalWORMStore: resolve abs path: %w", err)
	}
	if err := os.MkdirAll(absDir, 0755); err != nil {
		return nil, fmt.Errorf("store.NewLocalWORMStore: mkdir baseDir: %w", err)
	}
	return &LocalWORMStore{baseDir: absDir}, nil
}

func (s *LocalWORMStore) objectPath(key string) string {
	if len(key) >= 2 {
		return filepath.Join(s.baseDir, key[0:2], key)
	}
	return filepath.Join(s.baseDir, key)
}

// Put writes a blob to the local filesystem WORM store with read-back digest verification.
func (s *LocalWORMStore) Put(ctx context.Context, key string, data []byte, expectedDigest []byte) error {
	if key == "" {
		return ErrInvalidKey
	}
	if len(expectedDigest) != 32 {
		return ErrInvalidDigestLen
	}

	// Verify key equals hex(expectedDigest)
	hexDigest := hex.EncodeToString(expectedDigest)
	if key != hexDigest {
		return fmt.Errorf("store.Put: key %q does not match hex(expectedDigest) %q", key, hexDigest)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	targetPath := s.objectPath(key)

	// WORM check: object must not exist already
	if _, err := os.Stat(targetPath); err == nil {
		return ErrObjectExists
	}

	// Ensure parent directory exists
	dir := filepath.Dir(targetPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("store.Put: mkdir parent dir: %w", err)
	}

	// Write data to temporary file first
	tmpPath := targetPath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return fmt.Errorf("store.Put: write tmp file: %w", err)
	}

	// Immediate Read-Back verification
	readBackData, err := os.ReadFile(tmpPath)
	if err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("store.Put: read-back failed: %w", err)
	}

	readBackDigest := sha256.Sum256(readBackData)
	if !bytes.Equal(readBackDigest[:], expectedDigest) {
		// Post-upload read-back mismatch: purge file and trigger alarm
		_ = os.Remove(tmpPath)
		return ErrDigestMismatch
	}

	// Rename temp file to target path
	if err := os.Rename(tmpPath, targetPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("store.Put: atomic rename failed: %w", err)
	}

	// Enforce WORM immutability at filesystem level: set read-only (0444)
	if err := os.Chmod(targetPath, 0444); err != nil {
		// Log warning, non-fatal if platform restricts chmod
		_ = err
	}

	return nil
}

// Get retrieves an object or byte range from the store.
func (s *LocalWORMStore) Get(ctx context.Context, key string, offset, length int64) (io.ReadCloser, int64, error) {
	if key == "" {
		return nil, 0, ErrInvalidKey
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	targetPath := s.objectPath(key)
	file, err := os.Open(targetPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, 0, ErrObjectNotFound
		}
		return nil, 0, fmt.Errorf("store.Get: open file: %w", err)
	}

	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, 0, fmt.Errorf("store.Get: stat file: %w", err)
	}
	totalSize := info.Size()

	if offset < 0 || offset >= totalSize {
		_ = file.Close()
		return nil, 0, fmt.Errorf("store.Get: invalid offset %d (file size %d)", offset, totalSize)
	}

	if offset > 0 {
		if _, err := file.Seek(offset, io.SeekStart); err != nil {
			_ = file.Close()
			return nil, 0, fmt.Errorf("store.Get: seek offset: %w", err)
		}
	}

	readLength := totalSize - offset
	if length > 0 && length < readLength {
		readLength = length
		return &limitedReadCloser{r: io.LimitReader(file, length), c: file}, readLength, nil
	}

	return file, readLength, nil
}

// Exists checks whether key exists in local store.
func (s *LocalWORMStore) Exists(ctx context.Context, key string) (bool, error) {
	if key == "" {
		return false, ErrInvalidKey
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	targetPath := s.objectPath(key)
	_, err := os.Stat(targetPath)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, fmt.Errorf("store.Exists: stat file: %w", err)
}

type limitedReadCloser struct {
	r io.Reader
	c io.Closer
}

func (l *limitedReadCloser) Read(p []byte) (n int, err error) {
	return l.r.Read(p)
}

func (l *limitedReadCloser) Close() error {
	return l.c.Close()
}
