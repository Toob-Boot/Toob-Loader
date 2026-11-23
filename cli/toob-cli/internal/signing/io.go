package signing

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
)

func zeroizeBytes(b []byte) {
	clear(b)
}

func safeUint32(n int) (uint32, error) {
	if n < 0 {
		return 0, fmt.Errorf("negative length %d cannot convert to uint32", n)
	}
	u := uint64(n)
	if u > math.MaxUint32 {
		return 0, fmt.Errorf("length %d exceeds uint32 maximum", n)
	}
	return uint32(u), nil
}

func isAllZero(b []byte) bool {
	var acc byte
	for _, v := range b {
		acc |= v
	}
	return subtle.ConstantTimeByteEq(acc, 0) == 1
}

func readFileBounded(path string, maxBytes int64) ([]byte, error) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return nil, errors.New("file path must not be empty")
	}
	cleanPath := filepath.Clean(trimmed)

	f, err := os.Open(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", cleanPath, err)
	}
	defer func() {
		_ = f.Close()
	}()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", cleanPath, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", cleanPath)
	}
	if maxBytes > 0 && info.Size() > maxBytes {
		return nil, fmt.Errorf("%s exceeds maximum size (%d > %d bytes)", cleanPath, info.Size(), maxBytes)
	}

	limit := maxBytes + 1
	if maxBytes <= 0 {
		limit = 64<<20 + 1
	}
	data, err := io.ReadAll(io.LimitReader(f, limit))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", cleanPath, err)
	}
	if int64(len(data)) >= limit {
		return nil, fmt.Errorf("%s exceeds maximum size (%d bytes)", cleanPath, limit-1)
	}
	return data, nil
}

func writeFileAtomic(path string, data []byte, perm os.FileMode, overwrite bool) error {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return errors.New("output path must not be empty")
	}
	cleanPath := filepath.Clean(trimmed)

	if !overwrite {
		return writeFileExclusive(cleanPath, data, perm)
	}

	dir := filepath.Dir(cleanPath)
	tmp, err := os.CreateTemp(dir, ".toob-signing-*")
	if err != nil {
		return fmt.Errorf("create temp file in %s: %w", dir, err)
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	if err := writeSyncClose(tmp, data, perm); err != nil {
		return fmt.Errorf("write temp file %s: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, cleanPath); err != nil {
		return fmt.Errorf("rename %s to %s: %w", tmpPath, cleanPath, err)
	}
	cleanup = false
	return nil
}

func writeFileExclusive(cleanPath string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(cleanPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return fmt.Errorf("create %s: %w", cleanPath, err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(cleanPath)
		}
	}()

	if err := writeSyncClose(f, data, perm); err != nil {
		return fmt.Errorf("write %s: %w", cleanPath, err)
	}
	cleanup = false
	return nil
}

func writeSyncClose(f *os.File, data []byte, perm os.FileMode) error {
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Chmod(perm); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
