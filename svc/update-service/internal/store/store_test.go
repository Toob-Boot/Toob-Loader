package store_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/toob-boot/update-service/internal/store"
)

func TestLocalWORMStore_PutAndGet(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "toob_store_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	st, err := store.NewLocalWORMStore(tempDir)
	if err != nil {
		t.Fatalf("failed to create LocalWORMStore: %v", err)
	}

	ctx := context.Background()
	payload := []byte("Hello, Toob-Boot WORM Store!")
	digestArr := sha256.Sum256(payload)
	digest := digestArr[:]
	key := hex.EncodeToString(digest)

	// 1. Put valid object
	if err := st.Put(ctx, key, payload, digest); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	// 2. Exists should be true
	exists, err := st.Exists(ctx, key)
	if err != nil || !exists {
		t.Fatalf("expected Exists == true, got %v, err: %v", exists, err)
	}

	// 3. Get entire object
	rc, size, err := st.Get(ctx, key, 0, -1)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	defer rc.Close()

	if size != int64(len(payload)) {
		t.Errorf("expected size %d, got %d", len(payload), size)
	}

	gotData, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}
	if string(gotData) != string(payload) {
		t.Errorf("expected payload %q, got %q", payload, gotData)
	}
}

func TestLocalWORMStore_WORMImmutability(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "toob_store_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	st, err := store.NewLocalWORMStore(tempDir)
	if err != nil {
		t.Fatalf("failed to create LocalWORMStore: %v", err)
	}

	ctx := context.Background()
	payload := []byte("Original Blob Data")
	digestArr := sha256.Sum256(payload)
	digest := digestArr[:]
	key := hex.EncodeToString(digest)

	_ = st.Put(ctx, key, payload, digest)

	// Attempting to overwrite existing key must fail with ErrObjectExists
	err = st.Put(ctx, key, payload, digest)
	if !errors.Is(err, store.ErrObjectExists) {
		t.Fatalf("expected ErrObjectExists, got: %v", err)
	}
}

func TestLocalWORMStore_DigestMismatch(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "toob_store_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	st, err := store.NewLocalWORMStore(tempDir)
	if err != nil {
		t.Fatalf("failed to create LocalWORMStore: %v", err)
	}

	ctx := context.Background()
	payload := []byte("Original Blob Data")
	wrongDigest := sha256.Sum256([]byte("Corrupted Data"))
	key := hex.EncodeToString(wrongDigest[:])

	// Put with mismatched digest must fail with ErrDigestMismatch or key mismatch
	err = st.Put(ctx, key, payload, wrongDigest[:])
	if err == nil {
		t.Fatal("expected error on digest mismatch, got nil")
	}

	// Verify object was NOT saved
	objPath := filepath.Join(tempDir, key[0:2], key)
	if _, statErr := os.Stat(objPath); !os.IsNotExist(statErr) {
		t.Errorf("corrupted object was written to disk when it should have been purged!")
	}
}

func TestLocalWORMStore_ByteRangeGet(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "toob_store_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	st, err := store.NewLocalWORMStore(tempDir)
	if err != nil {
		t.Fatalf("failed to create LocalWORMStore: %v", err)
	}

	ctx := context.Background()
	payload := []byte("0123456789ABCDEF")
	digestArr := sha256.Sum256(payload)
	digest := digestArr[:]
	key := hex.EncodeToString(digest)

	_ = st.Put(ctx, key, payload, digest)

	// Read offset 4, length 4 ("4567")
	rc, size, err := st.Get(ctx, key, 4, 4)
	if err != nil {
		t.Fatalf("Get range failed: %v", err)
	}
	defer rc.Close()

	if size != 4 {
		t.Errorf("expected size 4, got %d", size)
	}

	gotData, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll range failed: %v", err)
	}
	if string(gotData) != "4567" {
		t.Errorf("expected range content '4567', got %q", gotData)
	}
}
