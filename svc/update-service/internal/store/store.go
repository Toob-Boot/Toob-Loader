// Package store provides content-addressed WORM (Write Once, Read Many) storage
// for firmware artifacts, with mandatory post-upload read-back digest verification
// (§7.4 in plan7.md, UPD-013 in plan8.md).
package store

import (
	"context"
	"errors"
	"fmt"
	"io"
)

// Common error definitions for storage operations.
var (
	ErrObjectExists    = errors.New("store: object already exists (WORM immutability protection)")
	ErrObjectNotFound  = errors.New("store: object not found")
	ErrDigestMismatch  = errors.New("store: post-upload read-back digest mismatch (data corruption detected)")
	ErrInvalidDigestLen = errors.New("store: expected digest must be 32 bytes (SHA-256)")
	ErrInvalidKey       = errors.New("store: object key must be non-empty hex string")
)

// ObjectStore defines the content-addressed WORM storage interface.
type ObjectStore interface {
	// Put stores an object by key. The key MUST equal hex(expectedDigest).
	// Immediately after writing, Put reads back the object, re-computes its digest,
	// and verifies it matches expectedDigest. If verification fails, the object is
	// deleted and ErrDigestMismatch is returned.
	Put(ctx context.Context, key string, data []byte, expectedDigest []byte) error

	// Get retrieves object content or a byte range.
	// Pass offset=0 and length=-1 to read the entire object.
	Get(ctx context.Context, key string, offset, length int64) (io.ReadCloser, int64, error)

	// Exists checks if an object is present in the WORM store.
	Exists(ctx context.Context, key string) (bool, error)
}
