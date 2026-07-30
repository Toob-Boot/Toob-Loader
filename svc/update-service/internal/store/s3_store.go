package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
)

// S3HTTPClient abstracts the S3 / Object Storage HTTP operations.
// Enables using minio-go, AWS SDK v2, or custom HTTP clients.
type S3HTTPClient interface {
	PutObject(ctx context.Context, bucket, key string, body io.Reader, size int64, opts S3PutOptions) error
	GetObject(ctx context.Context, bucket, key string, offset, length int64) (io.ReadCloser, int64, error)
	HeadObject(ctx context.Context, bucket, key string) (bool, error)
	DeleteObject(ctx context.Context, bucket, key string) error
}

// S3PutOptions contains headers for S3 Object Lock (WORM).
type S3PutOptions struct {
	ContentType        string
	ObjectLockMode     string // GOVERNANCE or COMPLIANCE
	ContentMD5         string
	CacheControl       string
}

// S3WORMStore implements ObjectStore over S3 / Hetzner / MinIO Object Storage.
// Enforces Object Lock (WORM) and performs immediate post-upload GET read-back digest verification.
type S3WORMStore struct {
	client S3HTTPClient
	bucket string
}

// NewS3WORMStore initializes an S3 Object Store adapter for bucket.
func NewS3WORMStore(client S3HTTPClient, bucket string) (*S3WORMStore, error) {
	if client == nil {
		return nil, fmt.Errorf("store.NewS3WORMStore: client cannot be nil")
	}
	if bucket == "" {
		return nil, fmt.Errorf("store.NewS3WORMStore: bucket cannot be empty")
	}
	return &S3WORMStore{client: client, bucket: bucket}, nil
}

// Put uploads data to S3 with WORM headers and performs post-upload read-back digest verification.
func (s *S3WORMStore) Put(ctx context.Context, key string, data []byte, expectedDigest []byte) error {
	if key == "" {
		return ErrInvalidKey
	}
	if len(expectedDigest) != 32 {
		return ErrInvalidDigestLen
	}

	hexDigest := hex.EncodeToString(expectedDigest)
	if key != hexDigest {
		return fmt.Errorf("store.S3.Put: key %q does not match hex(expectedDigest) %q", key, hexDigest)
	}

	// 1. Check if object already exists (WORM check)
	exists, err := s.client.HeadObject(ctx, s.bucket, key)
	if err != nil {
		return fmt.Errorf("store.S3.Put: head check failed: %w", err)
	}
	if exists {
		return ErrObjectExists
	}

	// 2. Put object to S3 with GOVERNANCE object lock and immutable cache control
	opts := S3PutOptions{
		ContentType:    "application/octet-stream",
		ObjectLockMode: "GOVERNANCE",
		CacheControl:   "public, max-age=31536000, immutable",
	}

	bodyReader := bytes.NewReader(data)
	if err := s.client.PutObject(ctx, s.bucket, key, bodyReader, int64(len(data)), opts); err != nil {
		return fmt.Errorf("store.S3.Put: put object failed: %w", err)
	}

	// 3. Immediate Read-Back verification via GET
	rc, _, err := s.client.GetObject(ctx, s.bucket, key, 0, -1)
	if err != nil {
		_ = s.client.DeleteObject(ctx, s.bucket, key)
		return fmt.Errorf("store.S3.Put: read-back GET failed: %w", err)
	}
	defer rc.Close()

	readBackData, err := io.ReadAll(rc)
	if err != nil {
		_ = s.client.DeleteObject(ctx, s.bucket, key)
		return fmt.Errorf("store.S3.Put: read-back stream read failed: %w", err)
	}

	readBackDigest := sha256.Sum256(readBackData)
	if !bytes.Equal(readBackDigest[:], expectedDigest) {
		// Digest mismatch: purge object immediately from S3 and return ErrDigestMismatch
		_ = s.client.DeleteObject(ctx, s.bucket, key)
		return ErrDigestMismatch
	}

	return nil
}

// Get retrieves an object stream from S3.
func (s *S3WORMStore) Get(ctx context.Context, key string, offset, length int64) (io.ReadCloser, int64, error) {
	if key == "" {
		return nil, 0, ErrInvalidKey
	}

	rc, contentLength, err := s.client.GetObject(ctx, s.bucket, key, offset, length)
	if err != nil {
		return nil, 0, fmt.Errorf("store.S3.Get: %w", err)
	}
	return rc, contentLength, nil
}

// Exists checks if object key exists in S3.
func (s *S3WORMStore) Exists(ctx context.Context, key string) (bool, error) {
	if key == "" {
		return false, ErrInvalidKey
	}
	return s.client.HeadObject(ctx, s.bucket, key)
}
