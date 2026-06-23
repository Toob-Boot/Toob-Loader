package cmd

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestDecompressArchive_Zip(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	// Create dummy files
	files := map[string]string{
		"readme.txt": "some documentation",
		"toob":       "dummy-executable-binary-content",
	}

	for name, content := range files {
		f, err := zw.Create(name)
		if err != nil {
			t.Fatalf("failed to create zip entry: %v", err)
		}
		if _, err := f.Write([]byte(content)); err != nil {
			t.Fatalf("failed to write zip entry: %v", err)
		}
	}

	if err := zw.Close(); err != nil {
		t.Fatalf("failed to close zip writer: %v", err)
	}

	decompressed, err := decompressArchive(buf.Bytes(), "toob-windows-amd64.zip")
	if err != nil {
		t.Fatalf("failed to decompress zip: %v", err)
	}

	expected := "dummy-executable-binary-content"
	if string(decompressed) != expected {
		t.Errorf("expected %q, got %q", expected, string(decompressed))
	}
}

func TestDecompressArchive_TarGz(t *testing.T) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	// Create dummy files
	files := map[string]string{
		"readme.txt": "some documentation",
		"toob":       "dummy-executable-binary-content-tar",
	}

	for name, content := range files {
		hdr := &tar.Header{
			Name: name,
			Mode: 0o755,
			Size: int64(len(content)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("failed to write tar header: %v", err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatalf("failed to write tar content: %v", err)
		}
	}

	if err := tw.Close(); err != nil {
		t.Fatalf("failed to close tar writer: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("failed to close gzip writer: %v", err)
	}

	decompressed, err := decompressArchive(buf.Bytes(), "toob-linux-amd64.tar.gz")
	if err != nil {
		t.Fatalf("failed to decompress tar.gz: %v", err)
	}

	expected := "dummy-executable-binary-content-tar"
	if string(decompressed) != expected {
		t.Errorf("expected %q, got %q", expected, string(decompressed))
	}
}

func TestDecompressArchive_NotFound(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	f, err := zw.Create("not-toob")
	if err != nil {
		t.Fatalf("failed to create zip entry: %v", err)
	}
	if _, err := f.Write([]byte("not matching")); err != nil {
		t.Fatalf("failed to write zip entry: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("failed to close zip writer: %v", err)
	}

	_, err = decompressArchive(buf.Bytes(), "toob-windows-amd64.zip")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestEd25519SignatureVerification(t *testing.T) {
	// Generate testing keypair
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate testing keys: %v", err)
	}

	// Set temporary environment variable
	pubKeyHex := hex.EncodeToString(pubKey)
	t.Setenv("TOOB_REGISTRY_PUBKEY", pubKeyHex)

	dummyArchiveContent := []byte("dummy-archive-data-for-signing")
	hash := sha256.Sum256(dummyArchiveContent)
	sigBytes := ed25519.Sign(privKey, hash[:])
	sigStr := hex.EncodeToString(sigBytes)

	// Verify using standard library to check our integration assumptions
	decodedSig, err := hex.DecodeString(sigStr)
	if err != nil {
		t.Fatalf("failed to decode signature: %v", err)
	}

	if !ed25519.Verify(pubKey, hash[:], decodedSig) {
		t.Fatal("expected signature to be valid")
	}
}
