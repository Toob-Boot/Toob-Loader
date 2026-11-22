package heatshrink

import (
	"bytes"
	"math/rand/v2"
	"testing"
)

func TestHeatshrinkEmpty(t *testing.T) {
	comp, err := Compress(nil)
	if err != nil {
		t.Fatalf("Compress empty error: %v", err)
	}
	decomp, err := Decompress(comp)
	if err != nil {
		t.Fatalf("Decompress empty error: %v", err)
	}
	if len(decomp) != 0 {
		t.Fatalf("Expected empty output, got %d bytes", len(decomp))
	}
}

func TestHeatshrinkSmallString(t *testing.T) {
	input := []byte("The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog.")
	comp, err := Compress(input)
	if err != nil {
		t.Fatalf("Compress failed: %v", err)
	}
	if len(comp) >= len(input) {
		t.Logf("Compressed size %d vs original %d", len(comp), len(input))
	}

	decomp, err := Decompress(comp)
	if err != nil {
		t.Fatalf("Decompress failed: %v", err)
	}
	if !bytes.Equal(input, decomp) {
		t.Fatalf("Roundtrip mismatch: expected %q, got %q", input, decomp)
	}
}

func TestHeatshrinkRepetitive(t *testing.T) {
	input := bytes.Repeat([]byte("ABCDEFGH12345678"), 50) // 800 bytes
	comp, err := Compress(input)
	if err != nil {
		t.Fatalf("Compress failed: %v", err)
	}
	if len(comp) >= len(input)/2 {
		t.Fatalf("Expected significant compression, got %d bytes from %d", len(comp), len(input))
	}

	decomp, err := Decompress(comp)
	if err != nil {
		t.Fatalf("Decompress failed: %v", err)
	}
	if !bytes.Equal(input, decomp) {
		t.Fatalf("Repetitive roundtrip failed")
	}
}

func TestHeatshrinkRandom(t *testing.T) {
	rng := rand.New(rand.NewPCG(42, 0))
	for iter := range 10 {
		sz := rng.IntN(1024) + 1
		data := make([]byte, sz)
		for i := range data {
			data[i] = byte(rng.UintN(256))
		}

		comp, err := Compress(data)
		if err != nil {
			t.Fatalf("Compress failed on iter %d: %v", iter, err)
		}
		decomp, err := Decompress(comp)
		if err != nil {
			t.Fatalf("Decompress failed on iter %d: %v", iter, err)
		}
		if !bytes.Equal(data, decomp) {
			t.Fatalf("Mismatch on iter %d (size %d)", iter, sz)
		}
	}
}
