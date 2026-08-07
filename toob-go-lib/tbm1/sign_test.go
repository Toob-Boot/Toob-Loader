package tbm1

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
)

func TestSignVerifyRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewLocalSigner(priv)
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := Build(sampleManifest(), signer)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !pkg.Signed {
		t.Fatal("package not marked signed")
	}
	if err := VerifyBlock(pkg.Block, pub); err != nil {
		t.Fatalf("VerifyBlock: %v", err)
	}

	// One flipped byte inside the signed region must break verification, even
	// with the header CRC repaired.
	bad := append([]byte(nil), pkg.Block...)
	bad[FixedLen] ^= 0x01
	resealCRC(bad)
	if err := VerifyBlock(bad, pub); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("expected ErrBadSignature, got %v", err)
	}
}

// TestSignBlockRefusesNonManifests is the custody guard: a signing node must
// never act as a general-purpose Ed25519 oracle.
func TestSignBlockRefusesNonManifests(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := NewLocalSigner(priv)

	for name, blob := range map[string][]byte{
		"empty":  nil,
		"short":  make([]byte, 100),
		"random": deterministicBytes(1024, 0x99),
	} {
		if _, err := SignBlock(blob, signer); err == nil {
			t.Fatalf("%s: signer accepted arbitrary bytes", name)
		}
	}
}

func TestLocalSignerCopiesItsKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	pub := priv.Public().(ed25519.PublicKey)

	signer, err := NewLocalSigner(priv)
	if err != nil {
		t.Fatal(err)
	}
	// Wiping the caller's buffer must not affect the signer.
	for i := range priv {
		priv[i] = 0
	}
	pkg, err := Build(sampleManifest(), signer)
	if err != nil {
		t.Fatalf("Build after the caller zeroised its key: %v", err)
	}
	if err := VerifyBlock(pkg.Block, pub); err != nil {
		t.Fatalf("VerifyBlock: %v", err)
	}

	// The exported public key must be a copy too.
	got := signer.Public()
	got[0] ^= 0xff
	if again := signer.Public(); again[0] != pub[0] {
		t.Fatal("Public() handed out the signer's own buffer")
	}
}
