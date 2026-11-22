package tbm1

import (
	"bytes"
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
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatalf("unexpected public key type %T", priv.Public())
	}

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

func TestSignerNegativeAndBoundary(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// 1. NewLocalSigner with bad key size
	for _, badLen := range []int{0, 32, 63, 65, 128} {
		badKey := make(ed25519.PrivateKey, badLen)
		if _, sErr := NewLocalSigner(badKey); sErr == nil {
			t.Fatalf("expected error for private key length %d", badLen)
		}
	}

	signer, err := NewLocalSigner(priv)
	if err != nil {
		t.Fatal(err)
	}

	pkg, err := (&Encoder{}).BuildUnsigned(sampleManifest())
	if err != nil {
		t.Fatal(err)
	}

	// 2. pkg.Sign with nil signer
	if sErr := pkg.Sign(nil); !errors.Is(sErr, ErrNoSigner) {
		t.Fatalf("expected ErrNoSigner, got %v", sErr)
	}

	// 3. SignBlock with nil signer
	if _, sErr := SignBlock(pkg.Block, nil); !errors.Is(sErr, ErrNoSigner) {
		t.Fatalf("expected ErrNoSigner, got %v", sErr)
	}

	// 4. pkg.SetSignature with bad signature length
	for _, badLen := range []int{0, 32, 63, 65} {
		badSig := make([]byte, badLen)
		if sErr := pkg.SetSignature(badSig); sErr == nil {
			t.Fatalf("expected error for signature length %d", badLen)
		}
	}

	// 5. Sign the package legitimately
	if sErr := pkg.Sign(signer); sErr != nil {
		t.Fatalf("Sign failed: %v", sErr)
	}

	// 6. VerifyBlock with wrong public key size
	for _, badLen := range []int{0, 16, 31, 33, 64} {
		badPub := make(ed25519.PublicKey, badLen)
		if vErr := VerifyBlock(pkg.Block, badPub); vErr == nil {
			t.Fatalf("expected error for public key length %d", badLen)
		}
	}

	// 7. VerifyBlock with mismatched public key
	wrongPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if vErr := VerifyBlock(pkg.Block, wrongPub); !errors.Is(vErr, ErrBadSignature) {
		t.Fatalf("expected ErrBadSignature for wrong key, got %v", vErr)
	}

	// 8. VerifyBlock with truncated block
	if vErr := VerifyBlock(pkg.Block[:200], pub); vErr == nil {
		t.Fatal("expected error for truncated block")
	}

	// 9. LocalSigner Zeroise
	signer.Zeroise()
	// Signing after zeroise produces invalid signature for the original pubkey
	msg := []byte("TEST_MSG")
	sig, err := signer.Sign(msg)
	if err != nil {
		t.Fatalf("Sign failed after Zeroise: %v", err)
	}
	if ed25519.Verify(pub, msg, sig) {
		t.Fatal("signature verified after Zeroise (key was not actually wiped)")
	}
}

func TestSignBlockSuccess(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := NewLocalSigner(priv)

	m := sampleManifest()
	pkg, err := BuildUnsigned(m)
	if err != nil {
		t.Fatal(err)
	}

	signedBlock, err := SignBlock(pkg.Block, signer)
	if err != nil {
		t.Fatalf("SignBlock failed: %v", err)
	}

	if err := VerifyBlock(signedBlock, pub); err != nil {
		t.Fatalf("VerifyBlock failed on signed block: %v", err)
	}

	// Test Package.Signature()
	if err := pkg.Sign(signer); err != nil {
		t.Fatal(err)
	}
	sig := pkg.Signature()
	if len(sig) != SigLen {
		t.Fatalf("Signature() len %d != %d", len(sig), SigLen)
	}
}

func TestExtractSignatureRoundTripAndReject(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewLocalSigner(priv)
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Zeroise()

	pkg, err := BuildUnsigned(sampleManifest())
	if err != nil {
		t.Fatal(err)
	}
	signedBlock, err := SignBlock(pkg.Block, signer)
	if err != nil {
		t.Fatalf("SignBlock: %v", err)
	}
	if vErr := VerifyBlock(signedBlock, pub); vErr != nil {
		t.Fatalf("VerifyBlock: %v", vErr)
	}

	sig, err := ExtractSignature(signedBlock)
	if err != nil {
		t.Fatalf("ExtractSignature: %v", err)
	}
	if len(sig) != SigLen {
		t.Fatalf("signature len %d != %d", len(sig), SigLen)
	}
	if !ed25519.Verify(pub, signedBlock[:len(signedBlock)-SigLen], sig) {
		t.Fatal("extracted signature did not verify against signed message")
	}

	// Returned slice must be an independent copy.
	origByte := signedBlock[len(signedBlock)-1]
	sig[len(sig)-1] ^= 0xFF
	if signedBlock[len(signedBlock)-1] != origByte {
		t.Fatal("ExtractSignature aliased signedBlock buffer")
	}

	// Compare against Package.Signature() after Package.Sign.
	if sErr := pkg.Sign(signer); sErr != nil {
		t.Fatalf("pkg.Sign: %v", sErr)
	}
	sig2, err := ExtractSignature(pkg.Block)
	if err != nil {
		t.Fatalf("ExtractSignature(pkg.Block): %v", err)
	}
	if !bytes.Equal(sig2, pkg.Signature()) {
		t.Fatal("ExtractSignature mismatch with Package.Signature()")
	}

	// Reject truncated and malformed blocks.
	badCRC := bytes.Clone(signedBlock)
	badCRC[FixedLen-1] ^= 0x01
	badMagic := bytes.Clone(signedBlock)
	badMagic[0] ^= 0x01

	for name, bad := range map[string][]byte{
		"nil":              nil,
		"empty":            {},
		"short_header":     signedBlock[:FixedLen-1],
		"truncated_tail":   signedBlock[:len(signedBlock)-1],
		"trailing_garbage": append(bytes.Clone(signedBlock), 0x00),
		"bad_crc":          badCRC,
		"bad_magic":        badMagic,
	} {
		if _, eErr := ExtractSignature(bad); eErr == nil {
			t.Fatalf("%s: expected ExtractSignature to reject invalid block", name)
		}
	}
}
