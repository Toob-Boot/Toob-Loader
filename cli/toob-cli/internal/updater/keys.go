package updater

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/toob-boot/toob/internal/paths"
)

const rfc8032TestVector1PubHex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"

// ToobMasterPublicKeyHex is the pinned Ed25519 trust-root public key in hex format,
// injected at release build time via -ldflags "-X github.com/toob-boot/toob/internal/updater.ToobMasterPublicKeyHex=...".
// In local/dev environments, override via TOOB_DEV=1 + TOOB_REGISTRY_PUBKEY.
var ToobMasterPublicKeyHex = ""

// GetUpdatePublicKey retrieves and validates the Ed25519 public key for signature verification.
// Fails closed on empty, all-zero, or RFC 8032 test-vector keys unless TOOB_DEV=1 and
// TOOB_REGISTRY_PUBKEY are explicitly set.
func GetUpdatePublicKey() (ed25519.PublicKey, error) {
	envPubHex := strings.TrimSpace(os.Getenv("TOOB_REGISTRY_PUBKEY"))
	devOverride := false
	var pubKeyHex string

	if envPubHex != "" {
		if !paths.IsDevMode() {
			return nil, errors.New("TOOB_REGISTRY_PUBKEY override requires dev mode (TOOB_DEV=1)")
		}
		pubKeyHex = envPubHex
		devOverride = true
	} else {
		pubKeyHex = strings.TrimSpace(ToobMasterPublicKeyHex)
	}

	if pubKeyHex == "" {
		return nil, errors.New("no registry trust-root public key configured; build with ToobMasterPublicKeyHex or set TOOB_DEV=1 and TOOB_REGISTRY_PUBKEY")
	}

	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil || len(pubKeyBytes) != ed25519.PublicKeySize {
		return nil, errors.New("invalid registry public key format (expected 64-char hex Ed25519 public key)")
	}

	var zeroKey [ed25519.PublicKeySize]byte
	if bytes.Equal(pubKeyBytes, zeroKey[:]) {
		return nil, errors.New("refusing all-zero placeholder Ed25519 public key; configure a valid trust-root key")
	}
	if !devOverride && strings.EqualFold(pubKeyHex, rfc8032TestVector1PubHex) {
		return nil, errors.New("refusing RFC 8032 test-vector Ed25519 public key outside explicit dev mode")
	}

	return ed25519.PublicKey(pubKeyBytes), nil
}

// DecodeSignature parses either a 128-character hex Ed25519 signature or a HashiCorp
// Vault Transit signature formatted as "vault:v<digits>:<base64>".
func DecodeSignature(rawSig string) ([]byte, error) {
	trimmed := strings.TrimSpace(rawSig)
	if trimmed == "" {
		return nil, errors.New("signature is empty")
	}

	if afterPrefix, ok := strings.CutPrefix(trimmed, "vault:v"); ok {
		keyVer, b64Payload, found := strings.Cut(afterPrefix, ":")
		if !found || keyVer == "" || b64Payload == "" {
			return nil, errors.New("invalid Vault signature format")
		}
		for i := range len(keyVer) {
			if keyVer[i] < '0' || keyVer[i] > '9' {
				return nil, fmt.Errorf("invalid Vault key version %q in signature", keyVer)
			}
		}
		sigBytes, err := base64.StdEncoding.DecodeString(b64Payload)
		if err != nil {
			sigBytes, err = base64.RawStdEncoding.DecodeString(b64Payload)
		}
		if err != nil || len(sigBytes) != ed25519.SignatureSize {
			return nil, errors.New("invalid Vault Ed25519 signature payload")
		}
		return sigBytes, nil
	}

	sigBytes, err := hex.DecodeString(trimmed)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return nil, errors.New("invalid Ed25519 signature format")
	}
	return sigBytes, nil
}

// VerifyHashSignature verifies rawSig (hex or "vault:v<N>:<base64>") over a 32-byte SHA-256 digest.
func VerifyHashSignature(digest []byte, rawSig string) error {
	if len(digest) != sha256.Size {
		return fmt.Errorf("expected %d-byte SHA-256 digest, got %d bytes", sha256.Size, len(digest))
	}
	pubKey, err := GetUpdatePublicKey()
	if err != nil {
		return fmt.Errorf("cannot load trust-root public key: %w", err)
	}
	sigBytes, err := DecodeSignature(rawSig)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pubKey, digest, sigBytes) {
		return errors.New("CRITICAL SECURITY ALERT: Ed25519 signature verification failed")
	}
	return nil
}

// VerifySignature hashes data with SHA-256 and verifies rawSig against the trust-root public key.
func VerifySignature(data []byte, rawSig string) error {
	sum := sha256.Sum256(data)
	return VerifyHashSignature(sum[:], rawSig)
}
