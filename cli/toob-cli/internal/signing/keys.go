package signing

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Toob-Boot/Toob-Loader/toob-go-lib/tbm1"
	"github.com/toob-boot/toob/internal/provision"
)

const maxKeyFileBytes = 4096

// KeySource selects exactly one Ed25519 signing key source.
type KeySource struct {
	Mock    bool
	KeyFile string
	KeyHex  string
}

// Validate enforces fail-closed mutual exclusivity across key sources.
func (s KeySource) Validate() error {
	hasFile := strings.TrimSpace(s.KeyFile) != ""
	hasHex := strings.TrimSpace(s.KeyHex) != ""

	if s.Mock && (hasFile || hasHex) {
		return errors.New("--mock cannot be combined with --key or --key-hex")
	}
	if hasFile && hasHex {
		return errors.New("--key and --key-hex are mutually exclusive")
	}
	if !s.Mock && !hasFile && !hasHex {
		return errors.New("no signing key specified: provide KeyFile, KeyHex, or Mock")
	}
	return nil
}

// LoadSigner loads an Ed25519 32-byte seed or 64-byte private key into a LocalSigner.
// RFC 8032 TV1 mock credentials are accepted only when src.Mock is true.
func LoadSigner(src KeySource) (*tbm1.LocalSigner, error) {
	if err := src.Validate(); err != nil {
		return nil, err
	}

	var keyBytes []byte
	defer func() {
		zeroizeBytes(keyBytes)
	}()

	switch {
	case src.Mock:
		seed, err := hex.DecodeString(provision.MockRootPrivateKeySeedHex)
		if err != nil {
			return nil, fmt.Errorf("decode mock root seed: %w", err)
		}
		keyBytes = seed
	case strings.TrimSpace(src.KeyFile) != "":
		raw, err := readFileBounded(src.KeyFile, maxKeyFileBytes)
		if err != nil {
			return nil, fmt.Errorf("read key file: %w", err)
		}
		defer zeroizeBytes(raw)

		parsed, err := parseKeyMaterialBytes(raw)
		if err != nil {
			return nil, fmt.Errorf("parse key file %s: %w", src.KeyFile, err)
		}
		keyBytes = parsed
	default:
		parsed, err := decodeKeyHexString(src.KeyHex)
		if err != nil {
			return nil, fmt.Errorf("parse key hex: %w", err)
		}
		keyBytes = parsed
	}

	priv, err := normalizeEd25519PrivateKey(keyBytes, src.Mock)
	if err != nil {
		return nil, err
	}
	defer zeroizeBytes(priv)

	signer, err := tbm1.NewLocalSigner(priv)
	if err != nil {
		return nil, fmt.Errorf("create local signer: %w", err)
	}
	return signer, nil
}

// GenerateKeypair creates a fresh Ed25519 keypair, writing private key bytes (0600)
// and optional public key bytes (0644) atomically without exposing secret material.
func GenerateKeypair(privOutPath, pubOutPath string, overwrite bool) (string, error) {
	privTrimmed := strings.TrimSpace(privOutPath)
	if privTrimmed == "" {
		return "", errors.New("private key output path must not be empty")
	}
	cleanPriv := filepath.Clean(privTrimmed)

	pubTrimmed := strings.TrimSpace(pubOutPath)
	var cleanPub string
	if pubTrimmed != "" {
		cleanPub = filepath.Clean(pubTrimmed)
		if cleanPub == cleanPriv {
			return "", errors.New("private and public key output paths must be distinct")
		}
		if !overwrite {
			if _, err := os.Lstat(cleanPub); err == nil {
				return "", fmt.Errorf("public key output path already exists: %s", cleanPub)
			} else if !errors.Is(err, os.ErrNotExist) {
				return "", fmt.Errorf("stat %s: %w", cleanPub, err)
			}
		}
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("generate Ed25519 keypair: %w", err)
	}
	defer zeroizeBytes(priv)

	if err := writeFileAtomic(cleanPriv, priv, 0o600, overwrite); err != nil {
		return "", fmt.Errorf("write private key: %w", err)
	}

	if cleanPub != "" {
		if err := writeFileAtomic(cleanPub, pub, 0o644, overwrite); err != nil {
			if !overwrite {
				_ = os.Remove(cleanPriv)
			}
			return "", fmt.Errorf("write public key: %w", err)
		}
	}

	return hex.EncodeToString(pub), nil
}

func parseKeyMaterialBytes(raw []byte) ([]byte, error) {
	if len(raw) == ed25519.SeedSize {
		out := make([]byte, ed25519.SeedSize)
		copy(out, raw)
		return out, nil
	}

	trimmed := bytes.TrimSpace(raw)
	if (len(trimmed) == ed25519.SeedSize*2 || len(trimmed) == ed25519.PrivateKeySize*2) && isAllASCIIHex(trimmed) {
		out := make([]byte, hex.DecodedLen(len(trimmed)))
		n, err := hex.Decode(out, trimmed)
		if err != nil {
			zeroizeBytes(out)
			return nil, fmt.Errorf("decode hex key material: %w", err)
		}
		return out[:n], nil
	}

	if len(raw) == ed25519.PrivateKeySize {
		out := make([]byte, ed25519.PrivateKeySize)
		copy(out, raw)
		return out, nil
	}

	return nil, fmt.Errorf("expected 32-byte seed or 64-byte private key (raw or hex), got %d bytes", len(raw))
}

func decodeKeyHexString(rawHex string) ([]byte, error) {
	trimmed := strings.TrimSpace(rawHex)
	trimmed = strings.TrimPrefix(trimmed, "0x")
	trimmed = strings.TrimPrefix(trimmed, "0X")
	if trimmed == "" {
		return nil, errors.New("key hex must not be empty")
	}

	decodedLen := hex.DecodedLen(len(trimmed))
	if len(trimmed)%2 != 0 || (decodedLen != ed25519.SeedSize && decodedLen != ed25519.PrivateKeySize) {
		return nil, fmt.Errorf("expected 64 or 128 hex chars (32 or 64 bytes), got %d chars", len(trimmed))
	}

	buf := make([]byte, decodedLen)
	n, err := hex.Decode(buf, []byte(trimmed))
	if err != nil {
		zeroizeBytes(buf)
		return nil, fmt.Errorf("invalid hex: %w", err)
	}
	return buf[:n], nil
}

func normalizeEd25519PrivateKey(keyBytes []byte, allowMockTV1 bool) (ed25519.PrivateKey, error) {
	if len(keyBytes) != ed25519.SeedSize && len(keyBytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid Ed25519 key length %d (expected 32 or 64)", len(keyBytes))
	}

	if !allowMockTV1 {
		mockSeed, err := hex.DecodeString(provision.MockRootPrivateKeySeedHex)
		if err != nil {
			return nil, fmt.Errorf("decode mock root seed: %w", err)
		}
		defer zeroizeBytes(mockSeed)

		if subtle.ConstantTimeCompare(keyBytes[:ed25519.SeedSize], mockSeed) == 1 {
			return nil, errors.New("refusing well-known RFC 8032 TV1 mock key without Mock=true")
		}
	}

	if len(keyBytes) == ed25519.SeedSize {
		return ed25519.NewKeyFromSeed(keyBytes), nil
	}

	derived := ed25519.NewKeyFromSeed(keyBytes[:ed25519.SeedSize])
	defer zeroizeBytes(derived)

	if subtle.ConstantTimeCompare(keyBytes[ed25519.SeedSize:], derived[ed25519.SeedSize:]) != 1 {
		return nil, errors.New("corrupt 64-byte Ed25519 private key: public half does not match seed")
	}

	priv := make(ed25519.PrivateKey, ed25519.PrivateKeySize)
	copy(priv, keyBytes)
	return priv, nil
}

func isAllASCIIHex(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		isDigit := c >= '0' && c <= '9'
		isLower := c >= 'a' && c <= 'f'
		isUpper := c >= 'A' && c <= 'F'
		if !isDigit && !isLower && !isUpper {
			return false
		}
	}
	return true
}
