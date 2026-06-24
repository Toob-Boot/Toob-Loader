package updater

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
)

// ToobMasterPublicKeyHex is the hardcoded Ed25519 public key in hex format.
var ToobMasterPublicKeyHex = "0000000000000000000000000000000000000000000000000000000000000000"

// GetUpdatePublicKey retrieves the Ed25519 public key for signature verification.
func GetUpdatePublicKey() (ed25519.PublicKey, error) {
	pubKeyHex := os.Getenv("TOOB_REGISTRY_PUBKEY")
	if pubKeyHex == "" {
		pubKeyHex = ToobMasterPublicKeyHex
	}
	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil || len(pubKeyBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid registry public key format")
	}
	return pubKeyBytes, nil
}
