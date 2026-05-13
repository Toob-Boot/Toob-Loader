package updater

import "aead.dev/minisign"

// ToobMasterKey is the Ed25519 public key used to cryptographically verify
// all official Toob ecosystem binaries and registries (Supply Chain Security).
// This key is baked into the CLI binary and cannot be modified by attackers
// even if the GitHub Release server is compromised.
const ToobMasterKey = "RWT7Oy6bzufiruCVFvbGv73+VZYvy9RYrqT7Xm508b2MJjn89v/wlQH9"

// GetPublicKey parses the hardcoded base64 key into a usable minisign.PublicKey object
func GetPublicKey() (minisign.PublicKey, error) {
	var pub minisign.PublicKey
	err := pub.UnmarshalText([]byte(ToobMasterKey))
	return pub, err
}
