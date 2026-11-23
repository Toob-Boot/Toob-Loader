package signing

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/Toob-Boot/Toob-Loader/toob-go-lib/tbm1"
)

// SignManifestBytes signs a raw or existing TBM1 manifest block and verifies the
// embedded signature before returning the complete signed block.
func SignManifestBytes(data []byte, signer tbm1.Signer) ([]byte, error) {
	if signer == nil {
		return nil, errors.New("signer must not be nil")
	}
	pub := signer.Public()
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("signer returned invalid public key length %d", len(pub))
	}
	if len(data) == 0 {
		return nil, errors.New("manifest block must not be empty")
	}

	signedBlock, err := tbm1.SignBlock(data, signer)
	if err != nil {
		return nil, fmt.Errorf("sign TBM1 manifest block: %w", err)
	}

	sig, err := tbm1.ExtractSignature(signedBlock)
	if err != nil {
		return nil, fmt.Errorf("extract trailing TBM1 signature: %w", err)
	}
	if len(sig) != tbm1.SigLen || isAllZero(sig) {
		return nil, errors.New("invalid trailing TBM1 Ed25519 signature")
	}

	if err := tbm1.VerifyBlock(signedBlock, pub); err != nil {
		return nil, fmt.Errorf("self-verify signed TBM1 manifest: %w", err)
	}
	return signedBlock, nil
}

// SignManifest reads a TBM1 manifest block from inPath, signs it with signer,
// self-verifies the trailing signature, and writes the signed block atomically to outPath
// (or back to inPath if outPath is empty).
func SignManifest(inPath, outPath string, signer tbm1.Signer) (string, error) {
	if signer == nil {
		return "", errors.New("signer must not be nil")
	}
	if strings.TrimSpace(inPath) == "" {
		return "", errors.New("input manifest path must not be empty")
	}

	data, err := readFileBounded(inPath, tbm1.MaxManifestLen)
	if err != nil {
		return "", fmt.Errorf("read manifest: %w", err)
	}

	signedBlock, err := SignManifestBytes(data, signer)
	if err != nil {
		return "", err
	}

	target := outPath
	if strings.TrimSpace(target) == "" {
		target = inPath
	}
	if err := writeFileAtomic(target, signedBlock, 0o644, true); err != nil {
		return "", fmt.Errorf("write signed manifest: %w", err)
	}

	return hex.EncodeToString(signer.Public()), nil
}
