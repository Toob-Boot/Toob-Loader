package tbm1

import (
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
)

// Signer is the only thing in this package that touches a private key.
// Implement it over a KMS or HSM in production; LocalSigner covers tests and
// self-hosted signing.
//
// Public must return a stable key, and implementations must be safe for
// concurrent use.
//
// Note for remote signers: Ed25519 is a two-pass algorithm over the message, so
// the whole signed area has to reach the signing service — it cannot be
// pre-hashed. With the default 4 KiB chunk size that is ~0.8% of the firmware
// size, so a 128 MiB image means a 1 MiB request. Budget for it.
type Signer interface {
	Public() ed25519.PublicKey
	Sign(msg []byte) ([]byte, error)
}

// LocalSigner holds an Ed25519 private key in process memory.
type LocalSigner struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

// NewLocalSigner wraps a raw 64-byte Ed25519 private key. The key is copied, so
// the caller may zeroise its own buffer immediately.
func NewLocalSigner(priv ed25519.PrivateKey) (*LocalSigner, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("tbm1: private key must be %d bytes, got %d", ed25519.PrivateKeySize, len(priv))
	}
	own := make(ed25519.PrivateKey, ed25519.PrivateKeySize)
	copy(own, priv)
	return &LocalSigner{priv: own, pub: own.Public().(ed25519.PublicKey)}, nil
}

// Public returns a copy, so a caller cannot corrupt the verification key.
func (s *LocalSigner) Public() ed25519.PublicKey {
	out := make(ed25519.PublicKey, len(s.pub))
	copy(out, s.pub)
	return out
}

func (s *LocalSigner) Sign(msg []byte) ([]byte, error) { return ed25519.Sign(s.priv, msg), nil }

// Zeroise wipes the in-memory private key. The signer is unusable afterwards.
func (s *LocalSigner) Zeroise() {
	for i := range s.priv {
		s.priv[i] = 0
	}
}

// Sign fills the signature slot using a Signer and verifies the result against
// the signer's public key. The read-back turns a glitching HSM or a
// mis-provisioned key into a build error rather than a bricked device.
func (p *Package) Sign(s Signer) error {
	if s == nil {
		return ErrNoSigner
	}
	msg := p.SignedMessage()
	sig, err := signAndCheck(s, msg)
	if err != nil {
		return err
	}
	return p.SetSignature(sig)
}

// Build is BuildUnsigned + Sign for callers that co-locate the key.
func (e *Encoder) Build(m Manifest, s Signer) (*Package, error) {
	pkg, err := e.BuildUnsigned(m)
	if err != nil {
		return nil, err
	}
	if err := pkg.Sign(s); err != nil {
		return nil, err
	}
	return pkg, nil
}

// Build assembles and signs with the default encoder.
func Build(m Manifest, s Signer) (*Package, error) { return (&Encoder{}).Build(m, s) }

// SignBlock validates that an unsigned block is a well-formed TBM1 manifest and
// then signs it. This is the custody-safe primitive: the signer never signs
// bytes that are not a valid manifest, so it is not a general Ed25519 oracle.
//
// A signing service should go further and call ParseHeader first, to check that
// the key index, key epoch and SVN in the block match what this node is
// authorised to sign. That policy belongs to the backend, not here.
func SignBlock(unsigned []byte, s Signer) ([]byte, error) {
	if s == nil {
		return nil, ErrNoSigner
	}
	if err := validateBlock(unsigned); err != nil {
		return nil, fmt.Errorf("tbm1: refusing to sign malformed manifest: %w", err)
	}
	total := binary.LittleEndian.Uint32(unsigned[offTotalLen:])
	signedLen := total - SigLen

	// Work on our own copy: the caller's buffer may be a shared request body,
	// and the bytes we sign must be exactly the bytes we return.
	out := make([]byte, len(unsigned))
	copy(out, unsigned)

	sig, err := signAndCheck(s, out[:signedLen])
	if err != nil {
		return nil, err
	}
	copy(out[signedLen:total], sig)
	return out, nil
}

// signAndCheck signs msg and, when the signer exposes a usable public key,
// verifies its own output before returning it.
func signAndCheck(s Signer, msg []byte) ([]byte, error) {
	sig, err := s.Sign(msg)
	if err != nil {
		return nil, fmt.Errorf("tbm1: signer failed: %w", err)
	}
	if len(sig) != SigLen {
		return nil, fmt.Errorf("tbm1: signer returned %d bytes, want %d", len(sig), SigLen)
	}
	if pub := s.Public(); len(pub) == ed25519.PublicKeySize && !ed25519.Verify(pub, msg, sig) {
		return nil, fmt.Errorf("%w: signer output does not verify against its own public key", ErrBadSignature)
	}
	return sig, nil
}
