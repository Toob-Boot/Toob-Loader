package signing

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"

	"github.com/Toob-Boot/Toob-Loader/toob-go-lib/tbm1"
)

const (
	// TCC1Magic identifies a toob_cloud_cmd_hdr_t frame ("TCC1" in little-endian).
	TCC1Magic uint32 = 0x31434354
	// TCC1Version is the wire protocol version supported by boot_cloud_cmd.c.
	TCC1Version uint8 = 1
	// TCC1HeaderLen is the fixed wire length of toob_cloud_cmd_hdr_t in bytes.
	TCC1HeaderLen = 64
	// TCC1Align is the required parameter/frame alignment in bytes.
	TCC1Align = 16
	// TCC1MaxParamsLen is the maximum cloud command parameter payload size in bytes.
	TCC1MaxParamsLen = 1664
	// TCC1MinTotalLen is the minimum valid TCC1 frame length (64B header + 64B Ed25519 signature).
	TCC1MinTotalLen = 128
	// TCC1MaxTotalLen is the maximum valid TCC1 frame length (64B + 1664B + 64B).
	TCC1MaxTotalLen = 1792

	// KDMSize is the fixed wire size of toob_kdm_t in bytes.
	KDMSize          = 128
	kdmSeqOffset     = 0
	kdmPubkeyOffset  = 4
	kdmSigOffset     = 36
	kdmPaddingOffset = 100
)

// CloudCommand represents a TCC1 wire command opcode (0..6).
type CloudCommand uint8

const (
	// CmdRotateKey carries a 128-byte toob_kdm_t envelope to rotate the cloud command key.
	CmdRotateKey CloudCommand = 4
	// TCC1MaxCommand is the highest command opcode accepted by boot_cloud_cmd.c.
	TCC1MaxCommand CloudCommand = 6
)

// TCC1Options configures construction and signing of one TCC1 cloud command frame.
type TCC1Options struct {
	Command    CloudCommand
	Flags      uint16
	CounterMin uint32
	IssuedAt   uint32
	DeviceID   [32]byte
	Params     []byte
}

// KDMOptions configures construction and signing of one 128-byte Key Delegation Message (toob_kdm_t).
type KDMOptions struct {
	SequenceNumber uint32
	NewCloudPubkey []byte
}

// SignCloudCommand serializes, checksums (IEEE CRC-32), Ed25519-signs, and self-verifies
// a 16-byte-aligned TCC1 cloud command wire frame matching toob_cloud_cmd_hdr_t.
func SignCloudCommand(opts TCC1Options, signer tbm1.Signer) ([]byte, error) {
	if signer == nil {
		return nil, errors.New("signer must not be nil")
	}
	pub := signer.Public()
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("signer returned invalid public key length %d", len(pub))
	}
	if opts.Command > TCC1MaxCommand {
		return nil, fmt.Errorf("unsupported TCC1 command %d (expected 0..%d)", opts.Command, TCC1MaxCommand)
	}
	if opts.Flags != 0 {
		return nil, fmt.Errorf("unsupported non-zero TCC1 flags 0x%04x", opts.Flags)
	}
	if isAllZero(opts.DeviceID[:]) {
		return nil, errors.New("TCC1 device_id must not be all zeros")
	}
	if len(opts.Params) > TCC1MaxParamsLen {
		return nil, fmt.Errorf("TCC1 params length %d exceeds maximum %d", len(opts.Params), TCC1MaxParamsLen)
	}
	if opts.Command == CmdRotateKey {
		if len(opts.Params) != KDMSize {
			return nil, fmt.Errorf("CmdRotateKey requires %d-byte KDM params, got %d", KDMSize, len(opts.Params))
		}
		if err := validateKDMStructure(opts.Params); err != nil {
			return nil, fmt.Errorf("CmdRotateKey invalid KDM payload: %w", err)
		}
	}

	paramsLen := len(opts.Params)
	paddedParamsLen := alignUpInt16(paramsLen)
	totalLen := TCC1HeaderLen + paddedParamsLen + Ed25519SignatureLen

	paramsLenU32, err := safeUint32(paramsLen)
	if err != nil {
		return nil, err
	}
	totalLenU32, err := safeUint32(totalLen)
	if err != nil {
		return nil, err
	}

	frame := make([]byte, totalLen)
	binary.LittleEndian.PutUint32(frame[0:4], TCC1Magic)
	frame[4] = TCC1Version
	frame[5] = uint8(opts.Command)
	binary.LittleEndian.PutUint16(frame[6:8], opts.Flags)
	binary.LittleEndian.PutUint32(frame[8:12], opts.CounterMin)
	binary.LittleEndian.PutUint32(frame[12:16], opts.IssuedAt)
	binary.LittleEndian.PutUint32(frame[16:20], paramsLenU32)
	binary.LittleEndian.PutUint32(frame[20:24], totalLenU32)
	copy(frame[24:56], opts.DeviceID[:])
	binary.LittleEndian.PutUint32(frame[56:60], crc32.ChecksumIEEE(frame[0:56]))
	// frame[60:64] (_reserved) stays zero.

	copy(frame[TCC1HeaderLen:TCC1HeaderLen+paramsLen], opts.Params)

	signedLen := totalLen - Ed25519SignatureLen
	sig, err := signer.Sign(frame[:signedLen])
	if err != nil {
		return nil, fmt.Errorf("sign TCC1 frame: %w", err)
	}
	if len(sig) != Ed25519SignatureLen || isAllZero(sig) {
		return nil, fmt.Errorf("invalid Ed25519 signature length %d", len(sig))
	}
	copy(frame[signedLen:], sig)

	if err := VerifyCloudCommand(frame, pub); err != nil {
		return nil, fmt.Errorf("self-verify TCC1 frame: %w", err)
	}
	return frame, nil
}

// VerifyCloudCommand verifies layout bounds, 16-byte alignment, IEEE header CRC-32,
// padding zero invariants, and Ed25519 signature on a TCC1 wire frame.
func VerifyCloudCommand(frame []byte, pub ed25519.PublicKey) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid public key length %d (expected %d)", len(pub), ed25519.PublicKeySize)
	}
	if len(frame) < TCC1MinTotalLen || len(frame) > TCC1MaxTotalLen {
		return fmt.Errorf("invalid TCC1 frame length %d (expected %d..%d)", len(frame), TCC1MinTotalLen, TCC1MaxTotalLen)
	}
	if len(frame)%TCC1Align != 0 {
		return fmt.Errorf("TCC1 frame length %d is not %d-byte aligned", len(frame), TCC1Align)
	}

	magic := binary.LittleEndian.Uint32(frame[0:4])
	if magic != TCC1Magic {
		return fmt.Errorf("invalid TCC1 magic 0x%08x (expected 0x%08x)", magic, TCC1Magic)
	}
	if frame[4] != TCC1Version {
		return fmt.Errorf("unsupported TCC1 version %d (expected %d)", frame[4], TCC1Version)
	}
	cmd := CloudCommand(frame[5])
	if cmd > TCC1MaxCommand {
		return fmt.Errorf("unsupported TCC1 command %d", cmd)
	}
	if flags := binary.LittleEndian.Uint16(frame[6:8]); flags != 0 {
		return fmt.Errorf("non-zero TCC1 flags 0x%04x", flags)
	}
	if reserved := binary.LittleEndian.Uint32(frame[60:64]); reserved != 0 {
		return fmt.Errorf("non-zero TCC1 reserved field 0x%08x", reserved)
	}
	if isAllZero(frame[24:56]) {
		return errors.New("TCC1 device_id must not be all zeros")
	}

	headerCRC := binary.LittleEndian.Uint32(frame[56:60])
	expectedCRC := crc32.ChecksumIEEE(frame[0:56])
	if headerCRC != expectedCRC {
		return fmt.Errorf("TCC1 header CRC-32 mismatch (got 0x%08x, expected 0x%08x)", headerCRC, expectedCRC)
	}

	paramsLen := binary.LittleEndian.Uint32(frame[16:20])
	if paramsLen > TCC1MaxParamsLen {
		return fmt.Errorf("TCC1 params_len %d exceeds maximum %d", paramsLen, TCC1MaxParamsLen)
	}
	paddedParamsLen := alignUpInt16(int(paramsLen))
	expectedTotal := TCC1HeaderLen + paddedParamsLen + Ed25519SignatureLen

	totalLen := binary.LittleEndian.Uint32(frame[20:24])
	if int(totalLen) != expectedTotal || len(frame) != expectedTotal {
		return fmt.Errorf("TCC1 total_len mismatch (header %d, actual %d, expected %d)", totalLen, len(frame), expectedTotal)
	}
	if !isAllZero(frame[TCC1HeaderLen+int(paramsLen) : TCC1HeaderLen+paddedParamsLen]) {
		return errors.New("TCC1 parameter alignment padding must be zero")
	}

	if cmd == CmdRotateKey {
		if paramsLen != KDMSize {
			return fmt.Errorf("CmdRotateKey requires %d-byte KDM params, got %d", KDMSize, paramsLen)
		}
		if err := validateKDMStructure(frame[TCC1HeaderLen : TCC1HeaderLen+KDMSize]); err != nil {
			return fmt.Errorf("CmdRotateKey invalid embedded KDM: %w", err)
		}
	}

	signedLen := expectedTotal - Ed25519SignatureLen
	sig := frame[signedLen:]
	if isAllZero(sig) || !ed25519.Verify(pub, frame[:signedLen], sig) {
		return errors.New("TCC1 Ed25519 signature verification failed")
	}
	return nil
}

// SignKDM builds, signs, and self-verifies a 128-byte Key Delegation Message (toob_kdm_t).
func SignKDM(opts KDMOptions, signer tbm1.Signer) ([]byte, error) {
	if signer == nil {
		return nil, errors.New("signer must not be nil")
	}
	pub := signer.Public()
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("signer returned invalid public key length %d", len(pub))
	}
	if len(opts.NewCloudPubkey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("new_cloud_pubkey must be %d bytes, got %d", ed25519.PublicKeySize, len(opts.NewCloudPubkey))
	}
	if isAllZero(opts.NewCloudPubkey) {
		return nil, errors.New("new_cloud_pubkey must not be all zeros")
	}

	kdm := make([]byte, KDMSize)
	binary.LittleEndian.PutUint32(kdm[kdmSeqOffset:kdmPubkeyOffset], opts.SequenceNumber)
	copy(kdm[kdmPubkeyOffset:kdmSigOffset], opts.NewCloudPubkey)

	sig, err := signer.Sign(kdm[:kdmSigOffset])
	if err != nil {
		return nil, fmt.Errorf("sign KDM envelope: %w", err)
	}
	if len(sig) != Ed25519SignatureLen || isAllZero(sig) {
		return nil, fmt.Errorf("invalid Ed25519 signature length %d", len(sig))
	}
	copy(kdm[kdmSigOffset:kdmPaddingOffset], sig)

	if err := VerifyKDM(kdm, pub); err != nil {
		return nil, fmt.Errorf("self-verify KDM envelope: %w", err)
	}
	return kdm, nil
}

// VerifyKDM validates the fixed 128-byte layout, zero tail padding, non-zero public key,
// and Ed25519 signature of a Key Delegation Message (toob_kdm_t).
func VerifyKDM(kdm []byte, pub ed25519.PublicKey) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid public key length %d (expected %d)", len(pub), ed25519.PublicKeySize)
	}
	if err := validateKDMStructure(kdm); err != nil {
		return err
	}
	if !ed25519.Verify(pub, kdm[:kdmSigOffset], kdm[kdmSigOffset:kdmPaddingOffset]) {
		return errors.New("KDM Ed25519 signature verification failed")
	}
	return nil
}

func validateKDMStructure(kdm []byte) error {
	if len(kdm) != KDMSize {
		return fmt.Errorf("invalid KDM length %d (expected %d)", len(kdm), KDMSize)
	}
	if isAllZero(kdm[kdmPubkeyOffset:kdmSigOffset]) {
		return errors.New("KDM new_cloud_pubkey must not be all zeros")
	}
	if isAllZero(kdm[kdmSigOffset:kdmPaddingOffset]) {
		return errors.New("KDM Ed25519 signature must not be all zeros")
	}
	if !isAllZero(kdm[kdmPaddingOffset:KDMSize]) {
		return errors.New("KDM trailing padding bytes must be zero")
	}
	return nil
}

func alignUpInt16(n int) int {
	return (n + (TCC1Align - 1)) &^ (TCC1Align - 1)
}
