package signing

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/Toob-Boot/Toob-Loader/toob-go-lib/tbm1"
	"github.com/toob-boot/toob/internal/manifest"
	"github.com/toob-boot/toob/internal/registry"
)

const (
	// ToobImageMagic identifies a 20-byte toob_image_header_t ("BOOT" in little-endian).
	ToobImageMagic uint32 = 0x544F4F42
	// ToobImageHeaderLen is the fixed wire size of toob_image_header_t in bytes.
	ToobImageHeaderLen = 20
	// ToobStage1SVNMagic tags bytes [12:16] of a Stage-1 image header ("TBS1" in little-endian).
	ToobStage1SVNMagic uint32 = 0x31534254
	// ToobImgSigMagic identifies the 72-byte TSIG trailer ("TSIG" in little-endian).
	ToobImgSigMagic uint32 = 0x54534947
	// ToobImgSigFlagSHA256 marks an Ed25519 signature over SHA-256(image[0 .. image_size-72)).
	ToobImgSigFlagSHA256 uint8 = 0x01
	// ToobImgSigTrailerLen is the fixed wire size of toob_img_sig_trailer_t in bytes.
	ToobImgSigTrailerLen = 72
	// Ed25519SignatureLen is the fixed byte length of an Ed25519 signature.
	Ed25519SignatureLen = 64
)

// ImageRole identifies which boot stage or flash slot an image targets.
type ImageRole string

const (
	RoleApp      ImageRole = "app"
	RoleRecovery ImageRole = "recovery"
	RoleStage1   ImageRole = "stage1"
	RoleStage1A  ImageRole = "stage1a"
	RoleStage1B  ImageRole = "stage1b"
	RoleNetcore  ImageRole = "netcore"
)

// ParseImageRole normalizes and validates a firmware image role string.
func ParseImageRole(raw string) (ImageRole, error) {
	switch ImageRole(strings.ToLower(strings.TrimSpace(raw))) {
	case RoleApp:
		return RoleApp, nil
	case RoleRecovery:
		return RoleRecovery, nil
	case RoleStage1:
		return RoleStage1, nil
	case RoleStage1A:
		return RoleStage1A, nil
	case RoleStage1B:
		return RoleStage1B, nil
	case RoleNetcore:
		return RoleNetcore, nil
	default:
		return "", fmt.Errorf("unsupported image role %q (expected app, recovery, stage1, stage1a, stage1b, or netcore)", raw)
	}
}

// IsStage1 reports whether the role represents a Stage-1 bootloader binary.
func (r ImageRole) IsStage1() bool {
	return r == RoleStage1 || r == RoleStage1A || r == RoleStage1B
}

// TargetSlot maps the image role to its TBM1 v2 target slot ID.
func (r ImageRole) TargetSlot() (uint8, error) {
	switch r {
	case RoleApp:
		return tbm1.SlotApp, nil
	case RoleNetcore:
		return tbm1.SlotNetcore, nil
	case RoleRecovery:
		return tbm1.SlotRecovery, nil
	case RoleStage1, RoleStage1A, RoleStage1B:
		return tbm1.SlotStage1, nil
	default:
		return 0, fmt.Errorf("cannot map unknown image role %q to TBM1 slot", r)
	}
}

// ImageOptions configures C-ABI Toob image header construction and Ed25519 signing.
type ImageOptions struct {
	InPath                 string
	OutPath                string
	Payload                []byte
	Chip                   string
	HardwarePath           string
	CacheDir               string
	Cache                  *registry.Cache
	HeaderOffset           *uint32
	EntryPoint             uint32
	Role                   ImageRole
	Stage1SVN              uint32
	ExecModel              string
	BaseFingerprint        *[32]byte
	RequireBaseFingerprint bool
	KeyIndex               uint8
	Unsigned               bool
}

// ImageResult summarizes a built and verified Toob firmware image.
type ImageResult struct {
	OutPath      string
	Role         ImageRole
	Chip         string
	HeaderOffset uint32
	EntryPoint   uint32
	ImageSize    uint32
	Data         []byte
}

// ValidateImageOptions configures structural and cryptographic checks in ValidateToobImage.
type ValidateImageOptions struct {
	Role                   ImageRole
	HeaderOffset           *uint32
	RAMExec                bool
	RequireNonZeroEntry    bool
	RequireBaseFingerprint bool
	RequireStage1Signature bool
	RequireImageSignature  bool
	KeyIndex               *uint8
	SignerPub              ed25519.PublicKey
}

// SignImage wraps a firmware binary with the 20-byte Toob image header and appends either
// the Stage-1 64-byte raw Ed25519 signature or a 72-byte TSIG trailer inside image_size
// for non-Stage-1 roles unless Unsigned is explicitly requested.
func SignImage(opts ImageOptions, signer tbm1.Signer) (*ImageResult, error) {
	role := opts.Role
	if role == "" {
		role = RoleApp
	} else {
		parsed, err := ParseImageRole(string(role))
		if err != nil {
			return nil, err
		}
		role = parsed
	}

	if opts.Unsigned {
		if role.IsStage1() {
			return nil, fmt.Errorf("--unsigned is not permitted for Stage-1 role %s", role)
		}
		if signer != nil {
			return nil, errors.New("--unsigned cannot be combined with a signing key")
		}
		if opts.KeyIndex != 0 {
			return nil, errors.New("--unsigned cannot be combined with non-zero --key-index")
		}
	} else {
		if signer == nil {
			if role.IsStage1() {
				return nil, fmt.Errorf("signer must not be nil for role %s", role)
			}
			return nil, fmt.Errorf("signer must not be nil for role %s (supply a signing key, --mock, or explicit --unsigned)", role)
		}
		if role.IsStage1() && opts.KeyIndex != 0 {
			return nil, fmt.Errorf("--key-index is not supported for Stage-1 role %s", role)
		}
	}

	rawPayload, err := loadImagePayload(opts)
	if err != nil {
		return nil, err
	}

	chipCtx, err := resolveChipContext(opts.Chip, opts.HardwarePath, opts.CacheDir, "", opts.Cache)
	if err != nil {
		return nil, err
	}

	var hw *manifest.HardwareJson
	var cm *manifest.ChipManifest
	if chipCtx != nil {
		hw = chipCtx.Hardware
		cm = chipCtx.ChipManifest
	}

	execModel := effectiveExecModel(opts.ExecModel, cm)
	if roleErr := validateRoleAgainstExecModel(role, execModel); roleErr != nil {
		return nil, roleErr
	}

	hdrOffset, err := resolveImageHeaderOffset(opts.HeaderOffset, hw, cm)
	if err != nil {
		return nil, err
	}

	paddedPayload := padTo4BytesFF(rawPayload)
	payloadLen, err := safeUint32(len(paddedPayload))
	if err != nil {
		return nil, fmt.Errorf("image payload exceeds 32-bit range: %w", err)
	}
	extraTrailer := uint32(0)
	if !role.IsStage1() && !opts.Unsigned {
		extraTrailer = ToobImgSigTrailerLen
	}
	if payloadLen > math.MaxUint32-ToobImageHeaderLen-extraTrailer {
		return nil, fmt.Errorf("image payload exceeds 32-bit addressable range (%d bytes)", payloadLen)
	}

	stage0ExecMode := strings.ToLower(effectiveStage0ExecMode(hw, cm))
	isRAMStage1 := role.IsStage1() && stage0ExecMode == "ram"

	totalXipLen := ToobImageHeaderLen + payloadLen
	if !isRAMStage1 && totalXipLen <= hdrOffset {
		return nil, fmt.Errorf("padded image length (%d + 20 = %d) does not reach image_header_offset (%d)", payloadLen, totalXipLen, hdrOffset)
	}

	entryPoint, err := resolveAndValidateEntryPoint(opts.EntryPoint, hdrOffset, totalXipLen, isRAMStage1, hw)
	if err != nil {
		return nil, err
	}

	var hdr [ToobImageHeaderLen]byte
	binary.LittleEndian.PutUint32(hdr[0:4], ToobImageMagic)
	binary.LittleEndian.PutUint32(hdr[8:12], entryPoint)

	var imageSize uint32
	if role.IsStage1() {
		if opts.Stage1SVN == 0 {
			return nil, errors.New("stage1_svn must be >= 1 for Stage-1 images")
		}
		imageSize = payloadLen
		binary.LittleEndian.PutUint32(hdr[4:8], imageSize)
		binary.LittleEndian.PutUint32(hdr[12:16], ToobStage1SVNMagic)
		binary.LittleEndian.PutUint32(hdr[16:20], opts.Stage1SVN)
	} else {
		imageSize = ToobImageHeaderLen + payloadLen + extraTrailer
		binary.LittleEndian.PutUint32(hdr[4:8], imageSize)
		fp, fpErr := resolveBaseFingerprint(paddedPayload, opts.BaseFingerprint, opts.RequireBaseFingerprint)
		if fpErr != nil {
			return nil, fpErr
		}
		copy(hdr[12:20], fp[:])
	}

	trailerCap := Ed25519SignatureLen
	if !role.IsStage1() {
		trailerCap = ToobImgSigTrailerLen
	}
	out := make([]byte, 0, ToobImageHeaderLen+len(paddedPayload)+trailerCap)
	out = append(out, hdr[:]...)
	out = append(out, paddedPayload...)

	valOpts := ValidateImageOptions{
		Role:                   role,
		HeaderOffset:           &hdrOffset,
		RAMExec:                isRAMStage1,
		RequireNonZeroEntry:    true,
		RequireBaseFingerprint: opts.RequireBaseFingerprint,
	}

	if role.IsStage1() {
		digest := sha256.Sum256(out)
		sig, signErr := signer.Sign(digest[:])
		if signErr != nil {
			return nil, fmt.Errorf("sign Stage-1 digest: %w", signErr)
		}
		if len(sig) != Ed25519SignatureLen || isAllZero(sig) {
			return nil, fmt.Errorf("invalid Ed25519 signature length %d from signer", len(sig))
		}
		out = append(out, sig...)
		valOpts.RequireStage1Signature = true
		valOpts.SignerPub = signer.Public()
	} else if !opts.Unsigned {
		digest := sha256.Sum256(out)
		sig, signErr := signer.Sign(digest[:])
		if signErr != nil {
			return nil, fmt.Errorf("sign image digest: %w", signErr)
		}
		if len(sig) != Ed25519SignatureLen || isAllZero(sig) {
			return nil, fmt.Errorf("invalid Ed25519 signature length %d from signer", len(sig))
		}
		var trailer [ToobImgSigTrailerLen]byte
		binary.LittleEndian.PutUint32(trailer[0:4], ToobImgSigMagic)
		trailer[4] = opts.KeyIndex
		trailer[5] = ToobImgSigFlagSHA256
		copy(trailer[8:ToobImgSigTrailerLen], sig)
		out = append(out, trailer[:]...)
		keyIdx := opts.KeyIndex
		valOpts.RequireImageSignature = true
		valOpts.KeyIndex = &keyIdx
		valOpts.SignerPub = signer.Public()
	}

	if verErr := ValidateToobImage(string(role), out, valOpts); verErr != nil {
		return nil, fmt.Errorf("self-verify signed image: %w", verErr)
	}

	if strings.TrimSpace(opts.OutPath) != "" {
		if writeErr := writeFileAtomic(opts.OutPath, out, 0o644, true); writeErr != nil {
			return nil, fmt.Errorf("write signed image: %w", writeErr)
		}
	}

	chipName := strings.TrimSpace(opts.Chip)
	if chipName == "" && hw != nil {
		chipName = hw.ChipFamily
	}

	return &ImageResult{
		OutPath:      opts.OutPath,
		Role:         role,
		Chip:         chipName,
		HeaderOffset: hdrOffset,
		EntryPoint:   entryPoint,
		ImageSize:    imageSize,
		Data:         out,
	}, nil
}

// ValidateToobImage enforces structural, boundary, fingerprint, and optional signature invariants
// on a Toob firmware image buffer.
func ValidateToobImage(label string, b []byte, opts ValidateImageOptions) error {
	if label == "" {
		label = "image"
	}
	if len(b) < ToobImageHeaderLen {
		return fmt.Errorf("%s: buffer too short (%d < %d bytes)", label, len(b), ToobImageHeaderLen)
	}

	magic := binary.LittleEndian.Uint32(b[0:4])
	if magic != ToobImageMagic {
		return fmt.Errorf("%s: invalid magic 0x%08x (expected 0x%08x)", label, magic, ToobImageMagic)
	}

	imageSize := binary.LittleEndian.Uint32(b[4:8])
	entryPoint := binary.LittleEndian.Uint32(b[8:12])
	if opts.RequireNonZeroEntry && entryPoint == 0 {
		return fmt.Errorf("%s: entry_point must not be zero", label)
	}

	isStage1 := opts.Role.IsStage1() || opts.RequireStage1Signature
	if isStage1 {
		return validateStage1Image(label, b, imageSize, entryPoint, opts)
	}

	requireSig := opts.RequireImageSignature || len(opts.SignerPub) > 0 || opts.KeyIndex != nil
	minSize := uint32(ToobImageHeaderLen + 4)
	if requireSig {
		minSize = uint32(ToobImageHeaderLen + 4 + ToobImgSigTrailerLen)
	}
	if imageSize < minSize || imageSize%4 != 0 {
		return fmt.Errorf("%s: invalid image_size %d (must be >= %d and 4-byte aligned)", label, imageSize, minSize)
	}
	if len(b) != int(imageSize) {
		return fmt.Errorf("%s: image length mismatch (got %d, header image_size %d)", label, len(b), imageSize)
	}
	if opts.RequireBaseFingerprint && isAllZero(b[12:20]) {
		return fmt.Errorf("%s: base_fingerprint must not be all zeros", label)
	}
	entryUpper := imageSize
	if requireSig {
		entryUpper = imageSize - ToobImgSigTrailerLen
	}
	if opts.HeaderOffset != nil {
		if entryPoint < *opts.HeaderOffset || entryPoint >= entryUpper {
			return fmt.Errorf("%s: entry_point 0x%x out of bounds [0x%x, 0x%x)", label, entryPoint, *opts.HeaderOffset, entryUpper)
		}
	}
	if requireSig {
		return validateImageSigTrailer(label, b, opts)
	}
	return nil
}

func validateImageSigTrailer(label string, b []byte, opts ValidateImageOptions) error {
	signedLen := len(b) - ToobImgSigTrailerLen
	trailer := b[signedLen : signedLen+ToobImgSigTrailerLen]

	trailerMagic := binary.LittleEndian.Uint32(trailer[0:4])
	if trailerMagic != ToobImgSigMagic {
		return fmt.Errorf("%s: invalid TSIG trailer magic 0x%08x (expected 0x%08x)", label, trailerMagic, ToobImgSigMagic)
	}
	if opts.KeyIndex != nil && trailer[4] != *opts.KeyIndex {
		return fmt.Errorf("%s: TSIG key_index %d != expected %d", label, trailer[4], *opts.KeyIndex)
	}
	if trailer[5] != ToobImgSigFlagSHA256 {
		return fmt.Errorf("%s: unsupported TSIG flags 0x%02x (expected 0x%02x)", label, trailer[5], ToobImgSigFlagSHA256)
	}
	if reserved := binary.LittleEndian.Uint16(trailer[6:8]); reserved != 0 {
		return fmt.Errorf("%s: non-zero TSIG reserved field 0x%04x", label, reserved)
	}

	sig := trailer[8:ToobImgSigTrailerLen]
	if isAllZero(sig) {
		return fmt.Errorf("%s: TSIG Ed25519 signature must not be all zeros", label)
	}
	if len(opts.SignerPub) > 0 {
		if len(opts.SignerPub) != ed25519.PublicKeySize {
			return fmt.Errorf("%s: invalid verification public key length %d", label, len(opts.SignerPub))
		}
		digest := sha256.Sum256(b[:signedLen])
		if !ed25519.Verify(opts.SignerPub, digest[:], sig) {
			return fmt.Errorf("%s: TSIG Ed25519 signature verification failed", label)
		}
	}
	return nil
}

func validateStage1Image(label string, b []byte, imageSize, entryPoint uint32, opts ValidateImageOptions) error {
	if imageSize < 4 || imageSize%4 != 0 {
		return fmt.Errorf("%s: invalid Stage-1 payload image_size %d (must be >= 4 and 4-byte aligned)", label, imageSize)
	}
	expectedTotal := ToobImageHeaderLen + int(imageSize) + Ed25519SignatureLen
	if len(b) != expectedTotal {
		return fmt.Errorf("%s: Stage-1 length mismatch (got %d, expected %d = 20 + %d + 64)", label, len(b), expectedTotal, imageSize)
	}

	svnMagic := binary.LittleEndian.Uint32(b[12:16])
	if svnMagic != ToobStage1SVNMagic {
		return fmt.Errorf("%s: invalid Stage-1 SVN magic 0x%08x (expected 0x%08x)", label, svnMagic, ToobStage1SVNMagic)
	}
	svn := binary.LittleEndian.Uint32(b[16:20])
	if svn == 0 {
		return fmt.Errorf("%s: stage1_svn must not be zero", label)
	}

	if !opts.RAMExec && opts.HeaderOffset != nil {
		xipEnd := ToobImageHeaderLen + imageSize
		if entryPoint < *opts.HeaderOffset || entryPoint >= xipEnd {
			return fmt.Errorf("%s: XIP entry_point 0x%x out of bounds [0x%x, 0x%x)", label, entryPoint, *opts.HeaderOffset, xipEnd)
		}
	}

	signedLen := ToobImageHeaderLen + int(imageSize)
	sig := b[signedLen : signedLen+Ed25519SignatureLen]
	if isAllZero(sig) {
		return fmt.Errorf("%s: Stage-1 Ed25519 signature must not be all zeros", label)
	}
	if len(opts.SignerPub) > 0 {
		if len(opts.SignerPub) != ed25519.PublicKeySize {
			return fmt.Errorf("%s: invalid verification public key length %d", label, len(opts.SignerPub))
		}
		digest := sha256.Sum256(b[:signedLen])
		if !ed25519.Verify(opts.SignerPub, digest[:], sig) {
			return fmt.Errorf("%s: Stage-1 Ed25519 signature verification failed", label)
		}
	}
	return nil
}

func loadImagePayload(opts ImageOptions) ([]byte, error) {
	if len(opts.Payload) > 0 {
		return opts.Payload, nil
	}
	if strings.TrimSpace(opts.InPath) == "" {
		return nil, errors.New("input image path or non-empty Payload is required")
	}
	raw, err := readFileBounded(opts.InPath, maxFirmwareFileBytes)
	if err != nil {
		return nil, fmt.Errorf("read input image: %w", err)
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("input image %s is empty", opts.InPath)
	}
	return raw, nil
}

func padTo4BytesFF(raw []byte) []byte {
	rem := len(raw) % 4
	pad := (4 - rem) % 4
	out := make([]byte, len(raw)+pad)
	copy(out, raw)
	for i := len(raw); i < len(out); i++ {
		out[i] = 0xFF
	}
	return out
}

func validateRoleAgainstExecModel(role ImageRole, execModel string) error {
	if !role.IsStage1() {
		return nil
	}
	em := strings.ToLower(strings.TrimSpace(execModel))
	if em == "" {
		return nil
	}

	isDualLink := strings.Contains(em, "dual_link") || strings.Contains(em, "duallink") || strings.Contains(em, "dual-link")
	if isDualLink && role == RoleStage1 {
		return fmt.Errorf("exec_model %q uses Dual-Link Stage-1: specify role stage1a or stage1b", execModel)
	}

	isSingle := em == "ram" || strings.Contains(em, "bank_swap") || strings.Contains(em, "remap") || strings.Contains(em, "single_stage")
	if isSingle && (role == RoleStage1A || role == RoleStage1B) {
		return fmt.Errorf("exec_model %q uses single-image Stage-1: role %s is incompatible", execModel, role)
	}
	return nil
}

func resolveImageHeaderOffset(explicit *uint32, hw *manifest.HardwareJson, cm *manifest.ChipManifest) (uint32, error) {
	if explicit != nil {
		off := *explicit
		if off < ToobImageHeaderLen || off%4 != 0 {
			return 0, fmt.Errorf("image_header_offset %d must be >= %d and 4-byte aligned", off, ToobImageHeaderLen)
		}
		if hw != nil {
			if vtor := effectiveVtorAlign(hw); vtor > 0 && (off < vtor || off%vtor != 0) {
				return 0, fmt.Errorf("image_header_offset %d violates hardware VTOR alignment %d", off, vtor)
			}
		}
		return off, nil
	}

	if hw == nil {
		return 0, errors.New("image_header_offset requires explicit HeaderOffset, Chip, or HardwarePath (refusing implicit fallback)")
	}
	if hw.Flash.ImageHeaderOffset > 0 {
		off := hw.Flash.ImageHeaderOffset
		if off < ToobImageHeaderLen || off%4 != 0 {
			return 0, fmt.Errorf("hardware flash.image_header_offset %d must be >= %d and 4-byte aligned", off, ToobImageHeaderLen)
		}
		return off, nil
	}
	if hw.Memory.ImageHeaderOffset > 0 {
		off := hw.Memory.ImageHeaderOffset
		if off < ToobImageHeaderLen || off%4 != 0 {
			return 0, fmt.Errorf("hardware memory.image_header_offset %d must be >= %d and 4-byte aligned", off, ToobImageHeaderLen)
		}
		return off, nil
	}
	if vtor := effectiveVtorAlign(hw); vtor > 0 {
		if vtor < ToobImageHeaderLen || vtor%4 != 0 {
			return 0, fmt.Errorf("hardware vtor_alignment %d cannot host 20-byte Toob image header", vtor)
		}
		return vtor, nil
	}
	if strings.Contains(strings.ToLower(effectiveArch(cm, hw)), "cortex-m") {
		return 0, errors.New("Cortex-M hardware.json omits image_header_offset and vtor_alignment (refusing 0x14 fallback)")
	}
	return ToobImageHeaderLen, nil
}

func resolveAndValidateEntryPoint(requested, hdrOffset, totalXipLen uint32, isRAMStage1 bool, hw *manifest.HardwareJson) (uint32, error) {
	if isRAMStage1 {
		if err := validateRAMEntryPoint(hw, requested); err != nil {
			return 0, err
		}
		return requested, nil
	}

	entry := requested
	if entry == 0 {
		entry = hdrOffset
	}
	if entry < hdrOffset || entry >= totalXipLen {
		return 0, fmt.Errorf("entry_point 0x%x out of valid XIP bounds [0x%x, 0x%x)", entry, hdrOffset, totalXipLen)
	}
	return entry, nil
}

func resolveBaseFingerprint(paddedPayload []byte, explicit *[32]byte, required bool) ([8]byte, error) {
	var out [8]byte
	if explicit != nil {
		copy(out[:], explicit[:8])
		if required && isAllZero(out[:]) {
			return out, errors.New("explicit base_fingerprint must not be all zeros")
		}
		return out, nil
	}

	sum := sha256.Sum256(paddedPayload)
	copy(out[:], sum[:8])
	if required && isAllZero(out[:]) {
		return out, errors.New("computed base_fingerprint is unexpectedly all zeros")
	}
	return out, nil
}
