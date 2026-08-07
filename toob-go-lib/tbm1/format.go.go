// Package tbm1 encodes, validates and signs TBM1 v2 fixed-format boot manifests.
//
// It is a library, not a service. There is no HTTP, no CLI and no configuration
// file here — drop it into a build or release backend and call it. The optional
// tbm1http subpackage shows one way to expose it, and is meant to be copied and
// adapted rather than used verbatim.
//
// Three concerns, deliberately kept apart:
//
//	Format   — constants, ParseHeader, ValidateBlock, VerifyBlock: pure, no key.
//	Encoder  — Manifest → Package. Pure, no key, no I/O beyond the payload
//	           sources the caller hands in.
//	Signer   — an interface over "Ed25519-sign these bytes", so the private key
//	           can live in memory, a KMS or an HSM. The encoder never sees it.
//
// Every layout constant mirrors boot_tbm1.h byte-for-byte; the shared golden
// vectors exist to catch drift between this writer and the C reader.
//
// Flat on-flash package (as libtoob streams it into staging):
//
//	[ Fixed Header 512 ][ Variable Regions … ][ Ed25519 Signature 64 ][ Image Data … ]
//	                    \______ signed: [0 .. total_len-64) ______/
//
// The signature covers header + regions (chunk hashes, PQC blobs, device bind),
// NOT the raw image payload — payload integrity comes from the signed chunk
// hashes.
//
// Arithmetic model: every on-flash length is a little-endian uint32. All layout
// math runs in uint64 and is narrowed exactly once, after an explicit range
// check, so no expression in this package can wrap silently.
//
// Requires Go 1.19 or newer (sync/atomic types). Standard library only.
package tbm1

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"math"
)

// ---- Layout constants (mirror boot_tbm1.h) ------------------------------

const (
	Magic        = 0x314D4254 // 'TBM1' little-endian
	VersionMajor = 2
	VersionMinor = 0
	FixedLen     = 512
	SigLen       = 64
	MaxImages    = 4
	MaxRegions   = 8
	CRCLen       = FixedLen - 4
	DigestLen    = 32 // SHA-256 per chunk

	DefaultChunkSize  = 4096
	DefaultSectorSize = 4096
)

// Region IDs.
const (
	RegionNone         = 0
	RegionChunkHashes  = 1
	RegionPQCSignature = 2
	RegionPQCPubkey    = 3
	RegionDeviceBind   = 4
	RegionDeltaScript  = 5
)

// Compression / delta enums.
const (
	CompNone       = 0
	CompHeatshrink = 1
	CompLZ4        = 2

	DeltaNone    = 0
	DeltaBSDiff  = 1
	DeltaDETools = 2
)

// Target slots.
const (
	SlotApp      = 0
	SlotNetcore  = 1
	SlotRecovery = 2
	SlotStage1   = 3
)

// flags_critical / flags_info bits.
const (
	CritPQCRequired = 1 << 0
	InfoDeviceBind  = 1 << 0
)

// Fixed-header field offsets.
const (
	offMagic          = 0
	offVersionMajor   = 4
	offVersionMinor   = 5
	offFixedLen       = 6
	offTotalLen       = 8
	offFlagsCritical  = 12
	offFlagsInfo      = 14
	offVendorID       = 16
	offProductID      = 18
	offHWRevMin       = 20
	offHWRevMax       = 22
	offKeyIndex       = 24
	offImageCount     = 25
	offBootRetryLimit = 26
	offMinReaderMajor = 28
	offMinReaderMinor = 30
	offSVN            = 32
	offStage1SVN      = 36
	offKeyEpoch       = 40
	offBuildNumber    = 44
	offFwVerMajor     = 48
	offFwVerMinor     = 50
	offFwVerPatch     = 52
	offSBOMDigest     = 56
	offRegions        = 88
	offImages         = 184
	offReservedTail   = 360
	offFixedCRC32     = 508

	regionStride = 12 // id(2) pad(2) off(4) len(4)
	imageStride  = 44
)

// Field offsets inside one image-table entry.
const (
	imgType       = 0
	imgTargetSlot = 1
	imgCompAlg    = 2
	imgDeltaAlg   = 3
	imgDataOff    = 4
	imgStoredLen  = 8
	imgInstalled  = 12
	imgChunkSize  = 16
	imgNumChunks  = 20
	imgBaseSVN    = 24
	imgVerMajor   = 28
	imgVerMinor   = 30
	imgVerPatch   = 32
	imgBaseFP     = 36 // 8 bytes
)

// Compile-time layout assertions. Each expression must evaluate to a
// non-negative untyped constant; if a field offset is ever edited so that two
// tables overlap, or the CRC stops terminating the fixed header, the package
// fails to compile instead of silently emitting corrupt manifests.
const (
	_ = uint(offImages - (offRegions + MaxRegions*regionStride))    // region table fits before the image table
	_ = uint(offReservedTail - (offImages + MaxImages*imageStride)) // image table fits before the reserved tail
	_ = uint(CRCLen - offReservedTail)                              // reserved tail lies inside the CRC-covered range
	_ = uint(offFixedCRC32 - CRCLen)                                // CRC field starts exactly where its coverage ends
	_ = uint(FixedLen - (offFixedCRC32 + 4))                        // …and ends the fixed header
	_ = uint(imageStride - (imgBaseFP + 8))                         // image entry holds all its fields
)

// ---- Safety limits ------------------------------------------------------

const (
	// MinChunkSize keeps the hash table below half the payload it protects
	// (DigestLen bytes per chunk); at 32 bytes per chunk it would equal the
	// image size, below that it would exceed it.
	MinChunkSize = 64
	MaxChunkSize = 1 << 24 // 16 MiB

	// MaxSectorSize bounds the staging alignment. Must be a power of two so
	// alignment is a mask rather than a division.
	MaxSectorSize = 1 << 20

	// MaxManifestLen bounds the signed block (header + regions + signature).
	// A 1 GiB image at the 4 KiB default chunk size needs ~8 MiB of hashes.
	MaxManifestLen = 64 << 20

	// MaxImageLen is dictated by the on-flash uint32 length fields.
	MaxImageLen = math.MaxUint32

	maxInt = int(^uint(0) >> 1)
)

// ---- Sentinel errors ----------------------------------------------------

var (
	// ErrInvalidManifest — the caller's Manifest cannot produce a legal block.
	ErrInvalidManifest = errors.New("tbm1: invalid manifest")
	// ErrMalformedBlock — a byte block failed the reader-mirroring checks.
	ErrMalformedBlock = errors.New("tbm1: malformed manifest block")
	// ErrLayoutOverflow — the layout does not fit the 32-bit on-flash format.
	ErrLayoutOverflow = errors.New("tbm1: layout overflow")
	// ErrUnsigned — an operation needs a signature that has not been set.
	ErrUnsigned = errors.New("tbm1: package is not signed")
	// ErrBadSignature — Ed25519 verification failed.
	ErrBadSignature = errors.New("tbm1: signature verification failed")
	// ErrNoSigner — a key-holding operation was attempted without a Signer.
	ErrNoSigner = errors.New("tbm1: no signer configured")
	// ErrPayload — a caller-supplied payload source failed or lied about its size.
	ErrPayload = errors.New("tbm1: payload source error")
)

// ---- Arithmetic helpers -------------------------------------------------

// ceilDivU32 computes ⌈a/b⌉ without the (a+b-1) overflow trap. It mirrors the
// reader's chunk-count derivation exactly; b must be non-zero.
func ceilDivU32(a, b uint32) uint32 {
	q := a / b
	if a%b != 0 {
		q++
	}
	return q
}

// alignUp64 rounds v up to a multiple of a. a must be a power of two (0 and 1
// are no-ops), which every call site validates beforehand.
func alignUp64(v, a uint64) uint64 {
	if a <= 1 {
		return v
	}
	return (v + a - 1) &^ (a - 1)
}

func isPow2U32(v uint32) bool { return v != 0 && v&(v-1) == 0 }

// headerCRC is the checksum over the fixed header, excluding the field that
// stores it. The C reader must use the same reflected CRC-32 (poly 0xEDB88320,
// init/xorout 0xFFFFFFFF); TestCRCVariant pins the variant to a golden value.
func headerCRC(block []byte) uint32 { return crc32.ChecksumIEEE(block[:CRCLen]) }

// ---- Header view --------------------------------------------------------

// Header is a decoded copy of the fixed header. A backend uses it to authorise
// and audit a block before handing it to a Signer: check the key index against
// the key the node actually holds, check the SVN against the release database,
// log the build number. The encoder itself never needs it.
type Header struct {
	VersionMajor, VersionMinor uint8
	TotalLen, SignedLen        uint32
	FlagsCritical, FlagsInfo   uint16
	VendorID, ProductID        uint16
	HWRevMin, HWRevMax         uint16
	KeyIndex                   uint8
	KeyEpoch                   uint32
	ImageCount                 uint8
	SVN, Stage1SVN             uint32
	BuildNumber                uint32
	FwVerMajor                 uint16
	FwVerMinor                 uint16
	FwVerPatch                 uint16
	SBOMDigest                 [32]byte
}

// ParseHeader validates block and returns its fixed header. It never panics,
// whatever bytes it is handed.
func ParseHeader(block []byte) (Header, error) {
	if err := validateBlock(block); err != nil {
		return Header{}, err
	}
	le := binary.LittleEndian
	h := Header{
		VersionMajor:  block[offVersionMajor],
		VersionMinor:  block[offVersionMinor],
		TotalLen:      le.Uint32(block[offTotalLen:]),
		FlagsCritical: le.Uint16(block[offFlagsCritical:]),
		FlagsInfo:     le.Uint16(block[offFlagsInfo:]),
		VendorID:      le.Uint16(block[offVendorID:]),
		ProductID:     le.Uint16(block[offProductID:]),
		HWRevMin:      le.Uint16(block[offHWRevMin:]),
		HWRevMax:      le.Uint16(block[offHWRevMax:]),
		KeyIndex:      block[offKeyIndex],
		KeyEpoch:      le.Uint32(block[offKeyEpoch:]),
		ImageCount:    block[offImageCount],
		SVN:           le.Uint32(block[offSVN:]),
		Stage1SVN:     le.Uint32(block[offStage1SVN:]),
		BuildNumber:   le.Uint32(block[offBuildNumber:]),
		FwVerMajor:    le.Uint16(block[offFwVerMajor:]),
		FwVerMinor:    le.Uint16(block[offFwVerMinor:]),
		FwVerPatch:    le.Uint16(block[offFwVerPatch:]),
	}
	h.SignedLen = h.TotalLen - SigLen
	copy(h.SBOMDigest[:], block[offSBOMDigest:offSBOMDigest+32])
	return h, nil
}

// ---- Validation: reader mirror, panic-safe on untrusted input ------------

// ValidateBlock reports whether b is a structurally sound TBM1 manifest block.
// It never panics, whatever bytes it is handed, and it does not look at the
// signature — use VerifyBlock for that.
func ValidateBlock(b []byte) error { return validateBlock(b) }

// VerifyBlock validates the structure and then checks the Ed25519 signature.
func VerifyBlock(b []byte, pub ed25519.PublicKey) error {
	if err := validateBlock(b); err != nil {
		return err
	}
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("tbm1: public key must be %d bytes, got %d", ed25519.PublicKeySize, len(pub))
	}
	total := binary.LittleEndian.Uint32(b[offTotalLen:])
	if !ed25519.Verify(pub, b[:total-SigLen], b[total-SigLen:total]) {
		return ErrBadSignature
	}
	return nil
}

func malformed(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrMalformedBlock, fmt.Sprintf(format, a...))
}

func validateBlock(b []byte) error {
	// Every fixed-offset read below is proven in range by this one length check
	// plus the compile-time assertion that both tables end before the CRC field.
	if len(b) < FixedLen {
		return malformed("block shorter than the %d-byte fixed header", FixedLen)
	}
	le := binary.LittleEndian
	if le.Uint32(b[offMagic:]) != Magic {
		return malformed("bad magic")
	}
	if le.Uint16(b[offFixedLen:]) != FixedLen {
		return malformed("bad fixed_len")
	}
	if b[offVersionMajor] != VersionMajor {
		return malformed("unsupported version_major %d", b[offVersionMajor])
	}
	total := le.Uint32(b[offTotalLen:])
	if total < FixedLen+SigLen {
		return malformed("total_len %d below the minimum %d", total, FixedLen+SigLen)
	}
	if uint64(total) != uint64(len(b)) {
		return malformed("total_len %d != block length %d", total, len(b))
	}
	if le.Uint32(b[offFixedCRC32:]) != headerCRC(b) {
		return malformed("header CRC mismatch")
	}

	// Regions: unique, ascending, non-overlapping, wholly inside the signed area.
	sigStart := total - SigLen
	var seen [MaxRegions]uint16
	nSeen := 0
	prevEnd := uint32(FixedLen)
	var chunkHashLen uint32
	foundChunkHashes := false

	for i := 0; i < MaxRegions; i++ {
		base := offRegions + i*regionStride
		id := le.Uint16(b[base:])
		if id == RegionNone {
			continue
		}
		for _, s := range seen[:nSeen] {
			if s == id {
				return malformed("duplicate region %d", id)
			}
		}
		seen[nSeen] = id
		nSeen++

		off := le.Uint32(b[base+4:])
		ln := le.Uint32(b[base+8:])
		if off > sigStart || ln > sigStart-off { // overflow-free bounds test
			return malformed("region %d [%d,+%d) leaves the signed area", id, off, ln)
		}
		if off < prevEnd {
			return malformed("region %d starts at %d, before the previous region ends at %d", id, off, prevEnd)
		}
		prevEnd = off + ln

		if id == RegionChunkHashes {
			chunkHashLen = ln
			foundChunkHashes = true
		}
	}
	if !foundChunkHashes {
		return malformed("missing chunk-hash region")
	}

	// Images: the chunk arithmetic must reproduce exactly, and payloads must sit
	// after the signed block without overlapping each other.
	nImg := int(b[offImageCount])
	if nImg < 1 || nImg > MaxImages {
		return malformed("image_count %d out of [1..%d]", nImg, MaxImages)
	}
	var hashAcc uint64
	payloadFloor := uint64(total)
	for i := 0; i < nImg; i++ {
		base := offImages + i*imageStride
		slot, comp, delta := b[base+imgTargetSlot], b[base+imgCompAlg], b[base+imgDeltaAlg]
		dataOff := le.Uint32(b[base+imgDataOff:])
		storedLen := le.Uint32(b[base+imgStoredLen:])
		installed := le.Uint32(b[base+imgInstalled:])
		chunkSize := le.Uint32(b[base+imgChunkSize:])
		numChunks := le.Uint32(b[base+imgNumChunks:])

		if slot > SlotStage1 || comp > CompLZ4 || delta > DeltaDETools {
			return malformed("image %d has an out-of-range slot/alg field", i)
		}
		if chunkSize == 0 || numChunks != ceilDivU32(installed, chunkSize) {
			return malformed("image %d chunk math: %d bytes / %d != %d chunks", i, installed, chunkSize, numChunks)
		}
		if uint64(dataOff) < payloadFloor {
			return malformed("image %d payload at %d overlaps the preceding data", i, dataOff)
		}
		payloadFloor = uint64(dataOff) + uint64(storedLen)

		hashAcc += uint64(numChunks) * DigestLen
	}
	if hashAcc != uint64(chunkHashLen) {
		return malformed("chunk-hash region is %d bytes, images need %d", chunkHashLen, hashAcc)
	}
	return nil
}
