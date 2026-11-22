// Package tci1 implements the canonical authenticated binary wire format for
// Toob Check-In Manifests v1 (TCI1, Cloud -> MCU check-in response body).
//
// Wire layout mirrors common/include/toob_checkin_wire.h byte-for-byte:
//   - [0 .. header_size)               : 88-byte little-endian header (8B aligned)
//   - [header_size .. +blob_path_len)  : RFC-3986 relative path (0 if control-only)
//   - [.. +32)                         : XOR-masked rotated_token (FlagHasRotatedToken)
//   - [.. +cloud_cmd_len)              : Signed TCC1 envelope (FlagHasCloudCmd)
//   - [total_len - 16 .. total_len)    : Trunc_128(HMAC-SHA256(K, "TCI1-AUTH-V1" || device_id || body))
package tci1

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"unsafe"
)

// Wire framing constants matching common/include/toob_checkin_wire.h.
const (
	Magic            uint32 = 0x31494354 // "TCI1" in little-endian
	Version          uint8  = 1
	HeaderSize       int    = 88
	AuthTagLen       int    = 16
	MinFrameSize     int    = HeaderSize + AuthTagLen // 104 bytes
	RotatedTokenLen  int    = 32
	AssignmentIDLen  int    = 16
	DeviceIDLen      int    = 32
	TokenKeyLen      int    = 32
	MaxBlobPathLen   int    = 120
	MinCloudCmdLen   int    = 128
	MaxCloudCmdLen   int    = 400
	CloudCmdAlign    int    = 16
	CloudCmdMagic    uint32 = 0x31434354 // "TCC1" in little-endian
	MaxFrameSize     int    = 512
	MinTBM1TotalSize uint32 = 576
	MaxRetryAfterSec uint32 = 604800 // 7 days

	FlagHasRotatedToken uint16 = 1 << 0
	FlagHasCloudCmd     uint16 = 1 << 1
	knownFlagsMask      uint16 = FlagHasRotatedToken | FlagHasCloudCmd

	AuthDomain = "TCI1-AUTH-V1"
	RotDomain  = "TCI1-ROT-V1"
)

// Slot identifies the target execution slot matching TBM1 target_slot values.
type Slot uint8

const (
	SlotApp     Slot = 0
	SlotNetcore Slot = 1
	SlotStage1  Slot = 3
)

// Sentinel errors returned by Parse, ParseView, Encode, and AppendEncode.
var (
	ErrTruncated            = errors.New("tci1: buffer shorter than minimum 104-byte frame")
	ErrFrameTooLarge        = errors.New("tci1: frame exceeds 512-byte maximum")
	ErrBadMagic             = errors.New("tci1: invalid magic (expected 'TCI1' 0x31494354)")
	ErrUnsupportedVersion   = errors.New("tci1: unsupported wire version")
	ErrUnknownFlags         = errors.New("tci1: unknown flags bit set")
	ErrInvalidHeaderSize    = errors.New("tci1: invalid header_size (must be >= 88 and 8-byte aligned)")
	ErrNonZeroReserved      = errors.New("tci1: non-zero reserved header field")
	ErrLengthMismatch       = errors.New("tci1: payload length does not match header + sections + 16B tag")
	ErrAuthFailed           = errors.New("tci1: HMAC-SHA256-128 authentication tag mismatch")
	ErrInvalidSeqEcho       = errors.New("tci1: seq_echo must be >= 1")
	ErrSeqEchoMismatch      = errors.New("tci1: seq_echo does not match request X-Toob-Seq")
	ErrInvalidRetryAfter    = errors.New("tci1: retry_after_sec exceeds 604800s upper bound")
	ErrInvalidTokenKey      = errors.New("tci1: degenerate all-0x00 or all-0xFF token key")
	ErrInvalidSlot          = errors.New("tci1: invalid target_slot (expected 0=App, 1=Netcore, or 3=Stage1)")
	ErrInvalidUpdateFields  = errors.New("tci1: update manifest requires total_size >= 576")
	ErrInvalidDigest        = errors.New("tci1: update sha256 cannot be all-0x00 or all-0xFF")
	ErrInvalidAssignmentID  = errors.New("tci1: update assignment_id cannot be all-0x00")
	ErrEmptyControlManifest = errors.New("tci1: control-only manifest must carry rotated_token or cloud_cmd")
	ErrNonZeroControlFields = errors.New("tci1: control-only manifest has non-zero update fields")
	ErrInvalidBlobPath      = errors.New("tci1: blob_path violates RFC-3986 relative path whitelist")
	ErrInvalidRotatedToken  = errors.New("tci1: rotated_token cannot be all-0x00 or all-0xFF")
	ErrInvalidCloudCmd      = errors.New("tci1: cloud_cmd must be a valid 16B-aligned TCC1 envelope (128..400 B)")
	ErrNilDestination       = errors.New("tci1: nil destination manifest pointer")
)

// Manifest represents a decoded or outgoing TCI1 check-in response.
type Manifest struct {
	TargetSlot      Slot
	SVN             uint32
	RemoteBuild     uint32
	TotalSize       uint32
	SHA256          [32]byte
	AssignmentID    [16]byte
	SeqEcho         uint64
	RetryAfterSec   uint32
	BlobPath        string
	HasRotatedToken bool
	RotatedToken    [32]byte
	CloudCommand    []byte
}

func isAllByte(b []byte, v byte) bool {
	var diff byte
	for i := range b {
		diff |= b[i] ^ v
	}
	return diff == 0
}

func isUnreservedASCII(c byte) bool {
	return (c >= 'A' && c <= 'Z') ||
		(c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9') ||
		c == '-' || c == '.' || c == '_' || c == '~'
}

// ValidateBlobPath enforces a closed O(n) RFC-3986 relative-path DFA:
//   - Length in [2, 120], leading '/'
//   - Non-empty path segments composed strictly of RFC-3986 unreserved chars [A-Za-z0-9-._~]
//   - Rejects '//', trailing '/', '.' segments, '..' segments, '%', '\', ':', '@', '#', whitespace, CRLF
//   - Optional '?query' suffix composed strictly of [A-Za-z0-9-._~&=] (non-empty)
func ValidateBlobPath(p string) error {
	n := len(p)
	if n < 2 || n > MaxBlobPathLen {
		return fmt.Errorf("%w: length %d out of [2, %d]", ErrInvalidBlobPath, n, MaxBlobPathLen)
	}
	if p[0] != '/' {
		return fmt.Errorf("%w: must start with '/'", ErrInvalidBlobPath)
	}

	inQuery := false
	segLen := 0
	dotCount := 0 // 0..2 while segment consists solely of '.'; 255 otherwise
	qLen := 0

	for i := 1; i < n; i++ {
		c := p[i]
		if !inQuery {
			if c == '?' {
				if segLen == 0 || dotCount == 1 || dotCount == 2 {
					return fmt.Errorf("%w: invalid segment before '?'", ErrInvalidBlobPath)
				}
				inQuery = true
				continue
			}
			if c == '/' {
				if segLen == 0 || dotCount == 1 || dotCount == 2 {
					return fmt.Errorf("%w: empty or dot-traversal path segment", ErrInvalidBlobPath)
				}
				segLen = 0
				dotCount = 0
				continue
			}
			if !isUnreservedASCII(c) {
				return fmt.Errorf("%w: disallowed path byte 0x%02X", ErrInvalidBlobPath, c)
			}
			segLen++
			if c == '.' && dotCount < 3 {
				dotCount++
			} else {
				dotCount = 255
			}
		} else {
			if !isUnreservedASCII(c) && c != '&' && c != '=' {
				return fmt.Errorf("%w: disallowed query byte 0x%02X", ErrInvalidBlobPath, c)
			}
			qLen++
		}
	}

	if !inQuery {
		if segLen == 0 || dotCount == 1 || dotCount == 2 {
			return fmt.Errorf("%w: trailing '/' or dot-traversal segment", ErrInvalidBlobPath)
		}
	} else if qLen == 0 {
		return fmt.Errorf("%w: empty query after '?'", ErrInvalidBlobPath)
	}
	return nil
}

func validateCloudCmd(cmd []byte) error {
	n := len(cmd)
	if n < MinCloudCmdLen || n > MaxCloudCmdLen || (n%CloudCmdAlign) != 0 {
		return fmt.Errorf("%w: length %d", ErrInvalidCloudCmd, n)
	}
	if binary.LittleEndian.Uint32(cmd[0:4]) != CloudCmdMagic || cmd[4] != 1 {
		return fmt.Errorf("%w: missing TCC1 v1 header", ErrInvalidCloudCmd)
	}
	if totalLen := binary.LittleEndian.Uint32(cmd[20:24]); totalLen != uint32(n) {
		return fmt.Errorf("%w: TCC1 total_len %d != %d", ErrInvalidCloudCmd, totalLen, n)
	}
	return nil
}

// computeAuthTag computes Trunc_128(HMAC-SHA256(key, "TCI1-AUTH-V1" || deviceID || body))
// entirely on the stack (0 heap allocations). Requires len(body) <= MaxFrameSize - AuthTagLen (496 B).
func computeAuthTag(key, deviceID [32]byte, body []byte) [AuthTagLen]byte {
	var innerBuf [64 + len(AuthDomain) + DeviceIDLen + (MaxFrameSize - AuthTagLen)]byte
	var outerBuf [64 + 32]byte

	for i := range 32 {
		innerBuf[i] = key[i] ^ 0x36
		outerBuf[i] = key[i] ^ 0x5c
	}
	for i := 32; i < 64; i++ {
		innerBuf[i] = 0x36
		outerBuf[i] = 0x5c
	}

	off := 64
	off += copy(innerBuf[off:], AuthDomain)
	off += copy(innerBuf[off:], deviceID[:])
	off += copy(innerBuf[off:], body)

	innerSum := sha256.Sum256(innerBuf[:off])
	copy(outerBuf[64:], innerSum[:])
	fullMAC := sha256.Sum256(outerBuf[:])

	var tag [AuthTagLen]byte
	copy(tag[:], fullMAC[:AuthTagLen])
	clear(innerBuf[:off])
	clear(outerBuf[:])
	return tag
}

// computeRotMask computes HMAC-SHA256(key, "TCI1-ROT-V1" || deviceID || le64(seqEcho))
// entirely on the stack (0 heap allocations).
func computeRotMask(key, deviceID [32]byte, seqEcho uint64) [RotatedTokenLen]byte {
	var innerBuf [64 + len(RotDomain) + DeviceIDLen + 8]byte
	var outerBuf [64 + 32]byte

	for i := range 32 {
		innerBuf[i] = key[i] ^ 0x36
		outerBuf[i] = key[i] ^ 0x5c
	}
	for i := 32; i < 64; i++ {
		innerBuf[i] = 0x36
		outerBuf[i] = 0x5c
	}

	off := 64
	off += copy(innerBuf[off:], RotDomain)
	off += copy(innerBuf[off:], deviceID[:])
	binary.LittleEndian.PutUint64(innerBuf[off:off+8], seqEcho)
	off += 8

	innerSum := sha256.Sum256(innerBuf[:off])
	copy(outerBuf[64:], innerSum[:])
	mask := sha256.Sum256(outerBuf[:])

	clear(innerBuf[:])
	clear(outerBuf[:])
	return mask
}

// ParseView authenticates and decodes a TCI1 wire frame into dst with zero heap allocations.
// Note: dst.BlobPath and dst.CloudCommand alias data; do not mutate data while dst is live.
func ParseView(
	data []byte,
	tokenKey [32]byte,
	deviceID [32]byte,
	expectedSeq uint64,
	dst *Manifest,
) error {
	if dst == nil {
		return ErrNilDestination
	}
	if isAllByte(tokenKey[:], 0x00) || isAllByte(tokenKey[:], 0xFF) {
		return ErrInvalidTokenKey
	}
	if expectedSeq == 0 {
		return ErrInvalidSeqEcho
	}
	if len(data) < MinFrameSize {
		return fmt.Errorf("%w: got %d bytes", ErrTruncated, len(data))
	}
	if len(data) > MaxFrameSize {
		return fmt.Errorf("%w: got %d bytes", ErrFrameTooLarge, len(data))
	}

	// Authenticate MAC BEFORE trusting any structural offsets or unmasking rotated_token (EtM).
	bodyLen := len(data) - AuthTagLen
	wantTag := computeAuthTag(tokenKey, deviceID, data[:bodyLen])
	if subtle.ConstantTimeCompare(wantTag[:], data[bodyLen:]) != 1 {
		return ErrAuthFailed
	}

	magic := binary.LittleEndian.Uint32(data[0:4])
	if magic != Magic {
		return fmt.Errorf("%w: got 0x%08X", ErrBadMagic, magic)
	}
	if ver := data[4]; ver != Version {
		return fmt.Errorf("%w: got %d", ErrUnsupportedVersion, ver)
	}

	slot := Slot(data[5])
	flags := binary.LittleEndian.Uint16(data[6:8])
	if (flags &^ knownFlagsMask) != 0 {
		return fmt.Errorf("%w: 0x%04X", ErrUnknownFlags, flags)
	}

	hdrSize := int(binary.LittleEndian.Uint16(data[8:10]))
	if hdrSize < HeaderSize || (hdrSize%8) != 0 || hdrSize > bodyLen {
		return fmt.Errorf("%w: %d", ErrInvalidHeaderSize, hdrSize)
	}

	pathLen := int(binary.LittleEndian.Uint16(data[10:12]))
	cmdLen := int(binary.LittleEndian.Uint16(data[12:14]))
	if reserved := binary.LittleEndian.Uint16(data[14:16]); reserved != 0 {
		return fmt.Errorf("%w: 0x%04X", ErrNonZeroReserved, reserved)
	}

	hasRot := (flags & FlagHasRotatedToken) != 0
	hasCmd := (flags & FlagHasCloudCmd) != 0
	if !hasCmd && cmdLen != 0 {
		return fmt.Errorf("%w: cloud_cmd_len=%d without FlagHasCloudCmd", ErrInvalidCloudCmd, cmdLen)
	}

	rotLen := 0
	if hasRot {
		rotLen = RotatedTokenLen
	}
	if hdrSize+pathLen+rotLen+cmdLen != bodyLen {
		return fmt.Errorf("%w: body=%d, sections=%d", ErrLengthMismatch, bodyLen, hdrSize+pathLen+rotLen+cmdLen)
	}

	remoteSVN := binary.LittleEndian.Uint32(data[16:20])
	totalSize := binary.LittleEndian.Uint32(data[20:24])
	seqEcho := binary.LittleEndian.Uint64(data[72:80])
	remoteBuild := binary.LittleEndian.Uint32(data[80:84])
	retryAfter := binary.LittleEndian.Uint32(data[84:88])

	if seqEcho != expectedSeq {
		return fmt.Errorf("%w: got %d, want %d", ErrSeqEchoMismatch, seqEcho, expectedSeq)
	}
	if retryAfter > MaxRetryAfterSec {
		return fmt.Errorf("%w: %d", ErrInvalidRetryAfter, retryAfter)
	}

	var sha [32]byte
	var asgnID [16]byte
	copy(sha[:], data[24:56])
	copy(asgnID[:], data[56:72])

	cursor := hdrSize
	var pathView string
	if pathLen > 0 {
		pathBytes := data[cursor : cursor+pathLen]
		pathView = unsafe.String(unsafe.SliceData(pathBytes), pathLen)
		cursor += pathLen
	}

	if totalSize > 0 {
		if totalSize < MinTBM1TotalSize {
			return fmt.Errorf("%w: total_size=%d", ErrInvalidUpdateFields, totalSize)
		}
		if slot != SlotApp && slot != SlotNetcore && slot != SlotStage1 {
			return fmt.Errorf("%w: got %d", ErrInvalidSlot, slot)
		}
		if isAllByte(sha[:], 0x00) || isAllByte(sha[:], 0xFF) {
			return ErrInvalidDigest
		}
		if isAllByte(asgnID[:], 0x00) {
			return ErrInvalidAssignmentID
		}
		if err := ValidateBlobPath(pathView); err != nil {
			return err
		}
	} else {
		if !hasRot && !hasCmd {
			return ErrEmptyControlManifest
		}
		if slot != 0 || remoteSVN != 0 || remoteBuild != 0 || pathLen != 0 ||
			!isAllByte(sha[:], 0x00) || !isAllByte(asgnID[:], 0x00) {
			return ErrNonZeroControlFields
		}
	}

	var unmaskedTok [RotatedTokenLen]byte
	if hasRot {
		mask := computeRotMask(tokenKey, deviceID, seqEcho)
		for i := range RotatedTokenLen {
			unmaskedTok[i] = data[cursor+i] ^ mask[i]
		}
		clear(mask[:])
		cursor += RotatedTokenLen
		if isAllByte(unmaskedTok[:], 0x00) || isAllByte(unmaskedTok[:], 0xFF) {
			clear(unmaskedTok[:])
			return ErrInvalidRotatedToken
		}
	}

	var cmdView []byte
	if hasCmd {
		cmdView = data[cursor : cursor+cmdLen]
		if err := validateCloudCmd(cmdView); err != nil {
			clear(unmaskedTok[:])
			return err
		}
	}

	*dst = Manifest{
		TargetSlot:      slot,
		SVN:             remoteSVN,
		RemoteBuild:     remoteBuild,
		TotalSize:       totalSize,
		SHA256:          sha,
		AssignmentID:    asgnID,
		SeqEcho:         seqEcho,
		RetryAfterSec:   retryAfter,
		BlobPath:        pathView,
		HasRotatedToken: hasRot,
		RotatedToken:    unmaskedTok,
		CloudCommand:    cmdView,
	}
	return nil
}

// Parse authenticates and decodes a TCI1 wire frame, returning an owning Manifest copy.
func Parse(
	data []byte,
	tokenKey [32]byte,
	deviceID [32]byte,
	expectedSeq uint64,
) (Manifest, error) {
	var m Manifest
	if err := ParseView(data, tokenKey, deviceID, expectedSeq, &m); err != nil {
		return Manifest{}, err
	}
	if len(m.BlobPath) > 0 {
		m.BlobPath = string([]byte(m.BlobPath))
	}
	if len(m.CloudCommand) > 0 {
		m.CloudCommand = append([]byte(nil), m.CloudCommand...)
	}
	return m, nil
}
