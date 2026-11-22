package tci1

import (
	"encoding/binary"
	"math"
)

// AppendEncode validates, masks any rotated token, serializes m into canonical TCI1 wire format,
// and appends the 16-byte HMAC-SHA256-128 authentication tag to dst.
// Performs zero heap allocations when cap(dst)-len(dst) >= frameLen.
func AppendEncode(
	dst []byte,
	m Manifest,
	tokenKey [32]byte,
	deviceID [32]byte,
) ([]byte, error) {
	if isAllByte(tokenKey[:], 0x00) || isAllByte(tokenKey[:], 0xFF) {
		return nil, ErrInvalidTokenKey
	}
	if m.SeqEcho == 0 {
		return nil, ErrInvalidSeqEcho
	}
	if m.RetryAfterSec > MaxRetryAfterSec {
		return nil, ErrInvalidRetryAfter
	}

	hasCmd := len(m.CloudCommand) > 0
	if m.TotalSize > 0 {
		if m.TotalSize < MinTBM1TotalSize {
			return nil, ErrInvalidUpdateFields
		}
		if m.TargetSlot != SlotApp && m.TargetSlot != SlotNetcore && m.TargetSlot != SlotStage1 {
			return nil, ErrInvalidSlot
		}
		if isAllByte(m.SHA256[:], 0x00) || isAllByte(m.SHA256[:], 0xFF) {
			return nil, ErrInvalidDigest
		}
		if isAllByte(m.AssignmentID[:], 0x00) {
			return nil, ErrInvalidAssignmentID
		}
		if err := ValidateBlobPath(m.BlobPath); err != nil {
			return nil, err
		}
	} else {
		if !m.HasRotatedToken && !hasCmd {
			return nil, ErrEmptyControlManifest
		}
		if m.TargetSlot != 0 || m.SVN != 0 || m.RemoteBuild != 0 || len(m.BlobPath) != 0 ||
			!isAllByte(m.SHA256[:], 0x00) || !isAllByte(m.AssignmentID[:], 0x00) {
			return nil, ErrNonZeroControlFields
		}
	}

	var flags uint16
	rotLen := 0
	if m.HasRotatedToken {
		if isAllByte(m.RotatedToken[:], 0x00) || isAllByte(m.RotatedToken[:], 0xFF) {
			return nil, ErrInvalidRotatedToken
		}
		flags |= FlagHasRotatedToken
		rotLen = RotatedTokenLen
	}
	if hasCmd {
		if err := validateCloudCmd(m.CloudCommand); err != nil {
			return nil, err
		}
		flags |= FlagHasCloudCmd
	}

	bodyLen := HeaderSize + len(m.BlobPath) + rotLen + len(m.CloudCommand)
	frameLen := bodyLen + AuthTagLen
	if frameLen > MaxFrameSize {
		return nil, ErrFrameTooLarge
	}

	start := len(dst)
	if cap(dst)-start >= frameLen {
		dst = dst[:start+frameLen]
		clear(dst[start:])
	} else {
		grown := make([]byte, start+frameLen)
		copy(grown, dst)
		dst = grown
	}
	buf := dst[start:]

	blobPathLen := len(m.BlobPath)
	cmdLen := len(m.CloudCommand)
	if blobPathLen < 0 || blobPathLen > math.MaxUint16 || cmdLen < 0 || cmdLen > math.MaxUint16 {
		return nil, ErrFrameTooLarge
	}

	binary.LittleEndian.PutUint32(buf[0:4], Magic)
	buf[4] = Version
	buf[5] = uint8(m.TargetSlot)
	binary.LittleEndian.PutUint16(buf[6:8], flags)
	binary.LittleEndian.PutUint16(buf[8:10], uint16(HeaderSize))
	binary.LittleEndian.PutUint16(buf[10:12], uint16(blobPathLen))
	binary.LittleEndian.PutUint16(buf[12:14], uint16(cmdLen))
	binary.LittleEndian.PutUint16(buf[14:16], 0)
	binary.LittleEndian.PutUint32(buf[16:20], m.SVN)
	binary.LittleEndian.PutUint32(buf[20:24], m.TotalSize)
	copy(buf[24:56], m.SHA256[:])
	copy(buf[56:72], m.AssignmentID[:])
	binary.LittleEndian.PutUint64(buf[72:80], m.SeqEcho)
	binary.LittleEndian.PutUint32(buf[80:84], m.RemoteBuild)
	binary.LittleEndian.PutUint32(buf[84:88], m.RetryAfterSec)

	cursor := HeaderSize
	cursor += copy(buf[cursor:], m.BlobPath)
	if m.HasRotatedToken {
		mask := computeRotMask(tokenKey, deviceID, m.SeqEcho)
		for i := range RotatedTokenLen {
			buf[cursor+i] = m.RotatedToken[i] ^ mask[i]
		}
		clear(mask[:])
		cursor += RotatedTokenLen
	}
	copy(buf[cursor:], m.CloudCommand)

	tag := computeAuthTag(tokenKey, deviceID, buf[:bodyLen])
	copy(buf[bodyLen:], tag[:])

	return dst, nil
}

// Encode validates and serializes m into a newly allocated, HMAC-authenticated TCI1 wire frame.
func Encode(m Manifest, tokenKey, deviceID [32]byte) ([]byte, error) {
	capHint := HeaderSize + len(m.BlobPath) + len(m.CloudCommand) + AuthTagLen
	if m.HasRotatedToken {
		capHint += RotatedTokenLen
	}
	return AppendEncode(make([]byte, 0, capHint), m, tokenKey, deviceID)
}
