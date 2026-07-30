package gateway

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// CBOR Encoding Errors
var (
	ErrResponseTooLarge = errors.New("gateway: checkin response exceeds 512-byte client buffer cap")
	ErrInvalidDigestLen = errors.New("gateway: sha256 digest must be exactly 32 bytes")
	ErrBlobPathTooLong  = errors.New("gateway: blob_path exceeds 128-byte limit")
)

// CheckinResponse represents the parameters to encode into the toob_checkin_resp CBOR map.
type CheckinResponse struct {
	SVN          uint32
	TotalSize    uint32
	SHA256       []byte // Must be 32 bytes
	ImageType    *uint8 // Optional (TBM1 target_slot)
	BlobPath     string // Max 128 bytes
	AssignmentID []byte // 16 bytes UUID or binary ID
	RotatedToken []byte // Optional 32 bytes
	CloudCommand []byte // Optional
}

// EncodeCheckinResponse encodes a CheckinResponse into a canonical CBOR map.
//
// CDDL Schema:
//
//	toob_checkin_resp = {
//	    1: uint .size 4,      ; svn
//	    2: uint .size 4,      ; total_size == artifacts.size_bytes
//	    3: bstr .size 32,     ; sha256 des Blobs == artifacts.digest
//	  ? 4: uint .size 1,      ; image_type (TBM1 target_slot des Primär-Images)
//	    5: tstr .size 1..128, ; blob_path — Pfad+Query, KEIN Host (§4.4)
//	    6: bstr .size 16,     ; assignment_id
//	  ? 7: bstr .size 32,     ; rotated_device_token (Server-initiierte Rotation)
//	  ? 20: bstr              ; Cloud-Command-Envelope (Phase 3)
//	}
//
// Guarantees:
//   - Total encoded size <= 512 bytes (ErrResponseTooLarge returned if exceeded).
//   - Ascending key order (1, 2, 3, 4, 5, 6, 7, 20).
//   - Zero trailing bytes after the map.
func EncodeCheckinResponse(resp CheckinResponse) ([]byte, error) {
	if len(resp.SHA256) != 32 {
		return nil, ErrInvalidDigestLen
	}
	if len(resp.BlobPath) > 128 {
		return nil, ErrBlobPathTooLong
	}

	// Count number of key-value pairs
	numPairs := 5 // mandatory: 1, 2, 3, 5, 6
	if resp.ImageType != nil {
		numPairs++
	}
	if len(resp.RotatedToken) > 0 {
		numPairs++
	}
	if len(resp.CloudCommand) > 0 {
		numPairs++
	}

	buf := make([]byte, 0, 512)

	// 1. CBOR Map Header (0xa0 | numPairs)
	if numPairs < 24 {
		buf = append(buf, byte(0xa0|numPairs))
	} else {
		buf = append(buf, 0xb8, byte(numPairs))
	}

	// Helper to encode CBOR uint key + uint value
	appendUintPair := func(key uint32, val uint32) {
		buf = appendCBORUint(buf, uint64(key))
		buf = appendCBORUint(buf, uint64(val))
	}

	// Helper to encode CBOR uint key + bstr value
	appendBstrPair := func(key uint32, b []byte) {
		buf = appendCBORUint(buf, uint64(key))
		buf = appendCBORBstr(buf, b)
	}

	// Helper to encode CBOR uint key + tstr value
	appendTstrPair := func(key uint32, s string) {
		buf = appendCBORUint(buf, uint64(key))
		buf = appendCBORTstr(buf, s)
	}

	// Key 1: SVN (uint)
	appendUintPair(1, resp.SVN)

	// Key 2: TotalSize (uint)
	appendUintPair(2, resp.TotalSize)

	// Key 3: SHA256 (bstr 32 bytes)
	appendBstrPair(3, resp.SHA256)

	// Key 4: ImageType (optional uint)
	if resp.ImageType != nil {
		appendUintPair(4, uint32(*resp.ImageType))
	}

	// Key 5: BlobPath (tstr max 128 bytes)
	appendTstrPair(5, resp.BlobPath)

	// Key 6: AssignmentID (bstr)
	appendBstrPair(6, resp.AssignmentID)

	// Key 7: RotatedToken (optional bstr)
	if len(resp.RotatedToken) > 0 {
		appendBstrPair(7, resp.RotatedToken)
	}

	// Key 20: CloudCommand (optional bstr)
	if len(resp.CloudCommand) > 0 {
		appendBstrPair(20, resp.CloudCommand)
	}

	// Hard Safety Limit Check: Client buffer cap is 512 bytes!
	if len(buf) > 512 {
		return nil, fmt.Errorf("%w: encoded size %d bytes > 512 bytes", ErrResponseTooLarge, len(buf))
	}

	return buf, nil
}

// RFC 8949 CBOR Encoders

func appendCBORUint(buf []byte, val uint64) []byte {
	if val < 24 {
		return append(buf, byte(val))
	} else if val <= 0xff {
		return append(buf, 0x18, byte(val))
	} else if val <= 0xffff {
		b := make([]byte, 3)
		b[0] = 0x19
		binary.BigEndian.PutUint16(b[1:], uint16(val))
		return append(buf, b...)
	} else if val <= 0xffffffff {
		b := make([]byte, 5)
		b[0] = 0x1a
		binary.BigEndian.PutUint32(b[1:], uint32(val))
		return append(buf, b...)
	} else {
		b := make([]byte, 9)
		b[0] = 0x1b
		binary.BigEndian.PutUint64(b[1:], val)
		return append(buf, b...)
	}
}

func appendCBORBstr(buf []byte, data []byte) []byte {
	l := uint64(len(data))
	if l < 24 {
		buf = append(buf, byte(0x40|l))
	} else if l <= 0xff {
		buf = append(buf, 0x58, byte(l))
	} else if l <= 0xffff {
		b := make([]byte, 3)
		b[0] = 0x59
		binary.BigEndian.PutUint16(b[1:], uint16(l))
		buf = append(buf, b...)
	} else {
		b := make([]byte, 5)
		b[0] = 0x5a
		binary.BigEndian.PutUint32(b[1:], uint32(l))
		buf = append(buf, b...)
	}
	return append(buf, data...)
}

func appendCBORTstr(buf []byte, str string) []byte {
	l := uint64(len(str))
	if l < 24 {
		buf = append(buf, byte(0x60|l))
	} else if l <= 0xff {
		buf = append(buf, 0x78, byte(l))
	} else if l <= 0xffff {
		b := make([]byte, 3)
		b[0] = 0x79
		binary.BigEndian.PutUint16(b[1:], uint16(l))
		buf = append(buf, b...)
	} else {
		b := make([]byte, 5)
		b[0] = 0x7a
		binary.BigEndian.PutUint32(b[1:], uint32(l))
		buf = append(buf, b...)
	}
	return append(buf, []byte(str)...)
}
