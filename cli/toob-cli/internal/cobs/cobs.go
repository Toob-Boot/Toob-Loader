package cobs

import (
	"bytes"
	"errors"
)

var (
	ErrEmptyFrame        = errors.New("cobs: empty encoded frame")
	ErrZeroByteInEncoded = errors.New("cobs: zero byte in encoded payload")
	ErrFrameOutOfBounds  = errors.New("cobs: frame length out of bounds")
)

// Encode performs Consistent Overhead Byte Stuffing (COBS) on src and appends
// a terminating 0x00 delimiter byte.
func Encode(src []byte) []byte {
	if len(src) == 0 {
		return []byte{0x01, 0x00}
	}
	maxLen := len(src) + (len(src) / 254) + 2
	dst := make([]byte, maxLen)
	codeIdx := 0
	writeIdx := 1
	var code byte = 1

	for idx, b := range src {
		if b == 0 {
			dst[codeIdx] = code
			codeIdx = writeIdx
			writeIdx++
			code = 1
		} else {
			dst[writeIdx] = b
			writeIdx++
			code++
			if code == 0xFF && idx+1 < len(src) {
				dst[codeIdx] = code
				codeIdx = writeIdx
				writeIdx++
				code = 1
			}
		}
	}
	dst[codeIdx] = code
	dst[writeIdx] = 0x00
	return dst[:writeIdx+1]
}

// Decode strips at most a single trailing 0x00 framing delimiter and decodes a
// COBS-encoded frame, failing fast on any remaining interior 0x00 byte.
func Decode(src []byte) ([]byte, error) {
	if len(src) > 0 && src[len(src)-1] == 0x00 {
		src = src[:len(src)-1]
	}
	if len(src) == 0 {
		return nil, ErrEmptyFrame
	}
	if bytes.IndexByte(src, 0x00) >= 0 {
		return nil, ErrZeroByteInEncoded
	}
	dst := make([]byte, 0, len(src))
	i := 0
	for i < len(src) {
		code := int(src[i])
		i++
		end := i + code - 1
		if end > len(src) {
			return nil, ErrFrameOutOfBounds
		}
		dst = append(dst, src[i:end]...)
		i = end
		if code < 0xFF && i < len(src) {
			dst = append(dst, 0x00)
		}
	}
	return dst, nil
}
