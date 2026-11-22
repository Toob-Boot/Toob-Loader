package heatshrink

import (
	"fmt"
	"math"
)

// Default embedded parameters for Toob-Boot (W=8, L=4: 256B window, 16B max match).
const (
	DefaultWindowBits    = 8
	DefaultLookaheadBits = 4
)

type bitWriter struct {
	buf         []byte
	currentByte byte
	bitIndex    byte
}

func (bw *bitWriter) pushBits(bits uint32, count uint8) {
	for i := int(count) - 1; i >= 0; i-- {
		if (bits & (1 << i)) != 0 {
			bw.currentByte |= bw.bitIndex
		}
		bw.bitIndex >>= 1
		if bw.bitIndex == 0 {
			bw.buf = append(bw.buf, bw.currentByte)
			bw.currentByte = 0
			bw.bitIndex = 0x80
		}
	}
}

func (bw *bitWriter) flush() {
	if bw.bitIndex != 0x80 {
		bw.buf = append(bw.buf, bw.currentByte)
		bw.currentByte = 0
		bw.bitIndex = 0x80
	}
}

type bitReader struct {
	src         []byte
	pos         int
	currentByte byte
	bitIndex    byte
}

func (br *bitReader) getBit() (uint8, bool) {
	if br.bitIndex == 0 {
		if br.pos >= len(br.src) {
			return 0, false
		}
		br.currentByte = br.src[br.pos]
		br.pos++
		br.bitIndex = 0x80
	}
	bit := uint8(0)
	if (br.currentByte & br.bitIndex) != 0 {
		bit = 1
	}
	br.bitIndex >>= 1
	return bit, true
}

func (br *bitReader) getBits(count uint8) (uint32, bool) {
	var val uint32
	for range count {
		b, ok := br.getBit()
		if !ok {
			return 0, false
		}
		val = (val << 1) | uint32(b)
	}
	return val, true
}

// Compress compresses data using standard Toob-Boot parameters (W=8, L=4).
func Compress(src []byte) ([]byte, error) {
	return Encode(src, DefaultWindowBits, DefaultLookaheadBits)
}

// Decompress decompresses data using standard Toob-Boot parameters (W=8, L=4).
func Decompress(src []byte) ([]byte, error) {
	return Decode(src, DefaultWindowBits, DefaultLookaheadBits)
}

// Encode compresses src using LZSS with specified window and lookahead sizes (in bits).
func Encode(src []byte, windowSz2, lookaheadSz2 uint8) ([]byte, error) {
	if windowSz2 < 4 || windowSz2 > 15 || lookaheadSz2 < 3 || lookaheadSz2 >= windowSz2 {
		return nil, fmt.Errorf("invalid heatshrink parameters: window=%d, lookahead=%d", windowSz2, lookaheadSz2)
	}
	windowSize := 1 << windowSz2
	maxLookahead := 1 << lookaheadSz2
	backrefBits := 1 + int(windowSz2) + int(lookaheadSz2)

	bw := &bitWriter{bitIndex: 0x80}
	pos := 0
	n := len(src)

	for pos < n {
		bestOffset := 0
		bestLen := 0

		winStart := pos - windowSize
		if winStart < 0 {
			winStart = 0
		}

		lookaheadLen := n - pos
		if lookaheadLen > maxLookahead {
			lookaheadLen = maxLookahead
		}

		for i := winStart; i < pos; i++ {
			matchLen := 0
			for matchLen < lookaheadLen && src[i+matchLen] == src[pos+matchLen] {
				matchLen++
			}
			if matchLen > bestLen {
				bestLen = matchLen
				bestOffset = pos - i
				if bestLen == lookaheadLen {
					break
				}
			}
		}

		if bestLen >= 2 && bestLen*9 > backrefBits {
			off := bestOffset - 1
			if off < 0 || off > math.MaxUint32 {
				return nil, fmt.Errorf("heatshrink backref offset %d out of range", bestOffset)
			}
			bw.pushBits(0, 1) // backreference tag 0
			bw.pushBits(uint32(off), windowSz2)
			bw.pushBits(uint32(bestLen-1), lookaheadSz2)
			pos += bestLen
		} else {
			bw.pushBits(1, 1) // literal tag 1
			bw.pushBits(uint32(src[pos]), 8)
			pos++
		}
	}

	bw.flush()
	return bw.buf, nil
}

// Decode decompresses src using LZSS with specified window and lookahead sizes (in bits).
func Decode(src []byte, windowSz2, lookaheadSz2 uint8) ([]byte, error) {
	if windowSz2 < 4 || windowSz2 > 15 || lookaheadSz2 < 3 || lookaheadSz2 >= windowSz2 {
		return nil, fmt.Errorf("invalid heatshrink parameters: window=%d, lookahead=%d", windowSz2, lookaheadSz2)
	}
	windowSize := 1 << windowSz2
	windowMask := windowSize - 1
	window := make([]byte, windowSize)
	headIndex := 0

	br := &bitReader{src: src}
	var out []byte

	for {
		tag, ok := br.getBit()
		if !ok {
			break
		}
		if tag == 1 {
			b, ok := br.getBits(8)
			if !ok {
				break
			}
			if b > math.MaxUint8 {
				return nil, fmt.Errorf("heatshrink literal byte %d out of range", b)
			}
			lit := byte(b)
			window[headIndex&windowMask] = lit
			headIndex++
			out = append(out, lit)
		} else {
			rawIdx, ok := br.getBits(windowSz2)
			if !ok {
				break // Trailing zero padding at end of input
			}
			rawCount, ok := br.getBits(lookaheadSz2)
			if !ok {
				break // Trailing zero padding at end of input
			}
			negOffset := int(rawIdx) + 1
			count := int(rawCount) + 1
			for range count {
				b := window[(headIndex-negOffset)&windowMask]
				window[headIndex&windowMask] = b
				headIndex++
				out = append(out, b)
			}
		}
	}
	return out, nil
}
