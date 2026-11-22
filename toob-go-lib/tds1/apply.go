package tds1

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"slices"

	"github.com/Toob-Boot/Toob-Loader/toob-go-lib/heatshrink"
)

const maxInitialAllocCap = 64 << 10

var (
	ErrBaseSizeMismatch   = errors.New("tds1: base size mismatch")
	ErrBaseHashMismatch   = errors.New("tds1: base fingerprint mismatch")
	ErrStreamCorrupted    = errors.New("tds1: stream corrupted")
	ErrTargetSizeMismatch = errors.New("tds1: target size mismatch")
)

// Apply decodes a TDS1 delta stream against base to reconstruct the target.
// It verifies all cryptographic invariants and strictly enforces bounds,
// integer overflow protection, and zip-bomb defense on every instruction.
func Apply(base, delta []byte) ([]byte, error) {
	hdr, err := ParseHeader(delta)
	if err != nil {
		return nil, fmt.Errorf("parse header: %w", err)
	}

	if uint64(len(base)) != uint64(hdr.BaseSize) {
		return nil, fmt.Errorf("%w: expected %d, got %d", ErrBaseSizeMismatch, hdr.BaseSize, len(base))
	}

	h := sha256.Sum256(base)
	if !bytes.Equal(h[:8], hdr.BaseFingerprint[:]) {
		return nil, ErrBaseHashMismatch
	}

	if hdr.ExpectedTargetSize > MaxTargetSize {
		return nil, fmt.Errorf("%w: expected target size %d exceeds %d-byte limit",
			ErrStreamCorrupted, hdr.ExpectedTargetSize, MaxTargetSize)
	}
	if hdr.InstrCount == 0 || hdr.InstrCount > MaxInstructions {
		return nil, fmt.Errorf("%w: invalid instruction count %d", ErrStreamCorrupted, hdr.InstrCount)
	}

	// Overflow-safe computation of literal block offset
	expectedLitOffset := uint64(HeaderSize) + uint64(hdr.InstrCount)*uint64(InstrSize)
	if expectedLitOffset > math.MaxUint32 || expectedLitOffset != uint64(hdr.LiteralBlockOffset) {
		return nil, fmt.Errorf("%w: literal block offset mismatch %d != %d", ErrStreamCorrupted, hdr.LiteralBlockOffset, expectedLitOffset)
	}

	if uint64(len(delta)) < expectedLitOffset {
		return nil, fmt.Errorf("%w: delta too small for instructions", ErrStreamCorrupted)
	}

	initCap := int(hdr.ExpectedTargetSize)
	if initCap > maxInitialAllocCap {
		initCap = maxInitialAllocCap
	}
	target := make([]byte, 0, initCap)
	litOffset := hdr.LiteralBlockOffset
	eofReached := false

	for i := range hdr.InstrCount {
		instStart := HeaderSize + i*InstrSize
		inst, err := ParseInstruction(delta[instStart : instStart+InstrSize])
		if err != nil {
			return nil, fmt.Errorf("instruction %d: %w", i, err)
		}

		if inst.Opcode == OpEOF {
			if inst.Length != 0 || inst.Offset != 0 {
				return nil, fmt.Errorf("%w: non-zero fields on EOF instruction", ErrStreamCorrupted)
			}
			eofReached = true
			if i != hdr.InstrCount-1 {
				return nil, fmt.Errorf("%w: EOF before final instruction", ErrStreamCorrupted)
			}
			break
		}

		switch inst.Opcode {
		case OpCopyBase:
			// Overflow-safe bounds check against base buffer
			if uint64(inst.Offset)+uint64(inst.Length) > uint64(len(base)) {
				return nil, fmt.Errorf("%w: copy base out of bounds offset=%d len=%d base_size=%d",
					ErrStreamCorrupted, inst.Offset, inst.Length, len(base))
			}
			// Zip-bomb guard against target expansion
			if uint64(len(target))+uint64(inst.Length) > uint64(hdr.ExpectedTargetSize) {
				return nil, fmt.Errorf("%w: copy base exceeds target capacity", ErrStreamCorrupted)
			}
			target = append(target, base[inst.Offset:inst.Offset+inst.Length]...)

		case OpBzero:
			// Zip-bomb guard against target expansion
			if uint64(len(target))+uint64(inst.Length) > uint64(hdr.ExpectedTargetSize) {
				return nil, fmt.Errorf("%w: bzero exceeds target capacity", ErrStreamCorrupted)
			}
			nZero := int(inst.Length)
			oldLen := len(target)
			target = slices.Grow(target, nZero)
			target = target[:oldLen+nZero]
			clear(target[oldLen:])

		case OpInsertLit:
			// Overflow-safe bounds check against delta stream
			if uint64(litOffset)+uint64(inst.Length) > uint64(len(delta)) {
				return nil, fmt.Errorf("%w: literal stream truncated offset=%d len=%d total=%d",
					ErrStreamCorrupted, litOffset, inst.Length, len(delta))
			}
			if inst.Offset > 0 && uint64(len(target))+uint64(inst.Offset) > uint64(hdr.ExpectedTargetSize) {
				return nil, fmt.Errorf("%w: declared literal length exceeds target capacity", ErrStreamCorrupted)
			}
			comp := delta[litOffset : litOffset+inst.Length]
			decomp, err := heatshrink.Decompress(comp)
			if err != nil {
				return nil, fmt.Errorf("decompress literal chunk at %d: %w", litOffset, err)
			}
			// Pre-flight check if uncompressed length is explicitly declared
			if inst.Offset > 0 && uint64(len(decomp)) != uint64(inst.Offset) {
				return nil, fmt.Errorf("%w: decompressed literal length mismatch declared=%d actual=%d",
					ErrStreamCorrupted, inst.Offset, len(decomp))
			}
			// Zip-bomb guard against target expansion
			if uint64(len(target))+uint64(len(decomp)) > uint64(hdr.ExpectedTargetSize) {
				return nil, fmt.Errorf("%w: decompressed literal exceeds target capacity", ErrStreamCorrupted)
			}
			target = append(target, decomp...)
			litOffset += inst.Length

		default:
			return nil, fmt.Errorf("%w: unknown opcode 0x%08X", ErrStreamCorrupted, inst.Opcode)
		}
	}

	if !eofReached {
		return nil, fmt.Errorf("%w: stream ended without EOF opcode", ErrStreamCorrupted)
	}

	if uint64(litOffset) != uint64(len(delta)) {
		return nil, fmt.Errorf("%w: trailing unparsed bytes in delta stream", ErrStreamCorrupted)
	}

	if uint64(len(target)) != uint64(hdr.ExpectedTargetSize) {
		return nil, fmt.Errorf("%w: expected %d, got %d", ErrTargetSizeMismatch, hdr.ExpectedTargetSize, len(target))
	}

	return target, nil
}
