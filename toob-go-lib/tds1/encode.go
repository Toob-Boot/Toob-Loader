package tds1

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/bits"

	"github.com/Toob-Boot/Toob-Loader/toob-go-lib/heatshrink"
)

// Algorithmic thresholds for optimal code reuse and compression
const (
	minZeroLenStandalone = 16        // Minimum zero run length when litAccum is empty (16-byte wire break-even)
	minZeroLenPendingLit = 48        // Minimum zero run when literals are pending (avoids splitting litAccum into dual instructions)
	lazyMatchMargin      = 4         // Minimum net gain advantage required to defer a match via lookahead
	maxCandidatesPerKey  = 64        // Maximum hash chain traversal depth to guarantee O(N) worst-case speed
	maxLiteralAccum      = 32 * 1024 // Bounded chunk size for literal blocks to preserve streaming locality
	instrWireCost        = 16        // Wire overhead of a new Instruction header in bytes
)

// matchCandidate holds the dimensions of a localized match spanning both backward
// absorption from the pending literal accumulator and forward extension into the target.
type matchCandidate struct {
	totalLen int // Total match length (back + fwd)
	basePos  int // Starting offset in base firmware (bPos - back)
	back     int // Number of bytes absorbed backward from pending litAccum
	fwd      int // Number of bytes matched forward from target[pos]
	netGain  int // Net bytes saved on wire: totalLen - wireCost (0 if coalesced, 16 if disjoint)
}

// deltaEncoder encapsulates the state of the TDS1 diff generation engine.
type deltaEncoder struct {
	base         []byte
	target       []byte
	baseIndex    map[uint32][]int
	instructions []Instruction
	literalBlock []byte
	litAccum     []byte
}

// newDeltaEncoder initializes the encoder and builds the fine-grained prefix index.
func newDeltaEncoder(base, target []byte) *deltaEncoder {
	baseLen := len(base)

	// Determine indexing step based on base size.
	// Step 1: Guarantees 100% phase-shift invariance on firmware <= 2 MB.
	// Step 2: Preserves 16-bit instruction-alignment (Thumb / RISC-V-C) on medium images (<= 8 MB).
	// Step 4: Preserves 32-bit word-alignment (ARM32 / AArch64 / RISC-V) on large images.
	indexStep := 1
	if baseLen > 8*1024*1024 {
		indexStep = 4
	} else if baseLen > 2*1024*1024 {
		indexStep = 2
	}

	hint := baseLen / (indexStep * 2)
	if hint < 256 {
		hint = 256
	}
	baseIndex := make(map[uint32][]int, hint)

	if baseLen >= 4 {
		for i := 0; i <= baseLen-4; i += indexStep {
			k := binary.LittleEndian.Uint32(base[i : i+4])
			if len(baseIndex[k]) < maxCandidatesPerKey {
				baseIndex[k] = append(baseIndex[k], i)
			}
		}
	}

	return &deltaEncoder{
		base:      base,
		target:    target,
		baseIndex: baseIndex,
	}
}

// emit appends an instruction with contiguous peephole coalescing and uint32 overflow protection.
func (e *deltaEncoder) emit(inst Instruction) {
	if len(e.instructions) > 0 {
		last := &e.instructions[len(e.instructions)-1]

		// Merge contiguous COPY_BASE instructions if within uint32 bounds
		if last.Opcode == OpCopyBase && inst.Opcode == OpCopyBase {
			if last.Offset+last.Length == inst.Offset {
				if uint64(last.Length)+uint64(inst.Length) <= math.MaxUint32 {
					last.Length += inst.Length
					return
				}
			}
		}

		// Merge contiguous BZERO instructions if within uint32 bounds
		if last.Opcode == OpBzero && inst.Opcode == OpBzero {
			if uint64(last.Length)+uint64(inst.Length) <= math.MaxUint32 {
				last.Length += inst.Length
				return
			}
		}
	}
	e.instructions = append(e.instructions, inst)
}

// flushLiterals compresses pending literals with Heatshrink LZSS and emits OpInsertLit.
// The uncompressed byte count is preserved in Instruction.Offset for instant resume fast-forward.
func (e *deltaEncoder) flushLiterals() error {
	if len(e.litAccum) == 0 {
		return nil
	}
	uncompressedLen := len(e.litAccum)
	comp, err := heatshrink.Compress(e.litAccum)
	if err != nil {
		return fmt.Errorf("compress literals failed: %w", err)
	}
	compLen := len(comp)
	if uncompressedLen < 0 || uncompressedLen > math.MaxUint32 || compLen < 0 || compLen > math.MaxUint32 {
		return fmt.Errorf("tds1: literal block size (%d -> %d) exceeds uint32", uncompressedLen, compLen)
	}
	e.emit(Instruction{
		Opcode: OpInsertLit,
		Length: uint32(compLen),
		Offset: uint32(uncompressedLen),
	})
	e.literalBlock = append(e.literalBlock, comp...)
	e.litAccum = nil
	return nil
}

// scanZeros detects contiguous runs of 0x00 using 64-bit parallel word comparisons.
func (e *deltaEncoder) scanZeros(pos int) int {
	targetLen := len(e.target)
	count := 0
	for pos+count+8 <= targetLen && binary.LittleEndian.Uint64(e.target[pos+count:pos+count+8]) == 0 {
		count += 8
	}
	for pos+count < targetLen && e.target[pos+count] == 0 {
		count++
	}
	return count
}

// canCoalesce reports whether a candidate match would seamlessly coalesce with the last instruction.
func (e *deltaEncoder) canCoalesce(candidateBasePos, back int) bool {
	if len(e.instructions) == 0 {
		return false
	}
	last := e.instructions[len(e.instructions)-1]
	if last.Opcode != OpCopyBase {
		return false
	}
	// If backward extension absorbs the entire literal accumulator, no intervening literal block is emitted
	if back == len(e.litAccum) && candidateBasePos >= 0 && uint64(candidateBasePos) == uint64(last.Offset)+uint64(last.Length) {
		return true
	}
	return false
}

// findBestMatch locates the candidate match yielding the maximum net wire size reduction.
// It evaluates both backward absorption into litAccum and 64-bit accelerated forward extension.
func (e *deltaEncoder) findBestMatch(pos int) matchCandidate {
	targetLen := len(e.target)
	baseLen := len(e.base)

	if pos+4 > targetLen || len(e.baseIndex) == 0 {
		return matchCandidate{}
	}

	k := binary.LittleEndian.Uint32(e.target[pos : pos+4])
	candidates, ok := e.baseIndex[k]
	if !ok {
		return matchCandidate{}
	}

	var best matchCandidate

	for _, bPos := range candidates {
		if bPos+4 > baseLen {
			continue
		}

		// 1. Backward extension into pending litAccum
		back := 0
		for back < len(e.litAccum) && bPos-back-1 >= 0 && pos-back-1 >= 0 {
			if e.target[pos-back-1] != e.base[bPos-back-1] {
				break
			}
			back++
		}

		// 2. Forward extension starting from pos+4
		fwd := 4
		maxFwd := targetLen - pos
		if baseLen-bPos < maxFwd {
			maxFwd = baseLen - bPos
		}

		// Accelerated 64-bit word comparison
		for pos+fwd+8 <= targetLen && bPos+fwd+8 <= baseLen {
			w1 := binary.LittleEndian.Uint64(e.target[pos+fwd : pos+fwd+8])
			w2 := binary.LittleEndian.Uint64(e.base[bPos+fwd : bPos+fwd+8])
			if w1 != w2 {
				diff := w1 ^ w2
				fwd += bits.TrailingZeros64(diff) / 8
				break
			}
			fwd += 8
		}

		// Byte-by-byte tail comparison
		for fwd < maxFwd && e.target[pos+fwd] == e.base[bPos+fwd] {
			fwd++
		}

		totLen := back + fwd
		candidateBase := bPos - back

		// 3. Compute net gain: coalesced matches cost 0 bytes overhead; disjoint matches cost 16 bytes
		wireCost := instrWireCost
		if e.canCoalesce(candidateBase, back) {
			wireCost = 0
		}
		gain := totLen - wireCost

		if gain > 0 && gain > best.netGain {
			best.totalLen = totLen
			best.basePos = candidateBase
			best.back = back
			best.fwd = fwd
			best.netGain = gain

			if totLen >= 1024 {
				break // Early-exit heuristic for large contiguous blocks
			}
		}
	}

	return best
}

// GenerateDelta creates a mathematically optimized TDS1 delta stream from base to target.
// It employs fine-grained prefix indexing, unified backward/forward match absorption,
// simulated lookahead lazy matching, 64-bit accelerated scanning, zero-run folding,
// and peephole instruction coalescing to minimize total wire size while maintaining O(N) speed.
func GenerateDelta(base, target []byte) ([]byte, error) {
	if uint64(len(base)) > math.MaxUint32 {
		return nil, fmt.Errorf("tds1: base length %d exceeds uint32 limit", len(base))
	}
	if uint64(len(target)) > MaxTargetSize {
		return nil, fmt.Errorf("tds1: target length %d exceeds %d-byte limit", len(target), MaxTargetSize)
	}

	var baseFingerprint [8]byte
	h := sha256.Sum256(base)
	copy(baseFingerprint[:], h[:8])

	targetLen := len(target)
	baseLen := len(base)

	e := newDeltaEncoder(base, target)

	tPos := 0
	for tPos < targetLen {
		// 1. Direct Contiguous Extension:
		// If last instruction is OpCopyBase and litAccum is empty, check if target directly
		// continues base from last.Offset + last.Length. This saves all hash lookups for sequential runs.
		if len(e.instructions) > 0 && len(e.litAccum) == 0 {
			last := &e.instructions[len(e.instructions)-1]
			if last.Opcode == OpCopyBase {
				expectedBase64 := uint64(last.Offset) + uint64(last.Length)
				if expectedBase64 < uint64(baseLen) && expectedBase64 <= math.MaxInt {
					expectedBase := int(expectedBase64)
					if e.target[tPos] == e.base[expectedBase] {
						cLen := 0
						maxContig := targetLen - tPos
						if baseLen-expectedBase < maxContig {
							maxContig = baseLen - expectedBase
						}
						for tPos+cLen+8 <= targetLen && expectedBase+cLen+8 <= baseLen {
							w1 := binary.LittleEndian.Uint64(e.target[tPos+cLen:])
							w2 := binary.LittleEndian.Uint64(e.base[expectedBase+cLen:])
							if w1 != w2 {
								cLen += bits.TrailingZeros64(w1^w2) / 8
								break
							}
							cLen += 8
						}
						for cLen < maxContig && e.target[tPos+cLen] == e.base[expectedBase+cLen] {
							cLen++
						}
						if cLen > 0 {
							last.Length += uint32(cLen)
							tPos += cLen
							continue
						}
					}
				}
			}
		}

		// 2. Check for run of zeros (BSS / unallocated space) using 64-bit acceleration
		minZeros := minZeroLenStandalone
		if len(e.litAccum) > 0 {
			minZeros = minZeroLenPendingLit
		}
		zeroCount := e.scanZeros(tPos)
		if zeroCount >= minZeros {
			if err := e.flushLiterals(); err != nil {
				return nil, err
			}
			if zeroCount < 0 || zeroCount > math.MaxUint32 {
				return nil, fmt.Errorf("tds1: zero run %d exceeds uint32", zeroCount)
			}
			e.emit(Instruction{
				Opcode: OpBzero,
				Length: uint32(zeroCount),
				Offset: 0,
			})
			tPos += zeroCount
			continue
		}

		// 3. Find best base match at current position evaluating net wire gain
		m := e.findBestMatch(tPos)

		if m.netGain > 0 {
			// Lazy Matching: Evaluate if tPos+1 yields a significantly superior net wire gain
			if tPos+1 < targetLen && m.totalLen < 1024 {
				// Simulate deferring target[tPos] into litAccum for lookahead evaluation
				e.litAccum = append(e.litAccum, e.target[tPos])
				nextM := e.findBestMatch(tPos + 1)
				if nextM.netGain > m.netGain+lazyMatchMargin {
					// Superior match confirmed: keep target[tPos] in litAccum and advance
					tPos++
					continue
				}
				// Revert simulated deferral
				e.litAccum = e.litAccum[:len(e.litAccum)-1]
			}

			// Absorb matched backward bytes from pending litAccum
			if m.back > 0 {
				e.litAccum = e.litAccum[:len(e.litAccum)-m.back]
			}

			// Flush any remaining literals before emitting the match
			if err := e.flushLiterals(); err != nil {
				return nil, err
			}

			if m.totalLen < 0 || m.totalLen > math.MaxUint32 || m.basePos < 0 || m.basePos > math.MaxUint32 {
				return nil, fmt.Errorf("tds1: match (%d, %d) exceeds uint32", m.totalLen, m.basePos)
			}
			e.emit(Instruction{
				Opcode: OpCopyBase,
				Length: uint32(m.totalLen),
				Offset: uint32(m.basePos),
			})

			tPos += m.fwd
			continue
		}

		// 4. Fallback: accumulate literal byte
		e.litAccum = append(e.litAccum, e.target[tPos])
		tPos++

		// Flush literals if maximum chunk size reached
		if len(e.litAccum) >= maxLiteralAccum {
			if err := e.flushLiterals(); err != nil {
				return nil, err
			}
		}
	}

	// Flush any trailing literals
	if err := e.flushLiterals(); err != nil {
		return nil, err
	}

	// Terminate instruction sequence with OpEOF
	e.emit(Instruction{
		Opcode: OpEOF,
		Length: 0,
		Offset: 0,
	})
	if len(e.instructions) > MaxInstructions {
		return nil, fmt.Errorf("tds1: instruction count %d exceeds %d limit", len(e.instructions), MaxInstructions)
	}

	litOff64 := uint64(HeaderSize) + uint64(len(e.instructions))*uint64(InstrSize)
	totalSize64 := litOff64 + uint64(len(e.literalBlock))
	if totalSize64 > math.MaxUint32 {
		return nil, fmt.Errorf("tds1: encoded stream length %d exceeds uint32 limit", totalSize64)
	}
	instrCount := len(e.instructions)
	if targetLen < 0 || targetLen > math.MaxUint32 || baseLen < 0 || baseLen > math.MaxUint32 || litOff64 > math.MaxUint32 || instrCount < 0 || instrCount > math.MaxUint32 {
		return nil, errors.New("tds1: stream header fields exceed uint32 limit")
	}

	hdr := Header{
		Magic:              Magic,
		ExpectedTargetSize: uint32(targetLen),
		BaseFingerprint:    baseFingerprint,
		BaseSize:           uint32(baseLen),
		LiteralBlockOffset: uint32(litOff64),
		InstrCount:         uint32(instrCount),
	}

	hdrBytes := hdr.Serialize()

	totalSize := int(totalSize64)
	out := make([]byte, 0, totalSize)
	out = append(out, hdrBytes...)
	for i := range e.instructions {
		out = append(out, e.instructions[i].Serialize()...)
	}
	out = append(out, e.literalBlock...)

	return out, nil
}
