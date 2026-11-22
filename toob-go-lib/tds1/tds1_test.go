package tds1

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"math/rand/v2"
	"testing"
)

func seededBytes(seed uint64, n int) []byte {
	rng := rand.New(rand.NewPCG(seed, 0))
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(rng.UintN(256))
	}
	return out
}

func parseAllInstructions(t *testing.T, delta []byte) []Instruction {
	t.Helper()
	hdr, err := ParseHeader(delta)
	if err != nil {
		t.Fatalf("ParseHeader failed: %v", err)
	}
	var instrs []Instruction
	for i := range hdr.InstrCount {
		off := HeaderSize + i*InstrSize
		inst, err := ParseInstruction(delta[off : off+InstrSize])
		if err != nil {
			t.Fatalf("ParseInstruction %d failed: %v", i, err)
		}
		instrs = append(instrs, *inst)
	}
	return instrs
}

func TestTDS1Identical(t *testing.T) {
	base := make([]byte, 1024)
	for i := range base {
		base[i] = byte(i % 251)
	}
	target := make([]byte, len(base))
	copy(target, base)

	delta, err := GenerateDelta(base, target)
	if err != nil {
		t.Fatalf("GenerateDelta failed: %v", err)
	}

	reconstructed, err := Apply(base, delta)
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	if !bytes.Equal(target, reconstructed) {
		t.Fatalf("Reconstructed target does not match original target")
	}

	instrs := parseAllInstructions(t, delta)
	if len(instrs) != 2 { // OpCopyBase + OpEOF
		t.Fatalf("expected 2 instructions for identical file, got %d", len(instrs))
	}
	if instrs[0].Opcode != OpCopyBase || instrs[0].Length != uint32(len(base)) {
		t.Fatalf("expected full OpCopyBase, got %+v", instrs[0])
	}
}

func TestTDS1Zeros(t *testing.T) {
	base := make([]byte, 512)
	target := make([]byte, 512) // all zeros

	delta, err := GenerateDelta(base, target)
	if err != nil {
		t.Fatalf("GenerateDelta failed: %v", err)
	}

	reconstructed, err := Apply(base, delta)
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	if !bytes.Equal(target, reconstructed) {
		t.Fatalf("Reconstructed target does not match original target")
	}

	instrs := parseAllInstructions(t, delta)
	if len(instrs) != 2 { // OpBzero + OpEOF
		t.Fatalf("expected 2 instructions for all-zero target, got %d", len(instrs))
	}
	if instrs[0].Opcode != OpBzero || instrs[0].Length != 512 {
		t.Fatalf("expected OpBzero of length 512, got %+v", instrs[0])
	}
}

func TestTDS1ScatteredEdits(t *testing.T) {
	base := seededBytes(42, 4096)

	target := make([]byte, len(base))
	copy(target, base)

	// Inject 3 edits:
	// 1. Zeros at offset 200..300
	for i := 200; i < 300; i++ {
		target[i] = 0
	}
	// 2. New data at offset 1000..1050
	for i := 1000; i < 1050; i++ {
		target[i] = byte(i ^ 0xAA)
	}
	// 3. Shifted block
	copy(target[2500:2600], base[1500:1600])

	delta, err := GenerateDelta(base, target)
	if err != nil {
		t.Fatalf("GenerateDelta failed: %v", err)
	}

	reconstructed, err := Apply(base, delta)
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	if !bytes.Equal(target, reconstructed) {
		t.Fatalf("Reconstructed target does not match original target")
	}
}

func TestTDS1CompletelyDifferent(t *testing.T) {
	base := bytes.Repeat([]byte{0x55}, 1024)
	target := bytes.Repeat([]byte{0xAA}, 1024)

	delta, err := GenerateDelta(base, target)
	if err != nil {
		t.Fatalf("GenerateDelta failed: %v", err)
	}

	reconstructed, err := Apply(base, delta)
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	if !bytes.Equal(target, reconstructed) {
		t.Fatalf("Reconstructed target does not match original target")
	}
}

func TestTDS1CorruptedHeaderCRC(t *testing.T) {
	base := []byte("hello base world 1234567890")
	target := []byte("hello target world 1234567890")

	delta, err := GenerateDelta(base, target)
	if err != nil {
		t.Fatalf("GenerateDelta failed: %v", err)
	}

	// Corrupt header CRC
	delta[28] ^= 0xFF

	_, err = Apply(base, delta)
	if err == nil {
		t.Fatalf("Apply should have failed on corrupted header CRC")
	}
}

func TestTDS1BaseFingerprintMismatch(t *testing.T) {
	base := []byte("hello base world 1234567890")
	target := []byte("hello target world 1234567890")

	delta, err := GenerateDelta(base, target)
	if err != nil {
		t.Fatalf("GenerateDelta failed: %v", err)
	}

	wrongBase := []byte("wrong base world 1234567890")
	_, err = Apply(wrongBase, delta)
	if err == nil {
		t.Fatalf("Apply should have failed on base mismatch")
	}
}

func TestTDS1PhaseShift(t *testing.T) {
	// Base contains 8192 bytes of pseudo-random firmware data
	base := seededBytes(1234, 8192)

	// Target inserts an odd 1-byte insertion at index 1000
	// This shifts every subsequent byte by 1, destroying alignment for multi-byte stepping
	target := make([]byte, 0, len(base)+1)
	target = append(target, base[:1000]...)
	target = append(target, 0xEF) // Single inserted byte
	target = append(target, base[1000:]...)

	delta, err := GenerateDelta(base, target)
	if err != nil {
		t.Fatalf("GenerateDelta failed: %v", err)
	}

	reconstructed, err := Apply(base, delta)
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	if !bytes.Equal(target, reconstructed) {
		t.Fatalf("Phase-shifted target failed reconstruction")
	}

	// Because step=1 is used for <= 2MB files, the 7192 remaining bytes
	// must be recognized as a single OpCopyBase match rather than literal fallback.
	// Total delta size should be extremely small (< 150 bytes) compared to 8KB target.
	if len(delta) > 200 {
		t.Fatalf("Delta too large (%d bytes); phase shift was not properly indexed", len(delta))
	}

	instrs := parseAllInstructions(t, delta)
	// Expect: OpCopyBase(1000) + OpInsertLit(1) + OpCopyBase(7192) + OpEOF = 4 instructions
	if len(instrs) != 4 {
		t.Fatalf("expected 4 instructions, got %d", len(instrs))
	}
}

func TestTDS1PeepholeCoalescing(t *testing.T) {
	base := seededBytes(999, 1024)

	// Target consists of the entire base firmware
	target := make([]byte, len(base))
	copy(target, base)

	delta, err := GenerateDelta(base, target)
	if err != nil {
		t.Fatalf("GenerateDelta failed: %v", err)
	}

	instrs := parseAllInstructions(t, delta)
	// Peephole coalescing must merge all contiguous slices into exactly 1 OpCopyBase + 1 OpEOF
	if len(instrs) != 2 {
		t.Fatalf("expected 2 instructions after peephole coalescing, got %d", len(instrs))
	}
	if instrs[0].Opcode != OpCopyBase || instrs[0].Length != uint32(len(base)) {
		t.Fatalf("expected single merged OpCopyBase of %d bytes, got %+v", len(base), instrs[0])
	}
}

func TestTDS1ZeroRunCoalescing(t *testing.T) {
	base := seededBytes(555, 2048)

	// Target has 4096 zeros
	target := make([]byte, 4096)

	delta, err := GenerateDelta(base, target)
	if err != nil {
		t.Fatalf("GenerateDelta failed: %v", err)
	}

	instrs := parseAllInstructions(t, delta)
	if len(instrs) != 2 {
		t.Fatalf("expected 2 instructions (OpBzero + OpEOF), got %d", len(instrs))
	}
	if instrs[0].Opcode != OpBzero || instrs[0].Length != 4096 {
		t.Fatalf("expected OpBzero of length 4096, got %+v", instrs[0])
	}

	reconstructed, err := Apply(base, delta)
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}
	if !bytes.Equal(target, reconstructed) {
		t.Fatalf("zero-run target reconstruction failed")
	}
}

func TestTDS1LazyMatchingAdvantage(t *testing.T) {
	// Construct base with:
	// - a decoy short 16-byte match at offset 100
	// - a superior 128-byte match at offset 500
	base := seededBytes(777, 1024)

	decoy := []byte("DECOY_MATCH_16B_")
	superior := bytes.Repeat([]byte("SUPERIOR_MATCH_128B_"), 6) // 120 bytes
	copy(base[100:116], decoy)
	copy(base[500:500+len(superior)], superior)

	// Target starts with 1 decoy byte, then immediately contains the superior 120 bytes
	target := make([]byte, 0, 200)
	target = append(target, decoy[0]) // Deferring this single byte allows matching superior
	target = append(target, superior...)

	delta, err := GenerateDelta(base, target)
	if err != nil {
		t.Fatalf("GenerateDelta failed: %v", err)
	}

	reconstructed, err := Apply(base, delta)
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}
	if !bytes.Equal(target, reconstructed) {
		t.Fatalf("Lazy-matching target reconstruction failed")
	}
}

func TestTDS1BackwardAbsorption(t *testing.T) {
	// Base has a 32-byte pattern
	base := seededBytes(888, 1024)

	pattern := bytes.Repeat([]byte("PATTERN_16_BYTES"), 2) // 32 bytes
	copy(base[200:232], pattern)

	// Target has random literals, followed by the exact pattern
	target := make([]byte, 0, 100)
	target = append(target, []byte("LITERAL_PREFIX_")...)
	target = append(target, pattern...)

	delta, err := GenerateDelta(base, target)
	if err != nil {
		t.Fatalf("GenerateDelta failed: %v", err)
	}

	reconstructed, err := Apply(base, delta)
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}
	if !bytes.Equal(target, reconstructed) {
		t.Fatalf("Backward-absorption target reconstruction failed")
	}
}

func TestTDS1RandomFuzzStress(t *testing.T) {
	rng := rand.New(rand.NewPCG(2026, 0))

	for iter := range 10 {
		baseSize := 1024 + rng.IntN(4096)
		base := make([]byte, baseSize)
		for i := range base {
			base[i] = byte(rng.UintN(256))
		}

		// Create target by copying slices of base with random edits and zero runs
		targetSize := 1024 + rng.IntN(4096)
		target := make([]byte, targetSize)

		tPos := 0
		for tPos < targetSize {
			rem := targetSize - tPos
			choice := rng.IntN(4)
			switch choice {
			case 0: // Copy from base
				copyLen := 16 + rng.IntN(128)
				if copyLen > rem {
					copyLen = rem
				}
				bOff := rng.IntN(baseSize - copyLen + 1)
				copy(target[tPos:tPos+copyLen], base[bOff:bOff+copyLen])
				tPos += copyLen
			case 1: // Run of zeros
				zeroLen := 16 + rng.IntN(64)
				if zeroLen > rem {
					zeroLen = rem
				}
				for z := range zeroLen {
					target[tPos+z] = 0
				}
				tPos += zeroLen
			case 2: // Random literals
				litLen := 1 + rng.IntN(32)
				if litLen > rem {
					litLen = rem
				}
				for l := range litLen {
					target[tPos+l] = byte(rng.IntN(256))
				}
				tPos += litLen
			case 3: // Repeated byte
				repLen := 8 + rng.IntN(64)
				if repLen > rem {
					repLen = rem
				}
				b := byte(rng.IntN(256))
				for r := range repLen {
					target[tPos+r] = b
				}
				tPos += repLen
			}
		}

		delta, err := GenerateDelta(base, target)
		if err != nil {
			t.Fatalf("iter %d: GenerateDelta failed: %v", iter, err)
		}

		reconstructed, err := Apply(base, delta)
		if err != nil {
			t.Fatalf("iter %d: Apply failed: %v", iter, err)
		}

		if !bytes.Equal(target, reconstructed) {
			t.Fatalf("iter %d: Fuzz test target mismatch! len(target)=%d len(reconstructed)=%d",
				iter, len(target), len(reconstructed))
		}
	}
}

func TestTDS1NegativeHeaderParsing(t *testing.T) {
	// Truncated buffer
	for _, size := range []int{0, 1, 15, 31} {
		buf := make([]byte, size)
		if _, err := ParseHeader(buf); !errors.Is(err, ErrBufferTooSmall) {
			t.Fatalf("expected ErrBufferTooSmall for size %d, got %v", size, err)
		}
	}

	validHeader := (&Header{
		Magic:              Magic,
		ExpectedTargetSize: 100,
		BaseSize:           50,
		LiteralBlockOffset: 64,
		InstrCount:         2,
	}).Serialize()

	// Invalid Magic
	badMagic := append([]byte(nil), validHeader...)
	badMagic[0] ^= 0xFF
	if _, err := ParseHeader(badMagic); !errors.Is(err, ErrInvalidMagic) {
		t.Fatalf("expected ErrInvalidMagic, got %v", err)
	}

	// Corrupted Header CRC32
	badCRC := append([]byte(nil), validHeader...)
	badCRC[28] ^= 0xFF
	if _, err := ParseHeader(badCRC); !errors.Is(err, ErrCRC32Mismatch) {
		t.Fatalf("expected ErrCRC32Mismatch, got %v", err)
	}
}

func TestTDS1NegativeInstructionParsing(t *testing.T) {
	// Truncated buffer
	for _, size := range []int{0, 4, 8, 15} {
		buf := make([]byte, size)
		if _, err := ParseInstruction(buf); !errors.Is(err, ErrBufferTooSmall) {
			t.Fatalf("expected ErrBufferTooSmall for size %d, got %v", size, err)
		}
	}

	// Valid roundtrip for all opcodes
	opcodes := []uint32{OpCopyBase, OpInsertLit, OpBzero, OpEOF}
	for _, op := range opcodes {
		inst := &Instruction{
			Opcode: op,
			Length: 1234,
			Offset: 5678,
		}
		raw := inst.Serialize()
		parsed, err := ParseInstruction(raw)
		if err != nil {
			t.Fatalf("ParseInstruction failed for op 0x%08X: %v", op, err)
		}
		if parsed.Opcode != inst.Opcode || parsed.Length != inst.Length || parsed.Offset != inst.Offset {
			t.Fatalf("parsed instruction mismatch: expected %+v, got %+v", inst, parsed)
		}
	}

	// Corrupted Instruction CRC
	inst := &Instruction{Opcode: OpCopyBase, Length: 100, Offset: 0}
	raw := inst.Serialize()
	raw[12] ^= 0xFF
	if _, err := ParseInstruction(raw); !errors.Is(err, ErrCRC32Mismatch) {
		t.Fatalf("expected ErrCRC32Mismatch on instruction, got %v", err)
	}
}

func TestTDS1NegativeApplyExecution(t *testing.T) {
	base := []byte("VALID_BASE_IMAGE_DATA_1234567890")
	target := []byte("VALID_TARGET_IMAGE_DATA_12345678")

	delta, err := GenerateDelta(base, target)
	if err != nil {
		t.Fatalf("GenerateDelta failed: %v", err)
	}

	// 1. Truncated delta (< HeaderSize)
	if _, aErr := Apply(base, delta[:20]); !errors.Is(aErr, ErrBufferTooSmall) {
		t.Fatalf("expected ErrBufferTooSmall, got %v", aErr)
	}

	// 2. Base size mismatch
	wrongSizeBase := append(bytes.Clone(base), 0x00)
	if _, aErr := Apply(wrongSizeBase, delta); !errors.Is(aErr, ErrBaseSizeMismatch) {
		t.Fatalf("expected ErrBaseSizeMismatch, got %v", aErr)
	}

	// 3. Base fingerprint mismatch (already tested, re-verify with ErrBaseHashMismatch)
	wrongDataSameSize := make([]byte, len(base))
	copy(wrongDataSameSize, base)
	wrongDataSameSize[0] ^= 0xFF
	if _, aErr := Apply(wrongDataSameSize, delta); !errors.Is(aErr, ErrBaseHashMismatch) {
		t.Fatalf("expected ErrBaseHashMismatch, got %v", aErr)
	}

	// 4. Literal block offset mismatch in header
	corruptedLitOff := append([]byte(nil), delta...)
	binary.LittleEndian.PutUint32(corruptedLitOff[20:24], 9999) // corrupt LiteralBlockOffset
	// Reseal header CRC
	corruptedLitOff[28] = 0
	corruptedLitOff[29] = 0
	corruptedLitOff[30] = 0
	corruptedLitOff[31] = 0
	hdrCRC := crc32.ChecksumIEEE(corruptedLitOff[0:28])
	binary.LittleEndian.PutUint32(corruptedLitOff[28:32], hdrCRC)
	if _, aErr := Apply(base, corruptedLitOff); !errors.Is(aErr, ErrStreamCorrupted) {
		t.Fatalf("expected ErrStreamCorrupted on lit offset mismatch, got %v", aErr)
	}

	// 5. Delta truncated before LiteralBlockOffset
	hdr, _ := ParseHeader(delta)
	truncatedAtInst := delta[:hdr.LiteralBlockOffset-1]
	if _, aErr := Apply(base, truncatedAtInst); !errors.Is(aErr, ErrStreamCorrupted) {
		t.Fatalf("expected ErrStreamCorrupted on truncated instruction area, got %v", aErr)
	}

	// 6. Unknown opcode
	badOpDelta := append([]byte(nil), delta...)
	badInst := &Instruction{Opcode: 0xDEADBEEF, Length: 10, Offset: 0}
	copy(badOpDelta[HeaderSize:HeaderSize+InstrSize], badInst.Serialize())
	if _, aErr := Apply(base, badOpDelta); !errors.Is(aErr, ErrStreamCorrupted) {
		t.Fatalf("expected ErrStreamCorrupted on unknown opcode, got %v", aErr)
	}

	// 7. OpCopyBase bounds violation (Offset + Length > baseSize)
	oobCopyDelta := append([]byte(nil), delta...)
	oobInst := &Instruction{Opcode: OpCopyBase, Length: uint32(len(base)) + 10, Offset: 5}
	copy(oobCopyDelta[HeaderSize:HeaderSize+InstrSize], oobInst.Serialize())
	if _, aErr := Apply(base, oobCopyDelta); !errors.Is(aErr, ErrStreamCorrupted) {
		t.Fatalf("expected ErrStreamCorrupted on OOB OpCopyBase, got %v", aErr)
	}

	// 8. OpInsertLit pointing past delta end
	oobLitDelta := append([]byte(nil), delta...)
	oobLitInst := &Instruction{Opcode: OpInsertLit, Length: uint32(len(delta)) + 100, Offset: 0}
	copy(oobLitDelta[HeaderSize:HeaderSize+InstrSize], oobLitInst.Serialize())
	if _, aErr := Apply(base, oobLitDelta); !errors.Is(aErr, ErrStreamCorrupted) {
		t.Fatalf("expected ErrStreamCorrupted on truncated literal block, got %v", aErr)
	}

	// 8b. OpInsertLit with corrupted heatshrink payload
	corruptedLitStream := append([]byte(nil), delta...)
	corruptedLitStream[hdr.LiteralBlockOffset] = 0x00
	corruptedLitStream[hdr.LiteralBlockOffset+1] = 0x00
	if _, aErr := Apply(base, corruptedLitStream); aErr == nil {
		t.Fatal("expected error on corrupted literal decompress")
	}

	// 9. Premature OpEOF (EOF before final instruction)
	prematureEOFDelta := append([]byte(nil), delta...)
	eofInst := &Instruction{Opcode: OpEOF, Length: 0, Offset: 0}
	copy(prematureEOFDelta[HeaderSize:HeaderSize+InstrSize], eofInst.Serialize())
	if _, aErr := Apply(base, prematureEOFDelta); !errors.Is(aErr, ErrStreamCorrupted) {
		t.Fatalf("expected ErrStreamCorrupted on premature EOF, got %v", aErr)
	}

	// 10. Missing OpEOF (instruction list ends with OpBzero instead of OpEOF)
	missingEOFDelta := append([]byte(nil), delta...)
	lastInstOff := HeaderSize + (hdr.InstrCount-1)*InstrSize
	bzeroInst := &Instruction{Opcode: OpBzero, Length: 1, Offset: 0}
	copy(missingEOFDelta[lastInstOff:lastInstOff+InstrSize], bzeroInst.Serialize())
	if _, aErr := Apply(base, missingEOFDelta); !errors.Is(aErr, ErrStreamCorrupted) {
		t.Fatalf("expected ErrStreamCorrupted on missing EOF, got %v", aErr)
	}

	// 11. Target size mismatch (produced target shorter than ExpectedTargetSize)
	mismatchTargetDelta := append([]byte(nil), delta...)
	binary.LittleEndian.PutUint32(mismatchTargetDelta[4:8], uint32(len(target))+50) // corrupt ExpectedTargetSize
	hdrCRC = crc32.ChecksumIEEE(mismatchTargetDelta[0:28])
	binary.LittleEndian.PutUint32(mismatchTargetDelta[28:32], hdrCRC)
	if _, aErr := Apply(base, mismatchTargetDelta); !errors.Is(aErr, ErrTargetSizeMismatch) {
		t.Fatalf("expected ErrTargetSizeMismatch, got %v", aErr)
	}

	// 12. OpInsertLit with mismatched declared uncompressed length (inst.Offset)
	declaredLenMismatchDelta := append([]byte(nil), delta...)
	litInstBytes := declaredLenMismatchDelta[HeaderSize+InstrSize : HeaderSize+2*InstrSize]
	litInst, err := ParseInstruction(litInstBytes)
	if err != nil {
		t.Fatalf("parse instruction failed: %v", err)
	}
	litInst.Offset += 100 // Tamper declared uncompressed length
	copy(declaredLenMismatchDelta[HeaderSize+InstrSize:HeaderSize+2*InstrSize], litInst.Serialize())
	if _, err := Apply(base, declaredLenMismatchDelta); !errors.Is(err, ErrStreamCorrupted) {
		t.Fatalf("expected ErrStreamCorrupted on declared literal length mismatch, got %v", err)
	}

	// 13. Trailing unparsed bytes appended to delta stream
	trailingGarbageDelta := append(append([]byte(nil), delta...), []byte("EXTRA_GARBAGE_PAYLOAD")...)
	if _, err := Apply(base, trailingGarbageDelta); !errors.Is(err, ErrStreamCorrupted) {
		t.Fatalf("expected ErrStreamCorrupted on trailing unparsed bytes, got %v", err)
	}
}

func TestTDS1BoundaryGenerateDelta(t *testing.T) {
	// 1. Both empty
	emptyDelta, err := GenerateDelta([]byte{}, []byte{})
	if err != nil {
		t.Fatalf("GenerateDelta on empty base/target failed: %v", err)
	}
	recon, err := Apply([]byte{}, emptyDelta)
	if err != nil || len(recon) != 0 {
		t.Fatalf("Apply on empty delta failed: recon_len=%d, err=%v", len(recon), err)
	}

	// 2. Empty base, non-empty target
	t1 := []byte("NON_EMPTY_TARGET_FIRMWARE_PAYLOAD_123456789")
	d1, err := GenerateDelta([]byte{}, t1)
	if err != nil {
		t.Fatalf("GenerateDelta on empty base failed: %v", err)
	}
	recon1, err := Apply([]byte{}, d1)
	if err != nil || !bytes.Equal(recon1, t1) {
		t.Fatalf("Apply with empty base failed")
	}

	// 3. Non-empty base, empty target
	b2 := []byte("NON_EMPTY_BASE_FIRMWARE_PAYLOAD_123456789")
	d2, err := GenerateDelta(b2, []byte{})
	if err != nil {
		t.Fatalf("GenerateDelta on empty target failed: %v", err)
	}
	recon2, err := Apply(b2, d2)
	if err != nil || len(recon2) != 0 {
		t.Fatalf("Apply with empty target failed")
	}

	// 4. Sub-4-byte base and target (prefix hashing boundary checks)
	for bSize := 1; bSize <= 3; bSize++ {
		for tSize := 1; tSize <= 3; tSize++ {
			b := make([]byte, bSize)
			tg := make([]byte, tSize)
			for i := range b {
				b[i] = byte(i + 1)
			}
			for i := range tg {
				tg[i] = byte(i + 10)
			}
			d, dErr := GenerateDelta(b, tg)
			if dErr != nil {
				t.Fatalf("bSize=%d tSize=%d GenerateDelta failed: %v", bSize, tSize, dErr)
			}
			rec, aErr := Apply(b, d)
			if aErr != nil || !bytes.Equal(rec, tg) {
				t.Fatalf("bSize=%d tSize=%d reconstruction failed: %v", bSize, tSize, aErr)
			}
		}
	}

	// 5. Target starting with zeros, then data, then ending with zeros
	targetZeros := make([]byte, 0, 100)
	targetZeros = append(targetZeros, make([]byte, 20)...) // 20 zeros at start
	targetZeros = append(targetZeros, []byte("INTERMEDIATE_DATA_BLOCK")...)
	targetZeros = append(targetZeros, make([]byte, 25)...) // 25 zeros at end
	dZeros, err := GenerateDelta([]byte("ARBITRARY_BASE"), targetZeros)
	if err != nil {
		t.Fatalf("GenerateDelta with leading/trailing zeros failed: %v", err)
	}
	recZeros, err := Apply([]byte("ARBITRARY_BASE"), dZeros)
	if err != nil || !bytes.Equal(recZeros, targetZeros) {
		t.Fatalf("zeros boundary test reconstruction failed")
	}

	// 6. Large zero block (> 64KB)
	largeZeros := make([]byte, 70000)
	dLargeZeros, err := GenerateDelta([]byte("BASE"), largeZeros)
	if err != nil {
		t.Fatalf("GenerateDelta with 70KB zeros failed: %v", err)
	}
	recLargeZeros, err := Apply([]byte("BASE"), dLargeZeros)
	if err != nil || !bytes.Equal(recLargeZeros, largeZeros) {
		t.Fatalf("70KB zeros reconstruction failed")
	}

	// 7. Large literal accumulator (> 32KB maxLiteralAccum threshold)
	largeLiterals := seededBytes(4321, 40000)
	dLargeLits, err := GenerateDelta([]byte("DIFFERENT_BASE"), largeLiterals)
	if err != nil {
		t.Fatalf("GenerateDelta with 40KB literals failed: %v", err)
	}
	recLargeLits, err := Apply([]byte("DIFFERENT_BASE"), dLargeLits)
	if err != nil || !bytes.Equal(recLargeLits, largeLiterals) {
		t.Fatalf("40KB literals reconstruction failed")
	}

	// 8. Highly repetitive data (testing hash chain bucket cap maxCandidatesPerKey = 64)
	repBase := bytes.Repeat([]byte{0x42}, 2000)
	repTarget := bytes.Repeat([]byte{0x42}, 2000)
	dRep, err := GenerateDelta(repBase, repTarget)
	if err != nil {
		t.Fatalf("GenerateDelta with repetitive data failed: %v", err)
	}
	recRep, err := Apply(repBase, dRep)
	if err != nil || !bytes.Equal(recRep, repTarget) {
		t.Fatalf("repetitive data reconstruction failed")
	}

	// 9. Medium firmware (> 2MB, exercises indexStep = 2)
	medBase := make([]byte, 2100000)
	medTarget := make([]byte, 2100000)
	copy(medTarget, medBase)
	medTarget[1000] = 0xAB
	dMed, err := GenerateDelta(medBase, medTarget)
	if err != nil {
		t.Fatalf("GenerateDelta on 2.1MB firmware failed: %v", err)
	}
	recMed, err := Apply(medBase, dMed)
	if err != nil || !bytes.Equal(recMed, medTarget) {
		t.Fatalf("2.1MB firmware reconstruction failed")
	}

	// 10. Large firmware (> 8MB, exercises indexStep = 4)
	largeBase := make([]byte, 8500000)
	largeTarget := make([]byte, 8500000)
	copy(largeTarget, largeBase)
	largeTarget[5000] = 0xCD
	dLarge, err := GenerateDelta(largeBase, largeTarget)
	if err != nil {
		t.Fatalf("GenerateDelta on 8.5MB firmware failed: %v", err)
	}
	recLarge, err := Apply(largeBase, dLarge)
	if err != nil || !bytes.Equal(recLarge, largeTarget) {
		t.Fatalf("8.5MB firmware reconstruction failed")
	}
}
