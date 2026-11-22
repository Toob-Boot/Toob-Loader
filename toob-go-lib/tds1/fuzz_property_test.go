package tds1

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"testing"
)

func resealTDS1HeaderCRC(delta []byte) {
	if len(delta) < HeaderSize {
		return
	}
	crc := crc32.ChecksumIEEE(delta[0:28])
	binary.LittleEndian.PutUint32(delta[28:32], crc)
}

func FuzzTDS1RoundtripEquivalence(f *testing.F) {
	sectorA := make([]byte, 4096)
	for i := range sectorA {
		sectorA[i] = byte((i*37 + 13) & 0xFF)
	}
	sectorB := bytes.Clone(sectorA)
	clear(sectorB[128:320]) // BZERO region
	copy(sectorB[1024:1120], bytes.Repeat([]byte("INSERT_LIT_LZSS_"), 6))
	sectorB = append(sectorB, make([]byte, 64)...) // trailing zero growth

	shifted := make([]byte, 0, len(sectorA)+3)
	shifted = append(shifted, 0xDE, 0xAD, 0xBE)
	shifted = append(shifted, sectorA...)

	f.Add([]byte{}, []byte{})
	f.Add([]byte{}, []byte{0x42})
	f.Add([]byte{0x42}, []byte{})
	f.Add([]byte{1, 2, 3}, []byte{4, 5, 6})
	f.Add(make([]byte, 512), make([]byte, 512))
	f.Add(sectorA, sectorA)
	f.Add(sectorA, sectorB)
	f.Add(sectorA[:4095], shifted[:4097])

	f.Fuzz(func(t *testing.T, oldImage, newImage []byte) {
		if len(oldImage) > 128<<10 || len(newImage) > 128<<10 {
			return
		}
		origOld := bytes.Clone(oldImage)
		origNew := bytes.Clone(newImage)

		// 1. Forward SDVM delta: Apply(oldImage, GenerateDelta(oldImage, newImage)) == newImage.
		fwdPatch, err := GenerateDelta(oldImage, newImage)
		if err != nil {
			t.Fatalf("GenerateDelta(forward) failed: %v", err)
		}
		if !bytes.Equal(oldImage, origOld) || !bytes.Equal(newImage, origNew) {
			t.Fatalf("GenerateDelta mutated input slices")
		}

		hdr, err := ParseHeader(fwdPatch)
		if err != nil {
			t.Fatalf("ParseHeader(fwdPatch) failed: %v", err)
		}
		wantFP := sha256.Sum256(oldImage)
		if hdr.ExpectedTargetSize != uint32(len(newImage)) ||
			hdr.BaseSize != uint32(len(oldImage)) ||
			hdr.BaseFingerprint != [8]byte(wantFP[:8]) {
			t.Fatalf("header metadata mismatch: %+v", hdr)
		}
		if hdr.InstrCount == 0 {
			t.Fatalf("emitted 0 instructions")
		}
		for i := range hdr.InstrCount {
			off := HeaderSize + i*InstrSize
			inst, pErr := ParseInstruction(fwdPatch[off : off+InstrSize])
			if pErr != nil {
				t.Fatalf("ParseInstruction(%d) failed: %v", i, pErr)
			}
			if i == hdr.InstrCount-1 && (inst.Opcode != OpEOF || inst.Length != 0 || inst.Offset != 0) {
				t.Fatalf("final instruction is not canonical OpEOF: %+v", inst)
			}
			if i < hdr.InstrCount-1 && inst.Opcode == OpEOF {
				t.Fatalf("premature OpEOF at instruction %d of %d", i, hdr.InstrCount)
			}
		}

		gotNew, err := Apply(oldImage, fwdPatch)
		if err != nil {
			t.Fatalf("Apply(forward) failed: %v", err)
		}
		if !bytes.Equal(gotNew, newImage) {
			t.Fatalf("forward roundtrip mismatch: got %d bytes, want %d bytes", len(gotNew), len(newImage))
		}

		// 2. Reverse SDVM delta: Apply(newImage, GenerateDelta(newImage, oldImage)) == oldImage.
		revPatch, err := GenerateDelta(newImage, oldImage)
		if err != nil {
			t.Fatalf("GenerateDelta(reverse) failed: %v", err)
		}
		gotOld, err := Apply(newImage, revPatch)
		if err != nil {
			t.Fatalf("Apply(reverse) failed: %v", err)
		}
		if !bytes.Equal(gotOld, oldImage) {
			t.Fatalf("reverse roundtrip mismatch: got %d bytes, want %d bytes", len(gotOld), len(oldImage))
		}
	})
}

func FuzzTDS1CorruptPatchSafety(f *testing.F) {
	base := bytes.Repeat([]byte("BASE_FIRMWARE_SECTOR_"), 32)
	target := append(bytes.Clone(base[:256]), make([]byte, 128)...)
	target = append(target, []byte("NEW_LITERAL_TRAILER_DATA_BLOCK_1234")...)

	validPatch, err := GenerateDelta(base, target)
	if err != nil {
		f.Fatalf("GenerateDelta seed: %v", err)
	}

	// Crafted zip-bomb patch with ExpectedTargetSize = 0xFFFFFFFF and resealed header CRC.
	zipBombPatch := bytes.Clone(validPatch)
	binary.LittleEndian.PutUint32(zipBombPatch[4:8], 0xFFFFFFFF)
	resealTDS1HeaderCRC(zipBombPatch)

	// Crafted OOB OpCopyBase wrapping uint32 Offset + Length.
	wrapCopyPatch := bytes.Clone(validPatch)
	wrapInst := (&Instruction{Opcode: OpCopyBase, Length: 0x20, Offset: 0xFFFFFFF0}).Serialize()
	copy(wrapCopyPatch[HeaderSize:HeaderSize+InstrSize], wrapInst)

	f.Add(base, validPatch)
	f.Add(base, zipBombPatch)
	f.Add(base, wrapCopyPatch)
	f.Add(base, validPatch[:HeaderSize-1])
	f.Add([]byte{}, []byte{})

	f.Fuzz(func(t *testing.T, oldImage, rawPatch []byte) {
		if len(oldImage) > 64<<10 || len(rawPatch) > 64<<10 {
			return
		}
		origOld := bytes.Clone(oldImage)
		origPatch := bytes.Clone(rawPatch)

		// 1. Arbitrary untrusted patch bytes must never panic or mutate inputs.
		_, _ = ParseHeader(rawPatch)
		_, _ = ParseInstruction(rawPatch)
		if out, err := Apply(oldImage, rawPatch); err == nil {
			hdr, hErr := ParseHeader(rawPatch)
			if hErr != nil || uint32(len(out)) != hdr.ExpectedTargetSize {
				t.Fatalf("Apply succeeded with inconsistent output size")
			}
			fp := sha256.Sum256(oldImage)
			if hdr.BaseSize != uint32(len(oldImage)) || !bytes.Equal(hdr.BaseFingerprint[:], fp[:8]) {
				t.Fatalf("Apply accepted mismatched base size or fingerprint")
			}
		}
		if !bytes.Equal(oldImage, origOld) || !bytes.Equal(rawPatch, origPatch) {
			t.Fatalf("Apply mutated caller slices")
		}

		// 2. Structured corruption over a valid patch derived from (oldImage, rawPatch).
		if len(oldImage) <= 4096 && len(rawPatch) >= 4 && len(rawPatch) <= 4096 {
			patch, err := GenerateDelta(oldImage, rawPatch)
			if err != nil {
				t.Fatalf("GenerateDelta failed: %v", err)
			}

			// 2a. Corrupt header CRC -> must reject with ErrCRC32Mismatch.
			badHdrCRC := bytes.Clone(patch)
			badHdrCRC[28] ^= 0x01
			if _, aErr := Apply(oldImage, badHdrCRC); !errors.Is(aErr, ErrCRC32Mismatch) {
				t.Fatalf("corrupted header CRC not rejected: %v", aErr)
			}

			// 2b. Corrupt base fingerprint + reseal header CRC -> must reject with ErrBaseHashMismatch.
			badFP := bytes.Clone(patch)
			badFP[8+int(rawPatch[0]%8)] ^= 0x80
			resealTDS1HeaderCRC(badFP)
			if _, aErr := Apply(oldImage, badFP); !errors.Is(aErr, ErrBaseHashMismatch) {
				t.Fatalf("corrupted BaseFingerprint not rejected: %v", aErr)
			}

			// 2c. Corrupt instruction CRC -> must reject with ErrCRC32Mismatch.
			pHdr, err := ParseHeader(patch)
			if err != nil {
				t.Fatalf("ParseHeader(patch) failed: %v", err)
			}
			badInstCRC := bytes.Clone(patch)
			instIdx := int(rawPatch[1]) % int(pHdr.InstrCount)
			badInstCRC[HeaderSize+instIdx*InstrSize] ^= 0x01
			if _, err := Apply(oldImage, badInstCRC); !errors.Is(err, ErrCRC32Mismatch) {
				t.Fatalf("corrupted instruction CRC not rejected: %v", err)
			}

			// 2d. Reseal header CRC over fuzzer-mutated header fields -> must never panic or OOM.
			if len(rawPatch) >= 28 {
				mutHdr := bytes.Clone(patch)
				mutOff := 4 + int(rawPatch[2]%24)
				mutHdr[mutOff] ^= rawPatch[3] | 1
				resealTDS1HeaderCRC(mutHdr)
				_, _ = Apply(oldImage, mutHdr)
			}
		}
	})
}

func TestTDS1OversizedHeaderAndInstructionBoundsRegression(t *testing.T) {
	base := []byte("REGRESSION_BASE_FIRMWARE_IMAGE_0123456789")
	target := []byte("REGRESSION_NEW_FIRMWARE_IMAGE__0123456789")
	delta, err := GenerateDelta(base, target)
	if err != nil {
		t.Fatalf("GenerateDelta: %v", err)
	}

	// 1. ExpectedTargetSize = 0xFFFFFFFF (4 GiB) with resealed CRC must fail fast without OOM/panic.
	hugeTarget := bytes.Clone(delta)
	binary.LittleEndian.PutUint32(hugeTarget[4:8], 0xFFFFFFFF)
	resealTDS1HeaderCRC(hugeTarget)
	if _, err := Apply(base, hugeTarget); !errors.Is(err, ErrStreamCorrupted) {
		t.Fatalf("expected ErrStreamCorrupted on ExpectedTargetSize > MaxTargetSize, got %v", err)
	}

	// 2. InstrCount = 0 and InstrCount > MaxInstructions with resealed CRC must fail fast.
	for _, badCount := range []uint32{0, MaxInstructions + 1, 0xFFFFFFFF} {
		corrupt := bytes.Clone(delta)
		binary.LittleEndian.PutUint32(corrupt[24:28], badCount)
		resealTDS1HeaderCRC(corrupt)
		if _, err := Apply(base, corrupt); !errors.Is(err, ErrStreamCorrupted) {
			t.Fatalf("InstrCount=%d: expected ErrStreamCorrupted, got %v", badCount, err)
		}
	}

	// 3. OpBzero zip-bomb exceeding MaxTargetSize with resealed CRCs must fail fast.
	fp := sha256.Sum256(base)
	var hdr Header
	hdr.Magic = Magic
	hdr.ExpectedTargetSize = MaxTargetSize + 1
	copy(hdr.BaseFingerprint[:], fp[:8])
	hdr.BaseSize = uint32(len(base))
	hdr.InstrCount = 2
	hdr.LiteralBlockOffset = HeaderSize + 2*InstrSize
	bzeroBomb := append([]byte(nil), hdr.Serialize()...)
	bzeroBomb = append(bzeroBomb, (&Instruction{Opcode: OpBzero, Length: MaxTargetSize + 1}).Serialize()...)
	bzeroBomb = append(bzeroBomb, (&Instruction{Opcode: OpEOF}).Serialize()...)
	if _, err := Apply(base, bzeroBomb); !errors.Is(err, ErrStreamCorrupted) {
		t.Fatalf("expected ErrStreamCorrupted on bzero zip-bomb, got %v", err)
	}
}
