package tbm1

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"math"
	"testing"
)

func deterministicFuzzSigner(tb testing.TB) (*LocalSigner, ed25519.PublicKey) {
	tb.Helper()
	seed := bytes.Repeat([]byte{0x5A, 0xC3, 0x19, 0xE7, 0x2B, 0x8D, 0x4F, 0x61}, 4)
	priv := ed25519.NewKeyFromSeed(seed)
	signer, err := NewLocalSigner(priv)
	if err != nil {
		tb.Fatalf("NewLocalSigner: %v", err)
	}
	pub := signer.Public()
	return signer, pub
}

func verifyAcceptedTBM1Invariants(t *testing.T, block []byte, signer *LocalSigner, pub ed25519.PublicKey) {
	t.Helper()

	hdr, err := ParseHeader(block)
	if err != nil {
		t.Fatalf("ValidateBlock succeeded but ParseHeader failed: %v", err)
	}
	if uint64(hdr.TotalLen) != uint64(len(block)) || hdr.SignedLen != hdr.TotalLen-SigLen {
		t.Fatalf("header length invariant broken: %+v (len=%d)", hdr, len(block))
	}
	if binary.LittleEndian.Uint32(block[offFixedCRC32:]) != headerCRC(block) {
		t.Fatalf("accepted block with bad fixed_crc32")
	}

	// Verify strict disjoint, ascending, 8B-aligned region directory inside [FixedLen .. SignedLen].
	le := binary.LittleEndian
	prevEnd := uint32(FixedLen)
	for i := range MaxRegions {
		base := offRegions + i*regionStride
		id := le.Uint16(block[base:])
		if id == RegionNone {
			continue
		}
		off := le.Uint32(block[base+4:])
		ln := le.Uint32(block[base+8:])
		if (off&7) != 0 || off < prevEnd || off > hdr.SignedLen || ln > hdr.SignedLen-off {
			t.Fatalf("accepted invalid region[%d] id=%d off=%d len=%d prevEnd=%d signedLen=%d",
				i, id, off, ln, prevEnd, hdr.SignedLen)
		}
		prevEnd = off + ln
	}

	// Custody signing roundtrip + Ed25519 single-bit flip rejection.
	signed, err := SignBlock(block, signer)
	if err != nil {
		t.Fatalf("SignBlock failed on valid block: %v", err)
	}
	if err := VerifyBlock(signed, pub); err != nil {
		t.Fatalf("VerifyBlock failed on freshly signed block: %v", err)
	}

	// Flip 1 bit inside the signed body [0 .. SignedLen) AND reseal fixed_crc32 -> must fail Ed25519!
	bodyBit := (len(signed)*7 + int(signed[offSVN])) % (int(hdr.SignedLen) * 8)
	tamperedBody := bytes.Clone(signed)
	tamperedBody[bodyBit/8] ^= 1 << (bodyBit % 8)
	resealCRC(tamperedBody)
	if err := VerifyBlock(tamperedBody, pub); err == nil {
		t.Fatalf("1-bit flip in signed body at bit %d (with resealed CRC) passed VerifyBlock", bodyBit)
	}

	// Flip 1 bit inside the 64-byte Ed25519 signature slot -> must fail with ErrBadSignature!
	sigBit := (len(signed)*11 + int(signed[hdr.SignedLen])) % (SigLen * 8)
	tamperedSig := bytes.Clone(signed)
	tamperedSig[int(hdr.SignedLen)+sigBit/8] ^= 1 << (sigBit % 8)
	if err := VerifyBlock(tamperedSig, pub); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("1-bit flip in Ed25519 signature at bit %d: expected ErrBadSignature, got %v", sigBit, err)
	}
}

func FuzzTBM1UntrustedParseAndBijection(f *testing.F) {
	signer, pub := deterministicFuzzSigner(f)
	defer signer.Zeroise()

	v1Img := bytes.Repeat([]byte("TBM1_V1_"), 16)
	v2Img := bytes.Clone(v1Img)
	copy(v2Img[32:], "TBM1_V2_")

	compactPkg, err := Build(Manifest{
		VendorID:   0x1234,
		ProductID:  0x5678,
		HWRevMin:   1,
		HWRevMax:   3,
		KeyIndex:   1,
		SVN:        5,
		AutoSBOM:   true,
		SectorSize: 512,
		Images: []Image{
			{TargetSlot: SlotApp, Installed: v2Img, ChunkSize: 64},
		},
	}, signer)
	if err != nil {
		f.Fatalf("Build compact seed: %v", err)
	}

	trailerPkg, err := Build(Manifest{
		VendorID:      0x1234,
		ProductID:     0x5678,
		HWRevMin:      1,
		HWRevMax:      3,
		SVN:           5,
		AutoSBOM:      true,
		TrailerLayout: true,
		SectorSize:    512,
		Images: []Image{
			{TargetSlot: SlotApp, Installed: v2Img, ChunkSize: 64},
		},
		ReverseDeltas: []ReverseDelta{
			{TargetSlot: SlotApp, DeltaAlg: DeltaTDS1, OldImage: v1Img},
		},
	}, signer)
	if err != nil {
		f.Fatalf("Build trailer seed: %v", err)
	}
	trailerBundle, err := trailerPkg.AssembleTrailer([][]byte{v2Img})
	if err != nil {
		f.Fatalf("AssembleTrailer seed: %v", err)
	}

	deltaPkg, err := Build(Manifest{
		VendorID:   0x1234,
		ProductID:  0x5678,
		HWRevMin:   1,
		HWRevMax:   3,
		SVN:        5,
		SectorSize: 512,
		Images: []Image{
			{TargetSlot: SlotApp, DeltaAlg: DeltaTDS1, Base: v1Img, Installed: v2Img, BaseSVN: 4, ChunkSize: 64},
		},
	}, signer)
	if err != nil {
		f.Fatalf("Build delta seed: %v", err)
	}
	deltaBundle, err := deltaPkg.AssembleFlat([][]byte{deltaPkg.Payloads[0].Data})
	if err != nil {
		f.Fatalf("AssembleFlat delta seed: %v", err)
	}

	unalignedReg := bytes.Clone(compactPkg.Block)
	binary.LittleEndian.PutUint32(unalignedReg[offRegions+4:], FixedLen+4)
	resealCRC(unalignedReg)

	loc := EncodeTrailerLocator(4096, compactPkg.TotalLen)

	f.Add([]byte{})
	f.Add(loc[:])
	f.Add(compactPkg.Block)
	f.Add(trailerBundle)
	f.Add(deltaBundle)
	f.Add(unalignedReg)

	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 128<<10 {
			return
		}
		orig := bytes.Clone(raw)

		// 1. Untrusted raw byte parsing across all TBM1 entry points: zero panics & input immutability.
		valErr := ValidateBlock(raw)
		_, hdrErr := ParseHeader(raw)
		verErr := VerifyBlock(raw, pub)
		_, signErr := SignBlock(raw, signer)
		_, _ = ParseRDeltaDesc(raw)
		locOff, locLen, locErr := ParseTrailerLocator(raw)

		if !bytes.Equal(raw, orig) {
			t.Fatalf("TBM1 parser/validator mutated caller buffer")
		}

		// Custody & structural gating equivalence invariants.
		if (valErr == nil) != (hdrErr == nil) {
			t.Fatalf("ValidateBlock (%v) != ParseHeader (%v)", valErr, hdrErr)
		}
		if (valErr == nil) != (signErr == nil) {
			t.Fatalf("ValidateBlock (%v) != SignBlock (%v): custody oracle violation", valErr, signErr)
		}
		if verErr == nil && valErr != nil {
			t.Fatalf("VerifyBlock succeeded on structurally invalid block: %v", valErr)
		}
		if valErr == nil {
			verifyAcceptedTBM1Invariants(t, raw, signer, pub)
		}

		// Trailer locator safety & roundtrip invariant.
		if locErr == nil {
			reLoc := EncodeTrailerLocator(locOff, locLen)
			if !bytes.Equal(reLoc[:], raw[len(raw)-TrailerLocatorLen:]) {
				t.Fatalf("TrailerLocator canonical bijection violated")
			}
			gotOff, gotLen, err2 := ParseTrailerLocator(reLoc[:])
			if err2 != nil || gotOff != locOff || gotLen != locLen {
				t.Fatalf("EncodeTrailerLocator -> ParseTrailerLocator roundtrip failed: %v", err2)
			}
			if len(raw) > TrailerLocatorLen {
				// Slicing bundle[locOff : locOff+locLen] must always be safe when ParseTrailerLocator succeeds.
				extracted := raw[locOff : locOff+locLen]
				_ = ValidateBlock(extracted)
				_ = VerifyBlock(extracted, pub)
			}
		}

		// 2. CRC-resealed projection so coverage-guided fuzzing penetrates past fixed_crc32 into region/image checks.
		if len(raw) >= FixedLen+SigLen && len(raw) <= 8192 {
			resealed := bytes.Clone(raw)
			binary.LittleEndian.PutUint32(resealed[offMagic:], Magic)
			resealed[offVersionMajor] = VersionMajor
			binary.LittleEndian.PutUint16(resealed[offFixedLen:], FixedLen)
			binary.LittleEndian.PutUint32(resealed[offTotalLen:], uint32(len(resealed)))
			resealCRC(resealed)
			if ValidateBlock(resealed) == nil {
				verifyAcceptedTBM1Invariants(t, resealed, signer, pub)
			}
		}

		// 3. Fuzzer-driven PackBundle TrailerLayout + Flat roundtrip & Ed25519 bit-flip check on compact payloads.
		if len(raw) >= 16 && len(raw) <= 256 && (raw[0]&0x0C) == 0 {
			trailerMode := (raw[0] & 1) != 0
			compressMode := (raw[0] & 2) != 0
			imgPayload := raw[4:]
			bundle, err := PackBundle(PackOptions{
				Installed:     imgPayload,
				Compress:      compressMode,
				TrailerLayout: trailerMode,
				VendorID:      binary.LittleEndian.Uint16(raw[0:2]),
				ProductID:     binary.LittleEndian.Uint16(raw[2:4]),
				HWRevMin:      1,
				HWRevMax:      2,
				SVN:           uint32(raw[1]) + 1,
				VerMajor:      1,
			}, signer)
			if err != nil {
				t.Fatalf("PackBundle failed on valid compact options: %v", err)
			}
			if trailerMode {
				tOff, tLen, err := ParseTrailerLocator(bundle)
				if err != nil {
					t.Fatalf("ParseTrailerLocator on PackBundle trailer failed: %v", err)
				}
				blk := bundle[tOff : tOff+tLen]
				if err := VerifyBlock(blk, pub); err != nil {
					t.Fatalf("VerifyBlock on extracted trailer block failed: %v", err)
				}
				corruptBlk := bytes.Clone(blk)
				corruptBlk[len(corruptBlk)-1] ^= 0x01
				if err := VerifyBlock(corruptBlk, pub); !errors.Is(err, ErrBadSignature) {
					t.Fatalf("expected ErrBadSignature on flipped trailer sig byte, got %v", err)
				}
			} else {
				tLen := binary.LittleEndian.Uint32(bundle[offTotalLen:])
				blk := bundle[:tLen]
				if err := VerifyBlock(blk, pub); err != nil {
					t.Fatalf("VerifyBlock on flat bundle header failed: %v", err)
				}
				corruptBlk := bytes.Clone(blk)
				corruptBlk[len(corruptBlk)-1] ^= 0x80
				if err := VerifyBlock(corruptBlk, pub); !errors.Is(err, ErrBadSignature) {
					t.Fatalf("expected ErrBadSignature on flipped flat sig byte, got %v", err)
				}
			}
		}
	})
}

func TestTBM1RegressionOverflowAndReaderMirrorProperties(t *testing.T) {
	signer, pub := deterministicFuzzSigner(t)
	defer signer.Zeroise()

	payload := bytes.Repeat([]byte{0xAB}, 4096)

	// 1. Regression: TailGap pushing nextCursor >= 2^32 must return ErrLayoutOverflow instead of silent uint32 wrap.
	overflowTrailer := Manifest{
		VendorID:      1,
		ProductID:     1,
		HWRevMin:      1,
		HWRevMax:      1,
		TrailerLayout: true,
		SectorSize:    4096,
		Images: []Image{
			{
				TargetSlot: SlotApp,
				Installed:  payload,
				TailGap:    0xFFFFF000,
			},
		},
	}
	if _, err := BuildUnsigned(overflowTrailer); !errors.Is(err, ErrLayoutOverflow) {
		t.Fatalf("expected ErrLayoutOverflow on TrailerLayout TailGap uint32 wrap, got %v", err)
	}

	overflowRDelta := Manifest{
		VendorID:   1,
		ProductID:  1,
		HWRevMin:   1,
		HWRevMax:   1,
		SectorSize: 4096,
		Images: []Image{
			{
				TargetSlot: SlotApp,
				Installed:  payload,
				TailGap:    0xFFFFF000,
			},
		},
		ReverseDeltas: []ReverseDelta{
			{
				TargetSlot:   SlotApp,
				DeltaAlg:     DeltaTDS1,
				Data:         bytes.Repeat([]byte{0x11}, 64),
				StoredSize:   64,
				RestoredSize: 4096,
			},
		},
	}
	if _, err := BuildUnsigned(overflowRDelta); !errors.Is(err, ErrLayoutOverflow) {
		t.Fatalf("expected ErrLayoutOverflow on ReverseDelta cursor uint32 wrap, got %v", err)
	}

	// 2. Regression: ValidateBlock / SignBlock reader-mirror checks matching Stage 1 boot_tbm1.c.
	basePkg, err := Build(Manifest{
		VendorID:  1,
		ProductID: 2,
		HWRevMin:  1,
		HWRevMax:  4,
		SVN:       1,
		Images:    []Image{{TargetSlot: SlotApp, Installed: payload, ChunkSize: 4096}},
	}, signer)
	if err != nil {
		t.Fatalf("Build basePkg: %v", err)
	}
	if err := VerifyBlock(basePkg.Block, pub); err != nil {
		t.Fatalf("VerifyBlock basePkg: %v", err)
	}

	cases := []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{
			name: "unaligned_region_offset",
			mutate: func(b []byte) []byte {
				grown := make([]byte, len(b)+8)
				copy(grown[:FixedLen], b[:FixedLen])
				copy(grown[FixedLen+4:FixedLen+4+DigestLen], b[FixedLen:FixedLen+DigestLen])
				binary.LittleEndian.PutUint32(grown[offTotalLen:], uint32(len(grown)))
				binary.LittleEndian.PutUint32(grown[offRegions+4:], FixedLen+4) // 516 is 4B-aligned, NOT 8B-aligned
				binary.LittleEndian.PutUint32(grown[offImages+imgDataOff:], 8192)
				resealCRC(grown)
				return grown
			},
		},
		{
			name: "min_reader_major_too_new",
			mutate: func(b []byte) []byte {
				binary.LittleEndian.PutUint16(b[offMinReaderMajor:], VersionMajor+1)
				resealCRC(b)
				return b
			},
		},
		{
			name: "min_reader_minor_too_new",
			mutate: func(b []byte) []byte {
				binary.LittleEndian.PutUint16(b[offMinReaderMajor:], VersionMajor)
				binary.LittleEndian.PutUint16(b[offMinReaderMinor:], VersionMinor+1)
				resealCRC(b)
				return b
			},
		},
		{
			name: "inverted_hw_rev_range",
			mutate: func(b []byte) []byte {
				binary.LittleEndian.PutUint16(b[offHWRevMin:], 5)
				binary.LittleEndian.PutUint16(b[offHWRevMax:], 2)
				resealCRC(b)
				return b
			},
		},
		{
			name: "zero_stored_size",
			mutate: func(b []byte) []byte {
				binary.LittleEndian.PutUint32(b[offImages+imgStoredLen:], 0)
				resealCRC(b)
				return b
			},
		},
		{
			name: "image_payload_end_uint32_overflow",
			mutate: func(b []byte) []byte {
				binary.LittleEndian.PutUint32(b[offImages+imgDataOff:], math.MaxUint32-100)
				binary.LittleEndian.PutUint32(b[offImages+imgStoredLen:], 200)
				resealCRC(b)
				return b
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mut := tc.mutate(bytes.Clone(basePkg.Block))
			if err := ValidateBlock(mut); !errors.Is(err, ErrMalformedBlock) {
				t.Fatalf("ValidateBlock got %v, want ErrMalformedBlock", err)
			}
			if _, err := SignBlock(mut, signer); err == nil {
				t.Fatalf("SignBlock signed malformed block (%s)", tc.name)
			}
		})
	}

	// 3. Regression: ParseTrailerLocator bounds checks on standalone locator and full bundle.
	badLenLoc := EncodeTrailerLocator(4096, 100) // < FixedLen + SigLen (576)
	if _, _, err := ParseTrailerLocator(badLenLoc[:]); !errors.Is(err, ErrMalformedBlock) {
		t.Fatalf("expected ErrMalformedBlock on undersized tbm1Len locator, got %v", err)
	}

	oobBundle := make([]byte, 1024)
	oobLoc := EncodeTrailerLocator(4096, 576) // exceeds 1024-byte bundle
	copy(oobBundle[len(oobBundle)-TrailerLocatorLen:], oobLoc[:])
	if _, _, err := ParseTrailerLocator(oobBundle); !errors.Is(err, ErrMalformedBlock) {
		t.Fatalf("expected ErrMalformedBlock on out-of-bundle locator, got %v", err)
	}
}
