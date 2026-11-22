package tdr1_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"testing"

	"github.com/Toob-Boot/Toob-Loader/toob-go-lib/tdr1"
)

func sealTDR1CRC(b []byte) {
	if len(b) < tdr1.CRCTrailerSize {
		return
	}
	crcOff := len(b) - tdr1.CRCTrailerSize
	binary.LittleEndian.PutUint32(b[crcOff:], crc32.ChecksumIEEE(b[:crcOff]))
}

func verifyTDR1FrameOracle(t *testing.T, candidate []byte) {
	t.Helper()

	orig := bytes.Clone(candidate)
	repHeap, errHeap := tdr1.Parse(candidate)

	var repStack tdr1.Report
	errStack := tdr1.ParseInto(candidate, &repStack)

	if !bytes.Equal(candidate, orig) {
		t.Fatalf("Parse/ParseInto mutated caller slice")
	}
	if (errHeap == nil) != (errStack == nil) {
		t.Fatalf("Parse vs ParseInto error mismatch: Parse=%v ParseInto=%v", errHeap, errStack)
	}
	if errStack != nil {
		return
	}
	if repHeap != repStack {
		t.Fatalf("Parse vs ParseInto struct mismatch:\nheap:  %+v\nstack: %+v", repHeap, repStack)
	}

	// Structural & domain post-conditions that must hold for every accepted byte slice.
	if len(candidate) < tdr1.MinFrameSize {
		t.Fatalf("accepted frame shorter than MinFrameSize: %d", len(candidate))
	}
	if gotMagic := binary.LittleEndian.Uint32(candidate[0:4]); gotMagic != tdr1.Magic {
		t.Fatalf("accepted bad magic: 0x%08X", gotMagic)
	}
	if candidate[4] != tdr1.Version {
		t.Fatalf("accepted bad version: %d", candidate[4])
	}
	if candidate[5] != uint8(tdr1.PartitionApp) && candidate[5] != uint8(tdr1.PartitionRecovery) {
		t.Fatalf("accepted invalid partition: %d", candidate[5])
	}
	flags := binary.LittleEndian.Uint16(candidate[6:8])
	if (flags &^ tdr1.FlagExtHealth) != 0 {
		t.Fatalf("accepted unknown flags: 0x%04X", flags)
	}
	hdrSize := int(binary.LittleEndian.Uint16(candidate[8:10]))
	if hdrSize < tdr1.HeaderSize || ((hdrSize-tdr1.HeaderSize)%8) != 0 {
		t.Fatalf("accepted invalid header_size: %d", hdrSize)
	}
	if candidate[10] < tdr1.MinDiagMajor {
		t.Fatalf("accepted diag_major < 3: %d", candidate[10])
	}
	if candidate[11] > uint8(tdr1.BootStateTentative) {
		t.Fatalf("accepted invalid boot_state: %d", candidate[11])
	}
	if candidate[12] > 1 {
		t.Fatalf("accepted invalid active_slot: %d", candidate[12])
	}
	if candidate[13] > tdr1.MaxResetReason {
		t.Fatalf("accepted invalid reset_reason: %d", candidate[13])
	}
	if candidate[14] > 1 || candidate[15] > 1 {
		t.Fatalf("accepted non-canonical boolean: fallback=%d wipe=%d", candidate[14], candidate[15])
	}
	if candidate[16] > uint8(tdr1.OutcomeDeferred) {
		t.Fatalf("accepted invalid outcome: %d", candidate[16])
	}
	if binary.LittleEndian.Uint16(candidate[30:32]) != 0 {
		t.Fatalf("accepted non-zero reserved field: 0x%04X", binary.LittleEndian.Uint16(candidate[30:32]))
	}
	crcOff := len(candidate) - tdr1.CRCTrailerSize
	if crc32.ChecksumIEEE(candidate[:crcOff]) != binary.LittleEndian.Uint32(candidate[crcOff:]) {
		t.Fatalf("accepted frame with mismatched CRC-32")
	}

	// Re-encoding canonical bijection check.
	reencodedNil, err := tdr1.AppendEncode(nil, repStack)
	if err != nil {
		t.Fatalf("AppendEncode(nil) failed on accepted Report: %v", err)
	}
	var scratch [tdr1.MaxSize]byte
	reencodedBuf, err := tdr1.AppendEncode(scratch[:0], repStack)
	if err != nil {
		t.Fatalf("AppendEncode(scratch) failed on accepted Report: %v", err)
	}
	encodedHeap, err := tdr1.Encode(repStack)
	if err != nil {
		t.Fatalf("Encode failed on accepted Report: %v", err)
	}
	if !bytes.Equal(reencodedNil, reencodedBuf) || !bytes.Equal(reencodedNil, encodedHeap) {
		t.Fatalf("AppendEncode(nil) / AppendEncode(scratch) / Encode disagreed")
	}

	if allocs := testing.AllocsPerRun(1, func() {
		_, _ = tdr1.AppendEncode(scratch[:0], repStack)
		_ = tdr1.ParseInto(candidate, &repStack)
	}); allocs != 0 {
		t.Fatalf("expected 0 allocs/op on AppendEncode+ParseInto, got %v", allocs)
	}

	if hdrSize == tdr1.HeaderSize {
		if !bytes.Equal(reencodedNil, candidate) {
			t.Fatalf("canonical v1 bijection violated:\ngot:  %x\nwant: %x", reencodedNil, candidate)
		}
	} else {
		// Forward-compatible extended header (hdrSize > 132): canonical v1 projection must preserve
		// all v1 header fields + ExtHealth and be idempotent on re-parse.
		if !bytes.Equal(reencodedNil[0:8], candidate[0:8]) ||
			!bytes.Equal(reencodedNil[10:tdr1.HeaderSize], candidate[10:tdr1.HeaderSize]) {
			t.Fatalf("extended-header projection altered base header fields")
		}
		if repStack.HasExtHealth {
			gotExt := reencodedNil[tdr1.HeaderSize : tdr1.HeaderSize+tdr1.ExtHealthSize]
			wantExt := candidate[hdrSize : hdrSize+tdr1.ExtHealthSize]
			if !bytes.Equal(gotExt, wantExt) {
				t.Fatalf("extended-header projection altered ExtHealth")
			}
		}
		repProj, err := tdr1.Parse(reencodedNil)
		if err != nil || repProj != repStack {
			t.Fatalf("canonical projection re-parse mismatch: err=%v", err)
		}
	}

	// Single-bit flip anywhere in an accepted frame must be rejected (1-bit Hamming distance >= 2 of IEEE CRC-32).
	bitIdx := (len(candidate)*13 + int(candidate[17])) % (len(candidate) * 8)
	flipped := bytes.Clone(candidate)
	flipped[bitIdx/8] ^= 1 << (bitIdx % 8)
	if _, err := tdr1.Parse(flipped); err == nil {
		t.Fatalf("1-bit flip at bit %d was accepted", bitIdx)
	}
}

func FuzzTDR1CanonicalBijection(f *testing.F) {
	var sbom [32]byte
	for i := range sbom {
		sbom[i] = byte(0x10 + i)
	}
	baseRep := tdr1.Report{
		BootedPartition:    tdr1.PartitionApp,
		DiagMajor:          3,
		BootState:          tdr1.BootStateCommitted,
		ActiveSlot:         0,
		ResetReason:        1,
		FallbackOccurred:   false,
		WipeRequested:      false,
		LastUpdateOutcome:  tdr1.OutcomeNone,
		LastUpdateReject:   0,
		ActiveKeyIndex:     1,
		ReaderMajor:        2,
		ReaderMinor:        1,
		FWVerMajor:         1,
		FWVerMinor:         2,
		FWVerPatch:         3,
		CheckinSeq:         1,
		CurrentSVN:         4,
		BuildNumber:        100,
		InstalledAppSVN:    4,
		InstalledStage1SVN: 2,
		MonotonicCounter:   7,
		SBOMDigest:         sbom,
		BootSessionID:      99,
	}
	seed136, err := tdr1.Encode(baseRep)
	if err != nil {
		f.Fatalf("Encode 136B seed: %v", err)
	}

	extRep := baseRep
	extRep.BootedPartition = tdr1.PartitionRecovery
	extRep.BootState = tdr1.BootStateTentative
	extRep.ActiveSlot = 1
	extRep.ResetReason = tdr1.MaxResetReason
	extRep.FallbackOccurred = true
	extRep.WipeRequested = true
	extRep.LastUpdateOutcome = tdr1.OutcomeDeferred
	extRep.LastUpdateReject = 0xFE
	extRep.HasExtHealth = true
	extRep.ExtHealth = tdr1.ExtHealth{
		WALEraseCount:         11,
		AppSlotEraseCount:     22,
		StagingSlotEraseCount: 33,
		SwapBufferEraseCount:  44,
	}
	seed152, err := tdr1.Encode(extRep)
	if err != nil {
		f.Fatalf("Encode 152B seed: %v", err)
	}

	future160 := make([]byte, 0, 160)
	future160 = append(future160, seed152[:tdr1.HeaderSize]...)
	future160 = append(future160, make([]byte, 8)...)
	future160 = append(future160, seed152[tdr1.HeaderSize:tdr1.HeaderSize+tdr1.ExtHealthSize]...)
	future160 = append(future160, 0, 0, 0, 0)
	binary.LittleEndian.PutUint16(future160[8:10], 140)
	sealTDR1CRC(future160)

	badReserved := bytes.Clone(seed136)
	badReserved[30] = 1
	sealTDR1CRC(badReserved)

	badBool := bytes.Clone(seed136)
	badBool[14] = 2
	sealTDR1CRC(badBool)

	f.Add([]byte{})
	f.Add(seed136[:tdr1.MinFrameSize-1])
	f.Add(seed136)
	f.Add(seed152)
	f.Add(future160)
	f.Add(badReserved)
	f.Add(badBool)

	f.Fuzz(func(t *testing.T, b []byte) {
		// 1. Direct untrusted byte slice verification.
		verifyTDR1FrameOracle(t, b)

		// 2. CRC-sealed projection so coverage-guided fuzzing penetrates past the 32-bit CRC gate.
		if len(b) >= tdr1.MinFrameSize && len(b) <= 256 {
			crcSealed := bytes.Clone(b)
			sealTDR1CRC(crcSealed)
			verifyTDR1FrameOracle(t, crcSealed)
		}

		// 3. Structured header-framed candidate keeping all enum/reserved/boolean bytes fuzzer-driven.
		if len(b) >= tdr1.HeaderSize {
			hasExt := (b[0] & 1) != 0
			frameLen := tdr1.MinFrameSize
			if hasExt && len(b) >= tdr1.HeaderSize+tdr1.ExtHealthSize {
				frameLen = tdr1.MaxSize
			}
			synth := make([]byte, frameLen)
			copy(synth, b[:frameLen-tdr1.CRCTrailerSize])
			binary.LittleEndian.PutUint32(synth[0:4], tdr1.Magic)
			synth[4] = tdr1.Version
			if hasExt && frameLen == tdr1.MaxSize {
				binary.LittleEndian.PutUint16(synth[6:8], tdr1.FlagExtHealth)
			} else {
				binary.LittleEndian.PutUint16(synth[6:8], 0)
			}
			binary.LittleEndian.PutUint16(synth[8:10], uint16(tdr1.HeaderSize))
			sealTDR1CRC(synth)
			verifyTDR1FrameOracle(t, synth)
		}
	})
}

func TestTDR1ExhaustiveDomainBitFlipAndZeroAllocProperties(t *testing.T) {
	baseRep := tdr1.Report{
		BootedPartition:   tdr1.PartitionApp,
		DiagMajor:         3,
		BootState:         tdr1.BootStateCommitted,
		ActiveSlot:        1,
		ResetReason:       2,
		FallbackOccurred:  true,
		WipeRequested:     false,
		LastUpdateOutcome: tdr1.OutcomeApplied,
		CheckinSeq:        99,
		CurrentSVN:        5,
	}
	wire136, err := tdr1.Encode(baseRep)
	if err != nil {
		t.Fatalf("Encode 136B: %v", err)
	}

	extRep := baseRep
	extRep.HasExtHealth = true
	extRep.ExtHealth = tdr1.ExtHealth{
		WALEraseCount:         100,
		AppSlotEraseCount:     200,
		StagingSlotEraseCount: 300,
		SwapBufferEraseCount:  400,
	}
	wire152, err := tdr1.Encode(extRep)
	if err != nil {
		t.Fatalf("Encode 152B: %v", err)
	}

	// 1. Exhaustive 256-value domain sweeps on every constrained single-byte field.
	for v := range 256 {
		b := bytes.Clone(wire136)
		b[5] = byte(v)
		sealTDR1CRC(b)
		_, err := tdr1.Parse(b)
		wantOK := v == int(tdr1.PartitionApp) || v == int(tdr1.PartitionRecovery)
		if (err == nil) != wantOK {
			t.Fatalf("partition=%d: got err=%v, wantOK=%v", v, err, wantOK)
		}

		b = bytes.Clone(wire136)
		b[10] = byte(v)
		sealTDR1CRC(b)
		_, err = tdr1.Parse(b)
		wantOK = v >= int(tdr1.MinDiagMajor)
		if (err == nil) != wantOK {
			t.Fatalf("diag_major=%d: got err=%v, wantOK=%v", v, err, wantOK)
		}

		b = bytes.Clone(wire136)
		b[11] = byte(v)
		sealTDR1CRC(b)
		_, err = tdr1.Parse(b)
		wantOK = v <= int(tdr1.BootStateTentative)
		if (err == nil) != wantOK {
			t.Fatalf("boot_state=%d: got err=%v, wantOK=%v", v, err, wantOK)
		}

		b = bytes.Clone(wire136)
		b[12] = byte(v)
		sealTDR1CRC(b)
		_, err = tdr1.Parse(b)
		wantOK = v <= 1
		if (err == nil) != wantOK {
			t.Fatalf("active_slot=%d: got err=%v, wantOK=%v", v, err, wantOK)
		}

		b = bytes.Clone(wire136)
		b[13] = byte(v)
		sealTDR1CRC(b)
		_, err = tdr1.Parse(b)
		wantOK = v <= int(tdr1.MaxResetReason)
		if (err == nil) != wantOK {
			t.Fatalf("reset_reason=%d: got err=%v, wantOK=%v", v, err, wantOK)
		}

		for _, boolOff := range []int{14, 15} {
			b = bytes.Clone(wire136)
			b[boolOff] = byte(v)
			sealTDR1CRC(b)
			_, err = tdr1.Parse(b)
			wantOK = v <= 1
			if (err == nil) != wantOK {
				t.Fatalf("bool[off=%d]=%d: got err=%v, wantOK=%v", boolOff, v, err, wantOK)
			}
		}

		b = bytes.Clone(wire136)
		b[16] = byte(v)
		sealTDR1CRC(b)
		_, err = tdr1.Parse(b)
		wantOK = v <= int(tdr1.OutcomeDeferred)
		if (err == nil) != wantOK {
			t.Fatalf("outcome=%d: got err=%v, wantOK=%v", v, err, wantOK)
		}
	}

	// 2. Exhaustive 16-bit reserved & unknown-flag bit rejection.
	for bit := range 16 {
		b := bytes.Clone(wire136)
		binary.LittleEndian.PutUint16(b[30:32], uint16(1<<bit))
		sealTDR1CRC(b)
		if _, err := tdr1.Parse(b); !errors.Is(err, tdr1.ErrNonZeroReserved) {
			t.Fatalf("reserved bit %d: expected ErrNonZeroReserved, got %v", bit, err)
		}
		if bit >= 1 {
			b = bytes.Clone(wire136)
			binary.LittleEndian.PutUint16(b[6:8], uint16(1<<bit))
			sealTDR1CRC(b)
			if _, err := tdr1.Parse(b); !errors.Is(err, tdr1.ErrUnknownFlags) {
				t.Fatalf("flag bit %d: expected ErrUnknownFlags, got %v", bit, err)
			}
		}
	}

	// 3. Exhaustive 1-bit flip across ALL bits of 136B and 152B canonical frames.
	for _, frame := range [][]byte{wire136, wire152} {
		for bit := range len(frame) * 8 {
			corrupt := bytes.Clone(frame)
			corrupt[bit/8] ^= 1 << (bit % 8)
			if _, err := tdr1.Parse(corrupt); err == nil {
				t.Fatalf("len=%d bit=%d flip was accepted", len(frame), bit)
			}
		}
	}

	// 4. Strict 0 allocs/op on ParseInto and AppendEncode for both 136B and 152B frames.
	var scratch [tdr1.MaxSize]byte
	var dst tdr1.Report
	for _, rep := range []tdr1.Report{baseRep, extRep} {
		var wire []byte
		encAllocs := testing.AllocsPerRun(100, func() {
			var encErr error
			wire, encErr = tdr1.AppendEncode(scratch[:0], rep)
			if encErr != nil {
				t.Fatalf("AppendEncode: %v", encErr)
			}
		})
		if encAllocs != 0 {
			t.Fatalf("HasExt=%v: AppendEncode allocated %v allocs/op (want 0)", rep.HasExtHealth, encAllocs)
		}
		decAllocs := testing.AllocsPerRun(100, func() {
			if decErr := tdr1.ParseInto(wire, &dst); decErr != nil {
				t.Fatalf("ParseInto: %v", decErr)
			}
		})
		if decAllocs != 0 {
			t.Fatalf("HasExt=%v: ParseInto allocated %v allocs/op (want 0)", rep.HasExtHealth, decAllocs)
		}
		if !bytes.Equal(wire, scratch[:len(wire)]) || dst != rep {
			t.Fatalf("zero-alloc roundtrip mismatch")
		}
	}
}
