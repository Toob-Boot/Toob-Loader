package tdr1_test

import (
	"encoding/binary"
	"testing"

	"github.com/Toob-Boot/Toob-Loader/toob-go-lib/tdr1"
)

func TestRoundTrip_BaseAndExtendedAndForwardCompat(t *testing.T) {
	var sbom [32]byte
	for i := range sbom {
		sbom[i] = byte(0xA0 + i)
	}

	in := tdr1.Report{
		BootedPartition:       tdr1.PartitionRecovery,
		DiagMajor:             3,
		BootState:             tdr1.BootStateTentative,
		ActiveSlot:            1,
		ResetReason:           3,
		FallbackOccurred:      true,
		WipeRequested:         true,
		LastUpdateOutcome:     tdr1.OutcomeReverted,
		LastUpdateReject:      0x42,
		ActiveKeyIndex:        2,
		ReaderMajor:           2,
		ReaderMinor:           1,
		FWVerMajor:            3,
		FWVerMinor:            4,
		FWVerPatch:            5,
		CheckinSeq:            0x0102030405060708,
		CurrentSVN:            17,
		BuildNumber:           304,
		InstalledAppSVN:       18,
		InstalledStage1SVN:    5,
		MonotonicCounter:      99,
		BootDurationMS:        48,
		VerifyTimeMS:          19,
		LastErrorCode:         0xE1100004,
		VendorError:           0x1234,
		HardwareFaultRecord:   0xCAFEBABE,
		EdgeRecoveryEvents:    2,
		RecoveryFailureEvents: 3,
		NetSearchAccumMS:      4200,
		WDTKicks:              11,
		SBOMDigest:            sbom,
		BootSessionID:         777,
		HasExtHealth:          false,
	}

	wire136, err := tdr1.Encode(in)
	if err != nil {
		t.Fatalf("Encode 136B: %v", err)
	}
	if len(wire136) != tdr1.MinFrameSize {
		t.Fatalf("expected 136 bytes, got %d", len(wire136))
	}
	gotBase, err := tdr1.Parse(wire136)
	if err != nil {
		t.Fatalf("Parse 136B: %v", err)
	}
	if gotBase != in {
		t.Fatalf("136B round-trip mismatch:\ngot:  %+v\nwant: %+v", gotBase, in)
	}

	in.HasExtHealth = true
	in.ExtHealth = tdr1.ExtHealth{
		WALEraseCount:         10,
		AppSlotEraseCount:     20,
		StagingSlotEraseCount: 30,
		SwapBufferEraseCount:  40,
	}
	wire152, err := tdr1.Encode(in)
	if err != nil {
		t.Fatalf("Encode 152B: %v", err)
	}
	if len(wire152) != tdr1.MaxSize {
		t.Fatalf("expected 152 bytes, got %d", len(wire152))
	}
	gotExt, err := tdr1.Parse(wire152)
	if err != nil {
		t.Fatalf("Parse 152B: %v", err)
	}
	if gotExt != in {
		t.Fatalf("152B round-trip mismatch:\ngot:  %+v\nwant: %+v", gotExt, in)
	}

	// Verify 8-byte-aligned future header extension (header_size = 140) preserves ExtHealth offset.
	future := make([]byte, 0, 140+tdr1.ExtHealthSize+tdr1.CRCTrailerSize)
	future = append(future, wire152[:tdr1.HeaderSize]...)
	future = append(future, make([]byte, 8)...)
	future = append(future, wire152[tdr1.HeaderSize:tdr1.HeaderSize+tdr1.ExtHealthSize]...)
	future = append(future, 0, 0, 0, 0)
	binary.LittleEndian.PutUint16(future[8:10], 140)
	reSealCRC(future)

	gotFuture, err := tdr1.Parse(future)
	if err != nil {
		t.Fatalf("Parse future 140B header: %v", err)
	}
	if gotFuture != in {
		t.Fatalf("future header mismatch:\ngot:  %+v\nwant: %+v", gotFuture, in)
	}
}

func TestZeroAlloc_AppendEncodeAndParseInto(t *testing.T) {
	rep := tdr1.Report{
		BootedPartition:   tdr1.PartitionApp,
		DiagMajor:         3,
		BootState:         tdr1.BootStateCommitted,
		ActiveSlot:        0,
		LastUpdateOutcome: tdr1.OutcomeApplied,
		CheckinSeq:        5,
		CurrentSVN:        10,
		BuildNumber:       100,
		InstalledAppSVN:   10,
		HasExtHealth:      true,
		ExtHealth:         tdr1.ExtHealth{WALEraseCount: 1},
	}

	var scratch [tdr1.MaxSize]byte
	var parsed tdr1.Report

	encAllocs := testing.AllocsPerRun(100, func() {
		out, err := tdr1.AppendEncode(scratch[:0], rep)
		if err != nil || len(out) != tdr1.MaxSize {
			t.Fatalf("AppendEncode failed: %v", err)
		}
	})
	if encAllocs != 0 {
		t.Fatalf("expected 0 allocs in AppendEncode, got %v", encAllocs)
	}

	wire, _ := tdr1.AppendEncode(scratch[:0], rep)
	decAllocs := testing.AllocsPerRun(100, func() {
		if err := tdr1.ParseInto(wire, &parsed); err != nil {
			t.Fatalf("ParseInto failed: %v", err)
		}
	})
	if decAllocs != 0 {
		t.Fatalf("expected 0 allocs in ParseInto, got %v", decAllocs)
	}
}
