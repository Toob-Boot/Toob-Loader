package tci1_test

import (
	"errors"
	"reflect"
	"testing"

	"github.com/Toob-Boot/Toob-Loader/toob-go-lib/tci1"
)

func TestRoundTrip_UpdateAndControlOnlyAndRejections(t *testing.T) {
	key := testKey()
	devID := testDeviceID()
	var sha [32]byte
	var asgn [16]byte
	var rot [32]byte
	for i := range sha {
		sha[i] = byte(0x21 + i)
		rot[i] = byte(0x81 + i)
	}
	for i := range asgn {
		asgn[i] = byte(0x50 + i)
	}

	// 1. Update + RotatedToken + CloudCommand
	inUpdate := tci1.Manifest{
		TargetSlot:      tci1.SlotApp,
		SVN:             12,
		RemoteBuild:     1200,
		TotalSize:       65536,
		SHA256:          sha,
		AssignmentID:    asgn,
		SeqEcho:         42,
		RetryAfterSec:   1800,
		BlobPath:        "/v1/blobs/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		HasRotatedToken: true,
		RotatedToken:    rot,
		CloudCommand:    makeValidTCC1(144),
	}
	wireUpd, err := tci1.Encode(inUpdate, key, devID)
	if err != nil {
		t.Fatalf("Encode update: %v", err)
	}
	gotUpd, err := tci1.Parse(wireUpd, key, devID, 42)
	if err != nil {
		t.Fatalf("Parse update: %v", err)
	}
	if !reflect.DeepEqual(gotUpd, inUpdate) {
		t.Fatalf("update round-trip mismatch:\ngot:  %+v\nwant: %+v", gotUpd, inUpdate)
	}

	// 2. Control-only (Token rotation + TCC1 without firmware update)
	inCtrl := tci1.Manifest{
		SeqEcho:         43,
		RetryAfterSec:   3600,
		HasRotatedToken: true,
		RotatedToken:    rot,
		CloudCommand:    makeValidTCC1(128),
	}
	wireCtrl, err := tci1.Encode(inCtrl, key, devID)
	if err != nil {
		t.Fatalf("Encode control-only: %v", err)
	}
	gotCtrl, err := tci1.Parse(wireCtrl, key, devID, 43)
	if err != nil {
		t.Fatalf("Parse control-only: %v", err)
	}
	if !reflect.DeepEqual(gotCtrl, inCtrl) {
		t.Fatalf("control-only mismatch:\ngot:  %+v\nwant: %+v", gotCtrl, inCtrl)
	}

	// 3. Domain rejections
	if _, err := tci1.Encode(tci1.Manifest{SeqEcho: 1}, key, devID); !errors.Is(err, tci1.ErrEmptyControlManifest) {
		t.Fatalf("expected ErrEmptyControlManifest, got %v", err)
	}
	badSlot := inUpdate
	badSlot.TargetSlot = tci1.Slot(2) // SlotRecovery prohibited for OTA!
	if _, err := tci1.Encode(badSlot, key, devID); !errors.Is(err, tci1.ErrInvalidSlot) {
		t.Fatalf("expected ErrInvalidSlot for Slot(2), got %v", err)
	}
	undersizedTBM1 := inUpdate
	undersizedTBM1.TotalSize = 575
	if _, err := tci1.Encode(undersizedTBM1, key, devID); !errors.Is(err, tci1.ErrInvalidUpdateFields) {
		t.Fatalf("expected ErrInvalidUpdateFields, got %v", err)
	}
}

func TestZeroAlloc_AppendEncodeAndParseView(t *testing.T) {
	key := testKey()
	devID := testDeviceID()
	var sha [32]byte
	var asgn [16]byte
	sha[0] = 0xAA
	asgn[0] = 0xBB

	m := tci1.Manifest{
		TargetSlot:    tci1.SlotApp,
		SVN:           3,
		RemoteBuild:   30,
		TotalSize:     4096,
		SHA256:        sha,
		AssignmentID:  asgn,
		SeqEcho:       7,
		RetryAfterSec: 3600,
		BlobPath:      "/v1/blobs/app_v3.tbm1",
	}

	var scratch [tci1.MaxFrameSize]byte
	var view tci1.Manifest

	encAllocs := testing.AllocsPerRun(100, func() {
		out, err := tci1.AppendEncode(scratch[:0], m, key, devID)
		if err != nil || len(out) == 0 {
			t.Fatalf("AppendEncode failed: %v", err)
		}
	})
	if encAllocs != 0 {
		t.Fatalf("expected 0 allocs in AppendEncode, got %v", encAllocs)
	}

	wire, _ := tci1.AppendEncode(scratch[:0], m, key, devID)
	decAllocs := testing.AllocsPerRun(100, func() {
		if err := tci1.ParseView(wire, key, devID, 7, &view); err != nil {
			t.Fatalf("ParseView failed: %v", err)
		}
	})
	if decAllocs != 0 {
		t.Fatalf("expected 0 allocs in ParseView, got %v", decAllocs)
	}
}
