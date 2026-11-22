package tdr1_test

import (
	"encoding/binary"
	"errors"
	"hash/crc32"
	"testing"

	"github.com/Toob-Boot/Toob-Loader/toob-go-lib/tdr1"
)

func reSealCRC(b []byte) {
	crcOff := len(b) - tdr1.CRCTrailerSize
	binary.LittleEndian.PutUint32(b[crcOff:], crc32.ChecksumIEEE(b[:crcOff]))
}

func TestParse_StrictDomainAndCorruptionRejections(t *testing.T) {
	base, err := tdr1.Encode(tdr1.Report{
		BootedPartition:       tdr1.PartitionApp,
		DiagMajor:             3,
		BootState:             tdr1.BootStateCommitted,
		ActiveSlot:            1,
		ResetReason:           3,
		FallbackOccurred:      false,
		WipeRequested:         false,
		LastUpdateOutcome:     tdr1.OutcomeApplied,
		LastUpdateReject:      0,
		ActiveKeyIndex:        1,
		ReaderMajor:           2,
		ReaderMinor:           1,
		FWVerMajor:            2,
		FWVerMinor:            0,
		FWVerPatch:            4,
		CheckinSeq:            42,
		CurrentSVN:            12,
		BuildNumber:           204,
		InstalledAppSVN:       12,
		InstalledStage1SVN:    3,
		MonotonicCounter:      9,
		RecoveryFailureEvents: 0,
		NetSearchAccumMS:      150,
	})
	if err != nil {
		t.Fatalf("Encode base: %v", err)
	}

	if err := tdr1.ParseInto(base, nil); !errors.Is(err, tdr1.ErrNilDestination) {
		t.Fatalf("expected ErrNilDestination, got %v", err)
	}
	if _, err := tdr1.Parse(base[:tdr1.MinFrameSize-1]); !errors.Is(err, tdr1.ErrTruncated) {
		t.Fatalf("expected ErrTruncated, got %v", err)
	}

	cases := []struct {
		name    string
		mutate  func([]byte) []byte
		wantErr error
	}{
		{
			name: "bad_magic",
			mutate: func(b []byte) []byte {
				b[0] ^= 0xFF
				reSealCRC(b)
				return b
			},
			wantErr: tdr1.ErrBadMagic,
		},
		{
			name: "bad_version",
			mutate: func(b []byte) []byte {
				b[4] = 2
				reSealCRC(b)
				return b
			},
			wantErr: tdr1.ErrUnsupportedVersion,
		},
		{
			name: "invalid_partition_1",
			mutate: func(b []byte) []byte {
				b[5] = 1
				reSealCRC(b)
				return b
			},
			wantErr: tdr1.ErrInvalidPartition,
		},
		{
			name: "unknown_flag",
			mutate: func(b []byte) []byte {
				binary.LittleEndian.PutUint16(b[6:8], 0x0002)
				reSealCRC(b)
				return b
			},
			wantErr: tdr1.ErrUnknownFlags,
		},
		{
			name: "unaligned_header_size",
			mutate: func(b []byte) []byte {
				grown := make([]byte, tdr1.HeaderSize+4+tdr1.CRCTrailerSize)
				copy(grown, b[:tdr1.HeaderSize])
				binary.LittleEndian.PutUint16(grown[8:10], uint16(tdr1.HeaderSize+4))
				reSealCRC(grown)
				return grown
			},
			wantErr: tdr1.ErrInvalidHeaderSize,
		},
		{
			name: "diag_major_below_3",
			mutate: func(b []byte) []byte {
				b[10] = 2
				reSealCRC(b)
				return b
			},
			wantErr: tdr1.ErrInvalidDiagMajor,
		},
		{
			name: "invalid_boot_state",
			mutate: func(b []byte) []byte {
				b[11] = 2
				reSealCRC(b)
				return b
			},
			wantErr: tdr1.ErrInvalidBootState,
		},
		{
			name: "invalid_active_slot",
			mutate: func(b []byte) []byte {
				b[12] = 2
				reSealCRC(b)
				return b
			},
			wantErr: tdr1.ErrInvalidActiveSlot,
		},
		{
			name: "invalid_reset_reason",
			mutate: func(b []byte) []byte {
				b[13] = 7
				reSealCRC(b)
				return b
			},
			wantErr: tdr1.ErrInvalidResetReason,
		},
		{
			name: "non_canonical_bool",
			mutate: func(b []byte) []byte {
				b[14] = 2
				reSealCRC(b)
				return b
			},
			wantErr: tdr1.ErrNonCanonicalBool,
		},
		{
			name: "invalid_outcome",
			mutate: func(b []byte) []byte {
				b[16] = 5
				reSealCRC(b)
				return b
			},
			wantErr: tdr1.ErrInvalidOutcome,
		},
		{
			name: "non_zero_reserved",
			mutate: func(b []byte) []byte {
				b[30] = 1
				reSealCRC(b)
				return b
			},
			wantErr: tdr1.ErrNonZeroReserved,
		},
		{
			name: "trailing_garbage",
			mutate: func(b []byte) []byte {
				return append(b, 0x00)
			},
			wantErr: tdr1.ErrLengthMismatch,
		},
		{
			name: "corrupted_payload_crc",
			mutate: func(b []byte) []byte {
				b[44] ^= 0x01
				return b
			},
			wantErr: tdr1.ErrCRCMismatch,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cp := append([]byte(nil), base...)
			mut := tc.mutate(cp)
			if _, err := tdr1.Parse(mut); !errors.Is(err, tc.wantErr) {
				t.Fatalf("got err=%v, want %v", err, tc.wantErr)
			}
		})
	}
}
