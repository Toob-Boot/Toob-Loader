// Package tdr1 implements the canonical fixed-offset binary wire format for
// Toob Diagnostic Reports v1 (TDR1, MCU -> Cloud check-in telemetry).
//
// Wire layout mirrors common/include/toob_checkin_wire.h byte-for-byte:
//   - [0 .. header_size)                 : 132-byte little-endian base header
//   - [header_size .. header_size + 16)  : Optional 16-byte flash wear block (FlagExtHealth)
//   - [total_len - 4 .. total_len)       : Single-pass IEEE 802.3 CRC-32 trailer
package tdr1

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
)

// Wire framing constants matching common/include/toob_checkin_wire.h.
const (
	Magic          uint32 = 0x31524454 // "TDR1" in little-endian
	Version        uint8  = 1
	MinDiagMajor   uint8  = 3
	HeaderSize     int    = 132
	ExtHealthSize  int    = 16
	CRCTrailerSize int    = 4
	MinFrameSize   int    = HeaderSize + CRCTrailerSize                 // 136 bytes
	MaxSize        int    = HeaderSize + ExtHealthSize + CRCTrailerSize // 152 bytes

	FlagExtHealth  uint16 = 1 << 0
	knownFlagsMask uint16 = FlagExtHealth

	MaxResetReason uint8 = 6
)

// Partition identifies the booted execution slot reported by Stage 1.
type Partition uint8

const (
	PartitionApp      Partition = 0
	PartitionRecovery Partition = 2
)

// BootState identifies whether the running slot is committed or still tentative.
type BootState uint8

const (
	BootStateCommitted BootState = 0
	BootStateTentative BootState = 1
)

// UpdateOutcome classifies the last Stage 1 update disposition.
type UpdateOutcome uint8

const (
	OutcomeNone     UpdateOutcome = 0
	OutcomeApplied  UpdateOutcome = 1
	OutcomeRejected UpdateOutcome = 2
	OutcomeReverted UpdateOutcome = 3
	OutcomeDeferred UpdateOutcome = 4
)

// Sentinel errors returned by Parse, ParseInto, Encode, and AppendEncode.
var (
	ErrTruncated          = errors.New("tdr1: buffer shorter than minimum 136-byte frame")
	ErrBadMagic           = errors.New("tdr1: invalid magic (expected 'TDR1' 0x31524454)")
	ErrUnsupportedVersion = errors.New("tdr1: unsupported wire version")
	ErrUnknownFlags       = errors.New("tdr1: unknown flags bit set")
	ErrInvalidHeaderSize  = errors.New("tdr1: invalid header_size")
	ErrInvalidDiagMajor   = errors.New("tdr1: diag_major must be >= 3")
	ErrInvalidPartition   = errors.New("tdr1: invalid booted_partition (expected 0=App or 2=Recovery)")
	ErrInvalidBootState   = errors.New("tdr1: invalid boot_state (expected 0=Committed or 1=Tentative)")
	ErrInvalidActiveSlot  = errors.New("tdr1: invalid active_slot (expected 0 or 1)")
	ErrInvalidResetReason = errors.New("tdr1: invalid reset_reason (expected 0..6)")
	ErrNonCanonicalBool   = errors.New("tdr1: non-canonical boolean byte (expected 0 or 1)")
	ErrInvalidOutcome     = errors.New("tdr1: invalid last_update_outcome (expected 0..4)")
	ErrNonZeroReserved    = errors.New("tdr1: non-zero reserved header field")
	ErrLengthMismatch     = errors.New("tdr1: payload length does not match header_size + flags + 4B CRC")
	ErrCRCMismatch        = errors.New("tdr1: CRC-32 trailer mismatch")
	ErrNilDestination     = errors.New("tdr1: nil destination report pointer")
)

// ExtHealth holds optional NOR flash erase-cycle telemetry.
type ExtHealth struct {
	WALEraseCount         uint32
	AppSlotEraseCount     uint32
	StagingSlotEraseCount uint32
	SwapBufferEraseCount  uint32
}

// Report represents a decoded TDR1 diagnostic report from an MCU check-in.
type Report struct {
	BootedPartition       Partition
	DiagMajor             uint8
	BootState             BootState
	ActiveSlot            uint8
	ResetReason           uint8
	FallbackOccurred      bool
	WipeRequested         bool
	LastUpdateOutcome     UpdateOutcome
	LastUpdateReject      uint8
	ActiveKeyIndex        uint16
	ReaderMajor           uint16
	ReaderMinor           uint16
	FWVerMajor            uint16
	FWVerMinor            uint16
	FWVerPatch            uint16
	CheckinSeq            uint64
	CurrentSVN            uint32
	BuildNumber           uint32
	InstalledAppSVN       uint32
	InstalledStage1SVN    uint32
	MonotonicCounter      uint32
	BootDurationMS        uint32
	VerifyTimeMS          uint32
	LastErrorCode         uint32
	VendorError           uint32
	HardwareFaultRecord   uint32
	EdgeRecoveryEvents    uint32
	RecoveryFailureEvents uint32
	NetSearchAccumMS      uint32
	WDTKicks              uint32
	SBOMDigest            [32]byte
	BootSessionID         uint32
	HasExtHealth          bool
	ExtHealth             ExtHealth
}

func validateDomain(
	part Partition,
	diagMajor uint8,
	bootState BootState,
	activeSlot uint8,
	resetReason uint8,
	outcome UpdateOutcome,
) error {
	if part != PartitionApp && part != PartitionRecovery {
		return fmt.Errorf("%w: got %d", ErrInvalidPartition, part)
	}
	if diagMajor < MinDiagMajor {
		return fmt.Errorf("%w: got %d", ErrInvalidDiagMajor, diagMajor)
	}
	if bootState != BootStateCommitted && bootState != BootStateTentative {
		return fmt.Errorf("%w: got %d", ErrInvalidBootState, bootState)
	}
	if activeSlot > 1 {
		return fmt.Errorf("%w: got %d", ErrInvalidActiveSlot, activeSlot)
	}
	if resetReason > MaxResetReason {
		return fmt.Errorf("%w: got %d", ErrInvalidResetReason, resetReason)
	}
	if outcome > OutcomeDeferred {
		return fmt.Errorf("%w: got %d", ErrInvalidOutcome, outcome)
	}
	return nil
}

// ParseInto decodes and CRC-verifies a canonical TDR1 wire frame into dst with zero heap allocations.
func ParseInto(data []byte, dst *Report) error {
	if dst == nil {
		return ErrNilDestination
	}
	if len(data) < MinFrameSize {
		return fmt.Errorf("%w: got %d bytes", ErrTruncated, len(data))
	}

	magic := binary.LittleEndian.Uint32(data[0:4])
	if magic != Magic {
		return fmt.Errorf("%w: got 0x%08X", ErrBadMagic, magic)
	}
	if ver := data[4]; ver != Version {
		return fmt.Errorf("%w: got %d", ErrUnsupportedVersion, ver)
	}

	flags := binary.LittleEndian.Uint16(data[6:8])
	if (flags &^ knownFlagsMask) != 0 {
		return fmt.Errorf("%w: 0x%04X", ErrUnknownFlags, flags)
	}

	hdrSize := int(binary.LittleEndian.Uint16(data[8:10]))
	if hdrSize < HeaderSize || ((hdrSize-HeaderSize)%8) != 0 || hdrSize > len(data)-CRCTrailerSize {
		return fmt.Errorf("%w: %d (payload=%d)", ErrInvalidHeaderSize, hdrSize, len(data))
	}

	hasExt := (flags & FlagExtHealth) != 0
	expectedLen := hdrSize + CRCTrailerSize
	if hasExt {
		expectedLen += ExtHealthSize
	}
	if len(data) != expectedLen {
		return fmt.Errorf("%w: got %d, want %d", ErrLengthMismatch, len(data), expectedLen)
	}

	if reserved := binary.LittleEndian.Uint16(data[30:32]); reserved != 0 {
		return fmt.Errorf("%w: 0x%04X", ErrNonZeroReserved, reserved)
	}

	part := Partition(data[5])
	diagMajor := data[10]
	bootState := BootState(data[11])
	activeSlot := data[12]
	resetReason := data[13]
	fallbackRaw := data[14]
	wipeRaw := data[15]
	outcome := UpdateOutcome(data[16])

	if fallbackRaw > 1 || wipeRaw > 1 {
		return fmt.Errorf("%w: fallback=%d wipe=%d", ErrNonCanonicalBool, fallbackRaw, wipeRaw)
	}
	if err := validateDomain(part, diagMajor, bootState, activeSlot, resetReason, outcome); err != nil {
		return err
	}

	crcOff := len(data) - CRCTrailerSize
	wantCRC := binary.LittleEndian.Uint32(data[crcOff:])
	gotCRC := crc32.ChecksumIEEE(data[:crcOff])
	if gotCRC != wantCRC {
		return fmt.Errorf("%w: got 0x%08X, want 0x%08X", ErrCRCMismatch, gotCRC, wantCRC)
	}

	*dst = Report{
		BootedPartition:       part,
		DiagMajor:             diagMajor,
		BootState:             bootState,
		ActiveSlot:            activeSlot,
		ResetReason:           resetReason,
		FallbackOccurred:      fallbackRaw == 1,
		WipeRequested:         wipeRaw == 1,
		LastUpdateOutcome:     outcome,
		LastUpdateReject:      data[17],
		ActiveKeyIndex:        binary.LittleEndian.Uint16(data[18:20]),
		ReaderMajor:           binary.LittleEndian.Uint16(data[20:22]),
		ReaderMinor:           binary.LittleEndian.Uint16(data[22:24]),
		FWVerMajor:            binary.LittleEndian.Uint16(data[24:26]),
		FWVerMinor:            binary.LittleEndian.Uint16(data[26:28]),
		FWVerPatch:            binary.LittleEndian.Uint16(data[28:30]),
		CheckinSeq:            binary.LittleEndian.Uint64(data[32:40]),
		CurrentSVN:            binary.LittleEndian.Uint32(data[40:44]),
		BuildNumber:           binary.LittleEndian.Uint32(data[44:48]),
		InstalledAppSVN:       binary.LittleEndian.Uint32(data[48:52]),
		InstalledStage1SVN:    binary.LittleEndian.Uint32(data[52:56]),
		MonotonicCounter:      binary.LittleEndian.Uint32(data[56:60]),
		BootDurationMS:        binary.LittleEndian.Uint32(data[60:64]),
		VerifyTimeMS:          binary.LittleEndian.Uint32(data[64:68]),
		LastErrorCode:         binary.LittleEndian.Uint32(data[68:72]),
		VendorError:           binary.LittleEndian.Uint32(data[72:76]),
		HardwareFaultRecord:   binary.LittleEndian.Uint32(data[76:80]),
		EdgeRecoveryEvents:    binary.LittleEndian.Uint32(data[80:84]),
		RecoveryFailureEvents: binary.LittleEndian.Uint32(data[84:88]),
		NetSearchAccumMS:      binary.LittleEndian.Uint32(data[88:92]),
		WDTKicks:              binary.LittleEndian.Uint32(data[92:96]),
		BootSessionID:         binary.LittleEndian.Uint32(data[128:132]),
		HasExtHealth:          hasExt,
	}
	copy(dst.SBOMDigest[:], data[96:128])

	if hasExt {
		ext := data[hdrSize : hdrSize+ExtHealthSize]
		dst.ExtHealth = ExtHealth{
			WALEraseCount:         binary.LittleEndian.Uint32(ext[0:4]),
			AppSlotEraseCount:     binary.LittleEndian.Uint32(ext[4:8]),
			StagingSlotEraseCount: binary.LittleEndian.Uint32(ext[8:12]),
			SwapBufferEraseCount:  binary.LittleEndian.Uint32(ext[12:16]),
		}
	}

	return nil
}

// Parse decodes and CRC-verifies a canonical TDR1 wire frame.
func Parse(data []byte) (Report, error) {
	var rep Report
	if err := ParseInto(data, &rep); err != nil {
		return Report{}, err
	}
	return rep, nil
}
