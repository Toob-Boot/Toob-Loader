package tdr1

import (
	"encoding/binary"
	"hash/crc32"
)

// AppendEncode serializes rep into canonical TDR1 wire format appended to dst.
// Performs zero heap allocations when cap(dst)-len(dst) >= 136 (or 152 with ExtHealth).
func AppendEncode(dst []byte, rep Report) ([]byte, error) {
	diagMajor := rep.DiagMajor
	if diagMajor == 0 {
		diagMajor = MinDiagMajor
	}
	if err := validateDomain(
		rep.BootedPartition,
		diagMajor,
		rep.BootState,
		rep.ActiveSlot,
		rep.ResetReason,
		rep.LastUpdateOutcome,
	); err != nil {
		return nil, err
	}

	frameLen := MinFrameSize
	var flags uint16
	if rep.HasExtHealth {
		frameLen = MaxSize
		flags |= FlagExtHealth
	}

	start := len(dst)
	if cap(dst)-start >= frameLen {
		dst = dst[:start+frameLen]
		clear(dst[start:])
	} else {
		grown := make([]byte, start+frameLen)
		copy(grown, dst)
		dst = grown
	}
	buf := dst[start:]

	binary.LittleEndian.PutUint32(buf[0:4], Magic)
	buf[4] = Version
	buf[5] = uint8(rep.BootedPartition)
	binary.LittleEndian.PutUint16(buf[6:8], flags)
	binary.LittleEndian.PutUint16(buf[8:10], uint16(HeaderSize))
	buf[10] = diagMajor
	buf[11] = uint8(rep.BootState)
	buf[12] = rep.ActiveSlot
	buf[13] = rep.ResetReason
	if rep.FallbackOccurred {
		buf[14] = 1
	}
	if rep.WipeRequested {
		buf[15] = 1
	}
	buf[16] = uint8(rep.LastUpdateOutcome)
	buf[17] = rep.LastUpdateReject
	binary.LittleEndian.PutUint16(buf[18:20], rep.ActiveKeyIndex)
	binary.LittleEndian.PutUint16(buf[20:22], rep.ReaderMajor)
	binary.LittleEndian.PutUint16(buf[22:24], rep.ReaderMinor)
	binary.LittleEndian.PutUint16(buf[24:26], rep.FWVerMajor)
	binary.LittleEndian.PutUint16(buf[26:28], rep.FWVerMinor)
	binary.LittleEndian.PutUint16(buf[28:30], rep.FWVerPatch)
	binary.LittleEndian.PutUint16(buf[30:32], 0)
	binary.LittleEndian.PutUint64(buf[32:40], rep.CheckinSeq)
	binary.LittleEndian.PutUint32(buf[40:44], rep.CurrentSVN)
	binary.LittleEndian.PutUint32(buf[44:48], rep.BuildNumber)
	binary.LittleEndian.PutUint32(buf[48:52], rep.InstalledAppSVN)
	binary.LittleEndian.PutUint32(buf[52:56], rep.InstalledStage1SVN)
	binary.LittleEndian.PutUint32(buf[56:60], rep.MonotonicCounter)
	binary.LittleEndian.PutUint32(buf[60:64], rep.BootDurationMS)
	binary.LittleEndian.PutUint32(buf[64:68], rep.VerifyTimeMS)
	binary.LittleEndian.PutUint32(buf[68:72], rep.LastErrorCode)
	binary.LittleEndian.PutUint32(buf[72:76], rep.VendorError)
	binary.LittleEndian.PutUint32(buf[76:80], rep.HardwareFaultRecord)
	binary.LittleEndian.PutUint32(buf[80:84], rep.EdgeRecoveryEvents)
	binary.LittleEndian.PutUint32(buf[84:88], rep.RecoveryFailureEvents)
	binary.LittleEndian.PutUint32(buf[88:92], rep.NetSearchAccumMS)
	binary.LittleEndian.PutUint32(buf[92:96], rep.WDTKicks)
	copy(buf[96:128], rep.SBOMDigest[:])
	binary.LittleEndian.PutUint32(buf[128:132], rep.BootSessionID)

	if rep.HasExtHealth {
		ext := buf[HeaderSize : HeaderSize+ExtHealthSize]
		binary.LittleEndian.PutUint32(ext[0:4], rep.ExtHealth.WALEraseCount)
		binary.LittleEndian.PutUint32(ext[4:8], rep.ExtHealth.AppSlotEraseCount)
		binary.LittleEndian.PutUint32(ext[8:12], rep.ExtHealth.StagingSlotEraseCount)
		binary.LittleEndian.PutUint32(ext[12:16], rep.ExtHealth.SwapBufferEraseCount)
	}

	crcOff := frameLen - CRCTrailerSize
	crc := crc32.ChecksumIEEE(buf[:crcOff])
	binary.LittleEndian.PutUint32(buf[crcOff:], crc)

	return dst, nil
}

// Encode serializes rep into a newly allocated canonical TDR1 wire frame (136 B or 152 B).
func Encode(rep Report) ([]byte, error) {
	capHint := MinFrameSize
	if rep.HasExtHealth {
		capHint = MaxSize
	}
	return AppendEncode(make([]byte, 0, capHint), rep)
}
