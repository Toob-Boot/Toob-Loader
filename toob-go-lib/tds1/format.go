package tds1

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
)

// Wire constants matching boot_delta.h
const (
	Magic = 0x31534454 // "TDS1" in Little Endian

	OpCopyBase  = 0xC0C0C0C0 // Kopiert N Bytes aus der alten Firmware
	OpInsertLit = 0x1A1A1A1A // Fügt N komprimierte Bytes aus dem Literal-Stream ein
	OpBzero     = 0x5A5A5A5A // Füllt N Bytes mit 0x00
	OpEOF       = 0x0F0F0F0F // Legitimes Ende des Delta-Streams

	HeaderSize      = 32
	InstrSize       = 16
	MaxTargetSize   = 128 << 20 // 128 MiB upper bound against zip-bomb / 32-bit int overflow
	MaxInstructions = 1_000_000 // Matches Stage 1 SDVM MAX_INSTRUCTIONS in boot_delta.c
)

var (
	ErrInvalidMagic   = errors.New("tds1: invalid magic")
	ErrCRC32Mismatch  = errors.New("tds1: crc32 mismatch")
	ErrBufferTooSmall = errors.New("tds1: buffer too small")
)

// Header represents the 32-byte P10-aligned TDS1 Header.
type Header struct {
	Magic              uint32
	ExpectedTargetSize uint32
	BaseFingerprint    [8]byte
	BaseSize           uint32
	LiteralBlockOffset uint32
	InstrCount         uint32
	HeaderCRC32        uint32
}

// Serialize serializes the header into 32 bytes little-endian.
func (h *Header) Serialize() []byte {
	buf := make([]byte, HeaderSize)
	binary.LittleEndian.PutUint32(buf[0:4], h.Magic)
	binary.LittleEndian.PutUint32(buf[4:8], h.ExpectedTargetSize)
	copy(buf[8:16], h.BaseFingerprint[:])
	binary.LittleEndian.PutUint32(buf[16:20], h.BaseSize)
	binary.LittleEndian.PutUint32(buf[20:24], h.LiteralBlockOffset)
	binary.LittleEndian.PutUint32(buf[24:28], h.InstrCount)
	h.HeaderCRC32 = crc32.ChecksumIEEE(buf[0:28])
	binary.LittleEndian.PutUint32(buf[28:32], h.HeaderCRC32)
	return buf
}

// ParseHeader parses and validates a 32-byte header.
func ParseHeader(data []byte) (*Header, error) {
	if len(data) < HeaderSize {
		return nil, ErrBufferTooSmall
	}
	h := &Header{
		Magic:              binary.LittleEndian.Uint32(data[0:4]),
		ExpectedTargetSize: binary.LittleEndian.Uint32(data[4:8]),
		BaseSize:           binary.LittleEndian.Uint32(data[16:20]),
		LiteralBlockOffset: binary.LittleEndian.Uint32(data[20:24]),
		InstrCount:         binary.LittleEndian.Uint32(data[24:28]),
		HeaderCRC32:        binary.LittleEndian.Uint32(data[28:32]),
	}
	copy(h.BaseFingerprint[:], data[8:16])

	if h.Magic != Magic {
		return nil, fmt.Errorf("%w: expected 0x%08X, got 0x%08X", ErrInvalidMagic, Magic, h.Magic)
	}

	calcCRC := crc32.ChecksumIEEE(data[0:28])
	if calcCRC != h.HeaderCRC32 {
		return nil, fmt.Errorf("%w: header crc expected 0x%08X, got 0x%08X", ErrCRC32Mismatch, h.HeaderCRC32, calcCRC)
	}

	return h, nil
}

// Instruction represents a 16-byte P10-aligned TDS1 VM instruction.
type Instruction struct {
	Opcode uint32
	Length uint32
	Offset uint32
	CRC32  uint32
}

// Serialize serializes the instruction into 16 bytes little-endian.
func (inst *Instruction) Serialize() []byte {
	buf := make([]byte, InstrSize)
	binary.LittleEndian.PutUint32(buf[0:4], inst.Opcode)
	binary.LittleEndian.PutUint32(buf[4:8], inst.Length)
	binary.LittleEndian.PutUint32(buf[8:12], inst.Offset)
	inst.CRC32 = crc32.ChecksumIEEE(buf[0:12])
	binary.LittleEndian.PutUint32(buf[12:16], inst.CRC32)
	return buf
}

// ParseInstruction parses and validates a 16-byte instruction.
func ParseInstruction(data []byte) (*Instruction, error) {
	if len(data) < InstrSize {
		return nil, ErrBufferTooSmall
	}
	inst := &Instruction{
		Opcode: binary.LittleEndian.Uint32(data[0:4]),
		Length: binary.LittleEndian.Uint32(data[4:8]),
		Offset: binary.LittleEndian.Uint32(data[8:12]),
		CRC32:  binary.LittleEndian.Uint32(data[12:16]),
	}

	calcCRC := crc32.ChecksumIEEE(data[0:12])
	if calcCRC != inst.CRC32 {
		return nil, fmt.Errorf("%w: instruction crc expected 0x%08X, got 0x%08X", ErrCRC32Mismatch, inst.CRC32, calcCRC)
	}

	return inst, nil
}
