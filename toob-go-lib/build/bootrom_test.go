package build

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func buildMinimalELF32(entry, secAddr uint32, payload []byte) []byte {
	const (
		ehdrSize = 52
		phdrSize = 32
		shdrSize = 40
	)
	shstrtab := []byte("\x00.text\x00.shstrtab\x00")
	dataOff := ehdrSize + phdrSize
	shstrOff := dataOff + len(payload)
	if pad := (4 - (shstrOff % 4)) % 4; pad > 0 {
		shstrOff += pad
	}
	shdrOff := shstrOff + len(shstrtab)
	if pad := (4 - (shdrOff % 4)) % 4; pad > 0 {
		shdrOff += pad
	}

	buf := make([]byte, shdrOff+3*shdrSize)
	copy(buf[0:4], []byte{0x7F, 'E', 'L', 'F'})
	buf[4] = 1
	buf[5] = 1
	buf[6] = 1
	binary.LittleEndian.PutUint16(buf[16:18], 2)
	binary.LittleEndian.PutUint16(buf[18:20], 0xF3)
	binary.LittleEndian.PutUint32(buf[20:24], 1)
	binary.LittleEndian.PutUint32(buf[24:28], entry)
	binary.LittleEndian.PutUint32(buf[28:32], ehdrSize)
	binary.LittleEndian.PutUint32(buf[32:36], uint32(shdrOff))
	binary.LittleEndian.PutUint16(buf[40:42], ehdrSize)
	binary.LittleEndian.PutUint16(buf[42:44], phdrSize)
	binary.LittleEndian.PutUint16(buf[44:46], 1)
	binary.LittleEndian.PutUint16(buf[46:48], shdrSize)
	binary.LittleEndian.PutUint16(buf[48:50], 3)
	binary.LittleEndian.PutUint16(buf[50:52], 2)

	ph := buf[ehdrSize : ehdrSize+phdrSize]
	binary.LittleEndian.PutUint32(ph[0:4], 1)
	binary.LittleEndian.PutUint32(ph[4:8], uint32(dataOff))
	binary.LittleEndian.PutUint32(ph[8:12], secAddr)
	binary.LittleEndian.PutUint32(ph[12:16], secAddr)
	binary.LittleEndian.PutUint32(ph[16:20], uint32(len(payload)))
	binary.LittleEndian.PutUint32(ph[20:24], uint32(len(payload)))
	binary.LittleEndian.PutUint32(ph[24:28], 5)
	binary.LittleEndian.PutUint32(ph[28:32], 4)

	copy(buf[dataOff:], payload)
	copy(buf[shstrOff:], shstrtab)

	sh1 := buf[shdrOff+shdrSize : shdrOff+2*shdrSize]
	binary.LittleEndian.PutUint32(sh1[0:4], 1)
	binary.LittleEndian.PutUint32(sh1[4:8], 1)
	binary.LittleEndian.PutUint32(sh1[8:12], 0x6)
	binary.LittleEndian.PutUint32(sh1[12:16], secAddr)
	binary.LittleEndian.PutUint32(sh1[16:20], uint32(dataOff))
	binary.LittleEndian.PutUint32(sh1[20:24], uint32(len(payload)))
	binary.LittleEndian.PutUint32(sh1[32:36], 4)

	sh2 := buf[shdrOff+2*shdrSize : shdrOff+3*shdrSize]
	binary.LittleEndian.PutUint32(sh2[0:4], 7)
	binary.LittleEndian.PutUint32(sh2[4:8], 3)
	binary.LittleEndian.PutUint32(sh2[16:20], uint32(shstrOff))
	binary.LittleEndian.PutUint32(sh2[20:24], uint32(len(shstrtab)))
	binary.LittleEndian.PutUint32(sh2[32:36], 1)

	return buf
}

func TestPackBootromSegmentedViaSoCExtends(t *testing.T) {
	packagesRoot := filepath.Clean(filepath.Join("..", "..", "toob-infra", "registry", "packages"))
	elfPath := filepath.Join(t.TempDir(), "stage0.elf")
	payload := []byte{0x13, 0x05, 0x00, 0x00, 0x67, 0x80, 0x00, 0x00}
	if err := os.WriteFile(elfPath, buildMinimalELF32(0x40380100, 0x40380000, payload), 0o644); err != nil {
		t.Fatalf("write ELF: %v", err)
	}

	var hw HardwareJson
	hw.ChipFamily = "test-soc"
	hw.Flash.Size = 8 << 20 // 8 MiB -> log2(8) << 4 = 0x30
	hw.BootromImage = &BootromImageSpec{
		Extends: "soc/esp/bootrom_image.json",
		Header: &BootromHeaderSpec{
			Fields: []BootromFieldSpec{
				{Offset: 12, Size: 2, Source: "const", Value: 0x0009, Endian: "little"},
			},
		},
	}

	img, err := PackStage0ELFWithPackagesDir(elfPath, &hw, packagesRoot)
	if err != nil {
		t.Fatalf("PackStage0ELFWithPackagesDir: %v", err)
	}
	if img[0] != 0xE9 || img[1] != 1 || img[2] != 0x02 || img[3] != 0x30 {
		t.Fatalf("unexpected header [0..4]: %x", img[:4])
	}
	if got := binary.LittleEndian.Uint16(img[12:14]); got != 0x0009 {
		t.Fatalf("merged field[12..14] = 0x%04X, want 0x0009", got)
	}
	body := img[:len(img)-32]
	wantSHA := sha256.Sum256(body)
	if !bytes.Equal(img[len(img)-32:], wantSHA[:]) {
		t.Fatalf("trailing SHA-256 mismatch")
	}
}

func TestPackBootromFlatWithCRC32Patch(t *testing.T) {
	elfPath := filepath.Join(t.TempDir(), "boot2.elf")
	raw := make([]byte, 300)
	for i := range raw {
		raw[i] = byte(i)
	}
	for i := 252; i < 256; i++ {
		raw[i] = 0xFF
	}
	if err := os.WriteFile(elfPath, buildMinimalELF32(0x10000101, 0x10000000, raw), 0o644); err != nil {
		t.Fatalf("write ELF: %v", err)
	}

	var hw HardwareJson
	hw.ChipFamily = "test-flat-crc"
	hw.BootromImage = &BootromImageSpec{
		Layout:  "flat",
		MinSize: 256,
		Patches: []BootromPatchSpec{
			{
				Op:         "crc32",
				Offset:     252,
				Size:       4,
				Endian:     "little",
				RangeStart: 0,
				RangeEnd:   252,
				Poly:       0x04C11DB7,
				Init:       0xFFFFFFFF,
				Reflect:    false,
				XorOut:     0x00000000,
			},
		},
	}

	img, err := PackStage0ELF(elfPath, &hw)
	if err != nil {
		t.Fatalf("PackStage0ELF: %v", err)
	}
	if len(img) != 300 {
		t.Fatalf("len(img) = %d, want 300", len(img))
	}
	wantCRC := computeGenericCRC32(raw[:252], 0x04C11DB7, 0xFFFFFFFF, 0, false)
	gotCRC := binary.LittleEndian.Uint32(img[252:256])
	if gotCRC != wantCRC {
		t.Fatalf("patched CRC32 = 0x%08X, want 0x%08X", gotCRC, wantCRC)
	}
}
