package tbm1

import (
	"encoding/binary"
	"errors"
	"hash/crc32"
	"testing"
)

// TestCRCVariant pins the checksum flavour. If this ever fails, the C reader
// and this writer have drifted apart on the polynomial or the reflection.
func TestCRCVariant(t *testing.T) {
	const check = 0xCBF43926 // CRC-32/ISO-HDLC over "123456789"
	if got := crc32.ChecksumIEEE([]byte("123456789")); got != check {
		t.Fatalf("CRC variant changed: got %#08x, want %#08x", got, check)
	}
}

func TestParseHeaderRoundTrip(t *testing.T) {
	m := sampleManifest()
	m.KeyEpoch, m.BuildNumber, m.Stage1SVN = 9, 4242, 3
	pkg := mustBuild(t, &Encoder{}, m)

	h, err := ParseHeader(pkg.Block)
	if err != nil {
		t.Fatal(err)
	}
	switch {
	case h.VendorID != m.VendorID, h.ProductID != m.ProductID:
		t.Fatal("vendor/product mismatch")
	case h.KeyIndex != m.KeyIndex, h.KeyEpoch != m.KeyEpoch:
		t.Fatal("key identity mismatch")
	case h.SVN != m.SVN, h.Stage1SVN != m.Stage1SVN, h.BuildNumber != m.BuildNumber:
		t.Fatal("version fields mismatch")
	case h.ImageCount != uint8(len(m.Images)):
		t.Fatal("image count mismatch")
	case h.TotalLen != pkg.TotalLen, h.SignedLen != pkg.SignedLen:
		t.Fatal("length fields mismatch")
	}
	if _, err := ParseHeader([]byte{1, 2, 3}); err == nil {
		t.Fatal("ParseHeader accepted a stub block")
	}
}

func TestValidateRejectsTampering(t *testing.T) {
	base := mustBuild(t, &Encoder{}, sampleManifest()).Block

	mutate := func(name string, f func(b []byte)) {
		t.Helper()
		b := append([]byte(nil), base...)
		f(b)
		err := validateBlock(b)
		if err == nil {
			t.Fatalf("%s: tampered block passed validation", name)
		}
		if !errors.Is(err, ErrMalformedBlock) {
			t.Fatalf("%s: expected ErrMalformedBlock, got %v", name, err)
		}
	}

	mutate("magic", func(b []byte) { b[offMagic] ^= 0xff })
	mutate("version", func(b []byte) { b[offVersionMajor] = VersionMajor + 1 })
	mutate("crc", func(b []byte) { b[offFixedCRC32] ^= 0x01 })
	mutate("vendor id without crc fixup", func(b []byte) { b[offVendorID] ^= 0x01 })
	mutate("truncated total_len", func(b []byte) { copy(b[offTotalLen:], []byte{0, 0, 0, 0}) })

	// The remaining cases re-seal the CRC, so only the deeper cross-checks can
	// catch them.
	mutate("chunk count", func(b []byte) {
		at := offImages + imgNumChunks
		binary.LittleEndian.PutUint32(b[at:], binary.LittleEndian.Uint32(b[at:])+1)
		resealCRC(b)
	})
	mutate("payload before the block", func(b []byte) {
		binary.LittleEndian.PutUint32(b[offImages+imgDataOff:], 0)
		resealCRC(b)
	})
	mutate("duplicate region", func(b []byte) {
		// clone the chunk-hash descriptor into the next, unused slot
		copy(b[offRegions+regionStride:offRegions+2*regionStride], b[offRegions:offRegions+regionStride])
		resealCRC(b)
	})
}

func TestCeilDivNeverOverflows(t *testing.T) {
	cases := [][3]uint32{
		{0, 4096, 0},
		{1, 4096, 1},
		{4096, 4096, 1},
		{4097, 4096, 2},
		{^uint32(0), 4096, 1048576},
		{^uint32(0), 1, ^uint32(0)}, // (a+b-1) would wrap to 0 here
	}
	for _, c := range cases {
		if got := ceilDivU32(c[0], c[1]); got != c[2] {
			t.Fatalf("ceilDivU32(%d,%d) = %d, want %d", c[0], c[1], got, c[2])
		}
	}
}
