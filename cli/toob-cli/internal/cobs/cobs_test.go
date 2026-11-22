package cobs

import (
	"bytes"
	"errors"
	"testing"
)

func TestCOBSRoundTrip(t *testing.T) {
	testCases := [][]byte{
		{},
		{0x00},
		{0x01},
		{0x00, 0x00},
		{0x01, 0x02, 0x03},
		{0x11, 0x22, 0x00, 0x33},
		{0x00, 0x11, 0x22, 0x00, 0x33, 0x00},
		{0x60, 0x55, 0xF9, 0x11, 0x22, 0x00},
		bytes.Repeat([]byte{0xAA}, 253),
		bytes.Repeat([]byte{0xAA}, 254),
		append(bytes.Repeat([]byte{0xAA}, 254), 0x00),
		bytes.Repeat([]byte{0xAA}, 255),
		bytes.Repeat([]byte{0xAA}, 508),
		append(bytes.Repeat([]byte{0xAA}, 508), 0x00),
		bytes.Repeat([]byte{0xAA}, 1024),
	}

	if got := Encode([]byte{0x00}); !bytes.Equal(got, []byte{0x01, 0x01, 0x00}) {
		t.Fatalf("Encode([0x00]) = %x, want 010100", got)
	}
	if got := Encode(bytes.Repeat([]byte{0xAA}, 254)); len(got) != 256 || got[0] != 0xFF || got[255] != 0x00 {
		t.Fatalf("Encode(254x0xAA) len=%d first=0x%02X last=0x%02X, want 256-byte canonical block", len(got), got[0], got[len(got)-1])
	}

	for i, tc := range testCases {
		enc := Encode(tc)
		if len(enc) == 0 || enc[len(enc)-1] != 0x00 {
			t.Fatalf("case %d: encoded data must end with 0x00 delimiter", i)
		}
		for j := range len(enc) - 1 {
			if enc[j] == 0x00 {
				t.Fatalf("case %d: zero byte found at offset %d inside encoded frame", i, j)
			}
		}

		// Decode both with single trailing 0x00 and with delimiter already stripped.
		for _, wire := range [][]byte{enc, enc[:len(enc)-1]} {
			dec, err := Decode(wire)
			if err != nil {
				t.Fatalf("case %d decode failed: %v", i, err)
			}
			if !bytes.Equal(dec, tc) {
				t.Fatalf("case %d mismatch: got %x, want %x", i, dec, tc)
			}
		}
	}
}

func TestCOBSInvalid(t *testing.T) {
	if _, err := Decode(nil); !errors.Is(err, ErrEmptyFrame) {
		t.Fatalf("expected ErrEmptyFrame on nil input, got %v", err)
	}
	if _, err := Decode([]byte{0x00}); !errors.Is(err, ErrEmptyFrame) {
		t.Fatalf("expected ErrEmptyFrame on bare 0x00 delimiter, got %v", err)
	}
	if _, err := Decode([]byte{0x00, 0x00}); !errors.Is(err, ErrZeroByteInEncoded) {
		t.Fatalf("expected ErrZeroByteInEncoded on double 0x00 delimiter, got %v", err)
	}
	if _, err := Decode([]byte{0x01, 0x00, 0x00}); !errors.Is(err, ErrZeroByteInEncoded) {
		t.Fatalf("expected ErrZeroByteInEncoded on extra trailing 0x00 delimiter, got %v", err)
	}
	if _, err := Decode([]byte{0x01, 0x00, 0x02}); !errors.Is(err, ErrZeroByteInEncoded) {
		t.Fatalf("expected ErrZeroByteInEncoded on interior 0x00 code byte, got %v", err)
	}
	if _, err := Decode([]byte{0x03, 0x00, 0x42}); !errors.Is(err, ErrZeroByteInEncoded) {
		t.Fatalf("expected ErrZeroByteInEncoded on interior 0x00 data byte inside COBS block, got %v", err)
	}
	if _, err := Decode([]byte{0x03, 0x42, 0x00, 0x00}); !errors.Is(err, ErrZeroByteInEncoded) {
		t.Fatalf("expected ErrZeroByteInEncoded on interior 0x00 data byte before trailing delimiter, got %v", err)
	}
	if _, err := Decode([]byte{0x05, 0x01, 0x02}); !errors.Is(err, ErrFrameOutOfBounds) {
		t.Fatalf("expected ErrFrameOutOfBounds on out-of-bounds code, got %v", err)
	}
}

func FuzzCOBSBijectionAndUntrustedDecode(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add([]byte{0x01, 0x01, 0x00})
	f.Add([]byte{0x60, 0x55, 0xF9, 0x11, 0x22, 0x00})
	f.Add(bytes.Repeat([]byte{0xAA}, 254))
	f.Add(append(bytes.Repeat([]byte{0xAA}, 254), 0x00))
	f.Add([]byte{0x05, 0x01, 0x02})
	f.Add([]byte{0x01, 0x00, 0x02})
	f.Add([]byte{0x03, 0x00, 0x42})

	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 65536 {
			return
		}
		enc := Encode(raw)
		if len(enc) < 2 || enc[len(enc)-1] != 0x00 {
			t.Fatalf("invalid delimiter on Encode(%x): %x", raw, enc)
		}
		if bytes.IndexByte(enc[:len(enc)-1], 0x00) >= 0 {
			t.Fatalf("zero byte inside COBS payload: %x", enc)
		}
		maxOverhead := 1
		if len(raw) > 0 {
			maxOverhead = (len(raw) + 253) / 254
		}
		if len(enc)-1 > len(raw)+maxOverhead {
			t.Fatalf("COBS overhead exceeded bound: raw=%d enc=%d", len(raw), len(enc)-1)
		}
		dec, err := Decode(enc)
		if err != nil {
			t.Fatalf("Decode(Encode(raw)) failed: %v", err)
		}
		if !bytes.Equal(dec, raw) {
			t.Fatalf("roundtrip mismatch: got %x, want %x", dec, raw)
		}

		untrustedDec, err := Decode(raw)
		if err == nil && untrustedDec != nil {
			reDec, err := Decode(Encode(untrustedDec))
			if err != nil || !bytes.Equal(reDec, untrustedDec) {
				t.Fatalf("untrusted decode re-roundtrip failed: %v", err)
			}
		}
	})
}
