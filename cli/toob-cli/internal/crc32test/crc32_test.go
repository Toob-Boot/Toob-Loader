package crc32test

import (
	"crypto/rand"
	"hash/crc32"
	"strconv"
	"testing"
)

func TestCRC32Equivalence(t *testing.T) {
	vectors := []struct {
		name string
		data []byte
		want uint32
	}{
		{
			name: "IEEE_802.3_Check_123456789",
			data: []byte("123456789"),
			want: 0xCBF43926,
		},
		{
			name: "IEEE_802.3_Contract_Vector",
			data: []byte("IEEE_802.3"),
			want: 0x6DF47C03,
		},
		{
			name: "Empty_Buffer",
			data: []byte{},
			want: 0x00000000,
		},
		{
			name: "Single_Byte_0x00",
			data: []byte{0x00},
			want: 0xD202EF8D,
		},
		{
			name: "Single_Byte_0xFF",
			data: []byte{0xFF},
			want: 0xFF000000,
		},
	}

	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			resLib := ComputeLibCRC32(v.data)
			resCore := ComputeBootCRC32(v.data)
			resIEEE := crc32.ChecksumIEEE(v.data)

			if resLib != resCore {
				t.Errorf("mismatch for vector %s: lib=%08X, core=%08X", v.name, resLib, resCore)
			}
			if resLib != v.want {
				t.Errorf("expected %08X for %s, got %08X", v.want, v.name, resLib)
			}
			if resLib != resIEEE {
				t.Errorf("stdlib IEEE mismatch for %s: got %08X, want %08X", v.name, resLib, resIEEE)
			}
		})
	}

	t.Run("Handoff_Struct_80B", func(t *testing.T) {
		data := make([]byte, 80)
		if _, err := rand.Read(data); err != nil {
			t.Fatalf("failed to generate random data: %v", err)
		}

		resLib := ComputeLibCRC32(data)
		resCore := ComputeBootCRC32(data)
		resIEEE := crc32.ChecksumIEEE(data)

		if resLib != resCore || resLib != resIEEE {
			t.Errorf("handoff buffer mismatch: lib=%08X, core=%08X, ieee=%08X", resLib, resCore, resIEEE)
		}
	})

	randomSizes := []int{1, 2, 3, 4, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 100, 256, 1024}
	for _, size := range randomSizes {
		t.Run("Size_"+strconv.Itoa(size), func(t *testing.T) {
			data := make([]byte, size)
			if _, err := rand.Read(data); err != nil {
				t.Fatalf("failed to generate random data: %v", err)
			}

			resLib := ComputeLibCRC32(data)
			resCore := ComputeBootCRC32(data)
			resIEEE := crc32.ChecksumIEEE(data)

			if resLib != resCore || resLib != resIEEE {
				t.Errorf("mismatch for size %d: lib=%08X, core=%08X, ieee=%08X", size, resLib, resCore, resIEEE)
			}
		})
	}
}
