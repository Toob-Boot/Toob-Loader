//go:build cgo
// +build cgo

package crc32test

import (
	"crypto/rand"
	"fmt"
	"testing"
)

func TestCRC32Equivalence(t *testing.T) {
	// Testvektoren
	vectors := []struct {
		name string
		data []byte
	}{
		{
			name: "IEEE_802.3 (Kommentar-Testvektor)",
			data: []byte("IEEE_802.3"),
		},
		{
			name: "Empty Buffer",
			data: []byte{},
		},
		{
			name: "Single Byte 0x00",
			data: []byte{0x00},
		},
		{
			name: "Single Byte 0xFF",
			data: []byte{0xFF},
		},
	}

	// 1. Statische Testvektoren prüfen
	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			resLib := ComputeLibCRC32(v.data)
			resCore := ComputeBootCRC32(v.data)

			if resLib != resCore {
				t.Errorf("Mismatch for vector %s: toob_lib_crc32=%08X, compute_boot_crc32=%08X", v.name, resLib, resCore)
			}

			// Spezifischer Check für "IEEE_802.3" -> 0x6DF47C03
			if v.name == "IEEE_802.3 (Kommentar-Testvektor)" && resLib != 0x6DF47C03 {
				t.Errorf("Expected 0x6DF47C03 for 'IEEE_802.3', got %08X", resLib)
			}
		})
	}

	// 2. Struct-Layout-Äquivalenz (Größe von toob_handoff_t = 80 Bytes)
	t.Run("Handoff Struct-Dump Emulator", func(t *testing.T) {
		data := make([]byte, 80)
		_, err := rand.Read(data)
		if err != nil {
			t.Fatalf("Failed to generate random data: %v", err)
		}

		resLib := ComputeLibCRC32(data)
		resCore := ComputeBootCRC32(data)

		if resLib != resCore {
			t.Errorf("Mismatch for simulated handoff: toob_lib_crc32=%08X, compute_boot_crc32=%08X", resLib, resCore)
		}
	})

	// 3. Zufällige Buffer-Größen
	randomSizes := []int{1, 2, 3, 4, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 100, 256, 1024}
	for _, size := range randomSizes {
		t.Run(fmt.Sprintf("Size_%d", size), func(t *testing.T) {
			data := make([]byte, size)
			_, err := rand.Read(data)
			if err != nil {
				t.Fatalf("Failed to generate random data: %v", err)
			}

			resLib := ComputeLibCRC32(data)
			resCore := ComputeBootCRC32(data)

			if resLib != resCore {
				t.Errorf("Mismatch for size %d: toob_lib_crc32=%08X, compute_boot_crc32=%08X", size, resLib, resCore)
			}
		})
	}
}
