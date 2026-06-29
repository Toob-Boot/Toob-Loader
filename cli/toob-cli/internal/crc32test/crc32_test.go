//go:build cgo
// +build cgo

package crc32test

/*
#cgo CFLAGS: -I../../../../sdk/libtoob -I../../../../sdk/libtoob/include -I../../../../common/include -I../../../../toobloader/core/include

#include "../../../../sdk/libtoob/toob_crc32.c"
#include "../../../../toobloader/core/boot_crc32.c"
*/
import "C"
import (
	"crypto/rand"
	"testing"
	"unsafe"
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
			var ptr *C.uint8_t
			if len(v.data) > 0 {
				ptr = (*C.uint8_t)(unsafe.Pointer(&v.data[0]))
			}
			length := C.size_t(len(v.data))

			resLib := uint32(C.toob_lib_crc32(ptr, length))
			resCore := uint32(C.compute_boot_crc32(ptr, length))

			if resLib != resCore {
				t.Errorf("Mismatch for vector %s: toob_lib_crc32=%08X, compute_boot_crc32=%08X", v.name, resLib, resCore)
			}

			// Spezifischer Check für "IEEE_802.3" -> 0xE0DFD6DA
			if v.name == "IEEE_802.3 (Kommentar-Testvektor)" && resLib != 0xE0DFD6DA {
				t.Errorf("Expected 0xE0DFD6DA for 'IEEE_802.3', got %08X", resLib)
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

		ptr := (*C.uint8_t)(unsafe.Pointer(&data[0]))
		length := C.size_t(len(data))

		resLib := uint32(C.toob_lib_crc32(ptr, length))
		resCore := uint32(C.compute_boot_crc32(ptr, length))

		if resLib != resCore {
			t.Errorf("Mismatch for simulated handoff: toob_lib_crc32=%08X, compute_boot_crc32=%08X", resLib, resCore)
		}
	})

	// 3. Zufällige Buffer-Größen
	randomSizes := []int{1, 2, 3, 4, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 100, 256, 1024}
	for _, size := range randomSizes {
		t.Run(t.Name(), func(t *testing.T) {
			data := make([]byte, size)
			_, err := rand.Read(data)
			if err != nil {
				t.Fatalf("Failed to generate random data: %v", err)
			}

			ptr := (*C.uint8_t)(unsafe.Pointer(&data[0]))
			length := C.size_t(len(data))

			resLib := uint32(C.toob_lib_crc32(ptr, length))
			resCore := uint32(C.compute_boot_crc32(ptr, length))

			if resLib != resCore {
				t.Errorf("Mismatch for size %d: toob_lib_crc32=%08X, compute_boot_crc32=%08X", size, resLib, resCore)
			}
		})
	}
}
