package tbm1

import (
	"encoding/binary"
	"testing"
)

// Shared fixtures and helpers. Everything here is package-scoped, so the three
// _test.go files use it without duplication.

// deterministicBytes gives reproducible pseudo-payloads without touching rand.
// Reproducibility matters: a golden vector built from random input is useless.
func deterministicBytes(n int, seed byte) []byte {
	b := make([]byte, n)
	acc := seed
	for i := range b {
		acc = acc*31 + byte(i)
		b[i] = acc
	}
	return b
}

// Package-level so the multi-megabyte fixture is built once per test binary,
// not once per test.
var (
	appImage  = deterministicBytes(3<<20+123, 0x5a) // odd tail exercises the ceil-div
	netImage  = deterministicBytes(5000, 0x17)
	netStored = deterministicBytes(2000, 0x18) // pretend-compressed
)

// sampleManifest is the baseline every test mutates a copy of: two images with
// different chunk sizes (so the scheduler sees heterogeneous work) and AutoSBOM
// on (so the concurrent digest pass is exercised).
func sampleManifest() Manifest {
	return Manifest{
		VendorID:  0x1234,
		ProductID: 0x5678,
		HWRevMin:  1,
		HWRevMax:  4,
		KeyIndex:  2,
		SVN:       7,
		AutoSBOM:  true,
		Images: []Image{
			{Type: 1, TargetSlot: SlotApp, Installed: appImage, VerMajor: 3, VerMinor: 1},
			{Type: 2, TargetSlot: SlotNetcore, Installed: netImage, Stored: netStored, ChunkSize: 1024},
		},
	}
}

func mustBuild(t *testing.T, e *Encoder, m Manifest) *Package {
	t.Helper()
	pkg, err := e.BuildUnsigned(m)
	if err != nil {
		t.Fatalf("BuildUnsigned: %v", err)
	}
	return pkg
}

// resealCRC recomputes the header checksum so a test can prove that a deeper
// check — not just the CRC — rejects a mutation.
func resealCRC(b []byte) {
	binary.LittleEndian.PutUint32(b[offFixedCRC32:], headerCRC(b))
}
