package tbm1

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/Toob-Boot/Toob-Loader/toob-go-lib/tds1"
)

func TestHeatshrinkAutoCompression(t *testing.T) {
	// Repetitive compressible payload
	installed := bytes.Repeat([]byte("TOOB_BOOTLOADER_COMPRESSION_TEST_STRING_12345678"), 50) // ~2400 bytes

	m := sampleManifest()
	m.Images = []Image{
		{
			Type:       0,
			TargetSlot: SlotApp,
			CompAlg:    CompHeatshrink,
			Installed:  installed,
			ChunkSize:  1024,
		},
	}

	pkg, err := BuildUnsigned(m)
	if err != nil {
		t.Fatalf("BuildUnsigned with CompHeatshrink failed: %v", err)
	}

	if len(pkg.StoredLen) != 1 {
		t.Fatalf("expected 1 stored length, got %d", len(pkg.StoredLen))
	}
	storedLen := pkg.StoredLen[0]
	if storedLen >= uint32(len(installed)) {
		t.Fatalf("expected compression to reduce size, got storedLen=%d >= installedLen=%d", storedLen, len(installed))
	}

	if len(pkg.Payloads) != 1 {
		t.Fatalf("expected 1 payload, got %d", len(pkg.Payloads))
	}
	if len(pkg.Payloads[0].Data) != int(storedLen) {
		t.Fatalf("payload data len %d != storedLen %d", len(pkg.Payloads[0].Data), storedLen)
	}
}

func TestTDS1AutoDelta(t *testing.T) {
	base := bytes.Repeat([]byte{0x11, 0x22, 0x33, 0x44}, 256) // 1024 bytes
	installed := make([]byte, len(base))
	copy(installed, base)
	// Modify a few bytes
	installed[100] = 0x99
	installed[101] = 0x88

	m := sampleManifest()
	m.Images = []Image{
		{
			Type:       0,
			TargetSlot: SlotApp,
			DeltaAlg:   DeltaTDS1,
			Installed:  installed,
			Base:       base,
			ChunkSize:  512,
		},
	}

	pkg, err := BuildUnsigned(m)
	if err != nil {
		t.Fatalf("BuildUnsigned with DeltaTDS1 failed: %v", err)
	}

	if len(pkg.StoredLen) != 1 {
		t.Fatalf("expected 1 stored len, got %d", len(pkg.StoredLen))
	}
	storedLen := pkg.StoredLen[0]
	if storedLen >= uint32(len(installed)) {
		t.Fatalf("expected delta to be smaller than installed image: storedLen=%d, installed=%d", storedLen, len(installed))
	}
}

func TestReverseDeltaRegion(t *testing.T) {
	oldApp := bytes.Repeat([]byte("OLD_FIRMWARE_V1_TEST_PATTERN"), 40)
	newApp := bytes.Repeat([]byte("NEW_FIRMWARE_V2_TEST_PATTERN"), 40)

	m := sampleManifest()
	m.Images = []Image{
		{
			Type:       0,
			TargetSlot: SlotApp,
			Installed:  newApp,
			ChunkSize:  512,
		},
	}
	m.ReverseDeltas = []ReverseDelta{
		{
			TargetSlot: SlotApp,
			DeltaAlg:   DeltaTDS1,
			OldImage:   oldApp,
		},
	}

	pkg, err := BuildUnsigned(m)
	if err != nil {
		t.Fatalf("BuildUnsigned with ReverseDeltas failed: %v", err)
	}

	// Verify that the manifest block contains RegionReverseDelta
	h, err := ParseHeader(pkg.Block)
	if err != nil {
		t.Fatalf("ParseHeader failed: %v", err)
	}
	if h.VersionMinor != VersionMinor {
		t.Fatalf("expected VersionMinor=%d, got %d", VersionMinor, h.VersionMinor)
	}

	// Find Region 6 in the block
	foundRDeltaRegion := false
	for i := range MaxRegions {
		base := offRegions + i*regionStride
		id := uint16(pkg.Block[base]) | (uint16(pkg.Block[base+1]) << 8)
		if id == RegionReverseDelta {
			foundRDeltaRegion = true
			off := uint32(pkg.Block[base+4]) | (uint32(pkg.Block[base+5]) << 8) | (uint32(pkg.Block[base+6]) << 16) | (uint32(pkg.Block[base+7]) << 24)
			ln := uint32(pkg.Block[base+8]) | (uint32(pkg.Block[base+9]) << 8) | (uint32(pkg.Block[base+10]) << 16) | (uint32(pkg.Block[base+11]) << 24)
			if ln != RDeltaDescSize {
				t.Fatalf("expected region 6 length %d, got %d", RDeltaDescSize, ln)
			}
			desc, err := ParseRDeltaDesc(pkg.Block[off : off+ln])
			if err != nil {
				t.Fatalf("ParseRDeltaDesc failed: %v", err)
			}
			if desc.TargetSlot != SlotApp {
				t.Fatalf("expected target slot %d, got %d", SlotApp, desc.TargetSlot)
			}
			if desc.DeltaAlg != DeltaTDS1 {
				t.Fatalf("expected delta alg %d, got %d", DeltaTDS1, desc.DeltaAlg)
			}
			if desc.RestoredSize != uint32(len(oldApp)) {
				t.Fatalf("expected restored size %d, got %d", len(oldApp), desc.RestoredSize)
			}
			expectedHash := sha256.Sum256(oldApp)
			if !bytes.Equal(desc.RestoredSHA256[:], expectedHash[:]) {
				t.Fatalf("restored sha256 mismatch")
			}
			break
		}
	}
	if !foundRDeltaRegion {
		t.Fatalf("RegionReverseDelta not found in block")
	}

	// Check Payloads
	if len(pkg.Payloads) != 2 {
		t.Fatalf("expected 2 payloads (1 image + 1 rdelta), got %d", len(pkg.Payloads))
	}
	if !pkg.Payloads[1].IsRDelta {
		t.Fatalf("expected payload 1 to be IsRDelta=true")
	}
}

func TestPayloadOffsetAndTailGap(t *testing.T) {
	appData := bytes.Repeat([]byte{0xAA}, 4096)

	m := sampleManifest()
	m.SectorSize = 4096
	m.Images = []Image{
		{
			Type:          0,
			TargetSlot:    SlotApp,
			Installed:     appData,
			ChunkSize:     4096,
			PayloadOffset: 4096, // 1 sector gap before payload
			TailGap:       8192, // 2 sectors gap after payload
		},
	}

	pkg, err := BuildUnsigned(m)
	if err != nil {
		t.Fatalf("BuildUnsigned failed: %v", err)
	}

	if len(pkg.DataOff) != 1 {
		t.Fatalf("expected 1 data_off")
	}
	// Total block size aligned to sector is 4096
	// PayloadOffset is 4096, so DataOff should start at 8192!
	if pkg.DataOff[0] < 8192 {
		t.Fatalf("expected DataOff >= 8192 due to PayloadOffset, got %d", pkg.DataOff[0])
	}
}

func TestParseRDeltaDescNegative(t *testing.T) {
	// Truncated buffer (< RDeltaDescSize = 48)
	for _, size := range []int{0, 10, 47} {
		buf := make([]byte, size)
		if _, err := ParseRDeltaDesc(buf); !errors.Is(err, ErrBufferTooSmall) {
			t.Fatalf("expected ErrBufferTooSmall for size %d, got %v", size, err)
		}
	}

	// Valid roundtrip
	desc := &RDeltaDesc{
		TargetSlot:     SlotApp,
		DeltaAlg:       DeltaTDS1,
		DataOff:        0x10000,
		StoredSize:     1234,
		RestoredSize:   5678,
		RestoredSHA256: sha256.Sum256([]byte("TEST_PAYLOAD")),
	}
	raw := desc.Serialize()
	parsed, err := ParseRDeltaDesc(raw)
	if err != nil {
		t.Fatalf("ParseRDeltaDesc failed: %v", err)
	}
	if parsed.TargetSlot != desc.TargetSlot ||
		parsed.DeltaAlg != desc.DeltaAlg ||
		parsed.DataOff != desc.DataOff ||
		parsed.StoredSize != desc.StoredSize ||
		parsed.RestoredSize != desc.RestoredSize ||
		!bytes.Equal(parsed.RestoredSHA256[:], desc.RestoredSHA256[:]) {
		t.Fatalf("parsed descriptor does not match original: %+v vs %+v", parsed, desc)
	}
}

func TestReverseDeltaRejections(t *testing.T) {
	// 1. Deriving reverse delta for slot without installed image
	m1 := sampleManifest()
	m1.ReverseDeltas = []ReverseDelta{
		{
			TargetSlot: SlotRecovery, // No recovery image in sampleManifest
			OldImage:   []byte("SOME_OLD_IMAGE"),
		},
	}
	if _, err := BuildUnsigned(m1); err == nil {
		t.Fatal("expected error when deriving reverse delta for missing image slot")
	}

	// 2. Reverse delta with zero stored size and no Data/OldImage
	m2 := sampleManifest()
	m2.ReverseDeltas = []ReverseDelta{
		{
			TargetSlot: SlotApp,
			StoredSize: 0,
			Data:       nil,
			OldImage:   nil,
		},
	}
	if _, err := BuildUnsigned(m2); err == nil {
		t.Fatal("expected error for reverse delta with 0 stored size")
	}

	// 3. Manual reverse delta data with manual StoredSize (explicit path succeeds)
	m3 := sampleManifest()
	m3.ReverseDeltas = []ReverseDelta{
		{
			TargetSlot:     SlotApp,
			DeltaAlg:       DeltaTDS1,
			Data:           []byte("EXPLICIT_PRECOMPUTED_DELTA_BYTES"),
			StoredSize:     32,
			RestoredSize:   100,
			RestoredSHA256: sha256.Sum256([]byte("RESTORED")),
		},
	}
	pkg, err := BuildUnsigned(m3)
	if err != nil {
		t.Fatalf("BuildUnsigned failed on valid manual reverse delta: %v", err)
	}
	if len(pkg.Payloads) != 3 { // 2 images + 1 rdelta
		t.Fatalf("expected 3 payloads, got %d", len(pkg.Payloads))
	}
}

func TestReverseDeltaAssembleRoundtrip(t *testing.T) {
	oldApp := bytes.Repeat([]byte("OLD_APP_V1_PAYLOAD_0123456789ABCDEF"), 120)
	newApp := make([]byte, len(oldApp))
	copy(newApp, oldApp)
	copy(newApp[256:], "PATCHED_SECTION_IN_V2_FIRMWARE!!")

	signer, err := NewLocalSigner(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize)))
	if err != nil {
		t.Fatalf("NewLocalSigner: %v", err)
	}
	defer signer.Zeroise()

	for _, trailer := range []bool{false, true} {
		m := Manifest{
			VendorID:      0x0001,
			ProductID:     0x0042,
			HWRevMin:      1,
			HWRevMax:      1,
			SVN:           2,
			SectorSize:    4096,
			TrailerLayout: trailer,
			Images: []Image{
				{
					TargetSlot: SlotApp,
					Installed:  newApp,
					ChunkSize:  1024,
				},
			},
			ReverseDeltas: []ReverseDelta{
				{
					TargetSlot: SlotApp,
					DeltaAlg:   DeltaTDS1,
					OldImage:   oldApp,
				},
			},
		}

		pkg, err := Build(m, signer)
		if err != nil {
			t.Fatalf("Build(trailer=%v): %v", trailer, err)
		}

		var bundle []byte
		if trailer {
			bundle, err = pkg.AssembleTrailer([][]byte{newApp})
		} else {
			bundle, err = pkg.AssembleFlat([][]byte{newApp})
			var streamed bytes.Buffer
			if _, werr := pkg.WriteFlat(&streamed, [][]byte{newApp}); werr != nil {
				t.Fatalf("WriteFlat: %v", werr)
			}
			if !bytes.Equal(bundle, streamed.Bytes()) {
				t.Fatalf("WriteFlat output differs from AssembleFlat")
			}
		}
		if err != nil {
			t.Fatalf("Assemble(trailer=%v): %v", trailer, err)
		}

		// Extract Region 6 descriptor from signed manifest block
		var desc *RDeltaDesc
		for i := range MaxRegions {
			base := offRegions + i*regionStride
			id := binary.LittleEndian.Uint16(pkg.Block[base:])
			if id == RegionReverseDelta {
				off := binary.LittleEndian.Uint32(pkg.Block[base+4:])
				ln := binary.LittleEndian.Uint32(pkg.Block[base+8:])
				desc, err = ParseRDeltaDesc(pkg.Block[off : off+ln])
				if err != nil {
					t.Fatalf("ParseRDeltaDesc: %v", err)
				}
				break
			}
		}
		if desc == nil {
			t.Fatalf("RegionReverseDelta missing")
		}

		if uint64(desc.DataOff)+uint64(desc.StoredSize) > uint64(len(bundle)) {
			t.Fatalf("trailer=%v: reverse delta [%d..%d) exceeds bundle len %d",
				trailer, desc.DataOff, desc.DataOff+desc.StoredSize, len(bundle))
		}
		rdeltaSlice := bundle[desc.DataOff : desc.DataOff+desc.StoredSize]
		restored, err := tds1.Apply(newApp, rdeltaSlice)
		if err != nil {
			t.Fatalf("trailer=%v: tds1.Apply on embedded reverse delta failed: %v", trailer, err)
		}
		if !bytes.Equal(restored, oldApp) {
			t.Fatalf("trailer=%v: restored image mismatch", trailer)
		}
	}
}

func TestTrailerLayoutDeltaReservesInstalledWindow(t *testing.T) {
	base := bytes.Repeat([]byte{0x10, 0x20, 0x30, 0x40}, 1500) // 6000 bytes
	target := make([]byte, len(base))
	copy(target, base)
	copy(target[500:], "ZERO_COPY_SCRATCHLESS_TDS1_UPDATE")

	signer, err := NewLocalSigner(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x24}, ed25519.SeedSize)))
	if err != nil {
		t.Fatalf("NewLocalSigner: %v", err)
	}
	defer signer.Zeroise()

	m := Manifest{
		VendorID:      0x0001,
		ProductID:     0x0042,
		HWRevMin:      1,
		HWRevMax:      1,
		SVN:           3,
		SectorSize:    4096,
		TrailerLayout: true,
		Images: []Image{
			{
				TargetSlot: SlotApp,
				DeltaAlg:   DeltaTDS1,
				Base:       base,
				Installed:  target,
				BaseSVN:    2,
				ChunkSize:  1024,
			},
		},
	}

	pkg, err := Build(m, signer)
	if err != nil {
		t.Fatalf("Build TrailerLayout + DeltaTDS1 failed: %v", err)
	}
	// Primary delta payload must sit at >= alignUp(6000, 4096) == 8192 so SDVM
	// streaming into [0..6000) never overwrites its own staged TDS1 stream.
	if pkg.DataOff[0] != 8192 {
		t.Fatalf("expected DataOff[0] == 8192, got %d", pkg.DataOff[0])
	}
	bundle, err := pkg.AssembleTrailer([][]byte{pkg.Payloads[0].Data})
	if err != nil {
		t.Fatalf("AssembleTrailer failed: %v", err)
	}
	if pkg.TrailerOffset < pkg.DataOff[0]+pkg.StoredLen[0] {
		t.Fatalf("TrailerOffset %d overlaps delta payload", pkg.TrailerOffset)
	}
	recon, err := tds1.Apply(base, bundle[pkg.DataOff[0]:pkg.DataOff[0]+pkg.StoredLen[0]])
	if err != nil || !bytes.Equal(recon, target) {
		t.Fatalf("roundtrip apply from assembled trailer bundle failed: %v", err)
	}
}
