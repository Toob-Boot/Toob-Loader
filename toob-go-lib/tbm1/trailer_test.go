package tbm1

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func TestTrailerLayoutRoundtripAndLocator(t *testing.T) {
	seed, err := hex.DecodeString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	if err != nil {
		t.Fatalf("decode seed: %v", err)
	}
	signer, err := NewLocalSigner(ed25519.NewKeyFromSeed(seed))
	if err != nil {
		t.Fatalf("NewLocalSigner: %v", err)
	}
	defer signer.Zeroise()

	appPayload := bytes.Repeat([]byte{0x5A, 0xA5, 0x3C, 0xC3}, 1250) // 5000 bytes (2 chunks)
	stage1Payload := bytes.Repeat([]byte{0x11, 0x22, 0x33, 0x44}, 600)

	pkg, err := Build(Manifest{
		VendorID:      0x0001,
		ProductID:     0x0042,
		HWRevMin:      1,
		HWRevMax:      1,
		SVN:           2,
		Stage1SVN:     1,
		AutoSBOM:      true,
		TrailerLayout: true,
		Images: []Image{
			{
				TargetSlot: SlotApp,
				Installed:  appPayload,
			},
			{
				TargetSlot: SlotStage1,
				Installed:  stage1Payload,
			},
		},
	}, signer)
	if err != nil {
		t.Fatalf("Build TrailerLayout: %v", err)
	}

	if pkg.DataOff[0] != 0 {
		t.Fatalf("expected primary image data_off == 0, got %d", pkg.DataOff[0])
	}
	if pkg.DataOff[1] != 8192 {
		t.Fatalf("expected secondary image sector-aligned at 8192, got %d", pkg.DataOff[1])
	}
	if pkg.TrailerOffset != 12288 {
		t.Fatalf("expected TrailerOffset == 12288, got %d", pkg.TrailerOffset)
	}

	hdr, err := ParseHeader(pkg.Block)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	if hdr.FlagsCritical&CritTrailerLayout == 0 {
		t.Fatalf("expected CritTrailerLayout flag in FlagsCritical, got 0x%04x", hdr.FlagsCritical)
	}

	bundle, err := pkg.AssembleTrailer([][]byte{appPayload, stage1Payload})
	if err != nil {
		t.Fatalf("AssembleTrailer: %v", err)
	}

	if !bytes.Equal(bundle[:len(appPayload)], appPayload) {
		t.Fatalf("primary image not placed verbatim at offset 0")
	}

	tbm1Off, tbm1Len, err := ParseTrailerLocator(bundle)
	if err != nil {
		t.Fatalf("ParseTrailerLocator: %v", err)
	}
	if tbm1Off != pkg.TrailerOffset || tbm1Len != pkg.TotalLen {
		t.Fatalf("locator mismatch: got (%d, %d), want (%d, %d)", tbm1Off, tbm1Len, pkg.TrailerOffset, pkg.TotalLen)
	}

	extractedBlock := bundle[tbm1Off : tbm1Off+tbm1Len]
	if err := VerifyBlock(extractedBlock, signer.Public()); err != nil {
		t.Fatalf("VerifyBlock on extracted trailer block failed: %v", err)
	}

	// Corrupting primary image data_off != 0 with CritTrailerLayout must fail validation.
	corrupt := append([]byte(nil), extractedBlock...)
	binary.LittleEndian.PutUint32(corrupt[offImages+imgDataOff:], 4096)
	binary.LittleEndian.PutUint32(corrupt[offFixedCRC32:], headerCRC(corrupt))
	if err := ValidateBlock(corrupt); err == nil {
		t.Fatalf("expected ValidateBlock to reject TrailerLayout with data_off != 0")
	}
}
