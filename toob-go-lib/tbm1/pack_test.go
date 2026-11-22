package tbm1

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func TestPackBundle_TrailerFlatDeltaAndCompress(t *testing.T) {
	seed, err := hex.DecodeString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewLocalSigner(ed25519.NewKeyFromSeed(seed))
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Zeroise()

	v1 := bytes.Repeat([]byte("TOOB-FW-V1-PAYLOAD-BLOCK-"), 128)
	v2 := append([]byte(nil), v1...)
	copy(v2[64:], "TOOB-FW-V2-UPDATED-BLOCK-")

	// 1. Trailer full bundle with reverse delta
	trailerBundle, err := PackBundle(PackOptions{
		Installed:     v2,
		ReverseOld:    v1,
		TrailerLayout: true,
		VendorID:      0x0001,
		ProductID:     0x0042,
		HWRevMin:      1,
		HWRevMax:      1,
		SVN:           2,
		VerMajor:      2,
	}, signer)
	if err != nil {
		t.Fatalf("PackBundle trailer: %v", err)
	}
	off, length, err := ParseTrailerLocator(trailerBundle)
	if err != nil {
		t.Fatalf("ParseTrailerLocator: %v", err)
	}
	tbm1Block := trailerBundle[off : off+length]
	if vErr := VerifyBlock(tbm1Block, signer.Public()); vErr != nil {
		t.Fatalf("VerifyBlock trailer: %v", vErr)
	}

	// 2. Flat TDS1 forward delta bundle
	deltaBundle, err := PackBundle(PackOptions{
		Installed:     v2,
		Base:          v1,
		BaseSVN:       1,
		TrailerLayout: false,
		VendorID:      0x0001,
		ProductID:     0x0042,
		HWRevMin:      1,
		HWRevMax:      1,
		SVN:           2,
		VerMajor:      2,
	}, signer)
	if err != nil {
		t.Fatalf("PackBundle delta: %v", err)
	}
	totalLen := binary.LittleEndian.Uint32(deltaBundle[offTotalLen : offTotalLen+4])
	if _, pErr := ParseHeader(deltaBundle[:totalLen]); pErr != nil {
		t.Fatalf("ParseHeader flat delta: %v", pErr)
	}
	if vErr := VerifyBlock(deltaBundle[:totalLen], signer.Public()); vErr != nil {
		t.Fatalf("VerifyBlock flat delta: %v", vErr)
	}
	if len(deltaBundle) >= len(trailerBundle) {
		t.Fatalf("expected TDS1 delta bundle (%d B) to be smaller than full bundle (%d B)", len(deltaBundle), len(trailerBundle))
	}

	// 3. Heatshrink compressed trailer bundle
	compBundle, err := PackBundle(PackOptions{
		Installed:     v2,
		Compress:      true,
		TrailerLayout: true,
		VendorID:      0x0001,
		ProductID:     0x0042,
		HWRevMin:      1,
		HWRevMax:      1,
		SVN:           2,
		VerMajor:      2,
	}, signer)
	if err != nil {
		t.Fatalf("PackBundle compress: %v", err)
	}
	cOff, cLen, err := ParseTrailerLocator(compBundle)
	if err != nil {
		t.Fatalf("ParseTrailerLocator compress: %v", err)
	}
	if err := VerifyBlock(compBundle[cOff:cOff+cLen], signer.Public()); err != nil {
		t.Fatalf("VerifyBlock compress: %v", err)
	}

	// 4. Mutual exclusion check
	if _, err := PackBundle(PackOptions{Installed: v2, Base: v1, Compress: true}, signer); err == nil {
		t.Fatal("expected error when both Base and Compress are set")
	}
}
