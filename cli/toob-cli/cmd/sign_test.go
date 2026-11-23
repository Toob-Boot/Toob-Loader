package cmd

import (
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tbm1 "github.com/Toob-Boot/Toob-Loader/toob-go-lib/tbm1"

	"github.com/toob-boot/toob/internal/provision"
	"github.com/toob-boot/toob/internal/signing"
)

func TestSignManifestRoundTripFixesCRIT48(t *testing.T) {
	tmp := t.TempDir()
	unsignedIn := filepath.Join(tmp, "unsigned.tbm1")
	signedOut := filepath.Join(tmp, "signed.tbm1")

	pkg, err := tbm1.BuildUnsigned(tbm1.Manifest{
		VendorID:  1,
		ProductID: 2,
		HWRevMax:  1,
		Images: []tbm1.Image{
			{
				Type:      tbm1.SlotApp,
				Installed: make([]byte, 256),
			},
		},
	})
	if err != nil {
		t.Fatalf("BuildUnsigned failed: %v", err)
	}
	if writeErr := os.WriteFile(unsignedIn, pkg.Block, 0o600); writeErr != nil {
		t.Fatalf("write unsigned block: %v", writeErr)
	}

	root := NewRootCmd()
	root.SetArgs([]string{"sign", "manifest", "--in", unsignedIn, "--out", signedOut, "--mock"})
	if execErr := root.Execute(); execErr != nil {
		t.Fatalf("sign manifest failed: %v", execErr)
	}

	signedBytes, err := os.ReadFile(signedOut)
	if err != nil {
		t.Fatalf("read signed manifest: %v", err)
	}
	if len(signedBytes) != len(pkg.Block) {
		t.Fatalf("manifest length changed: got %d want %d", len(signedBytes), len(pkg.Block))
	}

	mockPub := ed25519.PublicKey(provision.MockRootPublicKey)
	if err := tbm1.VerifyBlock(signedBytes, mockPub); err != nil {
		t.Fatalf("tbm1.VerifyBlock rejected signed manifest: %v", err)
	}
}

func TestSignImageCortexMVTORAndKeyMutualExclusivity(t *testing.T) {
	tmp := t.TempDir()
	hwPath := filepath.Join(tmp, "hardware.json")
	rawBin := filepath.Join(tmp, "app.raw.bin")
	outBin := filepath.Join(tmp, "app.signed.bin")

	hwJSON := `{
		"chip_family": "stm32f4",
		"constants": {
			"TOOB_IMAGE_HEADER_OFFSET": "0x100U"
		},
		"flash": {
			"size": 1048576,
			"write_alignment": 4,
			"app_alignment": 16384,
			"base": "0x08000000",
			"image_header_offset": 256,
			"regions": [{"type": "writable", "name": "bank0", "base": 134217728, "size": 1048576, "sector_size": 16384}]
		},
		"memory": {
			"iram_base": "0x20000000U",
			"iram_size": "0x20000U",
			"sram_base": "0x20000000U",
			"sram_size": "0x20000U"
		}
	}`
	if err := os.WriteFile(hwPath, []byte(hwJSON), 0o600); err != nil {
		t.Fatalf("write hardware.json: %v", err)
	}

	// Build a minimal 1024-byte Cortex-M payload with zeroed 20-byte header slot at offset 256.
	raw := make([]byte, 1024)
	for i := range raw {
		raw[i] = 0xA5
	}
	copy(raw[256:276], make([]byte, 20))
	if err := os.WriteFile(rawBin, raw, 0o600); err != nil {
		t.Fatalf("write raw binary: %v", err)
	}

	root := NewRootCmd()
	root.SetArgs([]string{
		"sign", "image", rawBin,
		"-o", outBin,
		"--hardware", hwPath,
		"--header-offset", "256",
		"--role", "app",
		"--mock",
	})
	if err := root.Execute(); err != nil {
		t.Fatalf("sign image failed: %v", err)
	}

	signedBytes, err := os.ReadFile(outBin)
	if err != nil {
		t.Fatalf("read signed image: %v", err)
	}
	if len(signedBytes) != signing.ToobImageHeaderLen+len(raw)+signing.ToobImgSigTrailerLen {
		t.Fatalf("signed app length = %d, want %d", len(signedBytes), signing.ToobImageHeaderLen+len(raw)+signing.ToobImgSigTrailerLen)
	}
	hdrOff := uint32(256)
	mockPub := ed25519.PublicKey(provision.MockRootPublicKey)
	if valErr := signing.ValidateToobImage(outBin, signedBytes, signing.ValidateImageOptions{
		Role:                  signing.RoleApp,
		HeaderOffset:          &hdrOff,
		RequireImageSignature: true,
		SignerPub:             mockPub,
	}); valErr != nil {
		t.Fatalf("ValidateToobImage failed: %v", valErr)
	}

	// Verify strict mutual exclusivity between --mock, --key-file, and --key-hex.
	privPath := filepath.Join(tmp, "dummy.priv")
	if writeErr := os.WriteFile(privPath, []byte(provision.MockRootPrivateKeySeedHex), 0o600); writeErr != nil {
		t.Fatalf("write dummy priv: %v", writeErr)
	}

	badRoot := NewRootCmd()
	badRoot.SetArgs([]string{
		"sign", "image", rawBin,
		"-o", outBin,
		"--mock",
		"--key-file", privPath,
	})
	if err := badRoot.Execute(); err == nil {
		t.Fatalf("expected error when both --mock and --key-file are provided")
	}

	badRoot2 := NewRootCmd()
	badRoot2.SetArgs([]string{
		"sign", "manifest",
		"--in", rawBin,
		"--out", outBin,
		"--mock",
		"--key-hex", provision.MockRootPrivateKeySeedHex,
	})
	if err := badRoot2.Execute(); err == nil {
		t.Fatalf("expected error when both --mock and --key-hex are provided")
	}
}

func TestSignKeygenTCC1AndKDMRoundTrip(t *testing.T) {
	tmp := t.TempDir()
	privPath := filepath.Join(tmp, "root.priv.bin")
	pubPath := filepath.Join(tmp, "root.pub.bin")

	kg := NewRootCmd()
	kg.SetArgs([]string{"sign", "keygen", "--priv", privPath, "--pub", pubPath})
	if err := kg.Execute(); err != nil {
		t.Fatalf("sign keygen failed: %v", err)
	}

	pubRaw, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatalf("read public key: %v", err)
	}
	if len(pubRaw) != ed25519.PublicKeySize {
		t.Fatalf("expected %d-byte public key, got %d", ed25519.PublicKeySize, len(pubRaw))
	}
	pubHex := hex.EncodeToString(pubRaw)

	// TCC1 sign & verify round-trip
	tccFrame := filepath.Join(tmp, "cmd.tcc1")
	devIDHex := strings.Repeat("11", 32)
	tccSign := NewRootCmd()
	tccSign.SetArgs([]string{"sign", "tcc1", "sign", "--out", tccFrame, "--command", "1", "--counter-min", "7", "--device-id", devIDHex, "--key-file", privPath})
	if err := tccSign.Execute(); err != nil {
		t.Fatalf("sign tcc1 sign failed: %v", err)
	}
	tccVerify := NewRootCmd()
	tccVerify.SetArgs([]string{"sign", "tcc1", "verify", "--in", tccFrame, "--pubkey", pubHex})
	if err := tccVerify.Execute(); err != nil {
		t.Fatalf("sign tcc1 verify failed: %v", err)
	}

	// KDM sign & verify round-trip
	kdmFile := filepath.Join(tmp, "delegate.kdm")
	kdmSign := NewRootCmd()
	kdmSign.SetArgs([]string{"sign", "kdm", "sign", "--out", kdmFile, "--delegate-pubkey", pubHex, "--sequence", "42", "--key-file", privPath})
	if err := kdmSign.Execute(); err != nil {
		t.Fatalf("sign kdm sign failed: %v", err)
	}
	kdmVerify := NewRootCmd()
	kdmVerify.SetArgs([]string{"sign", "kdm", "verify", "--in", kdmFile, "--pubkey", pubHex})
	if err := kdmVerify.Execute(); err != nil {
		t.Fatalf("sign kdm verify failed: %v", err)
	}
}

func TestSignImageTSIGKeyIndexAndUnsignedFlags(t *testing.T) {
	tmp := t.TempDir()
	rawBin := filepath.Join(tmp, "app.raw.bin")
	signedOut := filepath.Join(tmp, "app.signed.bin")
	recOut := filepath.Join(tmp, "rec.signed.bin")
	unsignedOut := filepath.Join(tmp, "app.unsigned.bin")

	raw := make([]byte, 512)
	for i := range raw {
		raw[i] = 0x55
	}
	if err := os.WriteFile(rawBin, raw, 0o600); err != nil {
		t.Fatalf("write raw binary: %v", err)
	}

	// Neither key/--mock nor --unsigned must fail cleanly.
	noKeyCmd := NewRootCmd()
	noKeyCmd.SetArgs([]string{
		"sign", "image", rawBin,
		"-o", signedOut,
		"--header-offset", "256",
		"--role", "app",
	})
	if err := noKeyCmd.Execute(); err == nil {
		t.Fatal("expected error when neither signing key nor --unsigned is provided")
	}

	// Signed app image with explicit --key-index.
	signAppCmd := NewRootCmd()
	signAppCmd.SetArgs([]string{
		"sign", "image", rawBin,
		"-o", signedOut,
		"--header-offset", "256",
		"--role", "app",
		"--key-index", "2",
		"--mock",
	})
	if err := signAppCmd.Execute(); err != nil {
		t.Fatalf("sign app image with --key-index failed: %v", err)
	}
	signedApp, err := os.ReadFile(signedOut)
	if err != nil {
		t.Fatalf("read signed app: %v", err)
	}
	hdrOff := uint32(256)
	wantKeyIdx := uint8(2)
	mockPub := ed25519.PublicKey(provision.MockRootPublicKey)
	if valErr := signing.ValidateToobImage(signedOut, signedApp, signing.ValidateImageOptions{
		Role:                  signing.RoleApp,
		HeaderOffset:          &hdrOff,
		RequireImageSignature: true,
		KeyIndex:              &wantKeyIdx,
		SignerPub:             mockPub,
	}); valErr != nil {
		t.Fatalf("ValidateToobImage app with --key-index failed: %v", valErr)
	}

	// Signed recovery image.
	signRecCmd := NewRootCmd()
	signRecCmd.SetArgs([]string{
		"sign", "image", rawBin,
		"-o", recOut,
		"--header-offset", "256",
		"--role", "recovery",
		"--mock",
	})
	if recErr := signRecCmd.Execute(); recErr != nil {
		t.Fatalf("sign recovery image failed: %v", recErr)
	}
	signedRec, err := os.ReadFile(recOut)
	if err != nil {
		t.Fatalf("read signed recovery: %v", err)
	}
	if valErr := signing.ValidateToobImage(recOut, signedRec, signing.ValidateImageOptions{
		Role:                  signing.RoleRecovery,
		HeaderOffset:          &hdrOff,
		RequireImageSignature: true,
		SignerPub:             mockPub,
	}); valErr != nil {
		t.Fatalf("ValidateToobImage recovery failed: %v", valErr)
	}

	// Explicit --unsigned opt-out produces header + payload without TSIG trailer.
	unsignedCmd := NewRootCmd()
	unsignedCmd.SetArgs([]string{
		"sign", "image", rawBin,
		"-o", unsignedOut,
		"--header-offset", "256",
		"--role", "app",
		"--unsigned",
	})
	if unsigErr := unsignedCmd.Execute(); unsigErr != nil {
		t.Fatalf("sign --unsigned failed: %v", unsigErr)
	}
	unsignedBytes, err := os.ReadFile(unsignedOut)
	if err != nil {
		t.Fatalf("read unsigned image: %v", err)
	}
	if len(unsignedBytes) != signing.ToobImageHeaderLen+len(raw) {
		t.Fatalf("unsigned image length = %d, want %d", len(unsignedBytes), signing.ToobImageHeaderLen+len(raw))
	}

	// Conflict cases: --unsigned + --mock, and --unsigned + stage1.
	conflictKey := NewRootCmd()
	conflictKey.SetArgs([]string{
		"sign", "image", rawBin,
		"-o", unsignedOut,
		"--header-offset", "256",
		"--unsigned",
		"--mock",
	})
	if execErr := conflictKey.Execute(); execErr == nil {
		t.Fatal("expected error combining --unsigned and --mock")
	}

	conflictStage1 := NewRootCmd()
	conflictStage1.SetArgs([]string{
		"sign", "image", rawBin,
		"-o", unsignedOut,
		"--header-offset", "256",
		"--role", "stage1",
		"--stage1-svn", "1",
		"--unsigned",
	})
	if execErr := conflictStage1.Execute(); execErr == nil {
		t.Fatal("expected error combining --unsigned and --role stage1")
	}

	// Legacy E2E flag compatibility: --entry implies XIP header offset and stage1 defaults --stage1-svn to 1.
	stage1EntryOut := filepath.Join(tmp, "stage1_entry.signed.bin")
	stage1EntryCmd := NewRootCmd()
	stage1EntryCmd.SetArgs([]string{
		"sign", "stage1", rawBin,
		"--entry", "0x100",
		"--mock",
		"-o", stage1EntryOut,
	})
	if entryErr := stage1EntryCmd.Execute(); entryErr != nil {
		t.Fatalf("sign stage1 --entry 0x100 --mock failed: %v", entryErr)
	}
	signedStage1Entry, err := os.ReadFile(stage1EntryOut)
	if err != nil {
		t.Fatalf("read stage1 signed image: %v", err)
	}
	if valErr := signing.ValidateToobImage(stage1EntryOut, signedStage1Entry, signing.ValidateImageOptions{
		Role:                   signing.RoleStage1,
		HeaderOffset:           &hdrOff,
		RequireNonZeroEntry:    true,
		RequireStage1Signature: true,
		SignerPub:              mockPub,
	}); valErr != nil {
		t.Fatalf("ValidateToobImage stage1 --entry 0x100 failed: %v", valErr)
	}

	// Explicit --stage1-svn 0 must still fail closed on stage1.
	explicitZeroSVNCmd := NewRootCmd()
	explicitZeroSVNCmd.SetArgs([]string{
		"sign", "stage1", rawBin,
		"--entry", "0x100",
		"--stage1-svn", "0",
		"--mock",
		"-o", stage1EntryOut,
	})
	if execErr := explicitZeroSVNCmd.Execute(); execErr == nil {
		t.Fatal("expected explicit --stage1-svn 0 on sign stage1 to fail closed")
	}

	// Non-Stage-1 sign image --entry 0x100 produces valid 72B TSIG trailer and entry 0x100.
	imgEntryOut := filepath.Join(tmp, "app_entry.signed.bin")
	imgEntryCmd := NewRootCmd()
	imgEntryCmd.SetArgs([]string{
		"sign", "image", rawBin,
		"--entry", "0x100",
		"--mock",
		"-o", imgEntryOut,
	})
	if entryErr := imgEntryCmd.Execute(); entryErr != nil {
		t.Fatalf("sign image --entry 0x100 --mock failed: %v", entryErr)
	}
	signedImgEntry, err := os.ReadFile(imgEntryOut)
	if err != nil {
		t.Fatalf("read signed app image (--entry): %v", err)
	}
	if valErr := signing.ValidateToobImage(imgEntryOut, signedImgEntry, signing.ValidateImageOptions{
		Role:                  signing.RoleApp,
		HeaderOffset:          &hdrOff,
		RequireNonZeroEntry:   true,
		RequireImageSignature: true,
		SignerPub:             mockPub,
	}); valErr != nil {
		t.Fatalf("ValidateToobImage image --entry 0x100 failed: %v", valErr)
	}
}
