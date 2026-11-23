package signing

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash/crc32"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Toob-Boot/Toob-Loader/toob-go-lib/tbm1"
	"github.com/toob-boot/toob/internal/provision"
)

func generateTestKeypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 keypair: %v", err)
	}
	t.Cleanup(func() {
		zeroizeBytes(priv)
	})
	return pub, priv
}

func newTestSigner(t *testing.T) (*tbm1.LocalSigner, ed25519.PublicKey) {
	t.Helper()
	pub, priv := generateTestKeypair(t)
	signer, err := tbm1.NewLocalSigner(priv)
	if err != nil {
		t.Fatalf("NewLocalSigner: %v", err)
	}
	t.Cleanup(signer.Zeroise)
	return signer, pub
}

func writeTestFile(t *testing.T, path string, data []byte, perm os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, perm); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func writeMinimalELF32(t *testing.T, path string, entry uint32, code []byte) {
	t.Helper()
	// Minimal little-endian ELF32 executable with PT_LOAD, .text (SHT_PROGBITS), and .shstrtab.
	const (
		ehdrSize = 52
		phdrSize = 32
		shdrSize = 40
	)
	shstrtab := []byte("\x00.text\x00.shstrtab\x00")
	payloadOff := uint32(ehdrSize + phdrSize)
	codeLen, err := safeUint32(len(code))
	if err != nil {
		t.Fatalf("code length overflow: %v", err)
	}
	shstrOff := payloadOff + codeLen
	paddedShstrLen := uint32(((len(shstrtab) + 3) / 4) * 4)
	shoff := shstrOff + paddedShstrLen
	totalLen := int(shoff) + 3*shdrSize

	buf := make([]byte, totalLen)
	copy(buf[0:4], []byte{0x7F, 'E', 'L', 'F'})
	buf[4] = 1
	buf[5] = 1
	buf[6] = 1
	binary.LittleEndian.PutUint16(buf[16:18], 2)
	binary.LittleEndian.PutUint16(buf[18:20], 40)
	binary.LittleEndian.PutUint32(buf[20:24], 1)
	binary.LittleEndian.PutUint32(buf[24:28], entry)
	binary.LittleEndian.PutUint32(buf[28:32], ehdrSize)
	binary.LittleEndian.PutUint32(buf[32:36], shoff)
	binary.LittleEndian.PutUint16(buf[40:42], ehdrSize)
	binary.LittleEndian.PutUint16(buf[42:44], phdrSize)
	binary.LittleEndian.PutUint16(buf[44:46], 1)
	binary.LittleEndian.PutUint16(buf[46:48], shdrSize)
	binary.LittleEndian.PutUint16(buf[48:50], 3)
	binary.LittleEndian.PutUint16(buf[50:52], 2)

	// PT_LOAD program header.
	p := buf[ehdrSize:]
	binary.LittleEndian.PutUint32(p[0:4], 1)
	binary.LittleEndian.PutUint32(p[4:8], payloadOff)
	binary.LittleEndian.PutUint32(p[8:12], entry)
	binary.LittleEndian.PutUint32(p[12:16], entry)
	binary.LittleEndian.PutUint32(p[16:20], codeLen)
	binary.LittleEndian.PutUint32(p[20:24], codeLen)
	binary.LittleEndian.PutUint32(p[24:28], 5)
	binary.LittleEndian.PutUint32(p[28:32], 4)

	copy(buf[payloadOff:], code)
	copy(buf[shstrOff:], shstrtab)

	// Section 1: .text (SHT_PROGBITS=1, SHF_ALLOC|SHF_EXECINSTR=6).
	s1 := buf[int(shoff)+shdrSize:]
	binary.LittleEndian.PutUint32(s1[0:4], 1)
	binary.LittleEndian.PutUint32(s1[4:8], 1)
	binary.LittleEndian.PutUint32(s1[8:12], 6)
	binary.LittleEndian.PutUint32(s1[12:16], entry)
	binary.LittleEndian.PutUint32(s1[16:20], payloadOff)
	binary.LittleEndian.PutUint32(s1[20:24], codeLen)
	binary.LittleEndian.PutUint32(s1[32:36], 4)

	// Section 2: .shstrtab (SHT_STRTAB=3).
	s2 := buf[int(shoff)+2*shdrSize:]
	shstrLen, err := safeUint32(len(shstrtab))
	if err != nil {
		t.Fatalf("shstrtab length overflow: %v", err)
	}
	binary.LittleEndian.PutUint32(s2[0:4], 7)
	binary.LittleEndian.PutUint32(s2[4:8], 3)
	binary.LittleEndian.PutUint32(s2[16:20], shstrOff)
	binary.LittleEndian.PutUint32(s2[20:24], shstrLen)
	binary.LittleEndian.PutUint32(s2[32:36], 1)

	writeTestFile(t, path, buf, 0o644)
}

func TestKeySourceMutualExclusivityAndZeroization(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "signer.key")
	pub, priv := generateTestKeypair(t)
	writeTestFile(t, keyPath, priv, 0o600)

	cases := []struct {
		name string
		src  KeySource
	}{
		{
			name: "mock and key file",
			src:  KeySource{Mock: true, KeyFile: keyPath},
		},
		{
			name: "mock and key hex",
			src:  KeySource{Mock: true, KeyHex: strings.Repeat("aa", 32)},
		},
		{
			name: "key file and key hex",
			src:  KeySource{KeyFile: keyPath, KeyHex: strings.Repeat("aa", 32)},
		},
		{
			name: "no source",
			src:  KeySource{},
		},
		{
			name: "TV1 seed in KeyHex without Mock",
			src:  KeySource{KeyHex: provision.MockRootPrivateKeySeedHex},
		},
		{
			name: "TV1 seed in KeyFile without Mock",
			src: KeySource{KeyFile: func() string {
				p := filepath.Join(dir, "tv1.hex")
				writeTestFile(t, p, []byte(provision.MockRootPrivateKeySeedHex+"\n"), 0o600)
				return p
			}()},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := LoadSigner(tc.src); err == nil {
				t.Fatalf("expected LoadSigner(%+v) to fail closed, got nil", tc.src)
			}
		})
	}

	mockSigner, err := LoadSigner(KeySource{Mock: true})
	if err != nil {
		t.Fatalf("LoadSigner mock failed: %v", err)
	}
	defer mockSigner.Zeroise()
	if !bytes.Equal(mockSigner.Public(), provision.MockRootPublicKey) {
		t.Fatalf("mock public key mismatch: got %x, want %x", mockSigner.Public(), provision.MockRootPublicKey)
	}

	// Verify 32B/64B raw & hex loading and corrupt 64B detection.
	rawSeedPath := filepath.Join(dir, "seed32.bin")
	writeTestFile(t, rawSeedPath, priv[:32], 0o600)
	hexPrivPath := filepath.Join(dir, "priv64.hex")
	writeTestFile(t, hexPrivPath, []byte(hex.EncodeToString(priv)+"\n"), 0o600)

	for _, src := range []KeySource{
		{KeyFile: keyPath},
		{KeyFile: rawSeedPath},
		{KeyFile: hexPrivPath},
		{KeyHex: hex.EncodeToString(priv[:32])},
		{KeyHex: "0x" + hex.EncodeToString(priv)},
	} {
		s, loadErr := LoadSigner(src)
		if loadErr != nil {
			t.Fatalf("LoadSigner(%+v) failed: %v", src, loadErr)
		}
		if !bytes.Equal(s.Public(), pub) {
			t.Fatalf("loaded signer public key mismatch for %+v", src)
		}
		sig, signErr := s.Sign([]byte("hello"))
		if signErr != nil || !ed25519.Verify(pub, []byte("hello"), sig) {
			t.Fatalf("loaded signer failed sign/verify: err=%v", signErr)
		}
		s.Zeroise()
	}

	corrupt := bytes.Clone(priv)
	corrupt[63] ^= 0xFF
	if _, err := LoadSigner(KeySource{KeyHex: hex.EncodeToString(corrupt)}); err == nil {
		t.Fatal("expected corrupt 64-byte private key (mismatched public half) to fail")
	}

	buf := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	zeroizeBytes(buf)
	if !isAllZero(buf) {
		t.Fatalf("zeroizeBytes did not zero slice: %v", buf)
	}
}

func TestGenerateKeypairPermissionsAndNoSecretLeak(t *testing.T) {
	dir := t.TempDir()
	privPath := filepath.Join(dir, "root.key")
	pubPath := filepath.Join(dir, "root.pub")

	pubHex, err := GenerateKeypair(privPath, pubPath, false)
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}
	if len(pubHex) != ed25519.PublicKeySize*2 {
		t.Fatalf("expected %d-char pubHex, got %d", ed25519.PublicKeySize*2, len(pubHex))
	}

	privBytes, err := os.ReadFile(privPath)
	if err != nil {
		t.Fatalf("read private key: %v", err)
	}
	if len(privBytes) != ed25519.PrivateKeySize {
		t.Fatalf("expected 64-byte private key, got %d", len(privBytes))
	}
	pubBytes, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatalf("read public key: %v", err)
	}
	if hex.EncodeToString(pubBytes) != pubHex {
		t.Fatalf("pubHex %s does not match written public key %x", pubHex, pubBytes)
	}
	if strings.Contains(pubHex, hex.EncodeToString(privBytes[:32])) {
		t.Fatal("returned pubHex must never contain private key seed")
	}

	if runtime.GOOS != "windows" {
		info, statErr := os.Stat(privPath)
		if statErr != nil {
			t.Fatalf("stat privPath: %v", statErr)
		}
		if mode := info.Mode().Perm(); mode != 0o600 {
			t.Fatalf("private key mode = %o, want 0600", mode)
		}
	}

	signer, err := LoadSigner(KeySource{KeyFile: privPath})
	if err != nil {
		t.Fatalf("LoadSigner on generated key: %v", err)
	}
	defer signer.Zeroise()
	if !bytes.Equal(signer.Public(), pubBytes) {
		t.Fatal("generated keypair pub/priv mismatch")
	}

	if _, dupErr := GenerateKeypair(privPath, pubPath, false); dupErr == nil {
		t.Fatal("expected GenerateKeypair without overwrite to fail on existing files")
	}

	newPubHex, err := GenerateKeypair(privPath, pubPath, true)
	if err != nil {
		t.Fatalf("GenerateKeypair with overwrite failed: %v", err)
	}
	if newPubHex == pubHex {
		t.Fatal("expected newly generated keypair on overwrite to have a fresh public key")
	}
}

func TestSignManifestRoundTripCrit48(t *testing.T) {
	signer, pub := newTestSigner(t)
	payload := bytes.Repeat([]byte{0xA5}, 256)

	unsignedPkg, err := tbm1.BuildUnsigned(tbm1.Manifest{
		VendorID:   1,
		ProductID:  2,
		SVN:        3,
		AutoSBOM:   true,
		SectorSize: 4096,
		Images: []tbm1.Image{
			{
				TargetSlot: tbm1.SlotApp,
				Installed:  payload,
			},
		},
	})
	if err != nil {
		t.Fatalf("BuildUnsigned: %v", err)
	}

	inMemSigned, err := SignManifestBytes(unsignedPkg.Block, signer)
	if err != nil {
		t.Fatalf("SignManifestBytes: %v", err)
	}
	if verifyErr := tbm1.VerifyBlock(inMemSigned, pub); verifyErr != nil {
		t.Fatalf("VerifyBlock on SignManifestBytes failed: %v", verifyErr)
	}

	dir := t.TempDir()
	inPath := filepath.Join(dir, "unsigned.tbm1")
	outPath := filepath.Join(dir, "signed.tbm1")
	writeTestFile(t, inPath, unsignedPkg.Block, 0o644)

	pubHex, err := SignManifest(inPath, outPath, signer)
	if err != nil {
		t.Fatalf("SignManifest: %v", err)
	}
	if pubHex != hex.EncodeToString(pub) {
		t.Fatalf("unexpected pubHex: got %s, want %x", pubHex, pub)
	}

	// Verify in-place signing when outPath is empty.
	inPlacePath := filepath.Join(dir, "inplace.tbm1")
	writeTestFile(t, inPlacePath, unsignedPkg.Block, 0o644)
	if _, inPlaceErr := SignManifest(inPlacePath, "", signer); inPlaceErr != nil {
		t.Fatalf("SignManifest in-place: %v", inPlaceErr)
	}
	inPlaceBytes, err := os.ReadFile(inPlacePath)
	if err != nil {
		t.Fatalf("read inplace.tbm1: %v", err)
	}
	if verifyErr := tbm1.VerifyBlock(inPlaceBytes, pub); verifyErr != nil {
		t.Fatalf("VerifyBlock on in-place manifest failed: %v", verifyErr)
	}

	signedBytes, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read signed.tbm1: %v", err)
	}
	if magic := binary.LittleEndian.Uint32(signedBytes[0:4]); magic != tbm1.Magic {
		t.Fatalf("manifest header magic corrupted (CRIT-48 regression!): got 0x%08x, want 0x%08x", magic, tbm1.Magic)
	}

	sig, err := tbm1.ExtractSignature(signedBytes)
	if err != nil {
		t.Fatalf("ExtractSignature: %v", err)
	}
	if len(sig) != tbm1.SigLen || isAllZero(sig) {
		t.Fatalf("invalid extracted signature length=%d", len(sig))
	}
	if verifyErr := tbm1.VerifyBlock(signedBytes, pub); verifyErr != nil {
		t.Fatalf("VerifyBlock failed: %v", verifyErr)
	}

	// Tampering signature or header must fail verification.
	tampered := bytes.Clone(signedBytes)
	tampered[len(tampered)-1] ^= 0x01
	if verifyErr := tbm1.VerifyBlock(tampered, pub); verifyErr == nil {
		t.Fatal("expected VerifyBlock to reject tampered signature")
	}

	otherPub, _ := generateTestKeypair(t)
	if verifyErr := tbm1.VerifyBlock(signedBytes, otherPub); verifyErr == nil {
		t.Fatal("expected VerifyBlock to reject wrong public key")
	}
}

func TestSignImageArchitecturesDualLinkAndValidation(t *testing.T) {
	signer, pub := newTestSigner(t)
	dir := t.TempDir()

	stmHW := filepath.Join(dir, "stm32_hardware.json")
	writeTestFile(t, stmHW, []byte(`{
		"chip_family": "stm32f4",
		"flash": {
			"size": 524288,
			"write_alignment": 4,
			"app_alignment": 131072,
			"vtor_alignment": 256,
			"image_header_offset": 256,
			"stage0_exec_mode": "xip",
			"regions": [
				{"type": "sector", "base": 0, "size": 524288, "sector_size": 131072, "count": 4}
			]
		},
		"memory": {"iram_base": "0x20000000", "iram_size": "0x30000"}
	}`), 0o644)
	stmCM := filepath.Join(dir, "chip_manifest.json")
	writeTestFile(t, stmCM, []byte(`{
		"name": "stm32f429",
		"arch": "cortex-m4",
		"compiler_prefix": "arm-none-eabi-",
		"version": "1.0.0",
		"min_core_sdk": "2.0.0",
		"min_compiler": "12.0.0",
		"slot_capabilities": {"exec_model": "xip_dual_link", "slot_count": 2, "has_scratch": false}
	}`), 0o644)

	// 1. Cortex-M app image resolves image_header_offset=256 declaratively and sets image_size = 20 + len(padded) + 72 (TSIG).
	cortexPayload := bytes.Repeat([]byte{0x42}, 500)
	appRes, err := SignImage(ImageOptions{
		Payload:                cortexPayload,
		HardwarePath:           stmHW,
		Role:                   RoleApp,
		RequireBaseFingerprint: true,
	}, signer)
	if err != nil {
		t.Fatalf("SignImage Cortex-M app failed: %v", err)
	}
	if appRes.HeaderOffset != 256 {
		t.Fatalf("Cortex-M HeaderOffset = %d, want 256", appRes.HeaderOffset)
	}
	if appRes.EntryPoint != 256 {
		t.Fatalf("Cortex-M default EntryPoint = %d, want 256", appRes.EntryPoint)
	}
	if appRes.ImageSize != 592 {
		t.Fatalf("Cortex-M app ImageSize = %d, want 592 (20 + 500 + 72)", appRes.ImageSize)
	}
	var wantKeyIdx uint8
	if valErr := ValidateToobImage("app", appRes.Data, ValidateImageOptions{
		Role:                   RoleApp,
		HeaderOffset:           &appRes.HeaderOffset,
		RequireNonZeroEntry:    true,
		RequireBaseFingerprint: true,
		RequireImageSignature:  true,
		KeyIndex:               &wantKeyIdx,
		SignerPub:              pub,
	}); valErr != nil {
		t.Fatalf("ValidateToobImage Cortex-M app failed: %v", valErr)
	}

	// Refuse Cortex-M hardware missing image_header_offset and vtor_alignment (no silent 0x14 fallback).
	noOffsetDir := filepath.Join(dir, "cortex_no_off")
	if mkErr := os.MkdirAll(noOffsetDir, 0o755); mkErr != nil {
		t.Fatalf("mkdir: %v", mkErr)
	}
	badCortexHW := filepath.Join(noOffsetDir, "hardware.json")
	writeTestFile(t, badCortexHW, []byte(`{
		"chip_family": "stm32f4",
		"flash": {"size": 65536, "write_alignment": 4, "app_alignment": 4096, "regions": [{"type": "uniform", "base": 0, "size": 65536, "sector_size": 4096}]},
		"memory": {"iram_base": "0x20000000", "iram_size": "0x4000"}
	}`), 0o644)
	writeTestFile(t, filepath.Join(noOffsetDir, "chip_manifest.json"), []byte(`{
		"name": "bad_cm",
		"arch": "cortex-m4",
		"compiler_prefix": "arm-none-eabi-",
		"version": "1.0.0",
		"min_core_sdk": "2.0.0",
		"min_compiler": "12.0.0",
		"slot_capabilities": {"exec_model": "xip_dual_link", "slot_count": 2}
	}`), 0o644)
	if _, noOffErr := SignImage(ImageOptions{Payload: cortexPayload, HardwarePath: badCortexHW, Role: RoleApp}, signer); noOffErr == nil {
		t.Fatal("expected Cortex-M missing image_header_offset/vtor_alignment to fail closed (CRIT-49)")
	}

	// 2. Dual-Link stage1a/stage1b support and rejection of ambiguous generic stage1 on Dual-Link chip.
	if _, genErr := SignImage(ImageOptions{
		Payload:      cortexPayload,
		HardwarePath: stmHW,
		Role:         RoleStage1,
		Stage1SVN:    3,
	}, signer); genErr == nil {
		t.Fatal("expected generic RoleStage1 to be rejected on xip_dual_link chip")
	}

	for _, role := range []ImageRole{RoleStage1A, RoleStage1B} {
		// Include unaligned payload length (501 bytes) to exercise 4-byte 0xFF padding -> 504.
		rawStage1 := bytes.Repeat([]byte{0x11}, 501)
		res, s1Err := SignImage(ImageOptions{
			Payload:      rawStage1,
			HardwarePath: stmHW,
			Role:         role,
			Stage1SVN:    7,
		}, signer)
		if s1Err != nil {
			t.Fatalf("SignImage %s failed: %v", role, s1Err)
		}
		if res.ImageSize != 504 {
			t.Fatalf("%s ImageSize = %d, want 504 (payload-only ABI)", role, res.ImageSize)
		}
		if len(res.Data) != 20+504+64 {
			t.Fatalf("%s total bytes = %d, want %d", role, len(res.Data), 20+504+64)
		}
		if gotPad := res.Data[20+501 : 20+504]; !bytes.Equal(gotPad, []byte{0xFF, 0xFF, 0xFF}) {
			t.Fatalf("%s padding bytes = %x, want ffffff", role, gotPad)
		}
		if valErr := ValidateToobImage(string(role), res.Data, ValidateImageOptions{
			Role:                   role,
			HeaderOffset:           &res.HeaderOffset,
			RequireNonZeroEntry:    true,
			RequireStage1Signature: true,
			SignerPub:              pub,
		}); valErr != nil {
			t.Fatalf("ValidateToobImage %s failed: %v", role, valErr)
		}
	}

	// 3. ESP32 (image_header_offset = 20, RAM stage0_exec_mode).
	espDir := filepath.Join(dir, "esp32c6")
	if mkErr := os.MkdirAll(espDir, 0o755); mkErr != nil {
		t.Fatalf("mkdir: %v", mkErr)
	}
	espHW := filepath.Join(espDir, "hardware.json")
	writeTestFile(t, espHW, []byte(`{
		"chip_family": "esp32c6",
		"flash": {
			"size": 4194304,
			"write_alignment": 4,
			"app_alignment": 65536,
			"image_header_offset": 20,
			"stage0_exec_mode": "ram",
			"regions": [
				{"type": "uniform", "base": 0, "size": 4194304, "sector_size": 4096}
			]
		},
		"memory": {"iram_base": "0x40800000", "iram_size": "0x80000"}
	}`), 0o644)
	writeTestFile(t, filepath.Join(espDir, "chip_manifest.json"), []byte(`{
		"name": "esp32c6",
		"arch": "riscv32",
		"compiler_prefix": "riscv32-esp-elf-",
		"version": "1.0.0",
		"min_core_sdk": "2.0.0",
		"min_compiler": "12.0.0",
		"slot_capabilities": {"exec_model": "ram", "slot_count": 1}
	}`), 0o644)

	espApp, err := SignImage(ImageOptions{
		Payload:      bytes.Repeat([]byte{0x77}, 128),
		HardwarePath: espHW,
		Role:         RoleApp,
	}, signer)
	if err != nil {
		t.Fatalf("SignImage ESP32 app failed: %v", err)
	}
	if espApp.HeaderOffset != 20 || espApp.EntryPoint != 20 || espApp.ImageSize != 220 {
		t.Fatalf("unexpected ESP32 app header layout: %+v", espApp)
	}
	if valErr := ValidateToobImage("esp_app", espApp.Data, ValidateImageOptions{
		Role:                  RoleApp,
		HeaderOffset:          &espApp.HeaderOffset,
		RequireImageSignature: true,
		SignerPub:             pub,
	}); valErr != nil {
		t.Fatalf("ValidateToobImage ESP32 app failed: %v", valErr)
	}

	espStage1, err := SignImage(ImageOptions{
		Payload:      bytes.Repeat([]byte{0x33}, 128),
		HardwarePath: espHW,
		Role:         RoleStage1,
		EntryPoint:   0x40801000,
		Stage1SVN:    1,
	}, signer)
	if err != nil {
		t.Fatalf("SignImage ESP32 RAM stage1 failed: %v", err)
	}
	if espStage1.ImageSize != 128 || espStage1.EntryPoint != 0x40801000 {
		t.Fatalf("unexpected ESP32 stage1 layout: %+v", espStage1)
	}

	if _, err := SignImage(ImageOptions{
		Payload:      bytes.Repeat([]byte{0x33}, 128),
		HardwarePath: espHW,
		Role:         RoleStage1,
		EntryPoint:   0x10000000,
		Stage1SVN:    1,
	}, signer); err == nil {
		t.Fatal("expected out-of-IRAM EntryPoint for RAM-exec stage1 to fail")
	}

	// 4. ValidateToobImage negative cases (zero entry_point, zero base_fingerprint, bad magic/size).
	zeroFP := bytes.Clone(appRes.Data)
	clear(zeroFP[12:20])
	if err := ValidateToobImage("zero_fp", zeroFP, ValidateImageOptions{Role: RoleApp, RequireBaseFingerprint: true}); err == nil {
		t.Fatal("expected all-zero base_fingerprint to fail ValidateToobImage")
	}

	zeroEntry := bytes.Clone(appRes.Data)
	binary.LittleEndian.PutUint32(zeroEntry[8:12], 0)
	if err := ValidateToobImage("zero_entry", zeroEntry, ValidateImageOptions{Role: RoleApp, RequireNonZeroEntry: true}); err == nil {
		t.Fatal("expected zero entry_point to fail ValidateToobImage")
	}

	badSize := bytes.Clone(appRes.Data)
	binary.LittleEndian.PutUint32(badSize[4:8], uint32(len(cortexPayload))) // missing +20 header ABI
	if err := ValidateToobImage("wrong_size", badSize, ValidateImageOptions{Role: RoleApp}); err == nil {
		t.Fatal("expected app image_size without 20B header to fail ValidateToobImage")
	}
}

func TestSignImageTSIGTrailerAndUnsignedOptOut(t *testing.T) {
	signer, pub := newTestSigner(t)
	_, otherPub := newTestSigner(t)
	hdrOff := uint32(256)
	payload := bytes.Repeat([]byte{0x5A}, 300)

	// Missing signer without explicit Unsigned opt-out must fail closed for all non-Stage-1 roles.
	for _, role := range []ImageRole{RoleApp, RoleRecovery, RoleNetcore} {
		if _, err := SignImage(ImageOptions{
			Payload:      payload,
			HeaderOffset: &hdrOff,
			Role:         role,
		}, nil); err == nil {
			t.Fatalf("expected missing signer without Unsigned=true to fail for role %s", role)
		}
	}

	// TSIG signing roundtrip for App, Recovery, and Netcore with custom KeyIndex.
	const testKeyIndex uint8 = 3
	for _, role := range []ImageRole{RoleApp, RoleRecovery, RoleNetcore} {
		res, err := SignImage(ImageOptions{
			Payload:      payload,
			HeaderOffset: &hdrOff,
			Role:         role,
			KeyIndex:     testKeyIndex,
		}, signer)
		if err != nil {
			t.Fatalf("SignImage TSIG role %s failed: %v", role, err)
		}
		wantTotal := uint32(ToobImageHeaderLen + len(payload) + ToobImgSigTrailerLen)
		if res.ImageSize != wantTotal || uint32(len(res.Data)) != wantTotal {
			t.Fatalf("%s signed size = (%d, %d), want %d", role, res.ImageSize, len(res.Data), wantTotal)
		}

		trailer := res.Data[len(res.Data)-ToobImgSigTrailerLen:]
		if gotMagic := binary.LittleEndian.Uint32(trailer[0:4]); gotMagic != ToobImgSigMagic {
			t.Fatalf("%s TSIG magic = 0x%08x, want 0x%08x", role, gotMagic, ToobImgSigMagic)
		}
		if trailer[4] != testKeyIndex {
			t.Fatalf("%s TSIG key_index = %d, want %d", role, trailer[4], testKeyIndex)
		}
		if trailer[5] != ToobImgSigFlagSHA256 {
			t.Fatalf("%s TSIG flags = 0x%02x, want 0x%02x", role, trailer[5], ToobImgSigFlagSHA256)
		}
		if reserved := binary.LittleEndian.Uint16(trailer[6:8]); reserved != 0 {
			t.Fatalf("%s TSIG reserved = 0x%04x, want 0", role, reserved)
		}
		digest := sha256.Sum256(res.Data[:len(res.Data)-ToobImgSigTrailerLen])
		if !ed25519.Verify(pub, digest[:], trailer[8:ToobImgSigTrailerLen]) {
			t.Fatalf("%s TSIG Ed25519 signature did not verify over SHA-256(image[0..len-72))", role)
		}

		wantIdx := testKeyIndex
		if valErr := ValidateToobImage(string(role), res.Data, ValidateImageOptions{
			Role:                  role,
			HeaderOffset:          &hdrOff,
			RequireNonZeroEntry:   true,
			RequireImageSignature: true,
			KeyIndex:              &wantIdx,
			SignerPub:             pub,
		}); valErr != nil {
			t.Fatalf("ValidateToobImage %s TSIG failed: %v", role, valErr)
		}
	}

	// Explicit Unsigned opt-out builds header+payload without TSIG trailer for non-Stage-1.
	unsignedRes, err := SignImage(ImageOptions{
		Payload:      payload,
		HeaderOffset: &hdrOff,
		Role:         RoleApp,
		Unsigned:     true,
	}, nil)
	if err != nil {
		t.Fatalf("SignImage Unsigned app failed: %v", err)
	}
	wantUnsignedSize := uint32(ToobImageHeaderLen + len(payload))
	if unsignedRes.ImageSize != wantUnsignedSize || uint32(len(unsignedRes.Data)) != wantUnsignedSize {
		t.Fatalf("unsigned image size = (%d, %d), want %d", unsignedRes.ImageSize, len(unsignedRes.Data), wantUnsignedSize)
	}
	if valErr := ValidateToobImage("unsigned_require_sig", unsignedRes.Data, ValidateImageOptions{
		Role:                  RoleApp,
		RequireImageSignature: true,
	}); valErr == nil {
		t.Fatal("expected unsigned image to fail ValidateToobImage when RequireImageSignature=true")
	}

	// Mutual exclusivity & Stage-1 guardrails.
	if _, err = SignImage(ImageOptions{Payload: payload, HeaderOffset: &hdrOff, Role: RoleStage1, Stage1SVN: 1, Unsigned: true}, nil); err == nil {
		t.Fatal("expected Unsigned=true on Stage-1 role to fail")
	}
	if _, err = SignImage(ImageOptions{Payload: payload, HeaderOffset: &hdrOff, Role: RoleApp, Unsigned: true}, signer); err == nil {
		t.Fatal("expected Unsigned=true with non-nil signer to fail")
	}
	if _, err = SignImage(ImageOptions{Payload: payload, HeaderOffset: &hdrOff, Role: RoleApp, Unsigned: true, KeyIndex: 1}, nil); err == nil {
		t.Fatal("expected Unsigned=true with KeyIndex!=0 to fail")
	}
	if _, err = SignImage(ImageOptions{Payload: payload, HeaderOffset: &hdrOff, Role: RoleStage1, Stage1SVN: 1, KeyIndex: 1}, signer); err == nil {
		t.Fatal("expected KeyIndex!=0 on Stage-1 role to fail")
	}

	// Corrupted TSIG negative checks.
	signedApp, err := SignImage(ImageOptions{
		Payload:      payload,
		HeaderOffset: &hdrOff,
		Role:         RoleApp,
		KeyIndex:     2,
	}, signer)
	if err != nil {
		t.Fatalf("SignImage signedApp: %v", err)
	}
	checkReject := func(name string, mutator func([]byte), keyIdx *uint8, verifyPub ed25519.PublicKey) {
		t.Helper()
		corrupt := bytes.Clone(signedApp.Data)
		mutator(corrupt)
		if valErr := ValidateToobImage(name, corrupt, ValidateImageOptions{
			Role:                  RoleApp,
			HeaderOffset:          &hdrOff,
			RequireImageSignature: true,
			KeyIndex:              keyIdx,
			SignerPub:             verifyPub,
		}); valErr == nil {
			t.Fatalf("expected TSIG validation failure for %s", name)
		}
	}

	trailerStart := len(signedApp.Data) - ToobImgSigTrailerLen
	checkReject("wrong_pubkey", func(_ []byte) {}, nil, otherPub)
	wrongIdx := uint8(1)
	checkReject("wrong_key_index", func(_ []byte) {}, &wrongIdx, pub)
	checkReject("corrupt_magic", func(b []byte) { b[trailerStart] ^= 0xFF }, nil, pub)
	checkReject("corrupt_flags", func(b []byte) { b[trailerStart+5] = 0x02 }, nil, pub)
	checkReject("nonzero_reserved", func(b []byte) { b[trailerStart+6] = 0x01 }, nil, pub)
	checkReject("zero_signature", func(b []byte) { clear(b[trailerStart+8 : trailerStart+ToobImgSigTrailerLen]) }, nil, nil)
	checkReject("tampered_payload", func(b []byte) { b[ToobImageHeaderLen+4] ^= 0x01 }, nil, pub)
	checkReject("entry_inside_tsig", func(b []byte) {
		binary.LittleEndian.PutUint32(b[8:12], uint32(trailerStart))
	}, nil, pub)
}

func TestPackStage0FailFastOnCorruptManifestAndValidPack(t *testing.T) {
	dir := t.TempDir()
	elfPath := filepath.Join(dir, "stage0.elf")
	writeMinimalELF32(t, elfPath, 0x40800000, bytes.Repeat([]byte{0x13, 0x00, 0x00, 0x00}, 16))

	corruptDir := filepath.Join(dir, "packages", "chips", "corruptchip")
	if err := os.MkdirAll(corruptDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	hwPath := filepath.Join(corruptDir, "hardware.json")
	writeTestFile(t, hwPath, []byte(`{
		"chip_family": "corruptchip",
		"bootrom_image": {"layout": "flat"},
		"flash": {"size": 65536, "write_alignment": 4, "app_alignment": 4096, "regions": [{"type": "uniform", "base": 0, "size": 65536, "sector_size": 4096}]},
		"memory": {"iram_base": "0x40800000", "iram_size": "0x10000"}
	}`), 0o644)

	// Corrupt JSON / unknown field / duplicate key must fail fast (HIGH-67).
	cmPath := filepath.Join(corruptDir, "chip_manifest.json")
	for _, badJSON := range []string{
		`{not-valid-json`,
		`{"arch":"riscv32","arch":"riscv32"}`,
		`{"arch":"riscv32","unknown_field":true}`,
		`{}`,
	} {
		writeTestFile(t, cmPath, []byte(badJSON), 0o644)
		_, err := PackStage0(Stage0Options{
			ELFPath:  elfPath,
			OutPath:  filepath.Join(dir, "out.bin"),
			Chip:     "corruptchip",
			CacheDir: dir,
		})
		if err == nil {
			t.Fatalf("expected PackStage0 to fail fast on corrupt chip_manifest %s", badJSON)
		}
	}

	// Valid chip_manifest + flat bootrom_image packs cleanly.
	writeTestFile(t, cmPath, []byte(`{
		"name": "corruptchip",
		"arch": "riscv32",
		"compiler_prefix": "riscv32-esp-elf-",
		"version": "1.0.0",
		"min_core_sdk": "2.0.0",
		"min_compiler": "12.0.0",
		"slot_capabilities": {"exec_model": "ram", "slot_count": 1}
	}`), 0o644)
	outBin := filepath.Join(dir, "stage0.bin")
	packRes, err := PackStage0(Stage0Options{
		ELFPath:  elfPath,
		OutPath:  outBin,
		Chip:     "corruptchip",
		CacheDir: dir,
	})
	if err != nil {
		t.Fatalf("PackStage0 valid pack failed: %v", err)
	}
	if packRes.Size != 64 {
		t.Fatalf("packed Stage-0 size = %d, want 64", packRes.Size)
	}
}

func TestSignBundleSTM32SectorSlotsBudgetAndPQC(t *testing.T) {
	signer, pub := newTestSigner(t)
	dir := t.TempDir()

	// STM32 multi-region flash where max sector_size = 128 KiB (131072 bytes).
	stmDir := filepath.Join(dir, "packages", "chips", "stm32f429")
	if err := os.MkdirAll(stmDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	hwPath := filepath.Join(stmDir, "hardware.json")
	writeTestFile(t, hwPath, []byte(`{
		"chip_family": "stm32f4",
		"flash": {
			"size": 2097152,
			"write_alignment": 4,
			"app_alignment": 131072,
			"vtor_alignment": 256,
			"image_header_offset": 256,
			"regions": [
				{"type": "sector", "base": 0, "size": 65536, "sector_size": 16384, "count": 4},
				{"type": "sector", "base": 65536, "size": 65536, "sector_size": 65536, "count": 1},
				{"type": "sector", "base": 131072, "size": 1966080, "sector_size": 131072, "count": 15}
			]
		},
		"memory": {"iram_base": "0x20000000", "iram_size": "0x30000"}
	}`), 0o644)
	writeTestFile(t, filepath.Join(stmDir, "chip_manifest.json"), []byte(`{
		"name": "stm32f429",
		"arch": "cortex-m4",
		"compiler_prefix": "arm-none-eabi-",
		"version": "1.0.0",
		"min_core_sdk": "2.0.0",
		"min_compiler": "12.0.0",
		"slot_capabilities": {"exec_model": "xip_dual_link", "slot_count": 2}
	}`), 0o644)

	devTomlPath := filepath.Join(dir, "device.toml")
	writeTestFile(t, devTomlPath, []byte(`
name = "stm-node"
version = "1.0.0"

[identity]
vendor_id = 42
product_id = 7
hw_rev = 1

[device]
chip = "stm32f429"

[crypto]
backend = "monocypher"
hash = "sha256"
pqc = "none"

[partitions]
stage0_size = 131072
stage1_size = 131072
app_size = 262144
wal_sectors = 2

[boot_config]
transport_provider = "oneway"
stage1_svn = 5
`), 0o644)

	// 1. Refuse bundle without explicit Role / TargetSlot (never hardcode SlotApp).
	appImg := bytes.Repeat([]byte{0x5A}, 4096)
	if _, slotErr := SignBundle(BundleOptions{
		Installed:      appImg,
		DeviceTomlPath: devTomlPath,
		CacheDir:       dir,
	}, signer); slotErr == nil {
		t.Fatal("expected SignBundle without Role/TargetSlot to fail closed")
	}

	// 2. Refuse undersized explicit SectorSize on 128 KiB STM32 flash.
	if _, secErr := SignBundle(BundleOptions{
		Installed:      appImg,
		Role:           RoleApp,
		DeviceTomlPath: devTomlPath,
		CacheDir:       dir,
		SectorSize:     4096,
	}, signer); secErr == nil {
		t.Fatal("expected SectorSize=4096 < STM32 131072 max sector size to fail closed")
	}

	// 3. 128 KiB sector trailer bundle on non-App slots (recovery, netcore, stage1a).
	outBundle := filepath.Join(dir, "recovery.tbm1")
	res, err := SignBundle(BundleOptions{
		Installed:      appImg,
		OutPath:        outBundle,
		Role:           RoleRecovery,
		DeviceTomlPath: devTomlPath,
		CacheDir:       dir,
		SVN:            9,
	}, signer)
	if err != nil {
		t.Fatalf("SignBundle STM32 recovery failed: %v", err)
	}
	if res.SectorSize != 131072 {
		t.Fatalf("resolved SectorSize = %d, want 131072", res.SectorSize)
	}
	if res.TargetSlot != tbm1.SlotRecovery {
		t.Fatalf("TargetSlot = %d, want %d", res.TargetSlot, tbm1.SlotRecovery)
	}
	if res.StagingBudget != 262144 {
		t.Fatalf("StagingBudget = %d, want 262144", res.StagingBudget)
	}
	if res.TransportProvider != "oneway" {
		t.Fatalf("TransportProvider = %q, want oneway", res.TransportProvider)
	}

	off, length, err := tbm1.ParseTrailerLocator(res.Data)
	if err != nil {
		t.Fatalf("ParseTrailerLocator: %v", err)
	}
	if off%131072 != 0 {
		t.Fatalf("trailer offset %d is not 128 KiB aligned", off)
	}
	if verErr := tbm1.VerifyBlock(res.Data[off:off+length], pub); verErr != nil {
		t.Fatalf("VerifyBlock on STM32 trailer manifest failed: %v", verErr)
	}

	// Netcore + Dual-Link Stage1A slot check (matching Stage1SVN header).
	s1Img, err := SignImage(ImageOptions{
		Payload:      bytes.Repeat([]byte{0x3C}, 512),
		HardwarePath: hwPath,
		Role:         RoleStage1A,
		Stage1SVN:    5,
	}, signer)
	if err != nil {
		t.Fatalf("SignImage stage1a: %v", err)
	}
	s1Bundle, err := SignBundle(BundleOptions{
		Installed:      s1Img.Data,
		Role:           RoleStage1A,
		DeviceTomlPath: devTomlPath,
		CacheDir:       dir,
		SVN:            9,
	}, signer)
	if err != nil {
		t.Fatalf("SignBundle stage1a failed: %v", err)
	}
	if s1Bundle.TargetSlot != tbm1.SlotStage1 {
		t.Fatalf("stage1a TargetSlot = %d, want %d", s1Bundle.TargetSlot, tbm1.SlotStage1)
	}

	// Stage1SVN disagreement must fail closed.
	if _, svnErr := SignBundle(BundleOptions{
		Installed:      s1Img.Data,
		Role:           RoleStage1A,
		DeviceTomlPath: devTomlPath,
		CacheDir:       dir,
		Stage1SVN:      99,
	}, signer); svnErr == nil {
		t.Fatal("expected Stage1SVN mismatch between bundle and image header to fail closed")
	}

	netcoreRes, err := SignBundle(BundleOptions{
		Installed:      appImg,
		Role:           RoleNetcore,
		DeviceTomlPath: devTomlPath,
		CacheDir:       dir,
	}, signer)
	if err != nil {
		t.Fatalf("SignBundle netcore failed: %v", err)
	}
	if netcoreRes.TargetSlot != tbm1.SlotNetcore {
		t.Fatalf("netcore TargetSlot = %d, want %d", netcoreRes.TargetSlot, tbm1.SlotNetcore)
	}

	// 4. Staging budget overflow rejection (MED-56) and swapmove spare-sector budget accounting.
	tightToml := filepath.Join(dir, "tight_device.toml")
	writeTestFile(t, tightToml, []byte(`
name = "tight"
version = "1.0.0"

[device]
chip = "stm32f429"

[partitions]
stage0_size = 131072
stage1_size = 131072
app_size = 131072

[boot_config]
transport_provider = "pointer"
`), 0o644)
	// With 131072 sector size + trailer + TrailerLocator, even a 4 KiB app bundle becomes >131072 bytes!
	overflowOut := filepath.Join(dir, "overflow.tbm1")
	if _, ovErr := SignBundle(BundleOptions{
		Installed:      appImg,
		OutPath:        overflowOut,
		Role:           RoleApp,
		DeviceTomlPath: tightToml,
		CacheDir:       dir,
	}, signer); ovErr == nil {
		t.Fatal("expected SignBundle to reject finished .tbm1 exceeding layout.Staging.Budget")
	}
	if _, statErr := os.Stat(overflowOut); !os.IsNotExist(statErr) {
		t.Fatal("overflowed bundle must not be written to disk")
	}

	swapMoveToml := filepath.Join(dir, "swapmove_device.toml")
	writeTestFile(t, swapMoveToml, []byte(`
name = "swapmove-node"
version = "1.0.0"

[device]
chip = "stm32f429"

[partitions]
stage0_size = 131072
stage1_size = 131072
app_size = 131072

[boot_config]
transport_provider = "swapmove"
`), 0o644)
	smRes, err := SignBundle(BundleOptions{
		Installed:      appImg,
		Role:           RoleApp,
		DeviceTomlPath: swapMoveToml,
		CacheDir:       dir,
	}, signer)
	if err != nil {
		t.Fatalf("SignBundle swapmove failed: %v", err)
	}
	if smRes.StagingBudget != 262144 {
		t.Fatalf("swapmove StagingBudget = %d, want 262144 (app_size + 1 spare sector)", smRes.StagingBudget)
	}

	// 5. PQC ml_dsa_65 fail-closed gate & detached valid PQC signature embedding.
	pqcToml := filepath.Join(dir, "pqc_device.toml")
	writeTestFile(t, pqcToml, []byte(`
name = "pqc-node"
version = "1.0.0"

[device]
chip = "stm32f429"

[crypto]
pqc = "ml_dsa_65"

[partitions]
stage0_size = 131072
stage1_size = 131072
app_size = 262144

[boot_config]
transport_provider = "oneway"
`), 0o644)
	if _, pqcErr := SignBundle(BundleOptions{
		Installed:      appImg,
		Role:           RoleApp,
		DeviceTomlPath: pqcToml,
		CacheDir:       dir,
	}, signer); pqcErr == nil {
		t.Fatal("expected ml_dsa_65 PQC bundle without detached pubkey/sig to fail closed")
	}

	pqcPub := bytes.Repeat([]byte{0x21}, MLDSA65PublicKeySize)
	pqcSig := bytes.Repeat([]byte{0x43}, MLDSA65SignatureSize)
	pqcRes, err := SignBundle(BundleOptions{
		Installed:      appImg,
		Role:           RoleApp,
		DeviceTomlPath: pqcToml,
		CacheDir:       dir,
		PQCPubkey:      pqcPub,
		PQCSig:         pqcSig,
	}, signer)
	if err != nil {
		t.Fatalf("SignBundle with ml_dsa_65 detached signature failed: %v", err)
	}
	if pqcRes.PQCAlgorithm != MLDSA65Algorithm {
		t.Fatalf("PQCAlgorithm = %q, want %q", pqcRes.PQCAlgorithm, MLDSA65Algorithm)
	}
	pOff, pLen, err := tbm1.ParseTrailerLocator(pqcRes.Data)
	if err != nil {
		t.Fatalf("ParseTrailerLocator PQC: %v", err)
	}
	hdr, err := tbm1.ParseHeader(pqcRes.Data[pOff : pOff+pLen])
	if err != nil {
		t.Fatalf("ParseHeader PQC: %v", err)
	}
	if hdr.FlagsCritical&tbm1.CritPQCRequired == 0 {
		t.Fatalf("expected CritPQCRequired flag on PQC bundle, got flags=0x%x", hdr.FlagsCritical)
	}
}

func TestCloudCommandAndKDMWireRoundTrips(t *testing.T) {
	rootSigner, rootPub := newTestSigner(t)
	cloudSigner, cloudPub := newTestSigner(t)
	_, nextCloudPub := newTestSigner(t)

	// 1. KDM exact 128-byte wire layout + signature + tamper checks.
	kdm, err := SignKDM(KDMOptions{
		SequenceNumber: 42,
		NewCloudPubkey: nextCloudPub,
	}, rootSigner)
	if err != nil {
		t.Fatalf("SignKDM: %v", err)
	}
	if len(kdm) != KDMSize {
		t.Fatalf("KDM length = %d, want %d", len(kdm), KDMSize)
	}
	if seq := binary.LittleEndian.Uint32(kdm[0:4]); seq != 42 {
		t.Fatalf("KDM sequence = %d, want 42", seq)
	}
	if !bytes.Equal(kdm[4:36], nextCloudPub) {
		t.Fatal("KDM pubkey mismatch")
	}
	if !isAllZero(kdm[100:128]) {
		t.Fatal("KDM trailing padding must be zero")
	}
	if !ed25519.Verify(rootPub, kdm[0:36], kdm[36:100]) {
		t.Fatal("KDM Ed25519 signature does not cover bytes [0:36]")
	}
	if verErr := VerifyKDM(kdm, rootPub); verErr != nil {
		t.Fatalf("VerifyKDM failed: %v", verErr)
	}

	tamperedKDM := bytes.Clone(kdm)
	tamperedKDM[0] ^= 0x01
	if verErr := VerifyKDM(tamperedKDM, rootPub); verErr == nil {
		t.Fatal("expected VerifyKDM to fail on sequence bit flip")
	}
	paddedKDM := bytes.Clone(kdm)
	paddedKDM[127] = 0x01
	if verErr := VerifyKDM(paddedKDM, rootPub); verErr == nil {
		t.Fatal("expected VerifyKDM to fail on non-zero tail padding")
	}
	if _, zeroPubErr := SignKDM(KDMOptions{SequenceNumber: 1, NewCloudPubkey: make([]byte, 32)}, rootSigner); zeroPubErr == nil {
		t.Fatal("expected SignKDM to reject all-zero pubkey")
	}

	// 2. TCC1 generic command with non-16-byte params verifying 16B alignment, IEEE CRC-32, and Ed25519 sig.
	sum := sha256.Sum256([]byte("device-serial-01"))
	devID := sum

	params := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01} // 5 bytes -> padded to 16
	frame, err := SignCloudCommand(TCC1Options{
		Command:    CloudCommand(1),
		CounterMin: 100,
		IssuedAt:   1700000000,
		DeviceID:   devID,
		Params:     params,
	}, cloudSigner)
	if err != nil {
		t.Fatalf("SignCloudCommand failed: %v", err)
	}
	if len(frame) != 64+16+64 {
		t.Fatalf("TCC1 frame length = %d, want 144", len(frame))
	}
	if magic := binary.LittleEndian.Uint32(frame[0:4]); magic != TCC1Magic {
		t.Fatalf("TCC1 magic = 0x%08x, want 0x%08x", magic, TCC1Magic)
	}
	if frame[4] != TCC1Version || frame[5] != 1 {
		t.Fatalf("TCC1 version/cmd = %d/%d", frame[4], frame[5])
	}
	if gotParamsLen := binary.LittleEndian.Uint32(frame[16:20]); gotParamsLen != 5 {
		t.Fatalf("TCC1 params_len = %d, want 5", gotParamsLen)
	}
	if gotTotalLen := binary.LittleEndian.Uint32(frame[20:24]); gotTotalLen != 144 {
		t.Fatalf("TCC1 total_len = %d, want 144", gotTotalLen)
	}
	if gotCRC := binary.LittleEndian.Uint32(frame[56:60]); gotCRC != crc32.ChecksumIEEE(frame[0:56]) {
		t.Fatalf("TCC1 header CRC mismatch: 0x%08x", gotCRC)
	}
	if !isAllZero(frame[69:80]) {
		t.Fatal("TCC1 alignment padding bytes must be zero")
	}
	if verErr := VerifyCloudCommand(frame, cloudPub); verErr != nil {
		t.Fatalf("VerifyCloudCommand failed: %v", verErr)
	}

	// Minimal zero-param TCC1 frame = 128 bytes.
	minFrame, err := SignCloudCommand(TCC1Options{
		Command:  CloudCommand(0),
		DeviceID: devID,
	}, cloudSigner)
	if err != nil {
		t.Fatalf("SignCloudCommand empty params failed: %v", err)
	}
	if len(minFrame) != TCC1MinTotalLen {
		t.Fatalf("empty params TCC1 frame length = %d, want %d", len(minFrame), TCC1MinTotalLen)
	}

	// 3. CmdRotateKey carrying 128-byte KDM.
	rotFrame, err := SignCloudCommand(TCC1Options{
		Command:    CmdRotateKey,
		CounterMin: 101,
		IssuedAt:   1700000100,
		DeviceID:   devID,
		Params:     kdm,
	}, cloudSigner)
	if err != nil {
		t.Fatalf("SignCloudCommand CmdRotateKey failed: %v", err)
	}
	if len(rotFrame) != 256 {
		t.Fatalf("CmdRotateKey frame length = %d, want 256", len(rotFrame))
	}
	if verErr := VerifyCloudCommand(rotFrame, cloudPub); verErr != nil {
		t.Fatalf("VerifyCloudCommand CmdRotateKey failed: %v", verErr)
	}
	if _, kdmLenErr := SignCloudCommand(TCC1Options{
		Command:  CmdRotateKey,
		DeviceID: devID,
		Params:   []byte{1, 2, 3},
	}, cloudSigner); kdmLenErr == nil {
		t.Fatal("expected CmdRotateKey with non-128B params to fail closed")
	}
	if _, cmdErr := SignCloudCommand(TCC1Options{
		Command:  TCC1MaxCommand + 1,
		DeviceID: devID,
	}, cloudSigner); cmdErr == nil {
		t.Fatal("expected unsupported TCC1 command > 6 to fail closed")
	}
	if _, devErr := SignCloudCommand(TCC1Options{
		Command: CloudCommand(0),
	}, cloudSigner); devErr == nil {
		t.Fatal("expected all-zero device_id to fail closed")
	}
	if _, flagErr := SignCloudCommand(TCC1Options{
		Command:  CloudCommand(0),
		Flags:    1,
		DeviceID: devID,
	}, cloudSigner); flagErr == nil {
		t.Fatal("expected non-zero flags to fail closed")
	}

	// Tamper checks on CRC, padding, reserved, signature.
	badSig := bytes.Clone(frame)
	badSig[64] ^= 0xFF
	if verErr := VerifyCloudCommand(badSig, cloudPub); verErr == nil {
		t.Fatal("expected VerifyCloudCommand to fail on tampered param byte")
	}
	badPad := bytes.Clone(frame)
	badPad[75] = 0xAA
	if verErr := VerifyCloudCommand(badPad, cloudPub); verErr == nil {
		t.Fatal("expected VerifyCloudCommand to fail on non-zero padding")
	}
	badCRC := bytes.Clone(frame)
	badCRC[56] ^= 0x01
	if verErr := VerifyCloudCommand(badCRC, cloudPub); verErr == nil {
		t.Fatal("expected VerifyCloudCommand to fail on header CRC mismatch")
	}
	badReserved := bytes.Clone(frame)
	badReserved[60] = 0x01
	if verErr := VerifyCloudCommand(badReserved, cloudPub); verErr == nil {
		t.Fatal("expected VerifyCloudCommand to fail on non-zero _reserved field")
	}
}
