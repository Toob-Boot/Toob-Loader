package cmd

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/pflag"
	"github.com/toob-boot/toob/internal/provision"
)

func resetSignTestFlags(t *testing.T) {
	t.Helper()
	for _, fs := range []*pflag.FlagSet{
		signCmd.PersistentFlags(),
		signImageCmd.Flags(),
		signStage1Cmd.Flags(),
		signBundleCmd.Flags(),
	} {
		fs.VisitAll(func(f *pflag.Flag) { f.Changed = false })
	}
	signMockFlag = true
	signKeyHexFlag = ""
	signKeyFileFlag = ""
	signOutFlag = ""
	signEntryFlag = 0
	stage1SVNFlag = 1
	bundleDeviceFlag = ""
	bundleBaseFlag = ""
	bundleBaseSVNFlag = 0
	bundleCompressFlag = false
	bundleRDeltaOldFlag = ""
	bundleTrailerFlag = true
	bundleVendorFlag = 0x0001
	bundleProductFlag = 0x0042
	bundleHWRevMinFlag = 1
	bundleHWRevMaxFlag = 1
	bundleSVNFlag = 1
}

func makeToobImageFile(t *testing.T, dir, name string, payload []byte) string {
	t.Helper()
	rawPath := filepath.Join(dir, name+".raw")
	outPath := filepath.Join(dir, name)
	if err := os.WriteFile(rawPath, payload, 0o644); err != nil {
		t.Fatal(err)
	}
	prevOut := signOutFlag
	signOutFlag = outPath
	defer func() { signOutFlag = prevOut }()
	if err := signImageCmd.RunE(signImageCmd, []string{rawPath}); err != nil {
		t.Fatalf("sign image (%s): %v", name, err)
	}
	return outPath
}

func TestSignKeygen(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "testkey.hex")

	signOutFlag = keyPath
	err := signKeygenCmd.RunE(signKeygenCmd, nil)
	if err != nil {
		t.Fatalf("sign keygen failed: %v", err)
	}

	content, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("failed to read key: %v", err)
	}

	trimmed := bytes.TrimSpace(content)
	if len(trimmed) != 64 {
		t.Fatalf("expected 64 hex characters (32 bytes), got %d", len(trimmed))
	}
}

func TestSignImageHeaderAndBounds(t *testing.T) {
	resetSignTestFlags(t)
	tmpDir := t.TempDir()
	appBin := filepath.Join(tmpDir, "app.bin")
	outBin := filepath.Join(tmpDir, "app.bin.toob")

	dummyPayload := bytes.Repeat([]byte{0xEF}, 100)
	if err := os.WriteFile(appBin, dummyPayload, 0o644); err != nil {
		t.Fatal(err)
	}

	signOutFlag = outBin
	if err := signImageCmd.RunE(signImageCmd, []string{appBin}); err != nil {
		t.Fatalf("sign image failed: %v", err)
	}

	tagged, err := os.ReadFile(outBin)
	if err != nil {
		t.Fatalf("read tagged binary: %v", err)
	}
	if len(tagged) != 120 {
		t.Fatalf("expected 120 bytes, got %d", len(tagged))
	}
	if !bytes.Equal(tagged[0:4], []byte{0x42, 0x4F, 0x4F, 0x54}) {
		t.Fatalf("magic mismatch: got %x", tagged[0:4])
	}

	// Empty binary must be rejected.
	emptyBin := filepath.Join(tmpDir, "empty.bin")
	if err := os.WriteFile(emptyBin, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := signImageCmd.RunE(signImageCmd, []string{emptyBin}); err == nil {
		t.Fatal("expected empty application binary to be rejected")
	}

	// Explicit --entry pointing inside the 20-byte header must be rejected.
	if err := signImageCmd.Flags().Set("entry", "4"); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = signImageCmd.Flags().Set("entry", "20") }()
	if err := signImageCmd.RunE(signImageCmd, []string{appBin}); err == nil || !strings.Contains(err.Error(), "20-byte") {
		t.Fatalf("expected header entry rejection, got %v", err)
	}
}

func TestResolveSignerMock(t *testing.T) {
	resetSignTestFlags(t)
	signer, err := resolveSigner()
	if err != nil {
		t.Fatalf("resolveSigner mock failed: %v", err)
	}

	pub := signer.Public()
	if !bytes.Equal(pub, provision.MockRootPublicKey) {
		t.Fatalf("mock public key mismatch: got %s, want %s", hex.EncodeToString(pub), hex.EncodeToString(provision.MockRootPublicKey))
	}
}

func TestSignStage1HeaderAndSVN(t *testing.T) {
	resetSignTestFlags(t)
	tmpDir := t.TempDir()
	s1Bin := filepath.Join(tmpDir, "stage1.bin")
	outBin := filepath.Join(tmpDir, "stage1.bin.signed")

	payload := bytes.Repeat([]byte{0xA5}, 256)
	if err := os.WriteFile(s1Bin, payload, 0o644); err != nil {
		t.Fatal(err)
	}

	signOutFlag = outBin
	stage1SVNFlag = 7

	// --entry 0 must be rejected even when explicitly passed.
	if err := signStage1Cmd.Flags().Set("entry", "0x0"); err != nil {
		t.Fatal(err)
	}
	if err := signStage1Cmd.RunE(signStage1Cmd, []string{s1Bin}); err == nil {
		t.Fatal("expected Stage 1 --entry 0 to be rejected")
	}

	if err := signStage1Cmd.Flags().Set("entry", "0x100"); err != nil {
		t.Fatal(err)
	}
	if err := signStage1Cmd.RunE(signStage1Cmd, []string{s1Bin}); err != nil {
		t.Fatalf("sign stage1 failed: %v", err)
	}

	signed, err := os.ReadFile(outBin)
	if err != nil {
		t.Fatal(err)
	}
	if len(signed) != 20+256+64 {
		t.Fatalf("expected 340 bytes, got %d", len(signed))
	}
	if got := binary.LittleEndian.Uint32(signed[12:16]); got != 0x31534254 {
		t.Fatalf("stage1 svn_magic = 0x%08X, want 0x31534254", got)
	}
	if got := binary.LittleEndian.Uint32(signed[16:20]); got != 7 {
		t.Fatalf("stage1_svn = %d, want 7", got)
	}
}

func TestSignBundleAndDeviceGate(t *testing.T) {
	resetSignTestFlags(t)
	tmpDir := t.TempDir()

	oldImg := makeToobImageFile(t, tmpDir, "v1.toob", bytes.Repeat([]byte{0x11, 0x22, 0x33, 0x44}, 128))
	newImg := makeToobImageFile(t, tmpDir, "v2.toob", bytes.Repeat([]byte{0x11, 0x22, 0x55, 0x66}, 128))
	rawUntagged := filepath.Join(tmpDir, "untagged.bin")
	if err := os.WriteFile(rawUntagged, bytes.Repeat([]byte{0xAA}, 128), 0o644); err != nil {
		t.Fatal(err)
	}

	// 1. Untagged raw binary must be rejected with clear guidance.
	if err := signBundleCmd.RunE(signBundleCmd, []string{rawUntagged}); err == nil || !strings.Contains(err.Error(), "TOOB") {
		t.Fatalf("expected untagged image rejection, got %v", err)
	}

	// 2. --base and --compress mutual exclusion must fail fast.
	bundleBaseFlag = oldImg
	bundleCompressFlag = true
	if err := signBundleCmd.RunE(signBundleCmd, []string{newImg}); err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("expected --base/--compress mutual exclusion error, got %v", err)
	}

	// 3. --device sign-time gate: forward delta rejected when enable_deltas = false.
	resetSignTestFlags(t)
	devNoDelta := filepath.Join(tmpDir, "device_nodelta.toml")
	if err := os.WriteFile(devNoDelta, []byte(`
name = "NoDeltaDev"
[identity]
vendor_id = 0x1234
product_id = 0x5678
hw_rev = 2
[device]
chip = "esp32c6"
[partitions]
stage0_size = 32768
stage1_size = 131072
app_size = 262144
enable_deltas = false
[boot_config]
max_retries = 3
`), 0o644); err != nil {
		t.Fatal(err)
	}
	bundleDeviceFlag = devNoDelta
	bundleBaseFlag = oldImg
	if err := signBundleCmd.RunE(signBundleCmd, []string{newImg}); err == nil || !strings.Contains(err.Error(), "enable_deltas is false") {
		t.Fatalf("expected sign-time delta rejection when enable_deltas=false, got %v", err)
	}

	// 4. --device sign-time HIGH-33 gate: forced oneway on scratch-less esp32c6 rejects forward delta.
	resetSignTestFlags(t)
	devHigh33 := filepath.Join(tmpDir, "device_high33.toml")
	if err := os.WriteFile(devHigh33, []byte(`
name = "High33Dev"
[identity]
vendor_id = 0x1234
product_id = 0x5678
hw_rev = 2
[device]
chip = "esp32c6"
[partitions]
stage0_size = 32768
stage1_size = 131072
app_size = 262144
enable_deltas = true
[boot_config]
max_retries = 3
transport_provider = "oneway"
`), 0o644); err != nil {
		t.Fatal(err)
	}
	bundleDeviceFlag = devHigh33
	bundleBaseFlag = oldImg
	if err := signBundleCmd.RunE(signBundleCmd, []string{newImg}); err == nil || !strings.Contains(err.Error(), "HIGH-33") {
		t.Fatalf("expected sign-time HIGH-33 rejection, got %v", err)
	}

	// 5. --device sign-time gate: reverse_delta backup requires --rdelta-old, and succeeds when supplied.
	resetSignTestFlags(t)
	devRDelta := filepath.Join(tmpDir, "device_rdelta.toml")
	if err := os.WriteFile(devRDelta, []byte(`
name = "RDeltaDev"
[identity]
vendor_id = 0x1915
product_id = 0x5284
hw_rev = 1
[device]
chip = "nrf52840"
[partitions]
stage0_size = 32768
stage1_size = 98304
app_size = 196608
enable_deltas = true
[boot_config]
max_retries = 3
transport_provider = "oneway"
backup_mode = "reverse_delta"
`), 0o644); err != nil {
		t.Fatal(err)
	}
	bundleDeviceFlag = devRDelta
	if err := signBundleCmd.RunE(signBundleCmd, []string{newImg}); err == nil || !strings.Contains(err.Error(), "--rdelta-old") {
		t.Fatalf("expected missing --rdelta-old rejection for reverse_delta mode, got %v", err)
	}

	bundleBaseFlag = oldImg
	bundleRDeltaOldFlag = oldImg
	outBundle := filepath.Join(tmpDir, "valid_delta.tbm1")
	signOutFlag = outBundle
	if err := signBundleCmd.RunE(signBundleCmd, []string{newImg}); err != nil {
		t.Fatalf("expected valid delta + reverse-delta bundle to succeed, got %v", err)
	}
	if st, err := os.Stat(outBundle); err != nil || st.Size() < 576 {
		t.Fatalf("expected non-empty signed TBM1 bundle, stat=%v err=%v", st, err)
	}
}
