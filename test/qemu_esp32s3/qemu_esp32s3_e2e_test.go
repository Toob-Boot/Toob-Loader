package qemu_esp32s3_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Toob-Boot/Toob-Loader/toob-go-lib/tbm1"
)

const (
	flashSizeBytes = 4 * 1024 * 1024
	efuseSizeBytes = 2048

	// ESP32-S3 partition offsets (generated from esp32s3/hardware.json + device.toml)
	offStage0      = 0x000000
	offStage1A     = 0x008000
	offStage1B     = 0x028000
	offAppSlot0    = 0x050000
	offStagingSlot = 0x0B0000
	offRecoveryOS  = 0x110000

	// ESP32-S3 eFuse shadow offsets relative to EFUSE_RD_WR_DIS_REG (+0x02C)
	efuseOffMAC  = 0x18 // Block 1: EFUSE_RD_MAC_SPI_SYS_0 (+0x044 - 0x02C)
	efuseOffUser = 0x50 // Block 3: EFUSE_RD_USR_DATA0 (+0x07C - 0x02C), byte 0 = DSLC
	efuseOffKey0 = 0x70 // Block 4: EFUSE_RD_KEY0_DATA0 (+0x09C - 0x02C)
	efuseOffKey1 = 0x90 // Block 5: EFUSE_RD_KEY1_DATA0 (+0x0BC - 0x02C)

	// Device identity matching test/qemu_esp32s3/device.toml
	testVendorID  = 0x0001
	testProductID = 0x0053
	testHWRev     = 1

	// RFC 8032 Test Vector 1 root signing key
	rootSeedHex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"

	// Provisioning protocol opcodes & high-Hamming status (boot_provisioning.c)
	bootStatusOK           = uint32(0x55AA55AA)
	bootStatusNotSupported = uint32(0xE8282828)
	provCmdBurnKey         = 0x01
	provCmdSetDSLC         = 0x02
	provCmdReadID          = 0x06
	provCmdLockBootFlash   = 0x07
	provCmdReboot          = 0xFF

	// XMODEM-CRC constants (recovery/main.c)
	xmSOH = 0x01
	xmEOT = 0x04
	xmACK = 0x06
	xmNAK = 0x15
	xmPAD = 0x1A
)

type qemuHarness struct {
	t      *testing.T
	cmd    *exec.Cmd
	conn   net.Conn
	ln     net.Listener
	cancel context.CancelFunc

	mu     sync.Mutex
	rxBuf  bytes.Buffer
	notify chan struct{}
}

func resolveQEMUBinary(t *testing.T) string {
	t.Helper()
	if env := os.Getenv("TOOB_QEMU_XTENSA"); env != "" {
		if _, err := os.Stat(env); err == nil {
			return env
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("UserHomeDir: %v", err)
	}
	exe := "qemu-system-xtensa"
	if runtime.GOOS == "windows" {
		exe += ".exe"
	}
	cand := filepath.Join(home, ".toob", "tools", "qemu-esp-xtensa", "qemu", "bin", exe)
	if _, err := os.Stat(cand); err != nil {
		t.Skipf("QEMU binary not found at %s (set TOOB_QEMU_XTENSA to override)", cand)
	}
	return cand
}

func startQEMU(t *testing.T, flashPath, efusePath string, maxLifetime time.Duration) *qemuHarness {
	t.Helper()
	qemuBin := resolveQEMUBinary(t)
	ctx, cancel := context.WithTimeout(context.Background(), maxLifetime)

	// Use TCP socket chardev instead of Windows stdio pipe so QEMU's char-socket
	// honors UART RX FIFO backpressure without dropping RX bytes.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		cancel()
		t.Fatalf("net.Listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port

	args := []string{
		"-machine", "esp32s3",
		"-accel", "tcg,tb-size=32",
		"-nographic",
		"-serial", fmt.Sprintf("tcp:127.0.0.1:%d", port),
		"-monitor", "none",
		"-drive", fmt.Sprintf("file=%s,if=mtd,format=raw", flashPath),
		"-drive", fmt.Sprintf("file=%s,if=none,format=raw,id=efuse", efusePath),
		"-global", "driver=nvram.esp32s3.efuse,property=drive,value=efuse",
		"-global", "driver=timer.esp32s3.timg,property=wdt-reset[0],value=/machine/soc/dig-reset[0]",
	}
	romDir := filepath.Clean(filepath.Join(filepath.Dir(qemuBin), "..", "share", "qemu"))
	if st, statErr := os.Stat(romDir); statErr == nil && st.IsDir() {
		args = append(args, "-L", romDir)
	}
	if traceLog := os.Getenv("TOOB_QEMU_TRACE_LOG"); traceLog != "" {
		args = append(args, "-d", "int,guest_errors", "-D", traceLog)
	}
	cmd := exec.CommandContext(ctx, qemuBin, args...)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		_ = ln.Close()
		cancel()
		t.Fatalf("start QEMU: %v", err)
	}

	_ = ln.(*net.TCPListener).SetDeadline(time.Now().Add(5 * time.Second))
	conn, err := ln.Accept()
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		_ = ln.Close()
		cancel()
		t.Fatalf("accept QEMU UART TCP connection: %v (stderr: %s)", err, stderr.String())
	}
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
	}

	h := &qemuHarness{
		t:      t,
		cmd:    cmd,
		conn:   conn,
		ln:     ln,
		cancel: cancel,
		notify: make(chan struct{}, 1),
	}

	go func() {
		tmp := make([]byte, 512)
		for {
			n, rerr := conn.Read(tmp)
			if n > 0 {
				h.mu.Lock()
				h.rxBuf.Write(tmp[:n])
				h.mu.Unlock()
				select {
				case h.notify <- struct{}{}:
				default:
				}
			}
			if rerr != nil {
				return
			}
		}
	}()

	t.Cleanup(func() {
		h.stop()
	})

	return h
}

func (h *qemuHarness) stop() {
	if h.conn != nil {
		_ = h.conn.Close()
	}
	if h.ln != nil {
		_ = h.ln.Close()
	}
	h.cancel()
	if h.cmd != nil && h.cmd.Process != nil {
		_ = h.cmd.Process.Kill()
		_ = h.cmd.Wait()
	}
}

func (h *qemuHarness) snapshot() []byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]byte, h.rxBuf.Len())
	copy(out, h.rxBuf.Bytes())
	return out
}

func (h *qemuHarness) markOffset() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.rxBuf.Len()
}

func (h *qemuHarness) waitForSince(offset int, needle []byte, timeout time.Duration) int {
	h.t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		h.mu.Lock()
		data := h.rxBuf.Bytes()
		if offset < len(data) {
			if idx := bytes.Index(data[offset:], needle); idx >= 0 {
				endPos := offset + idx + len(needle)
				h.mu.Unlock()
				return endPos
			}
		}
		h.mu.Unlock()

		rem := time.Until(deadline)
		if rem <= 0 {
			snap := string(h.snapshot())
			h.t.Fatalf("timeout (%v) waiting for %q after offset %d.\nFull UART log:\n%s",
				timeout, string(needle), offset, snap)
		}
		select {
		case <-h.notify:
		case <-time.After(min(rem, 50*time.Millisecond)):
		}
	}
}

func (h *qemuHarness) waitForStringSince(offset int, s string, timeout time.Duration) int {
	return h.waitForSince(offset, []byte(s), timeout)
}

func (h *qemuHarness) readExactByteSince(offset int, timeout time.Duration) (byte, int) {
	h.t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		h.mu.Lock()
		data := h.rxBuf.Bytes()
		if offset < len(data) {
			b := data[offset]
			h.mu.Unlock()
			return b, offset + 1
		}
		h.mu.Unlock()

		rem := time.Until(deadline)
		if rem <= 0 {
			h.t.Fatalf("timeout (%v) reading byte at offset %d.\nFull UART log:\n%s",
				timeout, offset, string(h.snapshot()))
		}
		select {
		case <-h.notify:
		case <-time.After(min(rem, 25*time.Millisecond)):
		}
	}
}

func (h *qemuHarness) readCOBSFrameSince(offset int, timeout time.Duration) ([]byte, int) {
	h.t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		h.mu.Lock()
		data := h.rxBuf.Bytes()
		if offset < len(data) {
			if zIdx := bytes.IndexByte(data[offset:], 0x00); zIdx >= 0 {
				if zIdx == 0 {
					// Skip leading COBS_MARKER_START (0x00) sync delimiter
					offset++
					h.mu.Unlock()
					continue
				}
				raw := append([]byte(nil), data[offset:offset+zIdx]...)
				nextOff := offset + zIdx + 1
				h.mu.Unlock()
				decoded, err := cobsDecode(raw)
				if err != nil {
					h.t.Fatalf("COBS decode error on %x: %v", raw, err)
				}
				return decoded, nextOff
			}
		}
		h.mu.Unlock()

		rem := time.Until(deadline)
		if rem <= 0 {
			h.t.Fatalf("timeout (%v) waiting for COBS 0x00 terminator at offset %d", timeout, offset)
		}
		select {
		case <-h.notify:
		case <-time.After(min(rem, 25*time.Millisecond)):
		}
	}
}

func (h *qemuHarness) writeAll(b []byte) {
	h.t.Helper()
	if _, err := h.conn.Write(b); err != nil {
		h.t.Fatalf("UART TCP write failed: %v", err)
	}
}

func cobsEncode(src []byte) []byte {
	out := make([]byte, 0, len(src)+len(src)/254+2)
	codeIdx := 0
	out = append(out, 0)
	code := byte(1)

	for _, b := range src {
		if b == 0 {
			out[codeIdx] = code
			codeIdx = len(out)
			out = append(out, 0)
			code = 1
		} else {
			out = append(out, b)
			code++
			if code == 0xFF {
				out[codeIdx] = code
				codeIdx = len(out)
				out = append(out, 0)
				code = 1
			}
		}
	}
	out[codeIdx] = code
	out = append(out, 0x00)
	return out
}

func cobsDecode(src []byte) ([]byte, error) {
	var out []byte
	i := 0
	for i < len(src) {
		code := src[i]
		if code == 0 {
			return nil, fmt.Errorf("unexpected zero byte at %d", i)
		}
		i++
		end := i + int(code) - 1
		if end > len(src) {
			return nil, fmt.Errorf("COBS block overruns frame (%d > %d)", end, len(src))
		}
		out = append(out, src[i:end]...)
		i = end
		if code < 0xFF && i < len(src) {
			out = append(out, 0x00)
		}
	}
	return out, nil
}

func buildProvFrame(cmd byte, payload []byte) []byte {
	body := make([]byte, 0, 1+len(payload)+4)
	body = append(body, cmd)
	body = append(body, payload...)
	crc := crc32.ChecksumIEEE(body)
	var crcBytes [4]byte
	binary.LittleEndian.PutUint32(crcBytes[:], crc)
	body = append(body, crcBytes[:]...)
	return cobsEncode(body)
}

func crc16CCITT(data []byte) uint16 {
	var crc uint16
	for _, b := range data {
		crc ^= uint16(b) << 8
		for range 8 {
			if (crc & 0x8000) != 0 {
				crc = (crc << 1) ^ 0x1021
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}

type firmwareArtifacts struct {
	stage0ESP    []byte
	stage1Signed []byte
	recoveryBin  []byte
	appV1        []byte
	appV2        []byte
	appV3        []byte
	appBadV4     []byte
	signer       tbm1.Signer
	rootPubKey   []byte
}

func loadArtifacts(t *testing.T) firmwareArtifacts {
	t.Helper()
	mustRead := func(rel string) []byte {
		t.Helper()
		p, err := filepath.Abs(rel)
		if err != nil {
			t.Fatalf("Abs(%s): %v", rel, err)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("missing build artifact %s (run scripts/run_qemu_esp32s3_e2e.ps1 first): %v", p, err)
		}
		return b
	}

	seed, err := hex.DecodeString(rootSeedHex)
	if err != nil {
		t.Fatalf("decode seed: %v", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	signer, err := tbm1.NewLocalSigner(priv)
	if err != nil {
		t.Fatalf("NewLocalSigner: %v", err)
	}
	t.Cleanup(signer.Zeroise)

	return firmwareArtifacts{
		stage0ESP:    mustRead("builds/build_esp32s3/toob_stage0.esp.bin"),
		stage1Signed: mustRead("builds/build_esp32s3/toob_stage1.signed.bin"),
		recoveryBin:  mustRead("builds/build_esp32s3/toob_recovery.bin"),
		appV1:        mustRead("builds/apps/app_v1.toob"),
		appV2:        mustRead("builds/apps/app_v2.toob"),
		appV3:        mustRead("builds/apps/app_v3.toob"),
		appBadV4:     mustRead("builds/apps/app_bad_v4.toob"),
		signer:       signer,
		rootPubKey:   append([]byte(nil), signer.Public()...),
	}
}

func buildFullTrailerBundle(t *testing.T, signer tbm1.Signer, keyIndex uint8, appImage []byte, svn uint32, major uint16) []byte {
	t.Helper()
	pkg, err := tbm1.Build(tbm1.Manifest{
		KeyIndex:      keyIndex,
		VendorID:      testVendorID,
		ProductID:     testProductID,
		HWRevMin:      testHWRev,
		HWRevMax:      testHWRev,
		SVN:           svn,
		FwVerMajor:    major,
		AutoSBOM:      true,
		TrailerLayout: true,
		Images: []tbm1.Image{
			{
				TargetSlot: tbm1.SlotApp,
				CompAlg:    tbm1.CompNone,
				DeltaAlg:   tbm1.DeltaNone,
				Installed:  appImage,
				VerMajor:   major,
			},
		},
	}, signer)
	if err != nil {
		t.Fatalf("tbm1.Build full v%d: %v", major, err)
	}
	bundle, err := pkg.AssembleTrailer([][]byte{appImage})
	if err != nil {
		t.Fatalf("AssembleTrailer v%d: %v", major, err)
	}
	return bundle
}

func buildDeltaTrailerBundle(t *testing.T, signer tbm1.Signer, keyIndex uint8, baseImage, targetImage []byte, baseSVN, targetSVN uint32, major uint16) ([]byte, int) {
	t.Helper()
	pkg, err := tbm1.Build(tbm1.Manifest{
		KeyIndex:      keyIndex,
		VendorID:      testVendorID,
		ProductID:     testProductID,
		HWRevMin:      testHWRev,
		HWRevMax:      testHWRev,
		SVN:           targetSVN,
		FwVerMajor:    major,
		AutoSBOM:      true,
		TrailerLayout: true,
		Images: []tbm1.Image{
			{
				TargetSlot: tbm1.SlotApp,
				DeltaAlg:   tbm1.DeltaTDS1,
				Base:       baseImage,
				BaseSVN:    baseSVN,
				Installed:  targetImage,
				VerMajor:   major,
			},
		},
	}, signer)
	if err != nil {
		t.Fatalf("tbm1.Build TDS1 delta v%d: %v", major, err)
	}
	deltaPayload := pkg.Payloads[0].Data
	bundle, err := pkg.AssembleTrailer([][]byte{deltaPayload})
	if err != nil {
		t.Fatalf("AssembleTrailer TDS1 v%d: %v", major, err)
	}
	return bundle, len(deltaPayload)
}

func streamUARTOTA(t *testing.T, h *qemuHarness, bundle []byte, chunkSize int) int {
	t.Helper()
	off := h.markOffset()
	cmd := fmt.Sprintf("OTA %d\n", len(bundle))
	h.writeAll([]byte(cmd))
	off = h.waitForStringSince(off, "[APP] OTA_READY\r\n", 8*time.Second)

	for pos := 0; pos < len(bundle); pos += chunkSize {
		end := min(pos+chunkSize, len(bundle))
		chunk := bundle[pos:end]
		var hdr [2]byte
		binary.LittleEndian.PutUint16(hdr[:], uint16(len(chunk)))
		pkt := make([]byte, 0, 2+len(chunk))
		pkt = append(pkt, hdr[:]...)
		pkt = append(pkt, chunk...)

		ackOff := h.markOffset()
		h.writeAll(pkt)
		ackByte, _ := h.readExactByteSince(ackOff, 8*time.Second)
		if ackByte != 'K' {
			t.Fatalf("expected chunk ACK 'K' at pos %d, got 0x%02X (%q).\nUART log:\n%s",
				pos, ackByte, string([]byte{ackByte}), string(h.snapshot()))
		}
	}

	off = h.waitForStringSince(off, "[APP] OTA_FINALIZED status=OK", 12*time.Second)
	return off
}

func writeInitialFlash(t *testing.T, dir string, art firmwareArtifacts, corruptApps bool) string {
	t.Helper()
	flash := bytes.Repeat([]byte{0xFF}, flashSizeBytes)
	copy(flash[offStage0:], art.stage0ESP)
	copy(flash[offStage1A:], art.stage1Signed)
	copy(flash[offStage1B:], art.stage1Signed)
	copy(flash[offRecoveryOS:], art.recoveryBin)
	if corruptApps {
		// Deterministic corruption in both App Slot 0 and Staging Slot 1
		copy(flash[offAppSlot0:], []byte("CORRUPTED_SLOT_0_HEADER!"))
		copy(flash[offStagingSlot:], []byte("CORRUPTED_SLOT_1_HEADER!"))
	} else {
		copy(flash[offAppSlot0:], art.appV1)
	}

	flashPath := filepath.Join(dir, "flash.bin")
	if err := os.WriteFile(flashPath, flash, 0o644); err != nil {
		t.Fatalf("write flash.bin: %v", err)
	}
	return flashPath
}

func TestQEMUESP32S3_1a_BlankEfuseFailClosed(t *testing.T) {
	art := loadArtifacts(t)
	tmp := t.TempDir()
	flashPath := writeInitialFlash(t, tmp, art, false)

	efusePath := filepath.Join(tmp, "efuse.bin")
	if err := os.WriteFile(efusePath, make([]byte, efuseSizeBytes), 0o644); err != nil {
		t.Fatalf("write blank efuse.bin: %v", err)
	}

	h := startQEMU(t, flashPath, efusePath, 15*time.Second)
	defer h.stop()

	off := h.waitForStringSince(0, "=== TOOB STAGE 0 BOOT ===", 8*time.Second)
	h.waitForStringSince(off, "[S0] read_pubkey failed or zero key!", 8*time.Second)

	snap := string(h.snapshot())
	if strings.Contains(snap, "[APP] BOOT") {
		t.Fatalf("SECURITY FAILURE: Guest App booted despite blank eFuse root key!\n%s", snap)
	}
}

func TestQEMUESP32S3_FullLifecycle_Provision_FullOTA_TDS1Delta_WDTRollback(t *testing.T) {
	art := loadArtifacts(t)
	tmp := t.TempDir()
	flashPath := writeInitialFlash(t, tmp, art, false)

	// Seed factory MAC (Block 1) + primary Root Key 0 (Block 4), keeping DSLC == 0x00 (unprovisioned!)
	efuse := make([]byte, efuseSizeBytes)
	expectedMAC := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x53}
	copy(efuse[efuseOffMAC:], expectedMAC)
	copy(efuse[efuseOffKey0:], art.rootPubKey)

	efusePath := filepath.Join(tmp, "efuse.bin")
	if err := os.WriteFile(efusePath, efuse, 0o644); err != nil {
		t.Fatalf("write factory efuse.bin: %v", err)
	}

	h := startQEMU(t, flashPath, efusePath, 120*time.Second)
	defer h.stop()

	// =========================================================================
	// PHASE 1: Factory UART COBS Provisioning (DSLC 0x00 -> 0x01) + Cold Boot v1.0.0
	// =========================================================================
	t.Log("Phase 1: Waiting for Stage 0 Ed25519 verify + Stage 1 COBS PROV banner...")
	off := h.waitForStringSince(0, "[S0] Signature verification PASSED!", 8*time.Second)
	provBanner := cobsEncode([]byte("PROV"))
	off = h.waitForSince(off, provBanner, 8*time.Second)

	// 1. PROV_CMD_READ_ID (0x06) -> status(BOOT_OK) + 6-byte factory MAC from hardware eFuse Block 1
	h.writeAll(buildProvFrame(provCmdReadID, nil))
	stFrame, off := h.readCOBSFrameSince(off, 5*time.Second)
	if len(stFrame) != 4 || binary.LittleEndian.Uint32(stFrame) != bootStatusOK {
		t.Fatalf("PROV_CMD_READ_ID status = %x, want %08x", stFrame, bootStatusOK)
	}
	uidFrame, off := h.readCOBSFrameSince(off, 5*time.Second)
	if !bytes.Equal(uidFrame, expectedMAC) {
		t.Fatalf("PROV_CMD_READ_ID chip UID = %x, want %x", uidFrame, expectedMAC)
	}

	// 2. PROV_CMD_LOCK_BOOT_FLASH (0x07) -> status(BOOT_ERR_NOT_SUPPORTED) on ESP32-S3 external NOR without WP OTP
	h.writeAll(buildProvFrame(provCmdLockBootFlash, nil))
	stFrame, off = h.readCOBSFrameSince(off, 5*time.Second)
	if len(stFrame) != 4 || binary.LittleEndian.Uint32(stFrame) != bootStatusNotSupported {
		t.Fatalf("PROV_CMD_LOCK_BOOT_FLASH status = %x, want %08x", stFrame, bootStatusNotSupported)
	}

	// 3. PROV_CMD_BURN_KEY (0x01, slot=1, rootPubKey) -> burns eFuse Block 5 (KEY1) via MMIO!
	// Stage 0 & Stage 1 auto-rotate to the highest contiguous non-zero OTP key slot (KEY1).
	burnPayload := append([]byte{0x01}, art.rootPubKey...)
	h.writeAll(buildProvFrame(provCmdBurnKey, burnPayload))
	stFrame, off = h.readCOBSFrameSince(off, 5*time.Second)
	if len(stFrame) != 4 || binary.LittleEndian.Uint32(stFrame) != bootStatusOK {
		t.Fatalf("PROV_CMD_BURN_KEY status = %x, want %08x", stFrame, bootStatusOK)
	}

	// 4. PROV_CMD_SET_DSLC (0x02, 0x01) -> burns DSLC=0x01 into eFuse Block 3 via MMIO!
	h.writeAll(buildProvFrame(provCmdSetDSLC, []byte{0x01}))
	stFrame, off = h.readCOBSFrameSince(off, 5*time.Second)
	if len(stFrame) != 4 || binary.LittleEndian.Uint32(stFrame) != bootStatusOK {
		t.Fatalf("PROV_CMD_SET_DSLC status = %x, want %08x", stFrame, bootStatusOK)
	}

	// 5. PROV_CMD_REBOOT (0xFF) -> hardware WDT reset -> boots App v1.0.0!
	h.writeAll(buildProvFrame(provCmdReboot, nil))
	stFrame, off = h.readCOBSFrameSince(off, 5*time.Second)
	if len(stFrame) != 4 || binary.LittleEndian.Uint32(stFrame) != bootStatusOK {
		t.Fatalf("PROV_CMD_REBOOT status = %x, want %08x", stFrame, bootStatusOK)
	}

	off = h.waitForStringSince(off, "[APP] BOOT ver=1.0.0 slot=0 tent=0 handoff=OK", 15*time.Second)
	t.Log("Phase 1 PASS: Provisioned eFuses over COBS UART & booted App v1.0.0!")

	// =========================================================================
	// PHASE 2: Live UART Full Signed TBM1 TrailerLayout OTA (v1.0.0 -> v2.0.0)
	// =========================================================================
	t.Log("Phase 2a: Verifying revoked KeyIndex=0 bundle is rejected without bricking...")
	revokedBundle := buildFullTrailerBundle(t, art.signer, 0, art.appV2, 11, 2)
	off = streamUARTOTA(t, h, revokedBundle, 113)
	off = h.waitForStringSince(off, "[APP] BOOT ver=1.0.0 slot=0 tent=0 handoff=OK", 15*time.Second)

	t.Log("Phase 2b: Streaming signed TBM1 TrailerLayout OTA v1.0.0 -> v2.0.0 with active KeyIndex=1 (113-byte prime odd chunks)...")
	bundleV2 := buildFullTrailerBundle(t, art.signer, 1, art.appV2, 11, 2)
	off = streamUARTOTA(t, h, bundleV2, 113)

	off = h.waitForStringSince(off, "[APP] BOOT ver=2.0.0 slot=1 tent=1 handoff=OK", 15*time.Second)
	h.writeAll([]byte("CONFIRM\n"))
	off = h.waitForStringSince(off, "[APP] CONFIRM status=OK", 5*time.Second)
	h.writeAll([]byte("REBOOT\n"))
	off = h.waitForStringSince(off, "[APP] BOOT ver=2.0.0 slot=1 tent=0 handoff=OK", 15*time.Second)
	t.Log("Phase 2 PASS: Revoked KeyIndex=0 rejected + Zero-Copy MMU A/B OTA v2.0.0 tentative -> confirmed -> committed!")

	// =========================================================================
	// PHASE 3: Live UART Signed TDS1 Forward-Delta OTA (v2.0.0 -> v3.0.0)
	// =========================================================================
	bundleDeltaV3, rawDeltaBytes := buildDeltaTrailerBundle(t, art.signer, 1, art.appV2, art.appV3, 11, 12, 3)
	t.Logf("Phase 3: Streaming signed TDS1 Forward-Delta OTA v2.0.0 -> v3.0.0 (delta payload=%d bytes vs full=%d bytes)...",
		rawDeltaBytes, len(art.appV3))
	off = streamUARTOTA(t, h, bundleDeltaV3, 113)

	off = h.waitForStringSince(off, "[APP] BOOT ver=3.0.0 slot=0 tent=1 handoff=OK", 18*time.Second)
	h.writeAll([]byte("CONFIRM\n"))
	off = h.waitForStringSince(off, "[APP] CONFIRM status=OK", 5*time.Second)
	h.writeAll([]byte("REBOOT\n"))
	off = h.waitForStringSince(off, "[APP] BOOT ver=3.0.0 slot=0 tent=0 handoff=OK", 15*time.Second)
	t.Log("Phase 3 PASS: Stage 1 Xtensa SDVM + Heatshrink reconstructed v3.0.0 in Slot 0 & confirmed!")

	// =========================================================================
	// PHASE 4: Unconfirmed Crashing Firmware Automatic Hardware WDT Rollback
	// =========================================================================
	t.Log("Phase 4: Streaming signed crashing firmware v4.0.0 (hangs without confirm) to verify TIMG0 WDT rollback...")
	bundleBadV4 := buildFullTrailerBundle(t, art.signer, 1, art.appBadV4, 13, 4)
	off = streamUARTOTA(t, h, bundleBadV4, 113)

	// Stage 1 boots v4.0.0 tentatively in Slot 1; v4.0.0 hangs without feeding TIMG0 WDT!
	off = h.waitForStringSince(off, "[APP] BOOT ver=4.0.0 slot=1 tent=1 CRASHING_WITHOUT_CONFIRM", 15*time.Second)
	// QEMU hardware TIMG0 WDT fires TG0WDT_SYS_RST across max_retries=2 (~4s per hang), then Stage 1 rolls back to v3.0.0!
	off = h.waitForStringSince(off, "[APP] BOOT ver=3.0.0 slot=0 tent=0 handoff=OK", 45*time.Second)
	t.Log("Phase 4 PASS: Hardware TIMG0 WDT fired TG0WDT_SYS_RST & Stage 1 rolled MMU back to v3.0.0 automatically!")

	h.stop()

	// Verify QEMU persisted the burned eFuses (DSLC=0x01 and KEY1=rootPubKey) to disk
	persistedEfuse, err := os.ReadFile(efusePath)
	if err != nil {
		t.Fatalf("read persisted efuse.bin: %v", err)
	}
	if persistedEfuse[efuseOffUser] != 0x01 {
		t.Fatalf("persisted DSLC byte in efuse.bin = 0x%02X, want 0x01", persistedEfuse[efuseOffUser])
	}
	if !bytes.Equal(persistedEfuse[efuseOffKey1:efuseOffKey1+32], art.rootPubKey) {
		t.Fatalf("persisted KEY1 in efuse.bin = %x, want %x",
			persistedEfuse[efuseOffKey1:efuseOffKey1+32], art.rootPubKey)
	}
}

func TestQEMUESP32S3_5_RecoveryOS_XMODEM_Rescue(t *testing.T) {
	art := loadArtifacts(t)
	tmp := t.TempDir()
	// Corrupt BOTH Slot 0 and Slot 1 while keeping signed Stage 0, Stage 1, and Recovery OS intact!
	flashPath := writeInitialFlash(t, tmp, art, true)

	efuse := make([]byte, efuseSizeBytes)
	copy(efuse[efuseOffMAC:], []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x99})
	efuse[efuseOffUser] = 0x01 // Provisioned device
	copy(efuse[efuseOffKey0:], art.rootPubKey)

	efusePath := filepath.Join(tmp, "efuse.bin")
	if err := os.WriteFile(efusePath, efuse, 0o644); err != nil {
		t.Fatalf("write efuse.bin: %v", err)
	}

	h := startQEMU(t, flashPath, efusePath, 75*time.Second)
	defer h.stop()

	t.Log("Phase 5: Booting with corrupted App slots -> expecting Stage 1 handoff to XIP Recovery OS...")
	off := h.waitForStringSince(0, "[REC] listening...", 20*time.Second)
	// Wait for XMODEM-CRC receiver poll byte 'C'
	off = h.waitForStringSince(off, "C", 5*time.Second)

	rescueBundle := buildFullTrailerBundle(t, art.signer, 0, art.appV3, 14, 3)
	totalBlocks := (len(rescueBundle) + 127) / 128
	t.Logf("Streaming %d-byte signed rescue TBM1 bundle (%d XMODEM-CRC 128B blocks)...", len(rescueBundle), totalBlocks)

	for blk := range totalBlocks {
		var data [128]byte
		for i := range data {
			data[i] = xmPAD // Standard XMODEM 0x1A EOF padding (trimmed by MED-22 sliding window!)
		}
		start := blk * 128
		end := min(start+128, len(rescueBundle))
		copy(data[:], rescueBundle[start:end])

		seq := byte((blk + 1) & 0xFF)
		crc := crc16CCITT(data[:])

		var pkt [133]byte
		pkt[0] = xmSOH
		pkt[1] = seq
		pkt[2] = ^seq
		copy(pkt[3:131], data[:])
		pkt[131] = byte(crc >> 8)
		pkt[132] = byte(crc & 0xFF)

		ackOff := h.markOffset()
		h.writeAll(pkt[:])

		// On block 1, Recovery OS prints "[REC] flashing...\r\n" right before processing packet 1;
		// skip any banner bytes until we read XMODEM ACK (0x06) or NAK (0x15).
		deadline := time.Now().Add(8 * time.Second)
		gotACK := false
		cur := ackOff
		for time.Now().Before(deadline) {
			b, next := h.readExactByteSince(cur, time.Until(deadline))
			cur = next
			if b == xmACK {
				gotACK = true
				break
			}
			if b == xmNAK {
				t.Fatalf("Recovery OS returned XMODEM NAK on block %d/%d.\nUART log:\n%s",
					blk+1, totalBlocks, string(h.snapshot()))
			}
		}
		if !gotACK {
			t.Fatalf("timeout waiting for XMODEM ACK on block %d/%d", blk+1, totalBlocks)
		}
	}

	// Send EOT (0x04) -> expect ACK, "[REC] resolved", hardware WDT reboot, and rescued v3.0.0 boot!
	eotOff := h.markOffset()
	h.writeAll([]byte{xmEOT})
	h.waitForStringSince(eotOff, "[REC] resolved", 12*time.Second)

	off = h.waitForStringSince(eotOff, "[APP] BOOT ver=3.0.0", 20*time.Second)
	h.writeAll([]byte("CONFIRM\n"))
	h.waitForStringSince(off, "[APP] CONFIRM status=OK", 5*time.Second)
	t.Log("Phase 5 PASS: Recovery OS rescued bricked device over XMODEM-CRC into verified v3.0.0!")
}
