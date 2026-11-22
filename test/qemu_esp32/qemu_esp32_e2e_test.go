package qemu_esp32_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"math/bits"
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
	efuseSizeBytes = 124 // Classic ESP32 4-Block eFuse NVRAM (31 x 32-bit words)

	// ESP32 partition offsets (Mask-ROM boots Stage 0 at 0x001000!)
	offStage0      = 0x001000
	offStage1A     = 0x010000
	offStage1B     = 0x030000
	offAppSlot0    = 0x050000
	offStagingSlot = 0x0B0000
	offRecoveryOS  = 0x110000

	// Classic ESP32 4-Block eFuse backing-file offsets
	efuseOffBLK0 = 0x00 // BLK0 RDATA0 (WR_DIS [15:0], RD_DIS [19:16], FLASH_CRYPT_CNT [26:20])
	efuseOffMAC  = 0x04 // BLK0 RDATA1..2: 48-bit factory MAC address
	efuseOffKey0 = 0x1C // BLK1 RDATA0..7: 256-bit Ed25519 Root PubKey Slot 0
	efuseOffKey1 = 0x3C // BLK2 RDATA0..7: 256-bit Ed25519 Root PubKey Slot 1
	efuseOffUser = 0x5C // BLK3 RDATA0: byte 0 = DSLC, bits [31:8] = lock flags
	efuseOffSVN  = 0x60 // BLK3 RDATA1..2: 64-bit unary monotonic SVN bitmap
	efuseOffLock = 0x68 // BLK3 RDATA3..4: immutable boot flash lock end + magic

	// Device identity matching test/qemu_esp32/device.toml
	testVendorID  = 0x0001
	testProductID = 0x0032
	testHWRev     = 1

	// RFC 8032 Test Vector 1 root signing key
	rootSeedHex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"

	// Provisioning protocol opcodes & high-Hamming status (boot_provisioning.c)
	bootStatusOK         = uint32(0x55AA55AA)
	provCmdBurnKey       = 0x01
	provCmdSetDSLC       = 0x02
	provCmdReadID        = 0x06
	provCmdLockBootFlash = 0x07
	provCmdReboot        = 0xFF

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
	stderr bytes.Buffer
	rxErr  error
	notify chan struct{}
}

type syncBuffer struct {
	mu  *sync.Mutex
	buf *bytes.Buffer
}

func (s syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func resolveWorkRoot() string {
	if env := os.Getenv("TOOB_ESP32_WORK_DIR"); env != "" {
		return env
	}
	return `D:\ToobStorage\tmp_build\w3b_esp32`
}

func makeQEMURunDir(t *testing.T) string {
	t.Helper()
	base := filepath.Join(resolveWorkRoot(), "qemu_runs")
	if err := os.MkdirAll(base, 0o755); err != nil {
		return t.TempDir()
	}
	dir, err := os.MkdirTemp(base, "run_*")
	if err != nil {
		t.Fatalf("MkdirTemp in %s: %v", base, err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(dir)
	})
	return dir
}

func resolveQEMUBinary(t *testing.T) string {
	t.Helper()
	exe := "qemu-system-xtensa"
	if runtime.GOOS == "windows" {
		exe += ".exe"
	}
	candidates := []string{}
	if env := os.Getenv("TOOB_QEMU_XTENSA"); env != "" {
		candidates = append(candidates, env)
	}
	candidates = append(candidates, `D:\ToobStorage\tools\qemu-esp-xtensa\qemu\bin\`+exe)
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates, filepath.Join(home, ".toob", "tools", "qemu-esp-xtensa", "qemu", "bin", exe))
	}
	for _, cand := range candidates {
		if _, err := os.Stat(cand); err == nil {
			return cand
		}
	}
	t.Skipf("QEMU binary not found in candidates %v (set TOOB_QEMU_XTENSA to override)", candidates)
	return ""
}

func startQEMU(t *testing.T, flashPath, efusePath string, maxLifetime time.Duration) *qemuHarness {
	t.Helper()
	qemuBin := resolveQEMUBinary(t)
	ctx, cancel := context.WithTimeout(context.Background(), maxLifetime)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		cancel()
		t.Fatalf("net.Listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port

	args := []string{
		"-machine", "esp32",
		"-accel", "tcg,tb-size=32",
		"-nographic",
		"-serial", fmt.Sprintf("tcp:127.0.0.1:%d", port),
		"-monitor", "none",
		"-drive", fmt.Sprintf("file=%s,if=mtd,format=raw", flashPath),
		"-drive", fmt.Sprintf("file=%s,if=none,format=raw,id=efuse", efusePath),
		"-global", "driver=nvram.esp32.efuse,property=drive,value=efuse",
	}
	romDir := filepath.Clean(filepath.Join(filepath.Dir(qemuBin), "..", "share", "qemu"))
	if st, statErr := os.Stat(romDir); statErr == nil && st.IsDir() {
		args = append(args, "-L", romDir)
	}
	if traceLog := os.Getenv("TOOB_QEMU_TRACE_LOG"); traceLog != "" {
		args = append(args, "-d", "int,guest_errors", "-D", traceLog)
	}
	cmd := exec.CommandContext(ctx, qemuBin, args...)

	h := &qemuHarness{
		t:      t,
		cmd:    cmd,
		ln:     ln,
		cancel: cancel,
		notify: make(chan struct{}, 1),
	}
	cmd.Stderr = syncBuffer{mu: &h.mu, buf: &h.stderr}

	if err := cmd.Start(); err != nil {
		_ = ln.Close()
		cancel()
		t.Fatalf("start QEMU: %v", err)
	}

	_ = ln.(*net.TCPListener).SetDeadline(time.Now().Add(15 * time.Second))
	conn, err := ln.Accept()
	_ = ln.Close()
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		cancel()
		t.Fatalf("accept QEMU UART TCP connection: %v (stderr: %s)", err, h.stderrSnapshot())
	}
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
	}
	h.conn = conn

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
				h.mu.Lock()
				h.rxErr = rerr
				h.mu.Unlock()
				select {
				case h.notify <- struct{}{}:
				default:
				}
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

func (h *qemuHarness) stderrSnapshot() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.rxErr != nil {
		return fmt.Sprintf("%s (rxErr=%v)", h.stderr.String(), h.rxErr)
	}
	return h.stderr.String()
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
			h.t.Fatalf("timeout (%v) waiting for %q after offset %d (stderr: %s).\nFull UART log:\n%s",
				timeout, string(needle), offset, h.stderrSnapshot(), snap)
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
			h.t.Fatalf("timeout (%v) waiting for byte at offset %d (stderr: %s).\nUART log:\n%s",
				timeout, offset, h.stderrSnapshot(), string(h.snapshot()))
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
				raw := append([]byte(nil), data[offset:offset+zIdx]...)
				nextOff := offset + zIdx + 1
				h.mu.Unlock()
				if len(raw) == 0 {
					offset = nextOff
					continue
				}
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
			h.t.Fatalf("timeout (%v) waiting for COBS 0x00 terminator at offset %d.\nUART log:\n%s",
				timeout, offset, string(h.snapshot()))
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
	workRoot := resolveWorkRoot()
	buildDir := filepath.Join(workRoot, "build_esp32")
	appsDir := filepath.Join(workRoot, "apps")

	mustRead := func(p string) []byte {
		t.Helper()
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("missing build artifact %s (run scripts/run_qemu_esp32_e2e.ps1 first): %v", p, err)
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
		stage0ESP:    mustRead(filepath.Join(buildDir, "toob_stage0.esp.bin")),
		stage1Signed: mustRead(filepath.Join(buildDir, "toob_stage1.signed.bin")),
		recoveryBin:  mustRead(filepath.Join(buildDir, "toob_recovery.bin")),
		appV1:        mustRead(filepath.Join(appsDir, "app_v1.toob")),
		appV2:        mustRead(filepath.Join(appsDir, "app_v2.toob")),
		appV3:        mustRead(filepath.Join(appsDir, "app_v3.toob")),
		appBadV4:     mustRead(filepath.Join(appsDir, "app_bad_v4.toob")),
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
	off = h.waitForStringSince(off, "[APP] OTA_READY\r\n", 20*time.Second)

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
		ackByte, _ := h.readExactByteSince(ackOff, 20*time.Second)
		if ackByte != 'K' {
			t.Fatalf("expected chunk ACK 'K' at pos %d, got 0x%02X (%q).\nUART log:\n%s",
				pos, ackByte, string([]byte{ackByte}), string(h.snapshot()))
		}
	}

	off = h.waitForStringSince(off, "[APP] OTA_FINALIZED status=OK", 25*time.Second)
	return off
}

func assertSplitIROMAndDROMBoot(t *testing.T, h *qemuHarness, offset int, wantVer string, wantSlot, wantTent int) int {
	t.Helper()
	prefix := fmt.Sprintf("[APP] BOOT ver=%s slot=%d tent=%d handoff=OK irom=0x400D", wantVer, wantSlot, wantTent)
	off := h.waitForStringSince(offset, prefix, 45*time.Second)
	off = h.waitForStringSince(off, " drom=0x3F40", 10*time.Second)
	off = h.waitForStringSince(off, " hdr=0x544F4F42 tag=ESP32-SPLIT-DROM-VERIFIED", 10*time.Second)
	return off
}

func writeInitialFlash(t *testing.T, dir string, art firmwareArtifacts, corruptApps bool) string {
	t.Helper()
	flash := bytes.Repeat([]byte{0xFF}, flashSizeBytes)
	// Offset 0x000000..0x000FFF stays 0xFF (reserved below ESP32 Mask-ROM 0x1000 offset!)
	copy(flash[offStage0:], art.stage0ESP)
	copy(flash[offStage1A:], art.stage1Signed)
	copy(flash[offStage1B:], art.stage1Signed)
	copy(flash[offRecoveryOS:], art.recoveryBin)
	if corruptApps {
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

func TestQEMUESP32_1a_BlankEfuseFailClosed(t *testing.T) {
	art := loadArtifacts(t)
	tmp := makeQEMURunDir(t)
	flashPath := writeInitialFlash(t, tmp, art, false)

	efusePath := filepath.Join(tmp, "efuse.bin")
	if err := os.WriteFile(efusePath, make([]byte, efuseSizeBytes), 0o644); err != nil {
		t.Fatalf("write blank efuse.bin: %v", err)
	}

	h := startQEMU(t, flashPath, efusePath, 45*time.Second)
	defer h.stop()

	// Verify authentic ESP32 Mask-ROM boots Stage 0 from 0x1000 and fails closed on blank 4-Block eFuse
	off := h.waitForStringSince(0, "SPI_FAST_FLASH_BOOT", 25*time.Second)
	off = h.waitForStringSince(off, "=== TOOB STAGE 0 BOOT ===", 15*time.Second)
	h.waitForStringSince(off, "[S0] read_pubkey failed or zero key!", 15*time.Second)

	snap := string(h.snapshot())
	if strings.Contains(snap, "[APP] BOOT") {
		t.Fatalf("SECURITY FAILURE: Guest App booted despite blank 4-Block eFuse root key!\n%s", snap)
	}
}

func TestQEMUESP32_FullLifecycle_Provision_SplitMMU_FullOTA_TDS1Delta_WDTRollback(t *testing.T) {
	art := loadArtifacts(t)
	tmp := makeQEMURunDir(t)
	flashPath := writeInitialFlash(t, tmp, art, false)

	// Seed factory MAC in BLK0 (0x04), primary Root Key 0 in BLK1 (0x1C), and unary eFuse epoch=2 (0x03) in BLK3 (0x60), keeping DSLC == 0x00!
	efuse := make([]byte, efuseSizeBytes)
	expectedMAC := []byte{0x24, 0x0A, 0xC4, 0xAA, 0xBB, 0x32}
	copy(efuse[efuseOffMAC:], expectedMAC)
	copy(efuse[efuseOffKey0:], art.rootPubKey)
	efuse[efuseOffSVN] = 0x03 // 2 unary bits -> hardware efuse_epoch = 2

	efusePath := filepath.Join(tmp, "efuse.bin")
	if err := os.WriteFile(efusePath, efuse, 0o644); err != nil {
		t.Fatalf("write factory efuse.bin: %v", err)
	}

	h := startQEMU(t, flashPath, efusePath, 240*time.Second)
	defer h.stop()

	// =========================================================================
	// PHASE 1: Factory UART COBS Provisioning (BLK0 MAC, BLK2 Key1, BLK3 Lock+DSLC)
	// =========================================================================
	t.Log("Phase 1: Waiting for ESP32 Mask-ROM (0x1000) -> Stage 0 Ed25519 -> Stage 1 COBS PROV banner...")
	off := h.waitForStringSince(0, "[S0] Signature verification PASSED!", 25*time.Second)
	provBanner := cobsEncode([]byte("PROV"))
	off = h.waitForSince(off, provBanner, 20*time.Second)

	// 1. PROV_CMD_READ_ID (0x06) -> status(BOOT_OK) + 6-byte factory MAC from BLK0 RDATA1..2
	h.writeAll(buildProvFrame(provCmdReadID, nil))
	stFrame, off := h.readCOBSFrameSince(off, 5*time.Second)
	if len(stFrame) != 4 || binary.LittleEndian.Uint32(stFrame) != bootStatusOK {
		t.Fatalf("PROV_CMD_READ_ID status = %x, want %08x", stFrame, bootStatusOK)
	}
	uidFrame, off := h.readCOBSFrameSince(off, 5*time.Second)
	if !bytes.Equal(uidFrame, expectedMAC) {
		t.Fatalf("PROV_CMD_READ_ID chip UID = %x, want %x", uidFrame, expectedMAC)
	}

	// 2. PROV_CMD_LOCK_BOOT_FLASH (0x07) -> burns immutable Stage 0 lock into BLK3 Words 3..4!
	h.writeAll(buildProvFrame(provCmdLockBootFlash, nil))
	stFrame, off = h.readCOBSFrameSince(off, 5*time.Second)
	if len(stFrame) != 4 || binary.LittleEndian.Uint32(stFrame) != bootStatusOK {
		t.Fatalf("PROV_CMD_LOCK_BOOT_FLASH status = %x, want %08x", stFrame, bootStatusOK)
	}

	// 3. PROV_CMD_BURN_KEY (0x01, slot=1, rootPubKey) -> burns BLK2 (Key Slot 1) + WR_DIS_BLK2 in BLK0!
	burnPayload := append([]byte{0x01}, art.rootPubKey...)
	h.writeAll(buildProvFrame(provCmdBurnKey, burnPayload))
	stFrame, off = h.readCOBSFrameSince(off, 5*time.Second)
	if len(stFrame) != 4 || binary.LittleEndian.Uint32(stFrame) != bootStatusOK {
		t.Fatalf("PROV_CMD_BURN_KEY status = %x, want %08x", stFrame, bootStatusOK)
	}

	// 4. PROV_CMD_SET_DSLC (0x02, 0x01) -> burns DSLC=0x01 into BLK3 Word 0!
	h.writeAll(buildProvFrame(provCmdSetDSLC, []byte{0x01}))
	stFrame, off = h.readCOBSFrameSince(off, 5*time.Second)
	if len(stFrame) != 4 || binary.LittleEndian.Uint32(stFrame) != bootStatusOK {
		t.Fatalf("PROV_CMD_SET_DSLC status = %x, want %08x", stFrame, bootStatusOK)
	}

	// 5. PROV_CMD_REBOOT (0xFF) -> hardware TIMG0 MWDT reset -> boots App v1.0.0 with Split IROM/DROM!
	h.writeAll(buildProvFrame(provCmdReboot, nil))
	stFrame, off = h.readCOBSFrameSince(off, 5*time.Second)
	if len(stFrame) != 4 || binary.LittleEndian.Uint32(stFrame) != bootStatusOK {
		t.Fatalf("PROV_CMD_REBOOT status = %x, want %08x", stFrame, bootStatusOK)
	}

	off = assertSplitIROMAndDROMBoot(t, h, off, "1.0.0", 0, 0)
	t.Log("Phase 1 PASS: Provisioned 4-Block eFuse over COBS UART & booted v1.0.0 with Split IROM+DROM!")

	// =========================================================================
	// PHASE 2: Split IROM (0x400D0000) + DROM (0x3F400000) DPORT MMU Full OTA (v1 -> v2)
	// =========================================================================
	t.Log("Phase 2a: Verifying revoked KeyIndex=0 and BLK3 unary eFuse SVN downgrade (svn=1 < epoch=2) are rejected...")
	revokedBundle := buildFullTrailerBundle(t, art.signer, 0, art.appV2, 2, 2)
	off = streamUARTOTA(t, h, revokedBundle, 113)
	off = assertSplitIROMAndDROMBoot(t, h, off, "1.0.0", 0, 0)

	downgradeBundle := buildFullTrailerBundle(t, art.signer, 1, art.appV2, 1, 2)
	off = streamUARTOTA(t, h, downgradeBundle, 113)
	off = assertSplitIROMAndDROMBoot(t, h, off, "1.0.0", 0, 0)

	t.Log("Phase 2b: Streaming signed TBM1 TrailerLayout OTA v1.0.0 -> v2.0.0 with active KeyIndex=1 & svn=2...")
	bundleV2 := buildFullTrailerBundle(t, art.signer, 1, art.appV2, 2, 2)
	off = streamUARTOTA(t, h, bundleV2, 113)

	off = assertSplitIROMAndDROMBoot(t, h, off, "2.0.0", 1, 1)
	h.writeAll([]byte("CONFIRM\n"))
	off = h.waitForStringSince(off, "[APP] CONFIRM status=OK", 5*time.Second)
	h.writeAll([]byte("REBOOT\n"))
	off = assertSplitIROMAndDROMBoot(t, h, off, "2.0.0", 1, 0)
	t.Log("Phase 2 PASS: Split IROM+DROM DPORT MMU A/B OTA v2.0.0 tentative -> RTC_SLOW_MEM confirmed -> committed!")

	// =========================================================================
	// PHASE 3: Live UART Signed TDS1 Forward-Delta OTA (v2.0.0 -> v3.0.0)
	// =========================================================================
	bundleDeltaV3, rawDeltaBytes := buildDeltaTrailerBundle(t, art.signer, 1, art.appV2, art.appV3, 2, 3, 3)
	t.Logf("Phase 3: Streaming signed TDS1 Forward-Delta OTA v2.0.0 -> v3.0.0 (delta payload=%d bytes vs full=%d bytes)...",
		rawDeltaBytes, len(art.appV3))
	if rawDeltaBytes >= 512 {
		t.Fatalf("expected compact TDS1 forward-delta (<512B), got %d bytes", rawDeltaBytes)
	}
	off = streamUARTOTA(t, h, bundleDeltaV3, 113)

	off = assertSplitIROMAndDROMBoot(t, h, off, "3.0.0", 0, 1)
	h.writeAll([]byte("CONFIRM\n"))
	off = h.waitForStringSince(off, "[APP] CONFIRM status=OK", 5*time.Second)
	h.writeAll([]byte("REBOOT\n"))
	off = assertSplitIROMAndDROMBoot(t, h, off, "3.0.0", 0, 0)
	t.Log("Phase 3 PASS: Stage 1 Xtensa LX6 SDVM + Heatshrink reconstructed v3.0.0 in Slot 0 & confirmed!")

	// =========================================================================
	// PHASE 4: Unconfirmed Crashing Firmware Automatic Hardware TIMG0 MWDT Rollback
	// =========================================================================
	t.Log("Phase 4: Streaming signed crashing firmware v4.0.0 (hangs without confirm) to verify TIMG0 MWDT rollback...")
	bundleBadV4 := buildFullTrailerBundle(t, art.signer, 1, art.appBadV4, 4, 4)
	off = streamUARTOTA(t, h, bundleBadV4, 113)

	off = h.waitForStringSince(off, "[APP] BOOT ver=4.0.0 slot=1 tent=1 CRASHING_WITHOUT_CONFIRM", 15*time.Second)
	off = assertSplitIROMAndDROMBoot(t, h, off, "3.0.0", 0, 0)
	t.Log("Phase 4 PASS: Hardware TIMG0 MWDT fired TG0WDT_SYS_RESET & Stage 1 rolled Split DPORT MMU back to v3.0.0!")

	h.stop()

	// Verify QEMU persisted all 4-Block eFuse burns (BLK0 WR_DIS_BLK2, BLK2 Key1, BLK3 DSLC + SVN + Lock)
	persistedEfuse, err := os.ReadFile(efusePath)
	if err != nil {
		t.Fatalf("read persisted efuse.bin: %v", err)
	}
	// QEMU's raw block backend rounds sector writes up to 512B (BDRV_SECTOR_SIZE); first 124B hold the 4 eFuse blocks.
	if len(persistedEfuse) < efuseSizeBytes {
		t.Fatalf("persisted efuse.bin length = %d, want >= %d", len(persistedEfuse), efuseSizeBytes)
	}
	blk0Word0 := binary.LittleEndian.Uint32(persistedEfuse[efuseOffBLK0 : efuseOffBLK0+4])
	if (blk0Word0 & (1 << 8)) == 0 {
		t.Fatalf("expected WR_DIS_BLK2 (bit 8) set in BLK0 RDATA0, got 0x%08X", blk0Word0)
	}
	if !bytes.Equal(persistedEfuse[efuseOffKey1:efuseOffKey1+32], art.rootPubKey) {
		t.Fatalf("persisted BLK2 Key1 = %x, want %x",
			persistedEfuse[efuseOffKey1:efuseOffKey1+32], art.rootPubKey)
	}
	if persistedEfuse[efuseOffUser] != 0x01 {
		t.Fatalf("persisted BLK3 DSLC byte = 0x%02X, want 0x01", persistedEfuse[efuseOffUser])
	}
	svnBitmap := binary.LittleEndian.Uint64(persistedEfuse[efuseOffSVN : efuseOffSVN+8])
	if gotSVN := bits.OnesCount64(svnBitmap); gotSVN != 2 {
		t.Fatalf("persisted BLK3 monotonic SVN popcount = %d (bitmap=0x%016X), want 2", gotSVN, svnBitmap)
	}
	lockEnd := binary.LittleEndian.Uint32(persistedEfuse[efuseOffLock : efuseOffLock+4])
	if lockEnd != offStage1A {
		t.Fatalf("persisted BLK3 bootlock end = 0x%08X, want 0x%08X", lockEnd, offStage1A)
	}
	lockMagic := binary.LittleEndian.Uint32(persistedEfuse[efuseOffLock+4 : efuseOffLock+8])
	if lockMagic != 0x544F4F42 {
		t.Fatalf("persisted BLK3 bootlock magic = 0x%08X, want 0x544F4F42", lockMagic)
	}
}

func TestQEMUESP32_5_RecoveryOS_XMODEM_Rescue(t *testing.T) {
	art := loadArtifacts(t)
	tmp := makeQEMURunDir(t)
	flashPath := writeInitialFlash(t, tmp, art, true)

	efuse := make([]byte, efuseSizeBytes)
	copy(efuse[efuseOffMAC:], []byte{0x24, 0x0A, 0xC4, 0xDD, 0xEE, 0x99})
	efuse[efuseOffUser] = 0x01
	copy(efuse[efuseOffKey0:], art.rootPubKey)

	efusePath := filepath.Join(tmp, "efuse.bin")
	if err := os.WriteFile(efusePath, efuse, 0o644); err != nil {
		t.Fatalf("write efuse.bin: %v", err)
	}

	h := startQEMU(t, flashPath, efusePath, 150*time.Second)
	defer h.stop()

	t.Log("Phase 5: Booting with corrupted App slots -> expecting Stage 1 handoff to Split IROM/DROM Recovery OS...")
	off := h.waitForStringSince(0, "[REC] listening...", 45*time.Second)
	off = h.waitForStringSince(off, "C", 15*time.Second)

	rescueBundle := buildFullTrailerBundle(t, art.signer, 0, art.appV3, 4, 3)
	totalBlocks := (len(rescueBundle) + 127) / 128
	t.Logf("Streaming %d-byte signed rescue TBM1 bundle (%d XMODEM-CRC 128B blocks)...", len(rescueBundle), totalBlocks)

	for blk := range totalBlocks {
		var data [128]byte
		for i := range data {
			data[i] = xmPAD
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

		deadline := time.Now().Add(20 * time.Second)
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

	eotOff := h.markOffset()
	h.writeAll([]byte{xmEOT})
	h.waitForStringSince(eotOff, "[REC] resolved", 25*time.Second)

	off = assertSplitIROMAndDROMBoot(t, h, eotOff, "3.0.0", 1, 1)
	h.writeAll([]byte("CONFIRM\n"))
	off = h.waitForStringSince(off, "[APP] CONFIRM status=OK", 5*time.Second)
	h.writeAll([]byte("REBOOT\n"))
	assertSplitIROMAndDROMBoot(t, h, off, "3.0.0", 1, 0)
	t.Log("Phase 5 PASS: Recovery OS rescued bricked ESP32 over XMODEM-CRC into verified & confirmed v3.0.0!")
}
