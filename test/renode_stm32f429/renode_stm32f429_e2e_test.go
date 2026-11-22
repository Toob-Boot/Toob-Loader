package renode_stm32f429_test

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
	flashSizeBytes = 2 * 1024 * 1024
	otpSizeBytes   = 0x220 // 512B OTP + 16B OTP lock bytes + 16B UID window

	// STM32F429 partition offsets relative to 0x08000000 (from generated/boot_layout.h)
	offStage0      = 0x000000 // 64 KB  (Bank 1 Sectors 0..3: 4 x 16 KB)
	offStage1A     = 0x020000 // 128 KB (Bank 1 Sector 5)
	offStage1B     = 0x040000 // 128 KB (Bank 1 Sector 6)
	offAppSlot0    = 0x060000 // 128 KB (Bank 1 Sector 7)
	offStagingSlot = 0x080000 // 128 KB (Bank 1 Sector 8)
	offRecoveryOS  = 0x0A0000 // 128 KB (Bank 1 Sector 9)

	// STM32F429 OTP offsets relative to 0x1FFF7800 (stm32_opt_otp/otp_real.c)
	otpOffKey0 = 0x000 // Block 0: 32B Ed25519 Root Key 0
	otpOffKey1 = 0x020 // Block 1: 32B Ed25519 Rotation Key 1
	otpOffDSLC = 0x080 // Block 4 bytes 0..2: 3-byte TMR inverted (raw = dslc ^ 0xFF)
	otpOffMono = 0x0A0 // Blocks 5..6: 512-bit 1->0 monotonic counter
	otpOffLock = 0x200 // 16 OTP lock bytes (0xFF = unlocked, 0x00 = locked)
	otpOffUID  = 0x210 // 96-bit (12-byte) factory UID at 0x1FFF7A10

	// Device identity matching test/renode_stm32f429/device.toml
	testVendorID  = 0x0483
	testProductID = 0x0429
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

var expectedFactoryUID = []byte{0x32, 0x04, 0x29, 0x00, 0x48, 0x33, 0x54, 0x4D, 0xAA, 0x55, 0x11, 0x22}

type renodeHarness struct {
	t       *testing.T
	cmd     *exec.Cmd
	uart    net.Conn
	mon     net.Conn
	cancel  context.CancelFunc
	monBuf  bytes.Buffer
	monLock sync.Mutex

	mu     sync.Mutex
	rxBuf  bytes.Buffer
	notify chan struct{}
}

func makeStm32TempDir(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		const dRoot = `D:\ToobStorage\tmp_stm32`
		if err := os.MkdirAll(dRoot, 0o755); err == nil {
			dir, err := os.MkdirTemp(dRoot, "e2e-*")
			if err == nil {
				t.Cleanup(func() {
					_ = os.RemoveAll(dir)
					_ = os.Remove(dRoot)
				})
				return dir
			}
		}
	}
	return t.TempDir()
}

func resolveRenodeBinary(t *testing.T) string {
	t.Helper()
	if env := os.Getenv("TOOB_RENODE_BIN"); env != "" {
		if _, err := os.Stat(env); err == nil {
			return env
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("UserHomeDir: %v", err)
	}
	exe := "renode"
	if runtime.GOOS == "windows" {
		exe = "renode.exe"
	}
	cand := filepath.Join(home, ".toob", "tools", "renode", "renode_1.17.0-portable", exe)
	if _, err := os.Stat(cand); err != nil {
		t.Skipf("Renode binary not found at %s (set TOOB_RENODE_BIN to override)", cand)
	}
	return cand
}

func reserveFreeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

func dialRetry(addr string, timeout time.Duration) (net.Conn, error) {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 250*time.Millisecond)
		if err == nil {
			if tcpConn, ok := conn.(*net.TCPConn); ok {
				_ = tcpConn.SetNoDelay(true)
			}
			return conn, nil
		}
		lastErr = err
		time.Sleep(40 * time.Millisecond)
	}
	return nil, lastErr
}

func toSlashPath(p string) string {
	return filepath.ToSlash(p)
}

func startRenode(t *testing.T, dir, flashPath, otpPath string, maxLifetime time.Duration) *renodeHarness {
	t.Helper()
	renodeBin := resolveRenodeBinary(t)
	ctx, cancel := context.WithTimeout(context.Background(), maxLifetime)

	overlayAbs, err := filepath.Abs("Stm32F429SocOverlay.cs")
	if err != nil {
		cancel()
		t.Fatalf("Abs(Stm32F429SocOverlay.cs): %v", err)
	}
	replAbs, err := filepath.Abs("stm32f429_toob.repl")
	if err != nil {
		cancel()
		t.Fatalf("Abs(stm32f429_toob.repl): %v", err)
	}

	monPort := reserveFreeTCPPort(t)
	uartPort := reserveFreeTCPPort(t)

	rescContent := fmt.Sprintf(`include @%s
mach create "stm32f429_e2e"
machine LoadPlatformDescription @%s
emulation CreateServerSocketTerminal %d "term" false
connector Connect sysbus.usart1 term
sysbus LoadBinary @%s 0x08000000
sysbus.otp LoadBinary @%s
sysbus.flashCtrl InstallFlashHooks

macro reset
"""
    sysbus.cpu VectorTableOffset 0x08000000
    sysbus.cpu SP `+"`sysbus ReadDoubleWord 0x08000000`"+`
    sysbus.cpu PC `+"`sysbus ReadDoubleWord 0x08000004`"+`
"""
runMacro $reset
`,
		toSlashPath(overlayAbs),
		toSlashPath(replAbs),
		uartPort,
		toSlashPath(flashPath),
		toSlashPath(otpPath),
	)

	rescPath := filepath.Join(dir, "boot.resc")
	if err := os.WriteFile(rescPath, []byte(rescContent), 0o644); err != nil {
		cancel()
		t.Fatalf("write boot.resc: %v", err)
	}

	args := []string{
		"--disable-xwt",
		"--plain",
		"--port", fmt.Sprintf("%d", monPort),
	}
	cmd := exec.CommandContext(ctx, renodeBin, args...)
	var outLog bytes.Buffer
	cmd.Stdout = &outLog
	cmd.Stderr = &outLog

	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatalf("start Renode: %v", err)
	}

	monConn, err := dialRetry(fmt.Sprintf("127.0.0.1:%d", monPort), 10*time.Second)
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		cancel()
		t.Fatalf("connect Renode Monitor (%d): %v\nRenode output:\n%s",
			monPort, err, outLog.String())
	}

	h := &renodeHarness{
		t:      t,
		cmd:    cmd,
		mon:    monConn,
		cancel: cancel,
		notify: make(chan struct{}, 1),
	}

	go func() {
		tmp := make([]byte, 512)
		for {
			n, rerr := monConn.Read(tmp)
			if n > 0 {
				h.monLock.Lock()
				h.monBuf.Write(tmp[:n])
				h.monLock.Unlock()
			}
			if rerr != nil {
				return
			}
		}
	}()

	time.Sleep(80 * time.Millisecond)
	h.execMonitor(fmt.Sprintf("include @%s", toSlashPath(rescPath)))

	uartConn, err := dialRetry(fmt.Sprintf("127.0.0.1:%d", uartPort), 15*time.Second)
	if err != nil {
		monSnap := h.monitorSnapshot()
		_ = monConn.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		cancel()
		t.Fatalf("connect Renode UART1 server socket (%d): %v\nRenode output:\n%s\nMonitor output:\n%s",
			uartPort, err, outLog.String(), monSnap)
	}
	h.uart = uartConn

	go func() {
		tmp := make([]byte, 512)
		for {
			n, rerr := uartConn.Read(tmp)
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

	// Start CPU execution only after UART reader goroutine is attached so zero early Stage 0 bytes are missed.
	time.Sleep(100 * time.Millisecond)
	h.execMonitor("start")

	return h
}

func (h *renodeHarness) execMonitor(cmdLine string) {
	h.t.Helper()
	if h.mon == nil {
		return
	}
	_, _ = h.mon.Write([]byte(cmdLine + "\r\n"))
}

func (h *renodeHarness) monitorSnapshot() string {
	h.monLock.Lock()
	defer h.monLock.Unlock()
	return h.monBuf.String()
}

func (h *renodeHarness) saveOtpAndQueryFlashState(otpOutPath string) string {
	h.t.Helper()
	h.execMonitor("pause")
	h.execMonitor(fmt.Sprintf("sysbus.otp SaveBinary @%s", toSlashPath(otpOutPath)))
	h.execMonitor("sysbus.flashCtrl CommittedOptcr")
	h.execMonitor("sysbus.flashCtrl BlockedOperations")
	h.execMonitor("sysbus.syscfg MemRmp")

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if info, err := os.Stat(otpOutPath); err == nil && info.Size() >= otpSizeBytes {
			time.Sleep(80 * time.Millisecond)
			return h.monitorSnapshot()
		}
		time.Sleep(40 * time.Millisecond)
	}
	h.t.Fatalf("timeout waiting for Renode to save OTP to %s.\nMonitor output:\n%s",
		otpOutPath, h.monitorSnapshot())
	return ""
}

func (h *renodeHarness) stop() {
	if h.mon != nil {
		_, _ = h.mon.Write([]byte("quit\r\n"))
		_ = h.mon.Close()
		h.mon = nil
	}
	if h.uart != nil {
		_ = h.uart.Close()
		h.uart = nil
	}
	h.cancel()
	if h.cmd != nil && h.cmd.Process != nil {
		_ = h.cmd.Process.Kill()
		_ = h.cmd.Wait()
	}
}

func (h *renodeHarness) snapshot() []byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]byte, h.rxBuf.Len())
	copy(out, h.rxBuf.Bytes())
	return out
}

func (h *renodeHarness) markOffset() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.rxBuf.Len()
}

func (h *renodeHarness) waitForSince(offset int, needle []byte, timeout time.Duration) int {
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
			h.t.Fatalf("timeout (%v) waiting for %q after offset %d.\nFull UART1 log:\n%s\nMonitor log:\n%s",
				timeout, string(needle), offset, snap, h.monitorSnapshot())
		}
		select {
		case <-h.notify:
		case <-time.After(min(rem, 50*time.Millisecond)):
		}
	}
}

func (h *renodeHarness) waitForStringSince(offset int, s string, timeout time.Duration) int {
	return h.waitForSince(offset, []byte(s), timeout)
}

func (h *renodeHarness) readExactByteSince(offset int, timeout time.Duration) (byte, int) {
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
			h.t.Fatalf("timeout (%v) reading byte at offset %d.\nFull UART1 log:\n%s",
				timeout, offset, string(h.snapshot()))
		}
		select {
		case <-h.notify:
		case <-time.After(min(rem, 25*time.Millisecond)):
		}
	}
}

func (h *renodeHarness) readCOBSFrameSince(offset int, timeout time.Duration) ([]byte, int) {
	h.t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		h.mu.Lock()
		data := h.rxBuf.Bytes()
		if offset < len(data) {
			if zIdx := bytes.IndexByte(data[offset:], 0x00); zIdx >= 0 {
				if zIdx == 0 {
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
			h.t.Fatalf("timeout (%v) waiting for COBS 0x00 terminator at offset %d.\nUART1 log:\n%s",
				timeout, offset, string(h.snapshot()))
		}
		select {
		case <-h.notify:
		case <-time.After(min(rem, 25*time.Millisecond)):
		}
	}
}

func (h *renodeHarness) writeAll(b []byte) {
	h.t.Helper()
	// STM32_UART has a 1-byte hardware DR without EasyDMA; pace slices slightly so
	// polling firmware never sees ORE during large XMODEM / OTA bursts.
	const sliceBytes = 32
	for pos := 0; pos < len(b); pos += sliceBytes {
		end := min(pos+sliceBytes, len(b))
		if _, err := h.uart.Write(b[pos:end]); err != nil {
			h.t.Fatalf("UART1 TCP write failed: %v", err)
		}
		if end < len(b) {
			time.Sleep(2 * time.Millisecond)
		}
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
	stage0Raw    []byte
	stage1Signed []byte
	recoveryBin  []byte
	appV1        []byte
	appV2        []byte
	appV3        []byte
	appV3Slot1   []byte
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
			t.Fatalf("missing build artifact %s (run scripts/run_renode_stm32f429_e2e.ps1 first): %v", p, err)
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
		stage0Raw:    mustRead("builds/build_stm32f429/toob_stage0.bin"),
		stage1Signed: mustRead("builds/build_stm32f429/toob_stage1.signed.bin"),
		recoveryBin:  mustRead("builds/build_stm32f429/toob_recovery.bin"),
		appV1:        mustRead("builds/apps/app_v1.toob"),
		appV2:        mustRead("builds/apps/app_v2.toob"),
		appV3:        mustRead("builds/apps/app_v3.toob"),
		appV3Slot1:   mustRead("builds/apps/app_v3_slot1.toob"),
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

func streamUARTOTA(t *testing.T, h *renodeHarness, bundle []byte, chunkSize int) int {
	t.Helper()
	off := h.markOffset()
	cmd := fmt.Sprintf("OTA %d\n", len(bundle))
	h.writeAll([]byte(cmd))
	off = h.waitForStringSince(off, "[APP] OTA_READY\r\n", 10*time.Second)

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
			t.Fatalf("expected chunk ACK 'K' at pos %d, got 0x%02X (%q).\nUART1 log:\n%s",
				pos, ackByte, string([]byte{ackByte}), string(h.snapshot()))
		}
	}

	off = h.waitForStringSince(off, "[APP] OTA_FINALIZED status=OK", 15*time.Second)
	return off
}

func writeInitialFlash(t *testing.T, dir string, art firmwareArtifacts, corruptApps bool) string {
	t.Helper()
	flash := bytes.Repeat([]byte{0xFF}, flashSizeBytes)
	copy(flash[offStage0:], art.stage0Raw)
	copy(flash[offStage1A:], art.stage1Signed)
	copy(flash[offStage1B:], art.stage1Signed)
	copy(flash[offRecoveryOS:], art.recoveryBin)
	if corruptApps {
		copy(flash[offAppSlot0:], []byte("CORRUPTED_APP_SLOT0_HEADER"))
		copy(flash[offStagingSlot:], []byte("CORRUPTED_STAGING1_HEADER!"))
	} else {
		copy(flash[offAppSlot0:], art.appV1)
	}

	flashPath := filepath.Join(dir, "flash.bin")
	if err := os.WriteFile(flashPath, flash, 0o644); err != nil {
		t.Fatalf("write flash.bin: %v", err)
	}
	return flashPath
}

func newErasedOtpWithUID() []byte {
	otp := bytes.Repeat([]byte{0xFF}, otpSizeBytes)
	copy(otp[otpOffUID:], expectedFactoryUID)
	return otp
}

func TestRenodeSTM32F429_1a_BlankOtpFailClosed(t *testing.T) {
	art := loadArtifacts(t)
	tmp := makeStm32TempDir(t)
	flashPath := writeInitialFlash(t, tmp, art, false)

	// Unprogrammed STM32F4 OTP is all 0xFF; stm32_opt_otp_read_pubkey must reject fail-closed!
	otpPath := filepath.Join(tmp, "otp.bin")
	if err := os.WriteFile(otpPath, newErasedOtpWithUID(), 0o644); err != nil {
		t.Fatalf("write blank otp.bin: %v", err)
	}

	h := startRenode(t, tmp, flashPath, otpPath, 25*time.Second)
	defer h.stop()

	off := h.waitForStringSince(0, "=== TOOB STAGE 0 BOOT ===", 10*time.Second)
	h.waitForStringSince(off, "[S0] read_pubkey failed or zero key!", 10*time.Second)

	snap := string(h.snapshot())
	if strings.Contains(snap, "[APP] BOOT") {
		t.Fatalf("SECURITY FAILURE: Guest App booted despite blank 0xFF OTP root key!\n%s", snap)
	}
}

func TestRenodeSTM32F429_FullLifecycle_Provision_nWRP_FullOTA_TDS1Delta_WDTRollback(t *testing.T) {
	art := loadArtifacts(t)
	tmp := makeStm32TempDir(t)
	flashPath := writeInitialFlash(t, tmp, art, false)

	// Seed primary Root Key 0 (OTP Block 0 + Lock Byte 0), keeping Block 4 = 0xFF (DSLC == 0x00 unprovisioned)
	otp := newErasedOtpWithUID()
	copy(otp[otpOffKey0:], art.rootPubKey)
	otp[otpOffLock+0] = 0x00

	otpPath := filepath.Join(tmp, "otp.bin")
	if err := os.WriteFile(otpPath, otp, 0o644); err != nil {
		t.Fatalf("write factory otp.bin: %v", err)
	}

	h := startRenode(t, tmp, flashPath, otpPath, 180*time.Second)
	defer h.stop()

	// =========================================================================
	// PHASE 1: Factory UART1 COBS Provisioning (READ_ID + BURN_KEY + LOCK_BOOT_FLASH + SET_DSLC + REBOOT)
	// =========================================================================
	t.Log("Phase 1: Waiting for Stage 0 Ed25519 verify + Stage 1 COBS PROV banner...")
	off := h.waitForStringSince(0, "[S0] Signature verification PASSED!", 12*time.Second)
	provBanner := cobsEncode([]byte("PROV"))
	off = h.waitForSince(off, provBanner, 10*time.Second)

	// 1. PROV_CMD_READ_ID (0x06) -> status(BOOT_OK) + 12-byte (96-bit) STM32F429 factory UID
	h.writeAll(buildProvFrame(provCmdReadID, nil))
	stFrame, off := h.readCOBSFrameSince(off, 8*time.Second)
	if len(stFrame) != 4 || binary.LittleEndian.Uint32(stFrame) != bootStatusOK {
		t.Fatalf("PROV_CMD_READ_ID status = %x, want %08x", stFrame, bootStatusOK)
	}
	uidFrame, off := h.readCOBSFrameSince(off, 8*time.Second)
	if !bytes.Equal(uidFrame, expectedFactoryUID) {
		t.Fatalf("PROV_CMD_READ_ID chip UID = %x, want %x", uidFrame, expectedFactoryUID)
	}

	// 2. PROV_CMD_BURN_KEY (0x01, slot=1, rootPubKey) -> burns OTP Block 1 + OTP Lock Byte 1 (0x00)!
	burnPayload := append([]byte{0x01}, art.rootPubKey...)
	h.writeAll(buildProvFrame(provCmdBurnKey, burnPayload))
	stFrame, off = h.readCOBSFrameSince(off, 8*time.Second)
	if len(stFrame) != 4 || binary.LittleEndian.Uint32(stFrame) != bootStatusOK {
		t.Fatalf("PROV_CMD_BURN_KEY status = %x, want %08x", stFrame, bootStatusOK)
	}

	// 3. PROV_CMD_LOCK_BOOT_FLASH (0x07) -> clears FLASH_OPTCR nWRP[3:0] (4x16KB Stage-0 sectors)!
	h.writeAll(buildProvFrame(provCmdLockBootFlash, nil))
	stFrame, off = h.readCOBSFrameSince(off, 8*time.Second)
	if len(stFrame) != 4 || binary.LittleEndian.Uint32(stFrame) != bootStatusOK {
		t.Fatalf("PROV_CMD_LOCK_BOOT_FLASH status = %x, want %08x", stFrame, bootStatusOK)
	}

	// 4. PROV_CMD_SET_DSLC (0x02, 0x01) -> burns 3-byte TMR 0xFE into OTP Block 4!
	h.writeAll(buildProvFrame(provCmdSetDSLC, []byte{0x01}))
	stFrame, off = h.readCOBSFrameSince(off, 8*time.Second)
	if len(stFrame) != 4 || binary.LittleEndian.Uint32(stFrame) != bootStatusOK {
		t.Fatalf("PROV_CMD_SET_DSLC status = %x, want %08x", stFrame, bootStatusOK)
	}

	// 5. PROV_CMD_REBOOT (0xFF) -> hardware IWDG reset -> cold boots App v1.0.0 at 0x08060100!
	h.writeAll(buildProvFrame(provCmdReboot, nil))
	stFrame, off = h.readCOBSFrameSince(off, 8*time.Second)
	if len(stFrame) != 4 || binary.LittleEndian.Uint32(stFrame) != bootStatusOK {
		t.Fatalf("PROV_CMD_REBOOT status = %x, want %08x", stFrame, bootStatusOK)
	}

	off = h.waitForStringSince(off, "[APP] BOOT ver=1.0.0 slot=0 tent=0 handoff=OK", 20*time.Second)
	t.Log("Phase 1 PASS: Provisioned OTP + FLASH_OPTCR nWRP over COBS UART1 & booted Cortex-M4 App v1.0.0!")

	// =========================================================================
	// PHASE 1b: Hardware Option-Byte nWRP Stage-0 Non-Brickability Verification
	// =========================================================================
	t.Log("Phase 1b: Verifying FLASH_OPTCR nWRP[3:0]=0 persists across warm reset & blocks Stage-0 erase/write...")
	h.writeAll([]byte("REBOOT\n"))
	off = h.waitForStringSince(off, "[APP] BOOT ver=1.0.0 slot=0 tent=0 handoff=OK", 15*time.Second)
	h.writeAll([]byte("TEST_WRP\n"))
	off = h.waitForStringSince(off, "[APP] WRP_TEST optcr_locked=1 wrperr_erase=1 wrperr_write=1 stage0_intact=1", 8*time.Second)
	t.Log("Phase 1b PASS: Hardware FLASH_OPTCR nWRP asserted WRPERR on both erase & write; Stage 0 100% intact!")

	// =========================================================================
	// PHASE 2: Live UART1 Full Signed TBM1 TrailerLayout OTA (v1.0.0 -> v2.0.0)
	// =========================================================================
	t.Log("Phase 2a: Verifying revoked KeyIndex=0 bundle is rejected without bricking...")
	revokedBundle := buildFullTrailerBundle(t, art.signer, 0, art.appV2, 1, 2)
	off = streamUARTOTA(t, h, revokedBundle, 113)
	off = h.waitForStringSince(off, "[APP] BOOT ver=1.0.0 slot=0 tent=0 handoff=OK", 18*time.Second)

	t.Log("Phase 2b: Streaming signed TBM1 TrailerLayout OTA v1.0.0 -> v2.0.0 with active KeyIndex=1 (113-byte prime chunks)...")
	bundleV2 := buildFullTrailerBundle(t, art.signer, 1, art.appV2, 1, 2)
	off = streamUARTOTA(t, h, bundleV2, 113)

	off = h.waitForStringSince(off, "[APP] BOOT ver=2.0.0 slot=1 tent=1 handoff=OK", 18*time.Second)
	h.writeAll([]byte("CONFIRM\n"))
	off = h.waitForStringSince(off, "[APP] CONFIRM status=OK", 8*time.Second)
	h.writeAll([]byte("REBOOT\n"))
	off = h.waitForStringSince(off, "[APP] BOOT ver=2.0.0 slot=1 tent=0 handoff=OK", 18*time.Second)
	t.Log("Phase 2 PASS: Revoked KeyIndex=0 rejected + Tier-0 Dual-Bank BFB2 OTA v2.0.0 tentative -> confirmed -> committed!")

	// =========================================================================
	// PHASE 3: Live UART1 Signed TDS1 Forward-Delta OTA (v2.0.0 -> v3.0.0)
	// =========================================================================
	bundleDeltaV3, rawDeltaBytes := buildDeltaTrailerBundle(t, art.signer, 1, art.appV2, art.appV3, 1, 2, 3)
	t.Logf("Phase 3: Streaming signed TDS1 Forward-Delta OTA v2.0.0 -> v3.0.0 (delta payload=%d bytes vs full=%d bytes)...",
		rawDeltaBytes, len(art.appV3))
	off = streamUARTOTA(t, h, bundleDeltaV3, 113)

	off = h.waitForStringSince(off, "[APP] BOOT ver=3.0.0 slot=0 tent=1 handoff=OK", 20*time.Second)
	h.writeAll([]byte("CONFIRM\n"))
	off = h.waitForStringSince(off, "[APP] CONFIRM status=OK", 8*time.Second)
	h.writeAll([]byte("REBOOT\n"))
	off = h.waitForStringSince(off, "[APP] BOOT ver=3.0.0 slot=0 tent=0 handoff=OK", 18*time.Second)
	t.Log("Phase 3 PASS: Stage 1 Cortex-M4 SDVM + Heatshrink reconstructed v3.0.0 across 128 KB sectors & confirmed!")

	// =========================================================================
	// PHASE 4: Unconfirmed Crashing Firmware Automatic Hardware IWDG Rollback
	// =========================================================================
	t.Log("Phase 4: Streaming signed crashing firmware v4.0.0 (hangs without confirm) to verify hardware IWDG rollback...")
	bundleBadV4 := buildFullTrailerBundle(t, art.signer, 1, art.appBadV4, 3, 4)
	off = streamUARTOTA(t, h, bundleBadV4, 113)

	off = h.waitForStringSince(off, "[APP] BOOT ver=4.0.0 slot=1 tent=1 CRASHING_WITHOUT_CONFIRM", 18*time.Second)
	// Hardware IWDG latches RCC_CSR.IWDGRSTF and Stage 1 reverts BFB2 back to Slot 0 (v3.0.0)!
	off = h.waitForStringSince(off, "[APP] BOOT ver=3.0.0 slot=0 tent=0 handoff=OK", 30*time.Second)
	t.Log("Phase 4 PASS: Hardware IWDG latched RCC_CSR.IWDGRSTF & Stage 1 rolled BFB2 back to v3.0.0 automatically!")

	// Verify persisted OTP blocks, OTP lock bytes, and FLASH_OPTCR nWRP state
	otpSavedPath := filepath.Join(tmp, "otp_after.bin")
	monOut := h.saveOtpAndQueryFlashState(otpSavedPath)
	persistedOtp, err := os.ReadFile(otpSavedPath)
	if err != nil {
		t.Fatalf("read saved otp_after.bin: %v", err)
	}
	for i := range 3 {
		if persistedOtp[otpOffDSLC+i] != 0xFE {
			t.Fatalf("persisted OTP DSLC TMR byte[%d] = 0x%02X, want 0xFE (~0x01)", i, persistedOtp[otpOffDSLC+i])
		}
	}
	if !bytes.Equal(persistedOtp[otpOffKey1:otpOffKey1+32], art.rootPubKey) {
		t.Fatalf("persisted OTP KEY1 = %x, want %x", persistedOtp[otpOffKey1:otpOffKey1+32], art.rootPubKey)
	}
	if persistedOtp[otpOffLock+1] != 0x00 {
		t.Fatalf("persisted OTP Lock Byte 1 = 0x%02X, want 0x00 (permanently locked)", persistedOtp[otpOffLock+1])
	}
	if !strings.Contains(monOut, "0x0FF0AAED") && !strings.Contains(monOut, "0x0ff0aaed") {
		t.Fatalf("expected CommittedOptcr = 0x0FF0AAED (nWRP[3:0]=0, BFB2=0) in monitor output, got:\n%s", monOut)
	}
}

func TestRenodeSTM32F429_RecoveryOS_XMODEM_Rescue(t *testing.T) {
	art := loadArtifacts(t)
	tmp := makeStm32TempDir(t)
	// Corrupt BOTH App Slot 0 and Staging Slot 1 while keeping Stage 0, Stage 1A/1B, and Recovery OS intact!
	flashPath := writeInitialFlash(t, tmp, art, true)

	otp := newErasedOtpWithUID()
	copy(otp[otpOffKey0:], art.rootPubKey)
	otp[otpOffLock+0] = 0x00
	otp[otpOffDSLC+0] = 0xFE // Provisioned (DSLC == 0x01)
	otp[otpOffDSLC+1] = 0xFE
	otp[otpOffDSLC+2] = 0xFE

	otpPath := filepath.Join(tmp, "otp.bin")
	if err := os.WriteFile(otpPath, otp, 0o644); err != nil {
		t.Fatalf("write otp.bin: %v", err)
	}

	h := startRenode(t, tmp, flashPath, otpPath, 90*time.Second)
	defer h.stop()

	t.Log("Booting with corrupted App & Staging slots -> expecting Stage 1 VTOR handoff to Recovery OS at 0x080A0100...")
	off := h.waitForStringSince(0, "[REC] listening...", 20*time.Second)
	off = h.waitForStringSince(off, "C", 8*time.Second)

	// With active_slot == 0 under TOOB_TRANSPORT_POINTER, Recovery OS stages into Slot 1 (0x08080000)
	rescueBundle := buildFullTrailerBundle(t, art.signer, 0, art.appV3Slot1, 1, 3)
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

		deadline := time.Now().Add(10 * time.Second)
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
				t.Fatalf("Recovery OS returned XMODEM NAK on block %d/%d.\nUART1 log:\n%s",
					blk+1, totalBlocks, string(h.snapshot()))
			}
		}
		if !gotACK {
			t.Fatalf("timeout waiting for XMODEM ACK on block %d/%d", blk+1, totalBlocks)
		}
	}

	eotOff := h.markOffset()
	h.writeAll([]byte{xmEOT})
	h.waitForStringSince(eotOff, "[REC] resolved", 12*time.Second)

	off = h.waitForStringSince(eotOff, "[APP] BOOT ver=3.0.0 slot=1 tent=1 handoff=OK", 20*time.Second)
	h.writeAll([]byte("CONFIRM\n"))
	h.waitForStringSince(off, "[APP] CONFIRM status=OK", 8*time.Second)
	t.Log("Recovery OS PASS: Rescued bricked STM32F429 over XMODEM-CRC into verified v3.0.0!")
}
