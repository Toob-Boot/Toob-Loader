package renode_stm32f103_test

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
	flashSizeBytes  = 512 * 1024 // 512 KB RM0008 Flash (512 x 1 KB homogeneous FPEC pages)
	fpecPageBytes   = 1024       // True 1 KB (1024-byte) FPEC erase page & TBM1 chunk size
	otpOptSizeBytes = 0x1000     // 4 KB block at 0x1FFFF000..0x1FFFFFFF (Keystore + Lock + UID + OB)

	// STM32F103 partition offsets relative to 0x08000000 (from generated/boot_layout.h)
	offStage0      = 0x00000 // 32 KB (8 x 4 KB OB.WRP0[7:0] units = 32 x 1 KB pages)
	offStage1A     = 0x08000 // 80 KB (80 x 1 KB pages)
	offStage1B     = 0x1C000 // 80 KB (80 x 1 KB pages)
	offAppSlot0    = 0x30000 // 32 KB (Swap-Move active XIP slot, VTOR at 0x08030100)
	offStagingSlot = 0x38000 // 32 KB (Swap-Move staging slot)
	offRecoveryOS  = 0x40000 // 24 KB (XMODEM-CRC Recovery OS, VTOR at 0x08040100)

	// STM32F103 Keystore / UID / Option-Byte offsets relative to 0x1FFFF000 (stm32f1_opt_key/otp_real.c)
	otpOffKey0 = 0x000 // Slot 0: 32B Ed25519 Root Key 0
	otpOffKey1 = 0x020 // Slot 1: 32B Ed25519 Rotation Key 1
	otpOffDSLC = 0x080 // 3 x 2B TMR halfwords (low byte = dslc ^ 0xFF, high byte = 0xFF)
	otpOffMono = 0x0A0 // 32 x 2B (512-bit) unary 1->0 monotonic counter
	otpOffLock = 0x200 // 4 x 2B per-slot permanent lock halfwords (0xFFFF=unlocked, 0x0000=locked)
	otpOffUID  = 0x7E8 // 96-bit (12-byte) RM0008 Section 30.2 factory UID at 0x1FFFF7E8
	otpOffOB   = 0x800 // 8 x 2B PM0075 Option Bytes at 0x1FFFF800 (RDP, USER, Data0..1, WRP0..3)

	// Device identity matching test/renode_stm32f103/device.toml
	testVendorID  = 0x0483
	testProductID = 0x0103
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

var expectedFactoryUID = []byte{0x31, 0x03, 0xF1, 0x03, 0x53, 0x54, 0x4D, 0x33, 0xAA, 0x55, 0x10, 0x3E}

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

func makeStm32f103TempDir(t *testing.T) string {
	t.Helper()
	if envRoot := os.Getenv("TOOB_STM32F103_TMP_ROOT"); envRoot != "" {
		if err := os.MkdirAll(envRoot, 0o755); err == nil {
			if dir, err := os.MkdirTemp(envRoot, "e2e-*"); err == nil {
				t.Cleanup(func() { _ = os.RemoveAll(dir) })
				return dir
			}
		}
	}
	if runtime.GOOS == "windows" {
		const dRoot = `D:\ToobStorage\tmp_build\w3c_stm32f103\e2e_runs`
		if err := os.MkdirAll(dRoot, 0o755); err == nil {
			if dir, err := os.MkdirTemp(dRoot, "e2e-*"); err == nil {
				t.Cleanup(func() { _ = os.RemoveAll(dir) })
				return dir
			}
		}
	}
	return t.TempDir()
}

func resolveRenodeBinary(t *testing.T) string {
	t.Helper()
	candidates := []string{}
	if env := os.Getenv("TOOB_RENODE_BIN"); env != "" {
		candidates = append(candidates, env)
	}
	if runtime.GOOS == "windows" {
		candidates = append(candidates,
			`D:\ToobStorage\tools\renode-1.17.0\renode_1.17.0-portable\Renode.exe`,
			`D:\ToobStorage\tools\renode\renode_1.17.0_portable\Renode.exe`,
		)
	}
	if home, err := os.UserHomeDir(); err == nil {
		exe := "renode"
		if runtime.GOOS == "windows" {
			exe = "Renode.exe"
		}
		candidates = append(candidates,
			filepath.Join(home, ".toob", "tools", "renode", "renode_1.17.0-portable", exe),
		)
	}
	for _, cand := range candidates {
		if _, err := os.Stat(cand); err == nil {
			return cand
		}
	}
	t.Fatalf("Renode 1.17.0 binary not found in candidates: %v (set TOOB_RENODE_BIN)", candidates)
	return ""
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

	overlayAbs, err := filepath.Abs("Stm32f103SocOverlay.cs")
	if err != nil {
		cancel()
		t.Fatalf("Abs(Stm32f103SocOverlay.cs): %v", err)
	}
	replAbs, err := filepath.Abs("stm32f103_toob.repl")
	if err != nil {
		cancel()
		t.Fatalf("Abs(stm32f103_toob.repl): %v", err)
	}

	monPort := reserveFreeTCPPort(t)
	uartPort := reserveFreeTCPPort(t)

	rescContent := fmt.Sprintf(`include @%s
mach create "stm32f103_e2e"
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

	monConn, err := dialRetry(fmt.Sprintf("127.0.0.1:%d", monPort), 60*time.Second)
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

	uartConn, err := dialRetry(fmt.Sprintf("127.0.0.1:%d", uartPort), 60*time.Second)
	if err != nil {
		monSnap := h.monitorSnapshot()
		_ = monConn.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		cancel()
		t.Fatalf("connect Renode USART1 server socket (%d): %v\nRenode output:\n%s\nMonitor output:\n%s",
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

func (h *renodeHarness) saveOtpAndQueryHardwareState(otpOutPath string) string {
	h.t.Helper()
	h.execMonitor("pause")
	h.execMonitor(fmt.Sprintf("sysbus.otp SaveBinary @%s", toSlashPath(otpOutPath)))
	h.execMonitor("sysbus.flashCtrl Wrpr")
	h.execMonitor("sysbus.flashCtrl BlockedOperations")
	h.execMonitor("sysbus.flashCtrl PgErrors")
	h.execMonitor("sysbus.flashCtrl PageErases")
	h.execMonitor("sysbus.bkp BlockedWrites")

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if info, err := os.Stat(otpOutPath); err == nil && info.Size() >= otpOptSizeBytes {
			time.Sleep(80 * time.Millisecond)
			return h.monitorSnapshot()
		}
		time.Sleep(40 * time.Millisecond)
	}
	h.t.Fatalf("timeout waiting for Renode to save OTP/OB block to %s.\nMonitor output:\n%s",
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
			h.t.Fatalf("timeout (%v) waiting for %q after offset %d.\nFull USART1 log:\n%s\nMonitor log:\n%s",
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
			h.t.Fatalf("timeout (%v) reading byte at offset %d.\nFull USART1 log:\n%s",
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
			h.t.Fatalf("timeout (%v) waiting for COBS 0x00 terminator at offset %d.\nUSART1 log:\n%s",
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
	const sliceBytes = 128
	for pos := 0; pos < len(b); pos += sliceBytes {
		end := min(pos+sliceBytes, len(b))
		if _, err := h.uart.Write(b[pos:end]); err != nil {
			h.t.Fatalf("USART1 TCP write failed: %v", err)
		}
		if end < len(b) {
			time.Sleep(1 * time.Millisecond)
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
	appBadV4     []byte
	signer       tbm1.Signer
	rootPubKey   []byte
}

func loadArtifacts(t *testing.T) firmwareArtifacts {
	t.Helper()
	buildDir := os.Getenv("TOOB_STM32F103_BUILD_DIR")
	if buildDir == "" {
		buildDir = `D:\ToobStorage\tmp_build\w3c_stm32f103\build_stm32f103`
	}
	appsDir := os.Getenv("TOOB_STM32F103_APPS_DIR")
	if appsDir == "" {
		appsDir = filepath.Join(buildDir, "apps")
	}

	mustReadAny := func(paths ...string) []byte {
		t.Helper()
		for _, p := range paths {
			abs, err := filepath.Abs(p)
			if err != nil {
				continue
			}
			if b, err := os.ReadFile(abs); err == nil {
				return b
			}
		}
		t.Fatalf("missing build artifact %v (run scripts/run_renode_stm32f103_e2e.ps1 first)", paths)
		return nil
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
		stage0Raw: mustReadAny(
			filepath.Join(buildDir, "toob_stage0.bin"),
			"builds/boot/toob_stage0.bin",
		),
		stage1Signed: mustReadAny(
			filepath.Join(buildDir, "toob_stage1.signed.bin"),
			"builds/boot/toob_stage1.signed.bin",
		),
		recoveryBin: mustReadAny(
			filepath.Join(buildDir, "toob_recovery.bin"),
			"builds/boot/toob_recovery.bin",
		),
		appV1: mustReadAny(
			filepath.Join(appsDir, "app_v1.toob"),
			"builds/apps/app_v1.toob",
		),
		appV2: mustReadAny(
			filepath.Join(appsDir, "app_v2.toob"),
			"builds/apps/app_v2.toob",
		),
		appV3: mustReadAny(
			filepath.Join(appsDir, "app_v3.toob"),
			"builds/apps/app_v3.toob",
		),
		appBadV4: mustReadAny(
			filepath.Join(appsDir, "app_bad_v4.toob"),
			"builds/apps/app_bad_v4.toob",
		),
		signer:     signer,
		rootPubKey: append([]byte(nil), signer.Public()...),
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
		SectorSize:    fpecPageBytes, // True 1 KB (1024-byte) RM0008 FPEC flash pages
		Images: []tbm1.Image{
			{
				TargetSlot: tbm1.SlotApp,
				CompAlg:    tbm1.CompNone,
				DeltaAlg:   tbm1.DeltaNone,
				Installed:  appImage,
				ChunkSize:  fpecPageBytes, // GAP-F17: ChunkSize <= CHIP_FLASH_MAX_SECTOR_SIZE (1024 B)
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
		SectorSize:    fpecPageBytes, // True 1 KB (1024-byte) RM0008 FPEC flash pages
		Images: []tbm1.Image{
			{
				TargetSlot: tbm1.SlotApp,
				DeltaAlg:   tbm1.DeltaTDS1,
				Base:       baseImage,
				BaseSVN:    baseSVN,
				Installed:  targetImage,
				ChunkSize:  fpecPageBytes, // GAP-F17: ChunkSize <= CHIP_FLASH_MAX_SECTOR_SIZE (1024 B)
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
		ackByte, _ := h.readExactByteSince(ackOff, 20*time.Second)
		if ackByte != 'K' {
			t.Fatalf("expected chunk ACK 'K' at pos %d, got 0x%02X (%q).\nUSART1 log:\n%s",
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

func encodeOptionByteHalfword(low byte) uint16 {
	return uint16(low) | (uint16(^low) << 8)
}

func newErasedOtpOptWithUID() []byte {
	otp := bytes.Repeat([]byte{0xFF}, otpOptSizeBytes)
	copy(otp[otpOffUID:], expectedFactoryUID)
	// PM0075 Section 4.1 factory Option Bytes at 0x1FFFF800..0x1FFFF80F:
	// [0] RDP=0xA5 (unprotected, ~0x5A), [1] USER=0xFF, [2..3] Data0..1=0xFF, [4..7] WRP0..3=0xFF (unprotected)
	binary.LittleEndian.PutUint16(otp[otpOffOB+0:], encodeOptionByteHalfword(0xA5))
	for i := 1; i < 8; i++ {
		binary.LittleEndian.PutUint16(otp[otpOffOB+(i*2):], encodeOptionByteHalfword(0xFF))
	}
	return otp
}

func TestRenodeSTM32F103_1_BlankKeystoreFailClosed(t *testing.T) {
	art := loadArtifacts(t)
	tmp := makeStm32f103TempDir(t)
	flashPath := writeInitialFlash(t, tmp, art, false)

	// Unprogrammed STM32F103 keystore is all 0xFF; stm32f1_opt_key_read_pubkey must reject fail-closed!
	otpPath := filepath.Join(tmp, "otp_opt.bin")
	if err := os.WriteFile(otpPath, newErasedOtpOptWithUID(), 0o644); err != nil {
		t.Fatalf("write blank otp_opt.bin: %v", err)
	}

	h := startRenode(t, tmp, flashPath, otpPath, 90*time.Second)
	defer h.stop()

	off := h.waitForStringSince(0, "=== TOOB STAGE 0 BOOT ===", 10*time.Second)
	h.waitForStringSince(off, "[S0] read_pubkey failed or zero key!", 10*time.Second)

	snap := string(h.snapshot())
	if strings.Contains(snap, "[APP] BOOT") {
		t.Fatalf("SECURITY FAILURE: Guest App booted despite blank 0xFF keystore root key!\n%s", snap)
	}

	otpAfter := filepath.Join(tmp, "otp_blank_after.bin")
	_ = h.saveOtpAndQueryHardwareState(otpAfter)
}

func TestRenodeSTM32F103_2_FullLifecycle_Provision_WRP_MPU_1KBFPEC_SwapMoveOTA_BKP_TDS1Delta_IWDGRollback(t *testing.T) {
	art := loadArtifacts(t)
	tmp := makeStm32f103TempDir(t)
	flashPath := writeInitialFlash(t, tmp, art, false)

	// Seed primary Root Key 0 (+0x000..+0x01F) + Lock Halfword 0 (+0x200 = 0x0000),
	// keeping DSLC (+0x080..+0x085) = 0xFF (unprovisioned DSLC == 0x00)
	otp := newErasedOtpOptWithUID()
	copy(otp[otpOffKey0:], art.rootPubKey)
	binary.LittleEndian.PutUint16(otp[otpOffLock+0:], 0x0000)

	otpPath := filepath.Join(tmp, "otp_opt.bin")
	if err := os.WriteFile(otpPath, otp, 0o644); err != nil {
		t.Fatalf("write factory otp_opt.bin: %v", err)
	}

	h := startRenode(t, tmp, flashPath, otpPath, 960*time.Second)
	defer h.stop()

	// =========================================================================
	// PHASE 2a: Factory USART1 COBS Provisioning (UID 0x1FFFF7E8 + Key + OB.WRP0 + DSLC)
	// =========================================================================
	t.Log("Phase 2a: Waiting for Cortex-M3 Stage 0 Ed25519 verify + Stage 1 COBS PROV banner...")
	off := h.waitForStringSince(0, "[S0] Signature verification PASSED!", 15*time.Second)
	provBanner := cobsEncode([]byte("PROV"))
	off = h.waitForSince(off, provBanner, 10*time.Second)

	// 1. PROV_CMD_READ_ID (0x06) -> status(BOOT_OK) + 12-byte (96-bit) STM32F103 factory UID at 0x1FFFF7E8
	h.writeAll(buildProvFrame(provCmdReadID, nil))
	stFrame, off := h.readCOBSFrameSince(off, 8*time.Second)
	if len(stFrame) != 4 || binary.LittleEndian.Uint32(stFrame) != bootStatusOK {
		t.Fatalf("PROV_CMD_READ_ID status = %x, want %08x", stFrame, bootStatusOK)
	}
	uidFrame, off := h.readCOBSFrameSince(off, 8*time.Second)
	if !bytes.Equal(uidFrame, expectedFactoryUID) {
		t.Fatalf("PROV_CMD_READ_ID chip UID = %x, want %x", uidFrame, expectedFactoryUID)
	}

	// 2. PROV_CMD_BURN_KEY (0x01, slot=1, rootPubKey) -> burns Keystore Slot 1 + Lock Halfword 1 (0x0000)!
	burnPayload := append([]byte{0x01}, art.rootPubKey...)
	h.writeAll(buildProvFrame(provCmdBurnKey, burnPayload))
	stFrame, off = h.readCOBSFrameSince(off, 8*time.Second)
	if len(stFrame) != 4 || binary.LittleEndian.Uint32(stFrame) != bootStatusOK {
		t.Fatalf("PROV_CMD_BURN_KEY status = %x, want %08x", stFrame, bootStatusOK)
	}

	// 3. PROV_CMD_LOCK_BOOT_FLASH (0x07) -> programs PM0075 OB.WRP0[7:0]=0x00 (8 x 4 KB = 32 KB Stage 0)!
	h.writeAll(buildProvFrame(provCmdLockBootFlash, nil))
	stFrame, off = h.readCOBSFrameSince(off, 8*time.Second)
	if len(stFrame) != 4 || binary.LittleEndian.Uint32(stFrame) != bootStatusOK {
		t.Fatalf("PROV_CMD_LOCK_BOOT_FLASH status = %x, want %08x", stFrame, bootStatusOK)
	}

	// 4. PROV_CMD_SET_DSLC (0x02, 0x01) -> burns 3 x 2B TMR halfwords 0xFFFE at 0x1FFFF080..0x1FFFF085!
	h.writeAll(buildProvFrame(provCmdSetDSLC, []byte{0x01}))
	stFrame, off = h.readCOBSFrameSince(off, 8*time.Second)
	if len(stFrame) != 4 || binary.LittleEndian.Uint32(stFrame) != bootStatusOK {
		t.Fatalf("PROV_CMD_SET_DSLC status = %x, want %08x", stFrame, bootStatusOK)
	}

	// 5. PROV_CMD_REBOOT (0xFF) -> hardware IWDG reset -> boots Cortex-M3 App v1.0.0 at 0x08030100!
	h.writeAll(buildProvFrame(provCmdReboot, nil))
	stFrame, off = h.readCOBSFrameSince(off, 8*time.Second)
	if len(stFrame) != 4 || binary.LittleEndian.Uint32(stFrame) != bootStatusOK {
		t.Fatalf("PROV_CMD_REBOOT status = %x, want %08x", stFrame, bootStatusOK)
	}

	off = h.waitForStringSince(off,
		"[APP] BOOT ver=1.0.0 slot=0 tent=0 bkp_dr5=0 handoff=OK",
		25*time.Second)
	h.writeAll([]byte("CONFIRM\n"))
	off = h.waitForStringSince(off, "[APP] CONFIRM status=OK", 8*time.Second)
	t.Log("Phase 2a PASS: Provisioned Keystore + OB.WRP0=0x00 + DSLC=0x01 & booted Cortex-M3 App v1.0.0 via SCB->VTOR=0x08030100!")

	// =========================================================================
	// PHASE 2b: Stage-0 FLASH_WRPR + Cortex-M3 MPU Negative Test & True 1 KB FPEC Proof
	// =========================================================================
	t.Log("Phase 2b: Verifying Cortex-M3 MPU RO lockdown, FLASH_WRPR=0xFFFFFF00 Stage-0 WRPRTERR, and true 1 KB FPEC page isolation...")
	h.writeAll([]byte("REBOOT\n"))
	off = h.waitForStringSince(off,
		"[APP] BOOT ver=1.0.0 slot=0 tent=0 bkp_dr5=0 handoff=OK",
		20*time.Second)

	h.writeAll([]byte("TEST_PROTECT\n"))
	off = h.waitForStringSince(off,
		"[APP] PROTECT_TEST mpu_active=1 mpu_trapped=1 wrpr_locked=1 wrperr_erase=1 wrperr_write=1 stage0_intact=1",
		8*time.Second)

	h.writeAll([]byte("TEST_FPEC_1KB\n"))
	off = h.waitForStringSince(off,
		"[APP] FPEC_1KB pgerr_0to1=1 page_1kb_isolated=1",
		8*time.Second)
	t.Log("Phase 2b PASS: Cortex-M3 MPU trapped privileged CPU store, FLASH_WRPR blocked Stage-0 erase/write, and 1 KB FPEC page isolation + NOR 0->1 PGERR verified!")

	// =========================================================================
	// PHASE 3: 1 KB-Page Swap-Move Full Signed TBM1 OTA (v1.0.0 -> v2.0.0) + 16-Bit BKP->DR1..DR4 Proof
	// =========================================================================
	t.Log("Phase 3a: Verifying revoked KeyIndex=0 bundle is rejected without bricking...")
	revokedBundle := buildFullTrailerBundle(t, art.signer, 0, art.appV2, 1, 2)
	off = streamUARTOTA(t, h, revokedBundle, 113)
	off = h.waitForStringSince(off,
		"[APP] BOOT ver=1.0.0 slot=0 tent=0 bkp_dr5=0 handoff=OK",
		22*time.Second)

	t.Log("Phase 3b: Streaming 1 KB-Page Swap-Move Full Signed TBM1 OTA v1.0.0 -> v2.0.0 (SectorSize=1024, ChunkSize=1024)...")
	bundleV2 := buildFullTrailerBundle(t, art.signer, 1, art.appV2, 1, 2)
	off = streamUARTOTA(t, h, bundleV2, 113)

	off = h.waitForStringSince(off,
		"[APP] BOOT ver=2.0.0 slot=0 tent=1 bkp_dr5=0 handoff=OK",
		25*time.Second)
	h.writeAll([]byte("CONFIRM\n"))
	off = h.waitForStringSince(off, "[APP] CONFIRM status=OK", 8*time.Second)

	// Verify PWR_CR.DBP gating, 16-bit BKP->DR5 masking, and live 64-bit boot_nonce split across BKP->DR1..DR4!
	h.writeAll([]byte("TEST_BKP\n"))
	off = h.waitForStringSince(off,
		"[APP] BKP_STATUS dbp_gated=1 dr5_16bit=1 dr1_4_nonzero=1",
		8*time.Second)

	h.writeAll([]byte("REBOOT\n"))
	off = h.waitForStringSince(off,
		"[APP] BOOT ver=2.0.0 slot=0 tent=0 bkp_dr5=1 handoff=OK",
		22*time.Second)
	t.Log("Phase 3 PASS: 1 KB-Page Swap-Move Full OTA v2.0.0 confirmed via 16-bit BKP->DR1..DR4 & persisted across warm reset (bkp_dr5=1)!")

	// =========================================================================
	// PHASE 4: Live USART1 Signed 136B+ TDS1 Forward-Delta OTA (v2.0.0 -> v3.0.0)
	// =========================================================================
	bundleDeltaV3, rawDeltaBytes := buildDeltaTrailerBundle(t, art.signer, 1, art.appV2, art.appV3, 1, 2, 3)
	if rawDeltaBytes < 136 {
		t.Fatalf("TDS1 delta payload = %d bytes, expected >= 136 bytes", rawDeltaBytes)
	}
	t.Logf("Phase 4: Streaming signed TDS1 Forward-Delta OTA v2.0.0 -> v3.0.0 (delta payload=%d bytes >= 136B vs full=%d bytes)...",
		rawDeltaBytes, len(art.appV3))
	off = streamUARTOTA(t, h, bundleDeltaV3, 113)

	off = h.waitForStringSince(off,
		"[APP] BOOT ver=3.0.0 slot=0 tent=1 bkp_dr5=1 handoff=OK",
		60*time.Second)
	h.writeAll([]byte("CONFIRM\n"))
	off = h.waitForStringSince(off, "[APP] CONFIRM status=OK", 15*time.Second)
	h.writeAll([]byte("REBOOT\n"))
	off = h.waitForStringSince(off,
		"[APP] BOOT ver=3.0.0 slot=0 tent=0 bkp_dr5=1 handoff=OK",
		45*time.Second)
	t.Log("Phase 4 PASS: Cortex-M3 SDVM + Heatshrink reconstructed v3.0.0 across 1 KB FPEC pages & confirmed!")

	// =========================================================================
	// PHASE 5: Bad v4 Hardware IWDG Watchdog Auto-Rollback (bad_v4 -> v3.0.0)
	// =========================================================================
	t.Log("Phase 5: Streaming signed crashing firmware v4.0.0 (hangs without confirm) to verify 40 kHz IWDG rollback...")
	bundleBadV4 := buildFullTrailerBundle(t, art.signer, 1, art.appBadV4, 3, 4)
	off = streamUARTOTA(t, h, bundleBadV4, 113)

	off = h.waitForStringSince(off,
		"[APP] BOOT ver=4.0.0 slot=0 tent=1 CRASHING_WITHOUT_CONFIRM",
		45*time.Second)
	off = h.waitForStringSince(off,
		"[APP] BOOT ver=3.0.0 slot=0 tent=0 bkp_dr5=1 handoff=OK",
		75*time.Second)
	t.Log("Phase 5 PASS: Hardware 40 kHz IWDG latched RCC_CSR.IWDGRSTF & 1 KB Swap-Move rolled back bad_v4 -> v3.0.0 automatically!")

	// Verify persisted Keystore, Lock halfword, OB.WRP0, and hardware FPEC/BKP counters!
	otpSavedPath := filepath.Join(tmp, "otp_after.bin")
	monOut := h.saveOtpAndQueryHardwareState(otpSavedPath)
	persistedOtp, err := os.ReadFile(otpSavedPath)
	if err != nil {
		t.Fatalf("read saved otp_after.bin: %v", err)
	}
	for i := range 3 {
		hw := binary.LittleEndian.Uint16(persistedOtp[otpOffDSLC+(i*2):])
		if hw != 0xFFFE {
			t.Fatalf("persisted Keystore DSLC TMR halfword[%d] = 0x%04X, want 0xFFFE", i, hw)
		}
	}
	if !bytes.Equal(persistedOtp[otpOffKey1:otpOffKey1+32], art.rootPubKey) {
		t.Fatalf("persisted Keystore KEY1 = %x, want %x", persistedOtp[otpOffKey1:otpOffKey1+32], art.rootPubKey)
	}
	if lock1 := binary.LittleEndian.Uint16(persistedOtp[otpOffLock+2:]); lock1 != 0x0000 {
		t.Fatalf("persisted Keystore Lock Halfword 1 = 0x%04X, want 0x0000", lock1)
	}
	if wrp0Hw := binary.LittleEndian.Uint16(persistedOtp[otpOffOB+8:]); wrp0Hw != 0xFF00 {
		t.Fatalf("persisted OB.WRP0 halfword = 0x%04X, want 0xFF00 (WRP0=0x00, ~WRP0=0xFF)", wrp0Hw)
	}
	if !strings.Contains(strings.ToUpper(monOut), "0XFFFFFF00") {
		t.Fatalf("expected flashCtrl.Wrpr = 0xFFFFFF00 in monitor output, got:\n%s", monOut)
	}
}

func TestRenodeSTM32F103_3_RecoveryOS_XMODEM_Rescue(t *testing.T) {
	art := loadArtifacts(t)
	tmp := makeStm32f103TempDir(t)
	// Corrupt BOTH App Slot and Staging Slot while keeping Stage 0, Stage 1A/1B, and Recovery OS intact!
	flashPath := writeInitialFlash(t, tmp, art, true)

	otp := newErasedOtpOptWithUID()
	copy(otp[otpOffKey0:], art.rootPubKey)
	binary.LittleEndian.PutUint16(otp[otpOffLock+0:], 0x0000)
	for i := range 3 {
		binary.LittleEndian.PutUint16(otp[otpOffDSLC+(i*2):], 0xFFFE) // DSLC == 0x01 (Operational)
	}
	// Stage-0 OB.WRP0[7:0]=0x00 required in operational DSLC by stm32f1_soc_lockdown_before_handoff()
	binary.LittleEndian.PutUint16(otp[otpOffOB+8:], encodeOptionByteHalfword(0x00))

	otpPath := filepath.Join(tmp, "otp_opt.bin")
	if err := os.WriteFile(otpPath, otp, 0o644); err != nil {
		t.Fatalf("write otp_opt.bin: %v", err)
	}

	h := startRenode(t, tmp, flashPath, otpPath, 300*time.Second)
	defer h.stop()

	t.Log("Phase 6: Booting with corrupted App & Staging slots -> expecting Stage 1 VTOR handoff to Recovery OS at 0x08040100...")
	off := h.waitForStringSince(0, "[REC] listening...", 25*time.Second)
	off = h.waitForStringSince(off, "C", 10*time.Second)

	rescueBundle := buildFullTrailerBundle(t, art.signer, 0, art.appV3, 1, 3)
	totalBlocks := (len(rescueBundle) + 127) / 128
	t.Logf("Streaming %d-byte signed rescue TBM1 bundle (%d XMODEM-CRC 128B blocks, 1 KB FPEC pages)...", len(rescueBundle), totalBlocks)

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
				t.Fatalf("Recovery OS returned XMODEM NAK on block %d/%d.\nUSART1 log:\n%s",
					blk+1, totalBlocks, string(h.snapshot()))
			}
		}
		if !gotACK {
			t.Fatalf("timeout waiting for XMODEM ACK on block %d/%d", blk+1, totalBlocks)
		}
	}

	eotOff := h.markOffset()
	h.writeAll([]byte{xmEOT})
	h.waitForStringSince(eotOff, "[REC] resolved", 15*time.Second)

	off = h.waitForStringSince(eotOff,
		"[APP] BOOT ver=3.0.0 slot=0 tent=1 bkp_dr5=0 handoff=OK",
		28*time.Second)
	h.writeAll([]byte("CONFIRM\n"))
	h.waitForStringSince(off, "[APP] CONFIRM status=OK", 8*time.Second)

	otpAfter := filepath.Join(tmp, "otp_rec_after.bin")
	_ = h.saveOtpAndQueryHardwareState(otpAfter)
	t.Log("Phase 6 PASS: Rescued bricked Cortex-M3 STM32F103 over XMODEM-CRC into verified v3.0.0!")
}
