package renode_stm32l476_test

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
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Toob-Boot/Toob-Loader/toob-go-lib/tbm1"
)

const (
	flashSizeBytes = 1 * 1024 * 1024
	otpSizeBytes   = 0x5A0 // 1 KB 64-bit ECC OTP (+0x000..+0x3FF) + 96-bit factory UID (+0x590..+0x59B)

	// STM32L476 partition offsets relative to 0x08000000 (from generated/boot_layout.h)
	offStage0      = 0x000000 // 32 KB  (Bank 1 Pages 0..15: 16 x 2 KB)
	offStage1A     = 0x008000 // 96 KB  (Bank 1 Pages 16..63)
	offStage1B     = 0x020000 // 96 KB  (Bank 1 Pages 64..111)
	offAppSlot0    = 0x038000 // 128 KB (Bank 1 Pages 112..175)
	offStagingSlot = 0x058000 // 128 KB (Bank 1 Pages 176..239)
	offRecoveryOS  = 0x078000 // 64 KB  (Bank 1 Pages 240..255 + Bank 2 Pages 0..15)

	// STM32L476 64-bit ECC OTP offsets relative to 0x1FFF7000 (stm32l4_opt_otp/otp_real.c)
	otpOffKey0  = 0x000 // Dwords 0..3:   32B Ed25519 Root Key 0
	otpOffKey1  = 0x020 // Dwords 4..7:   32B Ed25519 Rotation Key 1
	otpOffKey2  = 0x040 // Dwords 8..11:  32B Revoked Key 2 (all 0x00)
	otpOffLock0 = 0x080 // Dword 16:      8B Lock Word for Key 0 (0x0000000000000000 = locked)
	otpOffLock1 = 0x088 // Dword 17:      8B Lock Word for Key 1
	otpOffLock2 = 0x090 // Dword 18:      8B Lock Word for Key 2
	otpOffDSLC  = 0x0A0 // Dwords 20..27: 8 x 8B monotonic DSLC TMR transition slots
	otpOffMono  = 0x0E0 // Dwords 28..127: 100 x 8B write-once monotonic counter steps
	otpOffUID   = 0x590 // 96-bit (12-byte) factory UID at 0x1FFF7590

	// Device identity matching test/renode_stm32l476/device.toml
	testVendorID  = 0x0483
	testProductID = 0x0476
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

var expectedFactoryUID = []byte{0x32, 0x04, 0x76, 0x4C, 0x48, 0x33, 0x54, 0x4D, 0xAA, 0x55, 0x44, 0x76}
var hexValueRegex = regexp.MustCompile(`0x[0-9a-fA-F]+`)

type renodeHarness struct {
	t       *testing.T
	cmd     *exec.Cmd
	uart    net.Conn
	mon     net.Conn
	cancel  context.CancelFunc
	outLog  *bytes.Buffer
	monBuf  bytes.Buffer
	monLock sync.Mutex

	mu     sync.Mutex
	rxBuf  bytes.Buffer
	notify chan struct{}
}

func makeStm32TempDir(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		const dRoot = `D:\ToobStorage\tmp_build\stm32l476_work\tmp`
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
	var candidates []string
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
			exe = "renode.exe"
		}
		candidates = append(candidates, filepath.Join(home, ".toob", "tools", "renode", "renode_1.17.0-portable", exe))
	}
	for _, cand := range candidates {
		if _, err := os.Stat(cand); err == nil {
			return cand
		}
	}
	t.Skipf("Renode binary not found in %v (set TOOB_RENODE_BIN to override)", candidates)
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

	overlayAbs, err := filepath.Abs("Stm32L476SocOverlay.cs")
	if err != nil {
		cancel()
		t.Fatalf("Abs(Stm32L476SocOverlay.cs): %v", err)
	}
	replAbs, err := filepath.Abs("stm32l476_toob.repl")
	if err != nil {
		cancel()
		t.Fatalf("Abs(stm32l476_toob.repl): %v", err)
	}

	monPort := reserveFreeTCPPort(t)
	uartPort := reserveFreeTCPPort(t)

	rescContent := fmt.Sprintf(`include @%s
mach create "stm32l476_e2e"
machine LoadPlatformDescription @%s
emulation CreateServerSocketTerminal %d "term" false
connector Connect sysbus.usart1 term
sysbus LoadBinary @%s 0x08000000
sysbus.otp LoadBinary @%s
sysbus.flashCtrl SyncEccBitmapFromFlash
sysbus.flashCtrl InstallFlashHooks
logLevel 1 sysbus.flashCtrl

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

	monConn, err := dialRetry(fmt.Sprintf("127.0.0.1:%d", monPort), 25*time.Second)
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
		outLog: &outLog,
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

	uartConn, err := dialRetry(fmt.Sprintf("127.0.0.1:%d", uartPort), 20*time.Second)
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

func (h *renodeHarness) queryEccViolationCount() uint64 {
	h.t.Helper()
	before := len(h.monitorSnapshot())
	h.execMonitor("sysbus.flashCtrl DoubleWordDoubleWriteCount")

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		snap := h.monitorSnapshot()
		if len(snap) > before {
			tail := snap[before:]
			for _, line := range strings.Split(tail, "\n") {
				trimmed := strings.TrimSpace(line)
				if strings.Contains(trimmed, "DoubleWordDoubleWriteCount") {
					continue
				}
				if m := hexValueRegex.FindString(trimmed); m != "" {
					val, err := strconv.ParseUint(strings.TrimPrefix(strings.TrimPrefix(m, "0x"), "0X"), 16, 64)
					if err == nil {
						return val
					}
				}
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	h.t.Fatalf("timeout reading sysbus.flashCtrl EccDoubleWriteViolationCount.\nMonitor output:\n%s", h.monitorSnapshot())
	return 0
}

func (h *renodeHarness) saveOtpAndQueryFlashState(otpOutPath string) string {
	h.t.Helper()
	h.execMonitor("pause")
	h.execMonitor(fmt.Sprintf("sysbus.otp SaveBinary @%s", toSlashPath(otpOutPath)))
	h.execMonitor("sysbus.flashCtrl CommittedOptr")
	h.execMonitor("sysbus.flashCtrl CommittedWrp1ar")
	h.execMonitor("sysbus.flashCtrl BlockedOperations")
	h.execMonitor("sysbus.flashCtrl EccDoubleWriteViolationCount")
	h.execMonitor("sysbus.flashCtrl DoubleWordDoubleWriteCount")
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
			h.execMonitor("pause")
			h.execMonitor("sysbus.flashCtrl CommittedOptr")
			h.execMonitor("sysbus.flashCtrl EccDoubleWriteViolationCount")
	h.execMonitor("sysbus.flashCtrl DoubleWordDoubleWriteCount")
			time.Sleep(120 * time.Millisecond)
			snap := string(h.snapshot())
			renodeStdout := ""
			if h.outLog != nil {
				renodeStdout = h.outLog.String()
			}
			h.t.Fatalf("timeout (%v) waiting for %q after offset %d.\nFull UART1 log:\n%s\nMonitor log:\n%s\nRenode stdout:\n%s",
				timeout, string(needle), offset, snap, h.monitorSnapshot(), renodeStdout)
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

func resolveBuildDirs() (string, string) {
	buildDir := os.Getenv("TOOB_STM32L476_BUILD_DIR")
	if buildDir == "" {
		if _, err := os.Stat(`D:\ToobStorage\tmp_build\stm32l476_work\build_stm32l476\toob_stage0.bin`); err == nil {
			buildDir = `D:\ToobStorage\tmp_build\stm32l476_work\build_stm32l476`
		} else if _, err := os.Stat(`D:\ToobStorage\build_stm32l476\toob_stage0.bin`); err == nil {
			buildDir = `D:\ToobStorage\build_stm32l476`
		} else {
			buildDir = filepath.Join("builds", "build_stm32l476")
		}
	}
	appsDir := os.Getenv("TOOB_STM32L476_APPS_DIR")
	if appsDir == "" {
		cand := filepath.Join(buildDir, "apps")
		if _, err := os.Stat(filepath.Join(cand, "app_v1.toob")); err == nil {
			appsDir = cand
		} else {
			appsDir = filepath.Join("builds", "apps")
		}
	}
	return buildDir, appsDir
}

func loadArtifacts(t *testing.T) firmwareArtifacts {
	t.Helper()
	buildDir, appsDir := resolveBuildDirs()

	mustRead := func(p string) []byte {
		t.Helper()
		abs, err := filepath.Abs(p)
		if err != nil {
			t.Fatalf("Abs(%s): %v", p, err)
		}
		b, err := os.ReadFile(abs)
		if err != nil {
			t.Fatalf("missing build artifact %s (run scripts/run_renode_stm32l476_e2e.ps1 first): %v", abs, err)
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
		stage0Raw:    mustRead(filepath.Join(buildDir, "toob_stage0.bin")),
		stage1Signed: mustRead(filepath.Join(buildDir, "toob_stage1.signed.bin")),
		recoveryBin:  mustRead(filepath.Join(buildDir, "toob_recovery.bin")),
		appV1:        mustRead(filepath.Join(appsDir, "app_v1.toob")),
		appV2:        mustRead(filepath.Join(appsDir, "app_v2.toob")),
		appV3:        mustRead(filepath.Join(appsDir, "app_v3.toob")),
		appV3Slot1:   mustRead(filepath.Join(appsDir, "app_v3_slot1.toob")),
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
		SectorSize:    2048,
		Images: []tbm1.Image{
			{
				TargetSlot: tbm1.SlotApp,
				CompAlg:    tbm1.CompNone,
				DeltaAlg:   tbm1.DeltaNone,
				Installed:  appImage,
				ChunkSize:  2048,
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
		SectorSize:    2048,
		Images: []tbm1.Image{
			{
				TargetSlot: tbm1.SlotApp,
				DeltaAlg:   tbm1.DeltaTDS1,
				Base:       baseImage,
				BaseSVN:    baseSVN,
				Installed:  targetImage,
				ChunkSize:  2048,
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
		copy(flash[offAppSlot0:], []byte("CORRUPTED_APP_SLOT0_HEADER!"))
		copy(flash[offStagingSlot:], []byte("CORRUPTED_STAGING1_HEADER!!"))
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

func TestRenodeSTM32L476_1a_BlankOtpFailClosed(t *testing.T) {
	art := loadArtifacts(t)
	tmp := makeStm32TempDir(t)
	flashPath := writeInitialFlash(t, tmp, art, false)

	// Unprogrammed STM32L4 64-bit ECC OTP is all 0xFF; stm32l4_opt_otp_read_pubkey must reject fail-closed!
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
	if got := h.queryEccViolationCount(); got != 0 {
		t.Fatalf("unexpected EccDoubleWriteViolationCount = %d during fail-closed boot, want 0", got)
	}
}

func TestRenodeSTM32L476_FullLifecycle_Provision_64BitECC_MPU_WRP1AR_FullOTA_TDS1Delta_WDTRollback(t *testing.T) {
	art := loadArtifacts(t)
	tmp := makeStm32TempDir(t)
	flashPath := writeInitialFlash(t, tmp, art, false)

	// Seed primary Root Key 0 (dwords 0..3 + 64-bit lock dword 16), keeping Key 1 & Key 2 erased (0xFF)
	// and DSLC dwords 20..27 = 0xFF (DSLC == 0x00 unprovisioned).
	otp := newErasedOtpWithUID()
	copy(otp[otpOffKey0:], art.rootPubKey)
	for i := range 8 {
		otp[otpOffLock0+i] = 0x00
	}

	otpPath := filepath.Join(tmp, "otp.bin")
	if err := os.WriteFile(otpPath, otp, 0o644); err != nil {
		t.Fatalf("write factory otp.bin: %v", err)
	}

	h := startRenode(t, tmp, flashPath, otpPath, 210*time.Second)
	defer h.stop()

	// =========================================================================
	// PHASE 1: Factory UART1 COBS Provisioning (64-bit OTP dwords + WRP1AR)
	// =========================================================================
	t.Log("Phase 1: Waiting for Stage 0 Ed25519 verify + Stage 1 COBS PROV banner...")
	off := h.waitForStringSince(0, "[S0] Signature verification PASSED!", 12*time.Second)
	provBanner := cobsEncode([]byte("PROV"))
	off = h.waitForSince(off, provBanner, 10*time.Second)

	// 1. PROV_CMD_READ_ID (0x06) -> status(BOOT_OK) + 12-byte (96-bit) STM32L476 factory UID
	h.writeAll(buildProvFrame(provCmdReadID, nil))
	stFrame, off := h.readCOBSFrameSince(off, 8*time.Second)
	if len(stFrame) != 4 || binary.LittleEndian.Uint32(stFrame) != bootStatusOK {
		t.Fatalf("PROV_CMD_READ_ID status = %x, want %08x", stFrame, bootStatusOK)
	}
	uidFrame, off := h.readCOBSFrameSince(off, 8*time.Second)
	if !bytes.Equal(uidFrame, expectedFactoryUID) {
		t.Fatalf("PROV_CMD_READ_ID chip UID = %x, want %x", uidFrame, expectedFactoryUID)
	}

	// 2. PROV_CMD_BURN_KEY (0x01, slot=1, rootPubKey) -> burns 4x64-bit OTP dwords + 64-bit Lock Dword 17!
	burnPayload := append([]byte{0x01}, art.rootPubKey...)
	h.writeAll(buildProvFrame(provCmdBurnKey, burnPayload))
	stFrame, off = h.readCOBSFrameSince(off, 8*time.Second)
	if len(stFrame) != 4 || binary.LittleEndian.Uint32(stFrame) != bootStatusOK {
		t.Fatalf("PROV_CMD_BURN_KEY status = %x, want %08x", stFrame, bootStatusOK)
	}

	// 3. PROV_CMD_LOCK_BOOT_FLASH (0x07) -> programs FLASH_WRP1AR = 0xFF0FFF00 (Bank 1 Pages 0..15 = 32 KB Stage 0)!
	h.writeAll(buildProvFrame(provCmdLockBootFlash, nil))
	stFrame, off = h.readCOBSFrameSince(off, 8*time.Second)
	if len(stFrame) != 4 || binary.LittleEndian.Uint32(stFrame) != bootStatusOK {
		t.Fatalf("PROV_CMD_LOCK_BOOT_FLASH status = %x, want %08x", stFrame, bootStatusOK)
	}

	// 4. PROV_CMD_SET_DSLC (0x02, 0x01) -> burns 64-bit OTP DSLC transition slot 0!
	h.writeAll(buildProvFrame(provCmdSetDSLC, []byte{0x01}))
	stFrame, off = h.readCOBSFrameSince(off, 8*time.Second)
	if len(stFrame) != 4 || binary.LittleEndian.Uint32(stFrame) != bootStatusOK {
		t.Fatalf("PROV_CMD_SET_DSLC status = %x, want %08x", stFrame, bootStatusOK)
	}

	// 5. PROV_CMD_REBOOT (0xFF) -> hardware IWDG reset -> cold boots App v1.0.0 at 0x08038100!
	h.writeAll(buildProvFrame(provCmdReboot, nil))
	stFrame, off = h.readCOBSFrameSince(off, 8*time.Second)
	if len(stFrame) != 4 || binary.LittleEndian.Uint32(stFrame) != bootStatusOK {
		t.Fatalf("PROV_CMD_REBOOT status = %x, want %08x", stFrame, bootStatusOK)
	}

	off = h.waitForStringSince(off, "[APP] BOOT ver=1.0.0 slot=0 tent=0 handoff=OK", 20*time.Second)
	if got := h.queryEccViolationCount(); got != 0 {
		t.Fatalf("Phase 1 ECC violation count = %d after 64-bit OTP provisioning + boot, want 0", got)
	}
	t.Log("Phase 1 PASS: Provisioned 64-bit ECC OTP + FLASH_WRP1AR over COBS UART1 & booted App v1.0.0 (ECC violations = 0)!")

	// =========================================================================
	// PHASE 1b: ARMv7-M MPU Stage-0 RO Lockdown + Option-Byte WRP1AR Proof
	// =========================================================================
	t.Log("Phase 1b: Verifying ARMv7-M MPU (AP=0b110 RO) MemManage trap & FLASH_WRP1AR (Pages 0..15) after warm reset...")
	h.writeAll([]byte("REBOOT\n"))
	off = h.waitForStringSince(off, "[APP] BOOT ver=1.0.0 slot=0 tent=0 handoff=OK", 15*time.Second)
	h.writeAll([]byte("TEST_WRP_MPU\n"))
	off = h.waitForStringSince(off, "[APP] WRP_MPU_TEST mpu_active=1 mpu_trapped=1 wrp_locked=1 wrperr_erase=1 wrperr_write=1 stage0_intact=1", 8*time.Second)
	if got := h.queryEccViolationCount(); got != 0 {
		t.Fatalf("Phase 1b ECC violation count = %d, want 0", got)
	}
	t.Log("Phase 1b PASS: ARMv7-M MPU trapped privileged store (DACCVIOL) & FLASH_WRP1AR blocked erase/write; Stage 0 100% intact!")

	// =========================================================================
	// PHASE 1c: Negative Test of Renode 64-Bit ECC Write-Once Enforcer
	// =========================================================================
	t.Log("Phase 1c: Executing negative self-test against Renode 64-bit ECC Write-Once Enforcer (double-writing 0xFFFFFFFFFFFFFFFF without erase)...")
	h.writeAll([]byte("TEST_ECC_DOUBLE_WRITE\n"))
	off = h.waitForStringSince(off, "[APP] ECC_TEST first_ok=1 second_progerr=1 erase_recovers=1", 8*time.Second)
	if got := h.queryEccViolationCount(); got != 1 {
		t.Fatalf("expected EccDoubleWriteViolationCount == 1 after negative ECC double-write test, got %d", got)
	}
	t.Log("Phase 1c PASS: Renode 64-bit ECC Enforcer caught double-write of 0xFFFFFFFFFFFFFFFF (FLASH_SR.PROGERR=1, EccDoubleWriteViolationCount=1)!")

	// Baseline after deliberate negative test: MUST remain strictly 1 (0 new violations) across ALL remaining OTA/WAL/Mailbox/Rollback phases!
	const baselineAfterNegTest = uint64(1)

	// =========================================================================
	// PHASE 2: Live UART1 Full Signed TBM1 TrailerLayout OTA (v1.0.0 -> v2.0.0)
	// =========================================================================
	t.Log("Phase 2a: Verifying rotated/revoked KeyIndex=0 bundle is rejected without bricking...")
	revokedBundle := buildFullTrailerBundle(t, art.signer, 0, art.appV2, 1, 2)
	off = streamUARTOTA(t, h, revokedBundle, 113)
	off = h.waitForStringSince(off, "[APP] BOOT ver=1.0.0 slot=0 tent=0 handoff=OK", 18*time.Second)
	if got := h.queryEccViolationCount(); got != baselineAfterNegTest {
		t.Fatalf("Phase 2a introduced %d ECC double-write violations!", got-baselineAfterNegTest)
	}

	t.Log("Phase 2b: Streaming signed TBM1 TrailerLayout OTA v1.0.0 -> v2.0.0 with active KeyIndex=1 (113-byte prime chunks)...")
	bundleV2 := buildFullTrailerBundle(t, art.signer, 1, art.appV2, 1, 2)
	off = streamUARTOTA(t, h, bundleV2, 113)

	off = h.waitForStringSince(off, "[APP] BOOT ver=2.0.0 slot=1 tent=1 handoff=OK", 18*time.Second)
	h.writeAll([]byte("CONFIRM\n"))
	off = h.waitForStringSince(off, "[APP] CONFIRM status=OK", 8*time.Second)
	h.writeAll([]byte("REBOOT\n"))
	off = h.waitForStringSince(off, "[APP] BOOT ver=2.0.0 slot=1 tent=0 handoff=OK", 18*time.Second)
	if got := h.queryEccViolationCount(); got != baselineAfterNegTest {
		t.Fatalf("Phase 2b Full OTA + WAL + Mailbox + Confirm introduced %d ECC double-write violations!", got-baselineAfterNegTest)
	}
	t.Log("Phase 2 PASS: Revoked KeyIndex=0 rejected + Dual-Bank OPTR.BFB2 OTA v2.0.0 confirmed with 0 ECC double-write violations!")

	// =========================================================================
	// PHASE 3: Live UART1 Signed TDS1 Forward-Delta OTA (v2.0.0 -> v3.0.0)
	// =========================================================================
	bundleDeltaV3, rawDeltaBytes := buildDeltaTrailerBundle(t, art.signer, 1, art.appV2, art.appV3, 1, 2, 3)
	t.Logf("Phase 3: Streaming signed TDS1 Forward-Delta OTA v2.0.0 -> v3.0.0 (delta payload=%d bytes vs full=%d bytes)...",
		rawDeltaBytes, len(art.appV3))
	off = streamUARTOTA(t, h, bundleDeltaV3, 113)

	off = h.waitForStringSince(off, "[APP] BOOT ver=3.0.0 slot=0 tent=1 handoff=OK", 22*time.Second)
	h.writeAll([]byte("CONFIRM\n"))
	off = h.waitForStringSince(off, "[APP] CONFIRM status=OK", 8*time.Second)
	h.writeAll([]byte("REBOOT\n"))
	off = h.waitForStringSince(off, "[APP] BOOT ver=3.0.0 slot=0 tent=0 handoff=OK", 18*time.Second)
	if got := h.queryEccViolationCount(); got != baselineAfterNegTest {
		t.Fatalf("Phase 3 TDS1 Forward-Delta OTA introduced %d ECC double-write violations!", got-baselineAfterNegTest)
	}
	t.Log("Phase 3 PASS: Stage 1 Cortex-M4 SDVM + Heatshrink reconstructed v3.0.0 across 2 KB ECC pages with 0 ECC double-write violations!")

	// =========================================================================
	// PHASE 4: Unconfirmed Crashing Firmware Automatic Hardware IWDG Rollback
	// =========================================================================
	t.Log("Phase 4: Streaming signed crashing firmware v4.0.0 (hangs without confirm) to verify hardware IWDG rollback...")
	bundleBadV4 := buildFullTrailerBundle(t, art.signer, 1, art.appBadV4, 3, 4)
	off = streamUARTOTA(t, h, bundleBadV4, 113)

	off = h.waitForStringSince(off, "[APP] BOOT ver=4.0.0 slot=1 tent=1 CRASHING_WITHOUT_CONFIRM", 18*time.Second)
	// Hardware IWDG latches RCC_CSR.IWDGRSTF and Stage 1 reverts OPTR.BFB2 back to Slot 0 (v3.0.0)!
	off = h.waitForStringSince(off, "[APP] BOOT ver=3.0.0 slot=0 tent=0 handoff=OK", 30*time.Second)
	if got := h.queryEccViolationCount(); got != baselineAfterNegTest {
		t.Fatalf("Phase 4 Hardware IWDG Rollback introduced %d ECC double-write violations!", got-baselineAfterNegTest)
	}
	t.Log("Phase 4 PASS: Hardware IWDG latched RCC_CSR.IWDGRSTF & Stage 1 rolled OPTR.BFB2 back to v3.0.0 with 0 ECC double-write violations!")

	// Verify persisted 64-bit ECC OTP doublewords, lock doublewords, OPTR, and WRP1AR
	otpSavedPath := filepath.Join(tmp, "otp_after.bin")
	monOut := h.saveOtpAndQueryFlashState(otpSavedPath)
	persistedOtp, err := os.ReadFile(otpSavedPath)
	if err != nil {
		t.Fatalf("read saved otp_after.bin: %v", err)
	}
	expectedDslcDword := []byte{0xFE, 0xFE, 0xFE, 0x00, 0x00, 0x00, 0x00, 0x00}
	if !bytes.Equal(persistedOtp[otpOffDSLC:otpOffDSLC+8], expectedDslcDword) {
		t.Fatalf("persisted 64-bit OTP DSLC slot 0 = %x, want %x", persistedOtp[otpOffDSLC:otpOffDSLC+8], expectedDslcDword)
	}
	if !bytes.Equal(persistedOtp[otpOffKey1:otpOffKey1+32], art.rootPubKey) {
		t.Fatalf("persisted OTP KEY1 = %x, want %x", persistedOtp[otpOffKey1:otpOffKey1+32], art.rootPubKey)
	}
	if !bytes.Equal(persistedOtp[otpOffLock1:otpOffLock1+8], make([]byte, 8)) {
		t.Fatalf("persisted 64-bit OTP Lock Dword 1 = %x, want all zeros (permanently locked)", persistedOtp[otpOffLock1:otpOffLock1+8])
	}
	if !strings.Contains(strings.ToUpper(monOut), "0XFF0FFF00") {
		t.Fatalf("expected CommittedWrp1ar = 0xFF0FFF00 (Pages 0..15 locked) in monitor output, got:\n%s", monOut)
	}
	if !strings.Contains(strings.ToUpper(monOut), "0XFFEFF8AA") {
		t.Fatalf("expected CommittedOptr = 0xFFEFF8AA (BFB2=0 after rollback) in monitor output, got:\n%s", monOut)
	}
}

func TestRenodeSTM32L476_RecoveryOS_XMODEM_Rescue(t *testing.T) {
	art := loadArtifacts(t)
	tmp := makeStm32TempDir(t)
	// Corrupt BOTH App Slot 0 and Staging Slot 1 while keeping Stage 0, Stage 1A/1B, and Recovery OS intact!
	flashPath := writeInitialFlash(t, tmp, art, true)

	otp := newErasedOtpWithUID()
	copy(otp[otpOffKey0:], art.rootPubKey)
	for i := range 8 {
		otp[otpOffLock0+i] = 0x00
	}
	// Pre-seed provisioned DSLC == 0x01 in 64-bit OTP DSLC slot 0
	copy(otp[otpOffDSLC:otpOffDSLC+8], []byte{0xFE, 0xFE, 0xFE, 0x00, 0x00, 0x00, 0x00, 0x00})

	otpPath := filepath.Join(tmp, "otp.bin")
	if err := os.WriteFile(otpPath, otp, 0o644); err != nil {
		t.Fatalf("write otp.bin: %v", err)
	}

	h := startRenode(t, tmp, flashPath, otpPath, 90*time.Second)
	defer h.stop()

	t.Log("Booting with corrupted App & Staging slots -> expecting Stage 1 VTOR handoff to Recovery OS at 0x08078100...")
	off := h.waitForStringSince(0, "[REC] listening...", 20*time.Second)
	off = h.waitForStringSince(off, "C", 8*time.Second)

	// With active_slot == 0 under TOOB_TRANSPORT_POINTER, Recovery OS stages into Slot 1 (0x08058000)
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

	if got := h.queryEccViolationCount(); got != 0 {
		t.Fatalf("Recovery OS XMODEM rescue introduced %d ECC double-write violations, want 0", got)
	}
	t.Log("Recovery OS PASS: Rescued bricked STM32L476 over XMODEM-CRC into verified v3.0.0 with 0 ECC double-write violations!")
}
