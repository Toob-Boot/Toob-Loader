package renode_freertos_nrf52840_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
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
	flashSizeBytes = 1024 * 1024
	uicrSizeBytes  = 4096

	// nRF52840 partition offsets (generated from nrf52840/hardware.json + device.toml)
	offStage0      = 0x000000
	offStage1A     = 0x008000
	offAppSlot0    = 0x038000
	offStagingSlot = 0x068000
	offRecoveryOS  = 0x098000

	// nRF52840 UICR->CUSTOMER[0..31] offsets relative to UICR base (0x10001000)
	uicrOffKey0 = 0x080 // CUSTOMER[0..7]   : 32B Ed25519 Root Key 0
	uicrOffKey1 = 0x0A0 // CUSTOMER[8..15]  : 32B Ed25519 Rotation Key 1
	uicrOffDSLC = 0x0C0 // CUSTOMER[16]     : ~dslc in byte 0 (0xFFFFFFFE -> 0x01 provisioned)
	uicrOffLock = 0x0CC // CUSTOMER[19]     : ~locked_pages in low 16 bits (0xFFFFFFF7 -> 8 pages)

	// Device identity matching test/renode_nrf52840/device.toml
	testVendorID  = 0x1915
	testProductID = 0x5284
	testHWRev     = 1

	// RFC 8032 Test Vector 1 root signing key
	rootSeedHex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"

	// Toob image header constants (cli/toob-cli/cmd/sign.go)
	toobImageMagic     = uint32(0x544F4F42)
	toobImageHeaderLen = 20
	vtorEntryOffset    = uint32(0x100)
)

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

func resolveRenodeBinary(t *testing.T) string {
	t.Helper()
	if env := os.Getenv("TOOB_RENODE_BIN"); env != "" {
		if _, err := os.Stat(env); err == nil {
			return env
		}
	}

	exe := "renode"
	if runtime.GOOS == "windows" {
		exe = "renode.exe"
	}

	dStorageCand := filepath.Join(`D:\ToobStorage\tools\renode-1.17.0\renode_1.17.0-portable`, exe)
	if _, err := os.Stat(dStorageCand); err == nil {
		return dStorageCand
	}

	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("UserHomeDir: %v", err)
	}
	cand := filepath.Join(home, ".toob", "tools", "renode", "renode_1.17.0-portable", exe)
	if _, err := os.Stat(cand); err != nil {
		t.Skipf("Renode binary not found at %s or %s (set TOOB_RENODE_BIN to override)", dStorageCand, cand)
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

func startRenode(t *testing.T, dir, flashPath, uicrPath string, maxLifetime time.Duration) *renodeHarness {
	t.Helper()
	renodeBin := resolveRenodeBinary(t)
	ctx, cancel := context.WithTimeout(context.Background(), maxLifetime)

	overlayAbs, err := filepath.Abs("Nrf52840SocOverlay.cs")
	if err != nil {
		cancel()
		t.Fatalf("Abs(Nrf52840SocOverlay.cs): %v", err)
	}
	replAbs, err := filepath.Abs("nrf52840_toob.repl")
	if err != nil {
		cancel()
		t.Fatalf("Abs(nrf52840_toob.repl): %v", err)
	}

	monPort := reserveFreeTCPPort(t)
	uartPort := reserveFreeTCPPort(t)

	rescContent := fmt.Sprintf(`include @%s
mach create "nrf52840_freertos_e2e"
machine LoadPlatformDescription @%s
sysbus.nvmc InstallFlashHooks
emulation CreateServerSocketTerminal %d "term" false
connector Connect sysbus.uart0 term
sysbus.flash LoadBinary @%s 0x0
sysbus.uicr LoadBinary @%s

macro reset
"""
    sysbus.cpu VectorTableOffset 0x0
    sysbus.cpu SP `+"`sysbus ReadDoubleWord 0x0`"+`
    sysbus.cpu PC `+"`sysbus ReadDoubleWord 0x4`"+`
"""
runMacro $reset
`,
		toSlashPath(overlayAbs),
		toSlashPath(replAbs),
		uartPort,
		toSlashPath(flashPath),
		toSlashPath(uicrPath),
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
		rescPath,
	}
	cmd := exec.CommandContext(ctx, renodeBin, args...)
	var outLog bytes.Buffer
	cmd.Stdout = &outLog
	cmd.Stderr = &outLog

	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatalf("start Renode: %v", err)
	}

	uartConn, err := dialRetry(fmt.Sprintf("127.0.0.1:%d", uartPort), 15*time.Second)
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		cancel()
		t.Fatalf("connect Renode UART server socket (%d): %v\nRenode output:\n%s",
			uartPort, err, outLog.String())
	}

	monConn, err := dialRetry(fmt.Sprintf("127.0.0.1:%d", monPort), 10*time.Second)
	if err != nil {
		_ = uartConn.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		cancel()
		t.Fatalf("connect Renode Monitor (%d): %v\nRenode output:\n%s",
			monPort, err, outLog.String())
	}

	h := &renodeHarness{
		t:      t,
		cmd:    cmd,
		uart:   uartConn,
		mon:    monConn,
		cancel: cancel,
		notify: make(chan struct{}, 1),
	}

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

func (h *renodeHarness) waitForLineContainingSince(offset int, prefix string, timeout time.Duration) (string, int) {
	h.t.Helper()
	deadline := time.Now().Add(timeout)
	needle := []byte(prefix)
	for {
		h.mu.Lock()
		data := h.rxBuf.Bytes()
		if offset < len(data) {
			if idx := bytes.Index(data[offset:], needle); idx >= 0 {
				lineStart := offset + idx
				if nl := bytes.IndexByte(data[lineStart:], '\n'); nl >= 0 {
					endPos := lineStart + nl + 1
					line := strings.TrimRight(string(data[lineStart:endPos]), "\r\n")
					h.mu.Unlock()
					return line, endPos
				}
			}
		}
		h.mu.Unlock()

		rem := time.Until(deadline)
		if rem <= 0 {
			snap := string(h.snapshot())
			h.t.Fatalf("timeout (%v) waiting for line %q after offset %d.\nFull UART log:\n%s\nMonitor log:\n%s",
				timeout, prefix, offset, snap, h.monitorSnapshot())
		}
		select {
		case <-h.notify:
		case <-time.After(min(rem, 50*time.Millisecond)):
		}
	}
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
			h.t.Fatalf("timeout (%v) reading byte at offset %d.\nFull UART log:\n%s",
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
	const sliceBytes = 64
	for pos := 0; pos < len(b); pos += sliceBytes {
		end := min(pos+sliceBytes, len(b))
		if _, err := h.uart.Write(b[pos:end]); err != nil {
			h.t.Fatalf("UART TCP write failed: %v", err)
		}
		if end < len(b) {
			time.Sleep(2 * time.Millisecond)
		}
	}
}

// packToobImage prepends the 20-byte toob_image_header_t in-process and validates
// the Cortex-M4F FreeRTOS vector table at +0x100 (SCB->VTOR).
func packToobImage(t *testing.T, name string, rawBin []byte, entryOffset uint32) []byte {
	t.Helper()
	if pad := (4 - (len(rawBin) % 4)) % 4; pad > 0 {
		padded := make([]byte, len(rawBin)+pad)
		copy(padded, rawBin)
		for i := len(rawBin); i < len(padded); i++ {
			padded[i] = 0xFF
		}
		rawBin = padded
	}

	totalSize := uint32(toobImageHeaderLen + len(rawBin))
	header := make([]byte, toobImageHeaderLen)
	binary.LittleEndian.PutUint32(header[0:4], toobImageMagic)
	binary.LittleEndian.PutUint32(header[4:8], totalSize)
	binary.LittleEndian.PutUint32(header[8:12], entryOffset)
	fp := sha256.Sum256(rawBin)
	copy(header[12:20], fp[:8])

	img := make([]byte, 0, int(totalSize))
	img = append(img, header...)
	img = append(img, rawBin...)

	// Structural check: verify Cortex-M4F FreeRTOS vectors at +0x100 (SCB->VTOR)
	if len(img) < int(entryOffset)+16*4 {
		t.Fatalf("%s image too small (%d bytes) for Cortex-M4F vector table", name, len(img))
	}
	vec := func(idx int) uint32 {
		off := int(entryOffset) + idx*4
		return binary.LittleEndian.Uint32(img[off : off+4])
	}
	msp := vec(0)
	resetVec := vec(1)
	faultVec := vec(3)
	svcVec := vec(11)
	pendSVVec := vec(14)
	sysTickVec := vec(15)

	if msp < 0x20001000 || msp > 0x2003F000 {
		t.Fatalf("%s VTOR[0] initial MSP = 0x%08X outside SRAM", name, msp)
	}
	if (resetVec&1) == 0 || resetVec < (offAppSlot0+entryOffset) || resetVec >= offStagingSlot {
		t.Fatalf("%s VTOR[1] Reset_Handler = 0x%08X invalid for XIP Slot 0", name, resetVec)
	}
	if svcVec == faultVec || pendSVVec == faultVec || sysTickVec == faultVec {
		t.Fatalf("%s FreeRTOS handlers not installed in VTOR: SVC=0x%08X PendSV=0x%08X SysTick=0x%08X (fault=0x%08X)",
			name, svcVec, pendSVVec, sysTickVec, faultVec)
	}
	return img
}

type freertosArtifacts struct {
	stage0Raw    []byte
	stage1Signed []byte
	recoveryBin  []byte
	rtosV1       []byte
	rtosV2       []byte
	rtosBadV3    []byte
	signer       tbm1.Signer
	rootPubKey   []byte
}

func loadArtifacts(t *testing.T) freertosArtifacts {
	t.Helper()

	bootBuildDir := os.Getenv("TOOB_BOOTLOADER_BUILD_DIR")
	if bootBuildDir == "" {
		bootBuildDir = filepath.Join("..", "renode_nrf52840", "builds", "build_nrf52840")
	}
	rtosBuildDir := os.Getenv("TOOB_FREERTOS_BUILD_DIR")
	if rtosBuildDir == "" {
		rtosBuildDir = `D:\ToobStorage\renode_freertos_build`
	}

	mustRead := func(base, rel string) []byte {
		t.Helper()
		p, err := filepath.Abs(filepath.Join(base, rel))
		if err != nil {
			t.Fatalf("Abs(%s): %v", rel, err)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("missing build artifact %s (run scripts/run_renode_freertos_e2e.ps1 first): %v", p, err)
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

	rawV1 := mustRead(rtosBuildDir, filepath.Join("apps", "freertos_v1.raw.bin"))
	rawV2 := mustRead(rtosBuildDir, filepath.Join("apps", "freertos_v2.raw.bin"))
	rawBadV3 := mustRead(rtosBuildDir, filepath.Join("apps", "freertos_bad_v3.raw.bin"))

	return freertosArtifacts{
		stage0Raw:    mustRead(bootBuildDir, "toob_stage0.bin"),
		stage1Signed: mustRead(bootBuildDir, "toob_stage1.signed.bin"),
		recoveryBin:  mustRead(bootBuildDir, "toob_recovery.bin"),
		rtosV1:       packToobImage(t, "freertos_v1", rawV1, vtorEntryOffset),
		rtosV2:       packToobImage(t, "freertos_v2", rawV2, vtorEntryOffset),
		rtosBadV3:    packToobImage(t, "freertos_bad_v3", rawBadV3, vtorEntryOffset),
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

func streamVerifiedUARTOTA(t *testing.T, h *renodeHarness, bundle []byte, chunkSize int) (string, int) {
	t.Helper()
	sum := sha256.Sum256(bundle)
	shaHex := hex.EncodeToString(sum[:])

	off := h.markOffset()
	cmd := fmt.Sprintf("OTA %d %s\n", len(bundle), shaHex)
	h.writeAll([]byte(cmd))
	_, off = h.waitForLineContainingSince(off, "[RTOS] OTA_READY mode=SHA256", 10*time.Second)

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
		ackByte, _ := h.readExactByteSince(ackOff, 10*time.Second)
		if ackByte != 'K' {
			t.Fatalf("expected chunk ACK 'K' at pos %d/%d, got 0x%02X (%q).\nUART log:\n%s",
				pos, len(bundle), ackByte, string([]byte{ackByte}), string(h.snapshot()))
		}
	}

	finLine, off := h.waitForLineContainingSince(off, "[RTOS] OTA_FINALIZED status=OK", 15*time.Second)
	return finLine, off
}

func extractMetricUint(t *testing.T, line, key string) uint64 {
	t.Helper()
	re := regexp.MustCompile(`\b` + regexp.QuoteMeta(key) + `=(\d+)\b`)
	m := re.FindStringSubmatch(line)
	if len(m) != 2 {
		t.Fatalf("metric %s=<uint> not found in line: %q", key, line)
	}
	val, err := strconv.ParseUint(m[1], 10, 64)
	if err != nil {
		t.Fatalf("parse %s in %q: %v", key, line, err)
	}
	return val
}

func TestRenodeFreeRTOS_NRF52840_MultiTask_LiveOTA_DeadlockWDTRollback(t *testing.T) {
	art := loadArtifacts(t)
	tmp := t.TempDir()

	// Seed 1 MB nRF52840 flash: Stage 0 + signed Stage 1 + Recovery OS + FreeRTOS v1.0.0 in Slot 0
	flash := bytes.Repeat([]byte{0xFF}, flashSizeBytes)
	copy(flash[offStage0:], art.stage0Raw)
	copy(flash[offStage1A:], art.stage1Signed)
	copy(flash[offAppSlot0:], art.rtosV1)
	copy(flash[offRecoveryOS:], art.recoveryBin)

	flashPath := filepath.Join(tmp, "flash.bin")
	if err := os.WriteFile(flashPath, flash, 0o644); err != nil {
		t.Fatalf("write flash.bin: %v", err)
	}

	// Provisioned UICR: Key0 + Key1 + DSLC=0x01 (~0x01=0xFFFFFFFE) + Stage 0 BPROT 8 pages (0xFFFFFFF7)
	uicr := bytes.Repeat([]byte{0xFF}, uicrSizeBytes)
	copy(uicr[uicrOffKey0:], art.rootPubKey)
	copy(uicr[uicrOffKey1:], art.rootPubKey)
	binary.LittleEndian.PutUint32(uicr[uicrOffDSLC:uicrOffDSLC+4], 0xFFFFFFFE)
	binary.LittleEndian.PutUint32(uicr[uicrOffLock:uicrOffLock+4], 0xFFFFFFF7)

	uicrPath := filepath.Join(tmp, "uicr.bin")
	if err := os.WriteFile(uicrPath, uicr, 0o644); err != nil {
		t.Fatalf("write uicr.bin: %v", err)
	}

	h := startRenode(t, tmp, flashPath, uicrPath, 180*time.Second)
	defer h.stop()

	// =========================================================================
	// PHASE 1: Boot FreeRTOS v1.0.0 -> Verify Pre-Scheduler, Preemptive Tasks,
	//          VFP Context Switching, .noinit Survival & toob_os_lock Contention
	// =========================================================================
	t.Log("Phase 1: Booting Stage 0 -> Stage 1 -> Multi-Task FreeRTOS v1.0.0 on Cortex-M4F...")
	_, off := h.waitForLineContainingSince(0, "[S0] Signature verification PASSED!", 10*time.Second)
	_, off = h.waitForLineContainingSince(off, "[RTOS] SCHED_START ver=1.0.0 slot=0 tent=0 presched=OK", 15*time.Second)

	bootLineV1, off := h.waitForLineContainingSince(
		off,
		"[RTOS] BOOT_CONFIRMED ver=1.0.0 slot=0 tent=0 presched=OK handoff=OK confirm=OK",
		15*time.Second,
	)
	if !strings.Contains(bootLineV1, "fpu=OK") {
		t.Fatalf("expected fpu=OK in BOOT_CONFIRMED line, got: %s", bootLineV1)
	}
	ticksV1 := extractMetricUint(t, bootLineV1, "ticks")
	switchesV1 := extractMetricUint(t, bootLineV1, "switches")
	if ticksV1 < 12 || switchesV1 < 8 {
		t.Fatalf("expected preemptive SysTick>=12 & PendSV switches>=8, got ticks=%d switches=%d (%s)",
			ticksV1, switchesV1, bootLineV1)
	}

	diagLineV1, off := h.waitForLineContainingSince(off, "[RTOS] DIAG ver=1.0.0 status=OK", 10*time.Second)
	diagCallsV1 := extractMetricUint(t, diagLineV1, "diag_calls")
	if diagCallsV1 < 4 {
		t.Fatalf("expected concurrent TaskOtaWorker diag_calls >= 4 under toob_os_lock, got %d (%s)",
			diagCallsV1, diagLineV1)
	}

	h.writeAll([]byte("STATUS\n"))
	statusLineV1, off := h.waitForLineContainingSince(off, "[RTOS] STATUS ver=1.0.0", 8*time.Second)
	wdtFeedsV1 := extractMetricUint(t, statusLineV1, "wdt_feeds")
	if wdtFeedsV1 < 2 {
		t.Fatalf("expected TaskWatchdogHealth wdt_feeds >= 2, got %d (%s)", wdtFeedsV1, statusLineV1)
	}
	t.Logf("Phase 1 PASS: %s | %s", bootLineV1, diagLineV1)

	// =========================================================================
	// PHASE 2: Live Verified-SHA256 TBM1 Full OTA (FreeRTOS v1.0.0 -> v2.0.0)
	//          Streaming via TaskOtaWorker while TaskWatchdogHealth Feeds WDT
	// =========================================================================
	bundleV2 := buildFullTrailerBundle(t, art.signer, 1, art.rtosV2, 1, 2)
	t.Logf("Phase 2: Streaming signed TBM1 Full OTA FreeRTOS v1.0.0 -> v2.0.0 (%d bytes) over NRF_UART0...", len(bundleV2))
	finLineV2, off := streamVerifiedUARTOTA(t, h, bundleV2, 128)
	if extractMetricUint(t, finLineV2, "wdt_feeds") < 2 {
		t.Fatalf("expected TaskWatchdogHealth wdt_feeds >= 2 during OTA stream: %s", finLineV2)
	}

	// Stage 1 swaps FreeRTOS v2.0.0 into Slot 0 (tent=1); TaskWatchdogHealth confirms under toob_os_lock!
	_, off = h.waitForLineContainingSince(off, "[RTOS] SCHED_START ver=2.0.0 slot=0 tent=1 presched=OK", 20*time.Second)
	bootLineV2Tent, off := h.waitForLineContainingSince(
		off,
		"[RTOS] BOOT_CONFIRMED ver=2.0.0 slot=0 tent=1 presched=OK handoff=OK confirm=OK",
		15*time.Second,
	)
	diagLineV2, off := h.waitForLineContainingSince(off, "[RTOS] DIAG ver=2.0.0 status=OK", 10*time.Second)
	if extractMetricUint(t, diagLineV2, "svn") != 1 || extractMetricUint(t, diagLineV2, "fw_major") != 2 {
		t.Fatalf("expected svn=1 fw_major=2 after OTA to v2.0.0, got: %s", diagLineV2)
	}

	// Warm reboot to verify Stage 1 commits FreeRTOS v2.0.0 permanently (tent=0)
	h.writeAll([]byte("REBOOT\n"))
	bootLineV2Comm, off := h.waitForLineContainingSince(
		off,
		"[RTOS] BOOT_CONFIRMED ver=2.0.0 slot=0 tent=0 presched=OK handoff=OK confirm=OK",
		20*time.Second,
	)
	_, off = h.waitForLineContainingSince(off, "[RTOS] DIAG ver=2.0.0 status=OK", 10*time.Second)
	t.Logf("Phase 2 PASS: Tentative (%s) -> Committed (%s)", bootLineV2Tent, bootLineV2Comm)

	// =========================================================================
	// PHASE 3: Simulated Task-Deadlock Firmware (bad_v3.0.0) Starves NRF_WDT
	//          -> Hardware WDT Fires -> Stage 1 Automatically Rolls Back to v2.0.0
	// =========================================================================
	bundleBadV3 := buildFullTrailerBundle(t, art.signer, 1, art.rtosBadV3, 2, 3)
	t.Logf("Phase 3: Streaming unconfirmed deadlocking FreeRTOS bad_v3.0.0 (%d bytes)...", len(bundleBadV3))
	_, off = streamVerifiedUARTOTA(t, h, bundleBadV3, 128)
	postBadV3Start := off

	// bad_v3.0.0 starts scheduler, TaskOtaWorker + TaskDeadlockPeer enter AB-BA mutex deadlock,
	// AppSelfTest catches deadlock before toob_confirm_boot() and starves NRF_WDT!
	_, off = h.waitForLineContainingSince(off, "[RTOS] SCHED_START ver=3.0.0 slot=0 tent=1 presched=OK", 20*time.Second)
	failLineV3, off := h.waitForLineContainingSince(
		off,
		"[RTOS] SELF_TEST_FAIL ver=3.0.0 slot=0 tent=1 reason=TASK_DEADLOCK starving_wdt=1",
		15*time.Second,
	)
	t.Logf("Observed expected task deadlock self-test failure: %s", failLineV3)

	// NRF52840_Watchdog barks across max_retries=2 -> Stage 1 restores FreeRTOS v2.0.0 from Scratch!
	rollbackBootLine, off := h.waitForLineContainingSince(
		off,
		"[RTOS] BOOT_CONFIRMED ver=2.0.0 slot=0 tent=0 presched=OK handoff=OK confirm=OK",
		45*time.Second,
	)
	rollbackDiagLine, off := h.waitForLineContainingSince(off, "[RTOS] DIAG ver=2.0.0 status=OK", 10*time.Second)

	// Ensure bad_v3.0.0 NEVER confirmed boot and rollback recorded WATCHDOG reset_reason (3)
	fullSnap := string(h.snapshot()[postBadV3Start:])
	if strings.Contains(fullSnap, "[RTOS] BOOT_CONFIRMED ver=3.0.0") {
		t.Fatalf("SECURITY FAILURE: Deadlocked bad_v3.0.0 unexpectedly confirmed boot!\n%s", fullSnap)
	}
	if extractMetricUint(t, rollbackDiagLine, "reset_reason") != 3 {
		t.Fatalf("expected TOOB_RESET_WATCHDOG (3) after WDT rollback, got: %s", rollbackDiagLine)
	}

	// Verify interactive multi-task health on the rolled-back FreeRTOS v2.0.0 image
	h.writeAll([]byte("STATUS\n"))
	rollbackStatusLine, _ := h.waitForLineContainingSince(off, "[RTOS] STATUS ver=2.0.0", 8*time.Second)
	if extractMetricUint(t, rollbackStatusLine, "wdt_feeds") < 2 {
		t.Fatalf("expected active WDT feeds after rollback, got: %s", rollbackStatusLine)
	}
	t.Logf("Phase 3 PASS: Hardware WDT Auto-Rollback bad_v3.0.0 -> FreeRTOS v2.0.0 (%s | %s | %s)",
		rollbackBootLine, rollbackDiagLine, rollbackStatusLine)
}
