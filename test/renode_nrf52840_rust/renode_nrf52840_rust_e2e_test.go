package renode_nrf52840_rust_test

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
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Toob-Boot/Toob-Loader/toob-go-lib/tbm1"
)

const (
	flashSizeBytes = 1024 * 1024
	uicrSizeBytes  = 4096

	// Nordic nRF52840 partition offsets matching test/renode_nrf52840/device.toml
	offStage0      = 0x000000
	offStage1A     = 0x008000
	offAppSlot0    = 0x038000
	offRecoveryOS  = 0x098000

	// UICR->CUSTOMER offsets relative to UICR base (0x10001000)
	uicrOffKey0 = 0x080
	uicrOffDSLC = 0x0C0

	testVendorID  = 0x1915
	testProductID = 0x5284
	testHWRev     = 1

	// RFC 8032 Test Vector 1 root signing key
	rootSeedHex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
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
	var candidates []string
	if env := os.Getenv("TOOB_RENODE_BIN"); env != "" {
		candidates = append(candidates, env)
	}
	exe := "renode"
	if runtime.GOOS == "windows" {
		exe = "renode.exe"
	}
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates,
			filepath.Join(home, ".toob", "tools", "renode", "renode_1.17.0-portable", exe),
		)
	}
	if runtime.GOOS == "windows" {
		candidates = append(candidates,
			`D:\ToobStorage\tools\renode-1.17.0\renode_1.17.0-portable\renode.exe`,
			`D:\ToobStorage\tools\renode-1.17.0\bin\Renode.exe`,
		)
	}
	for _, cand := range candidates {
		if _, err := os.Stat(cand); err == nil {
			return cand
		}
	}
	t.Skipf("Renode 1.17.0 binary not found in candidates: %v", candidates)
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

func startRenode(t *testing.T, dir, flashPath, uicrPath string, maxLifetime time.Duration) *renodeHarness {
	t.Helper()
	renodeBin := resolveRenodeBinary(t)
	ctx, cancel := context.WithTimeout(context.Background(), maxLifetime)

	overlayAbs, err := filepath.Abs(filepath.Join("..", "renode_nrf52840", "Nrf52840SocOverlay.cs"))
	if err != nil {
		cancel()
		t.Fatalf("Abs(Nrf52840SocOverlay.cs): %v", err)
	}
	replAbs, err := filepath.Abs("nrf52840_toob_rust.repl")
	if err != nil {
		cancel()
		t.Fatalf("Abs(nrf52840_toob_rust.repl): %v", err)
	}

	monPort := reserveFreeTCPPort(t)
	uartPort := reserveFreeTCPPort(t)

	rescContent := fmt.Sprintf(`include @%s
mach create "nrf52840_rust_e2e"
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
		filepath.ToSlash(overlayAbs),
		filepath.ToSlash(replAbs),
		uartPort,
		filepath.ToSlash(flashPath),
		filepath.ToSlash(uicrPath),
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

	uartConn, err := dialRetry(fmt.Sprintf("127.0.0.1:%d", uartPort), 30*time.Second)
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		cancel()
		t.Fatalf("connect Renode UART (%d): %v\nRenode output:\n%s", uartPort, err, outLog.String())
	}

	monConn, err := dialRetry(fmt.Sprintf("127.0.0.1:%d", monPort), 10*time.Second)
	if err != nil {
		_ = uartConn.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		cancel()
		t.Fatalf("connect Renode Monitor (%d): %v\nRenode output:\n%s", monPort, err, outLog.String())
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

	t.Cleanup(h.stop)

	time.Sleep(100 * time.Millisecond)
	h.execMonitor("start")
	return h
}

func (h *renodeHarness) execMonitor(cmdLine string) {
	if h.mon != nil {
		_, _ = h.mon.Write([]byte(cmdLine + "\r\n"))
	}
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

func (h *renodeHarness) waitForStringSince(offset int, s string, timeout time.Duration) int {
	h.t.Helper()
	needle := []byte(s)
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
			h.t.Fatalf("timeout (%v) waiting for %q after offset %d.\nUART log:\n%s\nMonitor log:\n%s",
				timeout, s, offset, string(h.snapshot()), h.monitorSnapshot())
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
			h.t.Fatalf("timeout (%v) reading byte at offset %d.\nUART log:\n%s",
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
			h.t.Fatalf("UART write failed: %v", err)
		}
		if end < len(b) {
			time.Sleep(2 * time.Millisecond)
		}
	}
}

type rustArtifacts struct {
	stage0Raw    []byte
	stage1Signed []byte
	recoveryBin  []byte
	rustAppV1    []byte
	rustAppV2    []byte
	rustAppV3    []byte
	rustAppBadV4 []byte
	signer       tbm1.Signer
	rootPubKey   []byte
}

func loadRustArtifacts(t *testing.T) rustArtifacts {
	t.Helper()
	bootBuildDir := filepath.Join("..", "renode_nrf52840", "builds", "build_nrf52840")
	appsDir := os.Getenv("TOOB_RUST_APPS_DIR")
	if appsDir == "" {
		appsDir = `D:\ToobStorage\renode_rust_build\apps`
	}

	mustRead := func(p string) []byte {
		t.Helper()
		abs, err := filepath.Abs(p)
		if err != nil {
			t.Fatalf("Abs(%s): %v", p, err)
		}
		b, err := os.ReadFile(abs)
		if err != nil {
			t.Fatalf("missing artifact %s (run scripts/run_renode_nrf52840_rust_e2e.ps1): %v", abs, err)
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

	return rustArtifacts{
		stage0Raw:    mustRead(filepath.Join(bootBuildDir, "toob_stage0.bin")),
		stage1Signed: mustRead(filepath.Join(bootBuildDir, "toob_stage1.signed.bin")),
		recoveryBin:  mustRead(filepath.Join(bootBuildDir, "toob_recovery.bin")),
		rustAppV1:    mustRead(filepath.Join(appsDir, "rust_app_v1.toob")),
		rustAppV2:    mustRead(filepath.Join(appsDir, "rust_app_v2.toob")),
		rustAppV3:    mustRead(filepath.Join(appsDir, "rust_app_v3.toob")),
		rustAppBadV4: mustRead(filepath.Join(appsDir, "rust_app_bad_v4.toob")),
		signer:       signer,
		rootPubKey:   append([]byte(nil), signer.Public()...),
	}
}

func buildFullTrailerBundle(t *testing.T, signer tbm1.Signer, appImage []byte, svn uint32, major uint16) []byte {
	t.Helper()
	pkg, err := tbm1.Build(tbm1.Manifest{
		KeyIndex:      0,
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

func buildDeltaTrailerBundle(t *testing.T, signer tbm1.Signer, baseImage, targetImage []byte, baseSVN, targetSVN uint32, major uint16) ([]byte, int) {
	t.Helper()
	pkg, err := tbm1.Build(tbm1.Manifest{
		KeyIndex:      0,
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

func streamRustUARTOTA(t *testing.T, h *renodeHarness, bundle []byte, verifiedSHA bool, chunkSize int) int {
	t.Helper()
	off := h.markOffset()
	var cmd string
	var expectedMode string
	if verifiedSHA {
		sum := sha256.Sum256(bundle)
		cmd = fmt.Sprintf("OTAV %d %x\n", len(bundle), sum[:])
		expectedMode = "SHA256"
	} else {
		cmd = fmt.Sprintf("OTA %d\n", len(bundle))
		expectedMode = "UNVERIFIED"
	}
	h.writeAll([]byte(cmd))
	off = h.waitForStringSince(off, "[RUST] OTA_READY\r\n", 8*time.Second)

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

	expectedBanner := fmt.Sprintf("[RUST] OTA_FINALIZED mode=%s status=OK", expectedMode)
	return h.waitForStringSince(off, expectedBanner, 15*time.Second)
}

func TestRenodeNRF52840_RustNoStdGuest_Handoff_VerifiedOTA_TDS1Delta_WDTRollback(t *testing.T) {
	art := loadRustArtifacts(t)
	tmp := t.TempDir()

	flash := bytes.Repeat([]byte{0xFF}, flashSizeBytes)
	copy(flash[offStage0:], art.stage0Raw)
	copy(flash[offStage1A:], art.stage1Signed)
	copy(flash[offAppSlot0:], art.rustAppV1)
	copy(flash[offRecoveryOS:], art.recoveryBin)

	flashPath := filepath.Join(tmp, "flash.bin")
	if err := os.WriteFile(flashPath, flash, 0o644); err != nil {
		t.Fatalf("write flash.bin: %v", err)
	}

	// Provisioned UICR: Root Key 0 in CUSTOMER[0..7] + DSLC = 0x01 (~0x01 = 0xFFFFFFFE in CUSTOMER[16])
	uicr := bytes.Repeat([]byte{0xFF}, uicrSizeBytes)
	copy(uicr[uicrOffKey0:], art.rootPubKey)
	binary.LittleEndian.PutUint32(uicr[uicrOffDSLC:uicrOffDSLC+4], 0xFFFFFFFE)

	uicrPath := filepath.Join(tmp, "uicr.bin")
	if err := os.WriteFile(uicrPath, uicr, 0o644); err != nil {
		t.Fatalf("write uicr.bin: %v", err)
	}

	h := startRenode(t, tmp, flashPath, uicrPath, 150*time.Second)
	defer h.stop()

	// =========================================================================
	// PHASE 1: Stage 0 -> Stage 1 -> #![no_std] Rust Guest v1.0.0 (.noinit Handoff + Diag TDR1 + BPROT)
	// =========================================================================
	t.Log("Phase 1: Booting real Stage 0 -> Stage 1 -> #![no_std] Cortex-M4F Rust Guest v1.0.0...")
	off := h.waitForStringSince(0, "[S0] Signature verification PASSED!", 10*time.Second)
	off = h.waitForStringSince(off, "RUST_GUEST v1.0.0 slot=0 tent=0 handoff=OK", 15*time.Second)

	h.writeAll([]byte("DIAG\n"))
	off = h.waitForStringSince(off, "[RUST] DIAG wire_len=", 8*time.Second)

	expectedStage0Word := binary.LittleEndian.Uint32(art.stage0Raw[0x1000 : 0x1000+4])
	expectedBprot := fmt.Sprintf("[RUST] BPROT cfg0=0x000000FF pre=0x%08X post=0x%08X status=PROTECTED",
		expectedStage0Word, expectedStage0Word)
	h.writeAll([]byte("BPROT_ATTACK\n"))
	off = h.waitForStringSince(off, expectedBprot, 8*time.Second)
	t.Log("Phase 1 PASS: Rust Guest v1.0.0 validated .noinit handoff, TDR1 diag, and Stage-0 BPROT immutability!")

	// =========================================================================
	// PHASE 2: Streaming SHA-256 Verified OTA (v1.0.0 -> v2.0.0) via libtoob::OtaSession::begin_verified
	// =========================================================================
	bundleV2 := buildFullTrailerBundle(t, art.signer, art.rustAppV2, 1, 2)
	t.Logf("Phase 2: Streaming %d-byte signed TBM1 TrailerLayout OTA v1.0.0 -> v2.0.0 via OtaSession::begin_verified...", len(bundleV2))
	off = streamRustUARTOTA(t, h, bundleV2, true, 113)

	off = h.waitForStringSince(off, "RUST_GUEST v2.0.0 slot=0 tent=1 handoff=OK diag_svn=1", 18*time.Second)
	h.writeAll([]byte("CONFIRM\n"))
	off = h.waitForStringSince(off, "[RUST] CONFIRM status=OK", 8*time.Second)
	h.writeAll([]byte("REBOOT\n"))
	off = h.waitForStringSince(off, "RUST_GUEST v2.0.0 slot=0 tent=0 handoff=OK diag_svn=1", 15*time.Second)
	t.Log("Phase 2 PASS: Rust OtaSession::begin_verified staged v2.0.0, Stage 1 deployed tentatively, confirm_boot() committed!")

	// =========================================================================
	// PHASE 3: Streaming TDS1 Forward-Delta OTA (v2.0.0 -> v3.0.0) via libtoob::OtaSession::begin
	// =========================================================================
	bundleDeltaV3, rawDeltaLen := buildDeltaTrailerBundle(t, art.signer, art.rustAppV2, art.rustAppV3, 1, 2, 3)
	t.Logf("Phase 3: Streaming signed TDS1 Forward-Delta OTA v2.0.0 -> v3.0.0 (delta=%dB vs full=%dB)...",
		rawDeltaLen, len(art.rustAppV3))
	off = streamRustUARTOTA(t, h, bundleDeltaV3, false, 113)

	off = h.waitForStringSince(off, "RUST_GUEST v3.0.0 slot=0 tent=1 handoff=OK diag_svn=2", 18*time.Second)
	h.writeAll([]byte("CONFIRM\n"))
	off = h.waitForStringSince(off, "[RUST] CONFIRM status=OK", 8*time.Second)
	h.writeAll([]byte("REBOOT\n"))
	off = h.waitForStringSince(off, "RUST_GUEST v3.0.0 slot=0 tent=0 handoff=OK diag_svn=2", 15*time.Second)
	t.Log("Phase 3 PASS: Stage 1 SDVM + Heatshrink reconstructed Rust Guest v3.0.0 & confirmed!")

	// =========================================================================
	// PHASE 4: Unconfirmed Crashing Rust Firmware v4.0.0 -> Hardware WDT Auto-Rollback to v3.0.0
	// =========================================================================
	t.Log("Phase 4: Streaming crashing Rust Guest v4.0.0 to verify NRF52840_Watchdog automatic rollback...")
	bundleBadV4 := buildFullTrailerBundle(t, art.signer, art.rustAppBadV4, 3, 4)
	off = streamRustUARTOTA(t, h, bundleBadV4, true, 113)

	off = h.waitForStringSince(off, "RUST_GUEST v4.0.0 slot=0 tent=1 CRASHING_WITHOUT_CONFIRM", 15*time.Second)
	off = h.waitForStringSince(off, "RUST_GUEST v3.0.0 slot=0 tent=0 handoff=OK", 40*time.Second)

	snap := string(h.snapshot())
	if !strings.Contains(snap, "RUST_GUEST v2.0.0") || !strings.Contains(snap, "RUST_GUEST v3.0.0") {
		t.Fatalf("unexpected UART trace:\n%s", snap)
	}
	t.Log("Phase 4 PASS: Hardware WDT rolled back unconfirmed Rust v4.0.0 -> committed Rust v3.0.0!")
}
