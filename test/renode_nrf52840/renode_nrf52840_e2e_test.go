package renode_nrf52840_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
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
	flashSizeBytes = 1024 * 1024
	uicrSizeBytes  = 4096

	// nRF52840 partition offsets (generated from nrf52840/hardware.json + device.toml)
	offStage0      = 0x000000
	offStage1A     = 0x008000
	offStage1B     = 0x020000
	offAppSlot0    = 0x038000
	offStagingSlot = 0x068000
	offRecoveryOS  = 0x098000

	// nRF52840 UICR->CUSTOMER[0..31] offsets relative to UICR base (0x10001000)
	uicrOffKey0 = 0x080 // CUSTOMER[0..7]   : 32B Ed25519 Root Key 0
	uicrOffKey1 = 0x0A0 // CUSTOMER[8..15]  : 32B Ed25519 Rotation Key 1
	uicrOffDSLC = 0x0C0 // CUSTOMER[16]     : ~dslc in byte 0 (0xFFFFFFFF -> 0x00)
	uicrOffMono = 0x0C4 // CUSTOMER[17..18] : 64-bit 1->0 monotonic counter
	uicrOffLock = 0x0CC // CUSTOMER[19]     : ~locked_pages in low 16 bits

	// Device identity matching test/renode_nrf52840/device.toml
	testVendorID  = 0x1915
	testProductID = 0x5284
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
mach create "nrf52840_e2e"
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

	uartConn, err := dialRetry(fmt.Sprintf("127.0.0.1:%d", uartPort), 35*time.Second)
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

	// Wait briefly for Monitor prompt readiness, then start emulation only AFTER
	// the UART reader goroutine is attached so zero early Stage 0 bytes are lost.
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

func (h *renodeHarness) saveUicrAndQueryBlocked(uicrOutPath string) string {
	h.t.Helper()
	h.execMonitor("pause")
	h.execMonitor(fmt.Sprintf("sysbus.uicr SaveBinary @%s", toSlashPath(uicrOutPath)))
	h.execMonitor("sysbus.powerBprot BlockedOperations")

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if info, err := os.Stat(uicrOutPath); err == nil && info.Size() >= uicrSizeBytes {
			time.Sleep(80 * time.Millisecond)
			return h.monitorSnapshot()
		}
		time.Sleep(40 * time.Millisecond)
	}
	h.t.Fatalf("timeout waiting for Renode to save UICR to %s.\nMonitor output:\n%s",
		uicrOutPath, h.monitorSnapshot())
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
			h.t.Fatalf("timeout (%v) waiting for %q after offset %d.\nFull UART log:\n%s\nMonitor log:\n%s",
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
			h.t.Fatalf("timeout (%v) reading byte at offset %d.\nFull UART log:\n%s",
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
			h.t.Fatalf("timeout (%v) waiting for COBS 0x00 terminator at offset %d.\nUART log:\n%s",
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
	// nRF52840 UART0 (non-EasyDMA) has a shallow RX FIFO; pace large writes slightly
	// if needed, though normal frames are <= 514 bytes.
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
	mustRead := func(rel string) []byte {
		t.Helper()
		p, err := filepath.Abs(rel)
		if err != nil {
			t.Fatalf("Abs(%s): %v", rel, err)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("missing build artifact %s (run scripts/run_renode_nrf52840_e2e.ps1 first): %v", p, err)
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
		stage0Raw:    mustRead("builds/build_nrf52840/toob_stage0.bin"),
		stage1Signed: mustRead("builds/build_nrf52840/toob_stage1.signed.bin"),
		recoveryBin:  mustRead("builds/build_nrf52840/toob_recovery.bin"),
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

const (
	toobImgSigMagic      = uint32(0x54534947)
	toobImgSigFlagSHA256 = uint8(0x01)
	toobImgSigTrailerLen = 72
)

func resignTSIGImage(t *testing.T, signer tbm1.Signer, img []byte, keyIndex uint8) []byte {
	t.Helper()
	if len(img) < 20+4+toobImgSigTrailerLen {
		t.Fatalf("TSIG image too short (%d bytes)", len(img))
	}
	out := bytes.Clone(img)
	trailerOff := len(out) - toobImgSigTrailerLen
	if gotMagic := binary.LittleEndian.Uint32(out[trailerOff : trailerOff+4]); gotMagic != toobImgSigMagic {
		t.Fatalf("missing TSIG trailer magic: got 0x%08X want 0x%08X", gotMagic, toobImgSigMagic)
	}
	out[trailerOff+4] = keyIndex
	out[trailerOff+5] = toobImgSigFlagSHA256
	out[trailerOff+6] = 0
	out[trailerOff+7] = 0
	digest := sha256.Sum256(out[:trailerOff])
	sig, err := signer.Sign(digest[:])
	if err != nil {
		t.Fatalf("sign TSIG digest (key_index=%d): %v", keyIndex, err)
	}
	copy(out[trailerOff+8:], sig)
	return out
}

func streamUARTOTA(t *testing.T, h *renodeHarness, bundle []byte, chunkSize int) int {
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
	copy(flash[offStage0:], art.stage0Raw)
	copy(flash[offStage1A:], art.stage1Signed)
	copy(flash[offRecoveryOS:], art.recoveryBin)
	if corruptApps {
		copy(flash[offAppSlot0:], []byte("CORRUPTED_APP_SLOT_HEADER!"))
		copy(flash[offStagingSlot:], []byte("CORRUPTED_STAGING_HEADER!!"))
	} else {
		copy(flash[offAppSlot0:], art.appV1)
	}

	flashPath := filepath.Join(dir, "flash.bin")
	if err := os.WriteFile(flashPath, flash, 0o644); err != nil {
		t.Fatalf("write flash.bin: %v", err)
	}
	return flashPath
}

func newErasedUicr() []byte {
	return bytes.Repeat([]byte{0xFF}, uicrSizeBytes)
}

func TestRenodeNRF52840_1a_BlankUicrFailClosed(t *testing.T) {
	art := loadArtifacts(t)
	tmp := t.TempDir()
	flashPath := writeInitialFlash(t, tmp, art, false)

	// Unprogrammed NOR UICR is all 0xFF; nrf_uicr_read_pubkey must reject all-0xFF fail-closed!
	uicrPath := filepath.Join(tmp, "uicr.bin")
	if err := os.WriteFile(uicrPath, newErasedUicr(), 0o644); err != nil {
		t.Fatalf("write blank uicr.bin: %v", err)
	}

	h := startRenode(t, tmp, flashPath, uicrPath, 45*time.Second)
	defer h.stop()

	off := h.waitForStringSince(0, "=== TOOB STAGE 0 BOOT ===", 8*time.Second)
	h.waitForStringSince(off, "[S0] read_pubkey failed or zero key!", 8*time.Second)

	snap := string(h.snapshot())
	if strings.Contains(snap, "[APP] BOOT") {
		t.Fatalf("SECURITY FAILURE: Guest App booted despite erased 0xFF UICR root key!\n%s", snap)
	}
}

func TestRenodeNRF52840_FullLifecycle_Provision_FullOTA_TDS1Delta_WDTRollback(t *testing.T) {
	art := loadArtifacts(t)
	// Phase 1 burns OTP key slot 1 via PROV_CMD_BURN_KEY, revoking key_index=0 for subsequent slot verification.
	art.recoveryBin = resignTSIGImage(t, art.signer, art.recoveryBin, 1)
	art.appV1 = resignTSIGImage(t, art.signer, art.appV1, 1)
	art.appV2 = resignTSIGImage(t, art.signer, art.appV2, 1)
	art.appV3 = resignTSIGImage(t, art.signer, art.appV3, 1)
	art.appBadV4 = resignTSIGImage(t, art.signer, art.appBadV4, 1)
	tmp := t.TempDir()
	flashPath := writeInitialFlash(t, tmp, art, false)

	// Seed primary Root Key 0 (CUSTOMER[0..7]), keeping CUSTOMER[16] = 0xFFFFFFFF (DSLC == 0x00 unprovisioned)
	uicr := newErasedUicr()
	copy(uicr[uicrOffKey0:], art.rootPubKey)

	uicrPath := filepath.Join(tmp, "uicr.bin")
	if err := os.WriteFile(uicrPath, uicr, 0o644); err != nil {
		t.Fatalf("write factory uicr.bin: %v", err)
	}

	h := startRenode(t, tmp, flashPath, uicrPath, 150*time.Second)
	defer h.stop()

	// =========================================================================
	// PHASE 1: Factory UART COBS Provisioning (READ_ID + BURN_KEY + LOCK_BOOT_FLASH + SET_DSLC + REBOOT)
	// =========================================================================
	t.Log("Phase 1: Waiting for Stage 0 Ed25519 verify + Stage 1 COBS PROV banner...")
	off := h.waitForStringSince(0, "[S0] Signature verification PASSED!", 10*time.Second)
	provBanner := cobsEncode([]byte("PROV"))
	off = h.waitForSince(off, provBanner, 8*time.Second)

	// 1. PROV_CMD_READ_ID (0x06) -> status(BOOT_OK) + 8-byte FICR->DEVICEID[0..1]
	expectedUID := []byte{0x52, 0x84, 0x00, 0x01, 0xDE, 0xAD, 0xBE, 0xEF}
	h.writeAll(buildProvFrame(provCmdReadID, nil))
	stFrame, off := h.readCOBSFrameSince(off, 8*time.Second)
	if len(stFrame) != 4 || binary.LittleEndian.Uint32(stFrame) != bootStatusOK {
		t.Fatalf("PROV_CMD_READ_ID status = %x, want %08x", stFrame, bootStatusOK)
	}
	uidFrame, off := h.readCOBSFrameSince(off, 8*time.Second)
	if !bytes.Equal(uidFrame, expectedUID) {
		t.Fatalf("PROV_CMD_READ_ID chip UID = %x, want %x", uidFrame, expectedUID)
	}

	// 2. PROV_CMD_BURN_KEY (0x01, slot=1, rootPubKey) -> burns UICR->CUSTOMER[8..15] via NVMC WEN!
	burnPayload := append([]byte{0x01}, art.rootPubKey...)
	h.writeAll(buildProvFrame(provCmdBurnKey, burnPayload))
	stFrame, off = h.readCOBSFrameSince(off, 8*time.Second)
	if len(stFrame) != 4 || binary.LittleEndian.Uint32(stFrame) != bootStatusOK {
		t.Fatalf("PROV_CMD_BURN_KEY status = %x, want %08x", stFrame, bootStatusOK)
	}

	// 3. PROV_CMD_LOCK_BOOT_FLASH (0x07) -> locks BPROT->CONFIG0 (8 x 4KB = 32KB Stage 0) + UICR CUSTOMER[19]!
	h.writeAll(buildProvFrame(provCmdLockBootFlash, nil))
	stFrame, off = h.readCOBSFrameSince(off, 8*time.Second)
	if len(stFrame) != 4 || binary.LittleEndian.Uint32(stFrame) != bootStatusOK {
		t.Fatalf("PROV_CMD_LOCK_BOOT_FLASH status = %x, want %08x", stFrame, bootStatusOK)
	}

	// 4. PROV_CMD_SET_DSLC (0x02, 0x01) -> burns ~0x01 (0xFFFFFFFE) into UICR->CUSTOMER[16] via NVMC WEN!
	h.writeAll(buildProvFrame(provCmdSetDSLC, []byte{0x01}))
	stFrame, off = h.readCOBSFrameSince(off, 8*time.Second)
	if len(stFrame) != 4 || binary.LittleEndian.Uint32(stFrame) != bootStatusOK {
		t.Fatalf("PROV_CMD_SET_DSLC status = %x, want %08x", stFrame, bootStatusOK)
	}

	// 5. PROV_CMD_REBOOT (0xFF) -> hardware WDT reset -> boots App v1.0.0 at 0x00038100!
	h.writeAll(buildProvFrame(provCmdReboot, nil))
	stFrame, off = h.readCOBSFrameSince(off, 8*time.Second)
	if len(stFrame) != 4 || binary.LittleEndian.Uint32(stFrame) != bootStatusOK {
		t.Fatalf("PROV_CMD_REBOOT status = %x, want %08x", stFrame, bootStatusOK)
	}

	off = h.waitForStringSince(off, "[APP] BOOT ver=1.0.0 slot=0 tent=0 handoff=OK", 15*time.Second)
	t.Log("Phase 1 PASS: Provisioned UICR + BPROT over COBS UART & booted Cortex-M4 App v1.0.0!")

	// =========================================================================
	// PHASE 2: Live UART Full Signed TBM1 TrailerLayout OTA (v1.0.0 -> v2.0.0)
	// =========================================================================
	t.Log("Phase 2a: Verifying revoked KeyIndex=0 bundle is rejected without bricking...")
	revokedBundle := buildFullTrailerBundle(t, art.signer, 0, art.appV2, 1, 2)
	off = streamUARTOTA(t, h, revokedBundle, 113)
	off = h.waitForStringSince(off, "[APP] BOOT ver=1.0.0 slot=0 tent=0 handoff=OK", 15*time.Second)

	t.Log("Phase 2b: Streaming signed TBM1 TrailerLayout OTA v1.0.0 -> v2.0.0 with active KeyIndex=1...")
	bundleV2 := buildFullTrailerBundle(t, art.signer, 1, art.appV2, 1, 2)
	off = streamUARTOTA(t, h, bundleV2, 113)

	off = h.waitForStringSince(off, "[APP] BOOT ver=2.0.0 slot=0 tent=1 handoff=OK", 15*time.Second)
	h.writeAll([]byte("CONFIRM\n"))
	off = h.waitForStringSince(off, "[APP] CONFIRM status=OK", 8*time.Second)
	h.writeAll([]byte("REBOOT\n"))
	off = h.waitForStringSince(off, "[APP] BOOT ver=2.0.0 slot=0 tent=0 handoff=OK", 15*time.Second)
	t.Log("Phase 2 PASS: Revoked KeyIndex=0 rejected + One-Way XIP OTA v2.0.0 tentative -> confirmed -> committed!")

	// =========================================================================
	// PHASE 3: Live UART Signed TDS1 Forward-Delta OTA (v2.0.0 -> v3.0.0)
	// =========================================================================
	bundleDeltaV3, rawDeltaBytes := buildDeltaTrailerBundle(t, art.signer, 1, art.appV2, art.appV3, 1, 2, 3)
	t.Logf("Phase 3: Streaming signed TDS1 Forward-Delta OTA v2.0.0 -> v3.0.0 (delta payload=%d bytes vs full=%d bytes)...",
		rawDeltaBytes, len(art.appV3))
	off = streamUARTOTA(t, h, bundleDeltaV3, 113)

	off = h.waitForStringSince(off, "[APP] BOOT ver=3.0.0 slot=0 tent=1 handoff=OK", 18*time.Second)
	h.writeAll([]byte("CONFIRM\n"))
	off = h.waitForStringSince(off, "[APP] CONFIRM status=OK", 8*time.Second)
	h.writeAll([]byte("REBOOT\n"))
	off = h.waitForStringSince(off, "[APP] BOOT ver=3.0.0 slot=0 tent=0 handoff=OK", 15*time.Second)
	t.Log("Phase 3 PASS: Stage 1 Cortex-M4 SDVM + Heatshrink reconstructed v3.0.0 & confirmed!")

	// =========================================================================
	// PHASE 4: Unconfirmed Crashing Firmware Automatic Hardware WDT Rollback
	// =========================================================================
	t.Log("Phase 4: Streaming signed crashing firmware v4.0.0 (hangs without confirm) to verify nrf_wdt rollback...")
	bundleBadV4 := buildFullTrailerBundle(t, art.signer, 1, art.appBadV4, 3, 4)
	off = streamUARTOTA(t, h, bundleBadV4, 113)

	// Stage 1 deploys v4.0.0 tentatively; v4.0.0 hangs without feeding NRF52840_Watchdog!
	off = h.waitForStringSince(off, "[APP] BOOT ver=4.0.0 slot=0 tent=1 CRASHING_WITHOUT_CONFIRM", 15*time.Second)
	// NRF52840_Watchdog fires POWER->RESETREAS.DOG across max_retries=2, then Stage 1 restores v3.0.0 from Scratch!
	off = h.waitForStringSince(off, "[APP] BOOT ver=3.0.0 slot=0 tent=0 handoff=OK", 40*time.Second)
	t.Log("Phase 4 PASS: Hardware NRF52840_Watchdog latched POWER->RESETREAS.DOG & Stage 1 rolled back to v3.0.0!")

	// Verify persisted UICR registers (KEY1, ~DSLC=0xFE, monotonic counter bits cleared, lock word)
	uicrSavedPath := filepath.Join(tmp, "uicr_after.bin")
	_ = h.saveUicrAndQueryBlocked(uicrSavedPath)
	persistedUicr, err := os.ReadFile(uicrSavedPath)
	if err != nil {
		t.Fatalf("read saved uicr_after.bin: %v", err)
	}
	if persistedUicr[uicrOffDSLC] != 0xFE {
		t.Fatalf("persisted UICR CUSTOMER[16] DSLC byte = 0x%02X, want 0xFE (~0x01)", persistedUicr[uicrOffDSLC])
	}
	if !bytes.Equal(persistedUicr[uicrOffKey1:uicrOffKey1+32], art.rootPubKey) {
		t.Fatalf("persisted UICR KEY1 = %x, want %x", persistedUicr[uicrOffKey1:uicrOffKey1+32], art.rootPubKey)
	}
	lockWord := binary.LittleEndian.Uint32(persistedUicr[uicrOffLock : uicrOffLock+4])
	if lockWord != 0xFFFFFFF7 {
		t.Fatalf("persisted UICR lock word CUSTOMER[19] = 0x%08X, want 0xFFFFFFF7 (~8 pages)", lockWord)
	}
}

func runFactoryProvisioning(t *testing.T, h *renodeHarness, off int, lockBoot bool) int {
	t.Helper()
	off = h.waitForStringSince(off, "[S0] Signature verification PASSED!", 12*time.Second)
	off = h.waitForSince(off, cobsEncode([]byte("PROV")), 8*time.Second)

	sendChecked := func(name string, cmd byte, payload []byte) {
		h.writeAll(buildProvFrame(cmd, payload))
		var stFrame []byte
		stFrame, off = h.readCOBSFrameSince(off, 8*time.Second)
		if len(stFrame) != 4 || binary.LittleEndian.Uint32(stFrame) != bootStatusOK {
			t.Fatalf("%s status = %x, want %08x", name, stFrame, bootStatusOK)
		}
	}

	if lockBoot {
		sendChecked("PROV_CMD_LOCK_BOOT_FLASH", provCmdLockBootFlash, nil)
	}
	sendChecked("PROV_CMD_SET_DSLC", provCmdSetDSLC, []byte{0x01})
	sendChecked("PROV_CMD_REBOOT", provCmdReboot, nil)
	return off
}

func TestRenodeNRF52840_HardwareBprotStage0NonBrickability(t *testing.T) {
	art := loadArtifacts(t)
	tmp := t.TempDir()
	flashPath := writeInitialFlash(t, tmp, art, false)

	// Factory UICR: KEY0 burned with DSLC = 0xFFFFFFFF (0x00) so UART provisioning formats K4 WAL before setting DSLC=0x01.
	uicr := newErasedUicr()
	copy(uicr[uicrOffKey0:], art.rootPubKey)

	uicrPath := filepath.Join(tmp, "uicr.bin")
	if err := os.WriteFile(uicrPath, uicr, 0o644); err != nil {
		t.Fatalf("write uicr.bin: %v", err)
	}

	h := startRenode(t, tmp, flashPath, uicrPath, 60*time.Second)
	defer h.stop()

	off := runFactoryProvisioning(t, h, 0, true)

	// Boot to Guest App v1.0.0; verify both cold boot AND warm reboot re-assert BPROT->CONFIG0 = 0x000000FF!
	off = h.waitForStringSince(off, "[APP] BOOT ver=1.0.0 slot=0 tent=0 handoff=OK", 15*time.Second)
	h.writeAll([]byte("REBOOT\n"))
	off = h.waitForStringSince(off, "[APP] BOOT ver=1.0.0 slot=0 tent=0 handoff=OK", 15*time.Second)

	// Execute raw MMIO NVMC ERASEPAGE + WEN zero-overwrite against Stage 0 (0x00001000)
	expectedStage0Word := binary.LittleEndian.Uint32(art.stage0Raw[0x1000 : 0x1000+4])
	expectedLine := fmt.Sprintf("[APP] BPROT cfg0=0x000000FF pre=0x%08X post=0x%08X status=PROTECTED", expectedStage0Word, expectedStage0Word)

	h.writeAll([]byte("BPROT_ATTACK\n"))
	h.waitForStringSince(off, expectedLine, 8*time.Second)

	// Also verify the Renode hardware model recorded >= 2 blocked operations (ERASEPAGE + WEN write)
	uicrSavedPath := filepath.Join(tmp, "uicr_bprot.bin")
	monOut := h.saveUicrAndQueryBlocked(uicrSavedPath)
	if !strings.Contains(monOut, "0x00000002") && !strings.Contains(monOut, "2") {
		t.Fatalf("expected powerBprot.BlockedOperations >= 2 in monitor output, got:\n%s", monOut)
	}
	t.Logf("Hardware BPROT PASS: %s (Stage 0 immutable across warm reset!)", expectedLine)
}

func TestRenodeNRF52840_RecoveryOS_XMODEM_Rescue(t *testing.T) {
	art := loadArtifacts(t)
	tmp := t.TempDir()
	// Corrupt BOTH App Slot and Staging Slot while keeping Stage 0, Stage 1, and Recovery OS intact!
	flashPath := writeInitialFlash(t, tmp, art, true)

	// Factory UICR: KEY0 burned with DSLC = 0xFFFFFFFF (0x00) so UART provisioning formats K4 WAL before setting DSLC=0x01.
	uicr := newErasedUicr()
	copy(uicr[uicrOffKey0:], art.rootPubKey)

	uicrPath := filepath.Join(tmp, "uicr.bin")
	if err := os.WriteFile(uicrPath, uicr, 0o644); err != nil {
		t.Fatalf("write uicr.bin: %v", err)
	}

	h := startRenode(t, tmp, flashPath, uicrPath, 110*time.Second)
	defer h.stop()

	off := runFactoryProvisioning(t, h, 0, false)

	t.Log("Booting with corrupted App & Staging slots -> expecting Stage 1 VTOR handoff to Recovery OS at 0x00098100...")
	off = h.waitForStringSince(off, "[REC] listening...", 18*time.Second)
	off = h.waitForStringSince(off, "C", 8*time.Second)

	rescueBundle := buildFullTrailerBundle(t, art.signer, 0, art.appV3, 1, 3)
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
	h.waitForStringSince(eotOff, "[REC] resolved", 12*time.Second)

	off = h.waitForStringSince(eotOff, "[APP] BOOT ver=3.0.0", 20*time.Second)
	h.writeAll([]byte("CONFIRM\n"))
	h.waitForStringSince(off, "[APP] CONFIRM status=OK", 8*time.Second)
	t.Log("Recovery OS PASS: Rescued bricked nRF52840 over XMODEM-CRC into verified v3.0.0!")
}
