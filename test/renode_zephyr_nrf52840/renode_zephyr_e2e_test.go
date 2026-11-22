package renode_zephyr_nrf52840_test

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
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Toob-Boot/Toob-Loader/toob-go-lib/tbm1"
	"github.com/Toob-Boot/Toob-Loader/toob-go-lib/tci1"
	"github.com/Toob-Boot/Toob-Loader/toob-go-lib/tdr1"
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
	uicrOffLock = 0x0CC // CUSTOMER[19]     : ~locked_pages in low 16 bits

	// Device identity matching test/renode_zephyr_nrf52840/device.toml
	testVendorID  = 0x1915
	testProductID = 0x5284
	testHWRev     = 1

	// RFC 8032 Test Vector 1 root signing key
	rootSeedHex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"

	// Enrollment & rotated bearer tokens (32 bytes = 64 lower-case hex chars)
	initialTokenHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	rotatedTokenHex = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

	// Provisioning protocol opcodes & high-Hamming status (boot_provisioning.c)
	bootStatusOK         = uint32(0x55AA55AA)
	provCmdBurnKey       = 0x01
	provCmdSetDSLC       = 0x02
	provCmdReadID        = 0x06
	provCmdLockBootFlash = 0x07
	provCmdReboot        = 0xFF
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
	if runtime.GOOS == "windows" {
		storageCand := `D:\ToobStorage\tools\renode-1.17.0\renode_1.17.0-portable\Renode.exe`
		if _, err := os.Stat(storageCand); err == nil {
			return storageCand
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
	replAbs, err := filepath.Abs("nrf52840_zephyr.repl")
	if err != nil {
		cancel()
		t.Fatalf("Abs(nrf52840_zephyr.repl): %v", err)
	}

	monPort := reserveFreeTCPPort(t)
	uartPort := reserveFreeTCPPort(t)

	rescContent := fmt.Sprintf(`include @%s
mach create "nrf52840_zephyr_e2e"
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

func (h *renodeHarness) sliceFrom(offset int) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	data := h.rxBuf.Bytes()
	if offset >= len(data) {
		return ""
	}
	return string(data[offset:])
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

func (h *renodeHarness) waitForLinePrefixSince(offset int, prefix string, timeout time.Duration) (string, int) {
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
					rawLine := string(bytes.TrimRight(data[lineStart:lineStart+nl], "\r\n"))
					endPos := lineStart + nl + 1
					h.mu.Unlock()
					return rawLine, endPos
				}
			}
		}
		h.mu.Unlock()

		rem := time.Until(deadline)
		if rem <= 0 {
			h.t.Fatalf("timeout (%v) waiting for line %q after offset %d.\nFull UART log:\n%s\nMonitor log:\n%s",
				timeout, prefix, offset, string(h.snapshot()), h.monitorSnapshot())
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
	// Pace writes into 16-byte slices so non-EasyDMA NRF52840_UART 6-byte hardware FIFO
	// + Zephyr IRQ ring-buffer drain never overrun under heavy emulation load.
	const sliceBytes = 16
	for pos := 0; pos < len(b); pos += sliceBytes {
		end := min(pos+sliceBytes, len(b))
		if _, err := h.uart.Write(b[pos:end]); err != nil {
			h.t.Fatalf("UART TCP write failed: %v", err)
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

type firmwareArtifacts struct {
	stage0Raw    []byte
	stage1Signed []byte
	recoveryBin  []byte
	zephyrV1     []byte
	zephyrV2     []byte
	zephyrBadV3  []byte
	signer       tbm1.Signer
	rootPubKey   []byte
}

func resolveArtifactDir(envKey, winStorageDefault, localDefault string) string {
	if v := os.Getenv(envKey); v != "" {
		return v
	}
	if runtime.GOOS == "windows" {
		if _, err := os.Stat(winStorageDefault); err == nil {
			return winStorageDefault
		}
	}
	return localDefault
}

func loadArtifacts(t *testing.T) firmwareArtifacts {
	t.Helper()
	bootDir := resolveArtifactDir(
		"TOOB_ZEPHYR_BOOT_DIR",
		`D:\ToobStorage\tmp_build\r1_zephyr\build_nrf52840`,
		"builds/build_nrf52840",
	)
	appsDir := resolveArtifactDir(
		"TOOB_ZEPHYR_APPS_DIR",
		`D:\ToobStorage\tmp_build\r1_zephyr\apps`,
		"builds/apps",
	)

	mustRead := func(base, name string) []byte {
		t.Helper()
		p, err := filepath.Abs(filepath.Join(base, name))
		if err != nil {
			t.Fatalf("Abs(%s/%s): %v", base, name, err)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("missing build artifact %s (run scripts/run_renode_zephyr_e2e.ps1 first): %v", p, err)
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
		stage0Raw:    mustRead(bootDir, "toob_stage0.bin"),
		stage1Signed: mustRead(bootDir, "toob_stage1.signed.bin"),
		recoveryBin:  mustRead(bootDir, "toob_recovery.bin"),
		zephyrV1:     mustRead(appsDir, "zephyr_v1.toob"),
		zephyrV2:     mustRead(appsDir, "zephyr_v2.toob"),
		zephyrBadV3:  mustRead(appsDir, "zephyr_bad_v3.toob"),
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
		BuildNumber:   uint32(major) * 100,
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

func encodeTCI1Manifest(
	t *testing.T,
	tokenKey [32]byte,
	deviceID [32]byte,
	seqEcho uint64,
	remoteSVN uint32,
	bundle []byte,
	blobPath string,
	rotatedToken []byte,
) []byte {
	t.Helper()
	sum := sha256.Sum256(bundle)
	var asgnID [16]byte
	asgnID[0] = 0xFE
	asgnID[1] = 0xED
	binary.LittleEndian.PutUint32(asgnID[12:16], remoteSVN)

	m := tci1.Manifest{
		TargetSlot:    tci1.SlotApp,
		SVN:           remoteSVN,
		RemoteBuild:   remoteSVN * 100,
		TotalSize:     uint32(len(bundle)),
		SHA256:        sum,
		AssignmentID:  asgnID,
		SeqEcho:       seqEcho,
		RetryAfterSec: 3600,
		BlobPath:      blobPath,
	}
	if len(rotatedToken) == 32 {
		m.HasRotatedToken = true
		copy(m.RotatedToken[:], rotatedToken)
	}
	wire, err := tci1.Encode(m, tokenKey, deviceID)
	if err != nil {
		t.Fatalf("tci1.Encode: %v", err)
	}
	return wire
}

type capturedHTTPRequest struct {
	method      string
	url         string
	rangeOffset uint32
	headers     []string
	body        []byte
}

func readUARTHTTPRequest(t *testing.T, h *renodeHarness, offset int, timeout time.Duration) (capturedHTTPRequest, int) {
	t.Helper()
	beginLine, nextOff := h.waitForLinePrefixSince(offset, "@@HTTP_BEGIN ", timeout)
	_, endOff := h.waitForLinePrefixSince(nextOff, "@@HTTP_END", timeout)

	block := h.sliceFrom(offset)[:endOff-offset]
	lines := strings.Split(strings.ReplaceAll(block, "\r\n", "\n"), "\n")

	var req capturedHTTPRequest
	for _, fld := range strings.Fields(strings.TrimPrefix(beginLine, "@@HTTP_BEGIN ")) {
		kv := strings.SplitN(fld, "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "method":
			req.method = kv[1]
		case "url":
			req.url = kv[1]
		case "range":
			v, _ := strconv.ParseUint(kv[1], 10, 32)
			req.rangeOffset = uint32(v)
		}
	}

	for _, ln := range lines {
		if strings.HasPrefix(ln, "@@HDR ") {
			req.headers = append(req.headers, strings.TrimPrefix(ln, "@@HDR "))
		} else if strings.HasPrefix(ln, "@@BODY_HEX ") {
			hexStr := strings.TrimSpace(strings.TrimPrefix(ln, "@@BODY_HEX "))
			raw, err := hex.DecodeString(hexStr)
			if err != nil {
				t.Fatalf("invalid @@BODY_HEX %q: %v", hexStr, err)
			}
			req.body = raw
		}
	}
	return req, endOff
}

func sendUARTHTTPResponse(t *testing.T, h *renodeHarness, status uint16, retryAfter uint32, body []byte, chunkSize int) int {
	t.Helper()
	off := h.markOffset()
	rspHdr := fmt.Sprintf("@@RSP %d %d %d\n", status, retryAfter, len(body))
	h.writeAll([]byte(rspHdr))

	if len(body) == 0 {
		return off
	}

	readyByte, off := h.readExactByteSince(off, 10*time.Second)
	if readyByte != 'R' {
		t.Fatalf("expected HTTP stream ready byte 'R', got 0x%02X (%q).\nUART log:\n%s",
			readyByte, string([]byte{readyByte}), string(h.snapshot()))
	}

	for pos := 0; pos < len(body); pos += chunkSize {
		end := min(pos+chunkSize, len(body))
		chunk := body[pos:end]

		var hdr [2]byte
		binary.LittleEndian.PutUint16(hdr[:], uint16(len(chunk)))
		pkt := make([]byte, 0, 2+len(chunk))
		pkt = append(pkt, hdr[:]...)
		pkt = append(pkt, chunk...)

		ackOff := h.markOffset()
		h.writeAll(pkt)
		ackByte, nextAckOff := h.readExactByteSince(ackOff, 10*time.Second)
		if ackByte != 'K' {
			t.Fatalf("expected HTTP chunk ACK 'K' at pos %d/%d, got 0x%02X (%q).\nUART log:\n%s",
				pos, len(body), ackByte, string([]byte{ackByte}), string(h.snapshot()))
		}
		off = nextAckOff
	}
	return off
}

func parseKVFields(line string) map[string]string {
	out := make(map[string]string)
	for _, tok := range strings.Fields(line) {
		if eq := strings.IndexByte(tok, '='); eq > 0 {
			out[tok[:eq]] = tok[eq+1:]
		}
	}
	return out
}

func assertHeaderContains(t *testing.T, headers []string, expected string) {
	t.Helper()
	for _, hdr := range headers {
		if hdr == expected {
			return
		}
	}
	t.Fatalf("HTTP headers %v missing %q", headers, expected)
}

func writeInitialFlash(t *testing.T, dir string, art firmwareArtifacts) string {
	t.Helper()
	flash := bytes.Repeat([]byte{0xFF}, flashSizeBytes)
	copy(flash[offStage0:], art.stage0Raw)
	copy(flash[offStage1A:], art.stage1Signed)
	copy(flash[offRecoveryOS:], art.recoveryBin)
	copy(flash[offAppSlot0:], art.zephyrV1)

	flashPath := filepath.Join(dir, "flash.bin")
	if err := os.WriteFile(flashPath, flash, 0o644); err != nil {
		t.Fatalf("write flash.bin: %v", err)
	}
	return flashPath
}

func newErasedUicr() []byte {
	return bytes.Repeat([]byte{0xFF}, uicrSizeBytes)
}

func TestRenodeZephyrNRF52840_FullLifecycle_Provision_NVS_OSClientOTA_WDTRollback(t *testing.T) {
	art := loadArtifacts(t)
	tmp := t.TempDir()
	flashPath := writeInitialFlash(t, tmp, art)

	// Seed primary Root Key 0 (CUSTOMER[0..7]), keeping CUSTOMER[16] = 0xFFFFFFFF (DSLC == 0x00 unprovisioned)
	uicr := newErasedUicr()
	copy(uicr[uicrOffKey0:], art.rootPubKey)

	uicrPath := filepath.Join(tmp, "uicr.bin")
	if err := os.WriteFile(uicrPath, uicr, 0o644); err != nil {
		t.Fatalf("write factory uicr.bin: %v", err)
	}

	h := startRenode(t, tmp, flashPath, uicrPath, 210*time.Second)
	defer h.stop()

	// =========================================================================
	// PHASE 1: Factory UART COBS Provisioning (FICR + UICR + BPROT) -> Real Zephyr v1.0.0
	// =========================================================================
	t.Log("Phase 1: Waiting for Stage 0 Ed25519 verify + Stage 1 COBS PROV banner...")
	off := h.waitForStringSince(0, "[S0] Signature verification PASSED!", 12*time.Second)
	provBanner := cobsEncode([]byte("PROV"))
	off = h.waitForSince(off, provBanner, 10*time.Second)

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

	// 5. PROV_CMD_REBOOT (0xFF) -> hardware WDT reset -> boots real Zephyr 4.0 Kernel v1.0.0 at 0x00038100!
	h.writeAll(buildProvFrame(provCmdReboot, nil))
	stFrame, off = h.readCOBSFrameSince(off, 8*time.Second)
	if len(stFrame) != 4 || binary.LittleEndian.Uint32(stFrame) != bootStatusOK {
		t.Fatalf("PROV_CMD_REBOOT status = %x, want %08x", stFrame, bootStatusOK)
	}

	bootV1Line, off := h.waitForLinePrefixSince(off, "[ZEPHYR] BOOT ver=1.0.0 ", 20*time.Second)
	bootV1 := parseKVFields(bootV1Line)
	if bootV1["vtor"] != "0x00038100" || bootV1["tent"] != "0" || bootV1["reset"] != "3" || bootV1["handoff"] != "OK" {
		t.Fatalf("unexpected Zephyr v1.0.0 boot fields: %s", bootV1Line)
	}
	t.Logf("Phase 1 PASS: Booted real multi-threaded Zephyr 4.0 Kernel: %s", bootV1Line)

	// =========================================================================
	// PHASE 2: Boot Diagnostics, Multi-Thread Mutex, BPROT Lock, & Flash NVS Persistence
	// =========================================================================
	t.Log("Phase 2: Verifying toob_get_boot_diag, worker thread mutex concurrency, BPROT, and NVS persistence...")

	h.writeAll([]byte("DIAG\n"))
	diagLine, off := h.waitForLinePrefixSince(off, "[ZEPHYR] DIAG ", 8*time.Second)
	diagKV := parseKVFields(diagLine)
	if diagKV["status"] != "OK" {
		t.Fatalf("DIAG failed: %s", diagLine)
	}
	wticks, _ := strconv.Atoi(diagKV["worker_ticks"])
	if wticks < 1 {
		t.Fatalf("expected preemptive worker thread ticks >= 1, got %d (%s)", wticks, diagLine)
	}
	deviceIDHex := diagKV["dev_id"]
	if len(deviceIDHex) != 64 {
		t.Fatalf("expected 64-hex DICE device_id, got %q", deviceIDHex)
	}

	// Verify Stage 0 hardware BPROT immutability from inside Zephyr
	h.writeAll([]byte("BPROT_CHECK\n"))
	bprotLine, off := h.waitForLinePrefixSince(off, "[ZEPHYR] BPROT_CHECK ", 8*time.Second)
	bprotKV := parseKVFields(bprotLine)
	if bprotKV["config0"] != "0x000000FF" || bprotKV["intact"] != "1" {
		t.Fatalf("BPROT Stage-0 protection check failed: %s", bprotLine)
	}

	// Unenrolled NVS must fail-closed with NOT_FOUND
	h.writeAll([]byte("CRED\n"))
	credEmptyLine, off := h.waitForLinePrefixSince(off, "[ZEPHYR] CRED ", 8*time.Second)
	if !strings.Contains(credEmptyLine, "status=NOT_FOUND") {
		t.Fatalf("expected CRED status=NOT_FOUND before enrollment, got: %s", credEmptyLine)
	}

	h.writeAll([]byte("OTA_CHECKIN\n"))
	unenrolledOTA, off := h.waitForLinePrefixSince(off, "[ZEPHYR] OTA_CHECKIN ", 8*time.Second)
	if !strings.Contains(unenrolledOTA, "result=0xE1101CAE") {
		t.Fatalf("expected unenrolled OTA_CHECKIN to fail-closed with TOOB_ERR_NOT_FOUND (0xE1101CAE), got: %s", unenrolledOTA)
	}

	// Enroll credential into real Zephyr Flash NVS (storage_partition @ 0x000F8000)
	h.writeAll([]byte("ENROLL " + initialTokenHex + "\n"))
	enrollLine, off := h.waitForLinePrefixSince(off, "[ZEPHYR] ENROLL ", 10*time.Second)
	enrollKV := parseKVFields(enrollLine)
	if enrollKV["status"] != "OK" || enrollKV["seq"] != "0" || enrollKV["token"] != initialTokenHex {
		t.Fatalf("NVS ENROLL failed: %s", enrollLine)
	}

	// Warm-reboot Zephyr (sys_reboot(SYS_REBOOT_WARM) -> Stage 0 -> Stage 1 -> Zephyr v1.0.0)
	// and verify Flash NVS credentials survive hardware reset!
	h.writeAll([]byte("REBOOT\n"))
	bootV1WarmLine, off := h.waitForLinePrefixSince(off, "[ZEPHYR] BOOT ver=1.0.0 ", 20*time.Second)
	bootV1Warm := parseKVFields(bootV1WarmLine)
	if bootV1Warm["reset"] != "5" || bootV1Warm["handoff"] != "OK" {
		t.Fatalf("expected warm reboot reset=5 (TOOB_RESET_SOFTWARE), got: %s", bootV1WarmLine)
	}

	h.writeAll([]byte("CRED\n"))
	credPersistedLine, off := h.waitForLinePrefixSince(off, "[ZEPHYR] CRED ", 8*time.Second)
	credPersistedKV := parseKVFields(credPersistedLine)
	if credPersistedKV["status"] != "OK" || credPersistedKV["seq"] != "0" || credPersistedKV["token"] != initialTokenHex {
		t.Fatalf("Flash NVS credential did not persist across hardware reset: %s", credPersistedLine)
	}
	t.Log("Phase 2 PASS: Verified boot_diag TDR1 wire, multi-thread K_MUTEX worker, BPROT Stage 0 lock, and Flash NVS persistence across warm reset!")

	// =========================================================================
	// PHASE 3: Full TBM1 OTA (v1.0.0 -> v2.0.0) via sdk/os_client + Token Rotation + Confirm
	// =========================================================================
	t.Log("Phase 3: Triggering sdk/os_client toob_network_trigger_ota() for v1.0.0 -> v2.0.0...")
	bundleV2 := buildFullTrailerBundle(t, art.signer, 1, art.zephyrV2, 2, 2)
	initialTokenBytes, err := hex.DecodeString(initialTokenHex)
	if err != nil {
		t.Fatalf("decode initialTokenHex: %v", err)
	}
	rotatedTokenBytes, err := hex.DecodeString(rotatedTokenHex)
	if err != nil {
		t.Fatalf("decode rotatedTokenHex: %v", err)
	}
	deviceIDBytes, err := hex.DecodeString(deviceIDHex)
	if err != nil || len(deviceIDBytes) != 32 {
		t.Fatalf("decode deviceIDHex: %v", err)
	}
	var initialTokKey, rotatedTokKey, deviceIDArr [32]byte
	copy(initialTokKey[:], initialTokenBytes)
	copy(rotatedTokKey[:], rotatedTokenBytes)
	copy(deviceIDArr[:], deviceIDBytes)

	manifestV2 := encodeTCI1Manifest(t, initialTokKey, deviceIDArr, 1, 2, bundleV2, "/v1/blobs/zephyr_v2.tbm1", rotatedTokenBytes)

	reqStartOff := h.markOffset()
	h.writeAll([]byte("OTA_CHECKIN\n"))

	// 3a. Handle POST /v1/devices/<device_id>/checkin
	postReq, reqNextOff := readUARTHTTPRequest(t, h, reqStartOff, 12*time.Second)
	expectedCheckinURL := "http://ota.toob.local/v1/devices/" + deviceIDHex + "/checkin"
	if postReq.method != "POST" || postReq.url != expectedCheckinURL {
		t.Fatalf("unexpected checkin request: method=%q url=%q (want POST %q)",
			postReq.method, postReq.url, expectedCheckinURL)
	}
	assertHeaderContains(t, postReq.headers, "Authorization: Bearer "+initialTokenHex)
	assertHeaderContains(t, postReq.headers, "Content-Type: application/octet-stream")
	assertHeaderContains(t, postReq.headers, "X-Toob-Seq: 1")
	rep1, err := tdr1.Parse(postReq.body)
	if err != nil {
		t.Fatalf("expected valid TDR1 boot_diag telemetry body, got err=%v (%x)", err, postReq.body)
	}
	if rep1.CheckinSeq != 1 {
		t.Fatalf("TDR1 CheckinSeq = %d, want 1", rep1.CheckinSeq)
	}
	_ = reqNextOff

	getWaitOff := sendUARTHTTPResponse(t, h, 200, 0, manifestV2, 256)

	// 3b. Handle GET /v1/blobs/zephyr_v2.tbm1 -> stream signed TBM1 bundle into PSA SHA-256 + NVMC Staging
	getReq, _ := readUARTHTTPRequest(t, h, getWaitOff, 12*time.Second)
	if getReq.method != "GET" || getReq.url != "http://ota.toob.local/v1/blobs/zephyr_v2.tbm1" || getReq.rangeOffset != 0 {
		t.Fatalf("unexpected blob GET request: %+v", getReq)
	}

	rebootWaitOff := sendUARTHTTPResponse(t, h, 200, 0, bundleV2, 256)

	// sdk/os_client finalizes PSA SHA-256 + writes Mailbox intent + calls sys_reboot(SYS_REBOOT_WARM)!
	// Stage 0 -> Stage 1 verifies Ed25519 KeyIndex=1, swaps Staging -> App Slot 0, and boots Zephyr v2.0.0 TENTATIVE!
	bootV2TentLine, off := h.waitForLinePrefixSince(rebootWaitOff, "[ZEPHYR] BOOT ver=2.0.0 ", 30*time.Second)
	bootV2Tent := parseKVFields(bootV2TentLine)
	if bootV2Tent["vtor"] != "0x00038100" || bootV2Tent["tent"] != "1" || bootV2Tent["svn"] != "2" || bootV2Tent["key"] != "1" || bootV2Tent["outcome"] != "1" {
		t.Fatalf("unexpected tentative Zephyr v2.0.0 boot fields: %s", bootV2TentLine)
	}
	t.Logf("Phase 3a PASS: Stage 1 swapped & booted Zephyr v2.0.0 (TENTATIVE): %s", bootV2TentLine)

	// 3c. Verify NVS credentials persisted across v1 -> v2 OTA swap WITH server-rotated token & seq=1!
	h.writeAll([]byte("CRED\n"))
	credV2Line, off := h.waitForLinePrefixSince(off, "[ZEPHYR] CRED ", 8*time.Second)
	credV2KV := parseKVFields(credV2Line)
	if credV2KV["status"] != "OK" || credV2KV["seq"] != "1" || credV2KV["token"] != rotatedTokenHex {
		t.Fatalf("expected rotated NVS credential (seq=1, token=%s) on v2.0.0, got: %s", rotatedTokenHex, credV2Line)
	}

	// 3d. Confirm Zephyr v2.0.0 via toob_confirm_boot() -> verify GPREGRET + retained confirm SRAM + Mailbox!
	h.writeAll([]byte("CONFIRM\n"))
	confirmLine, off := h.waitForLinePrefixSince(off, "[ZEPHYR] CONFIRM ", 10*time.Second)
	confirmKV := parseKVFields(confirmLine)
	if confirmKV["status"] != "OK" || confirmKV["gpreg"] == "0x00" || confirmKV["sram_match"] != "1" {
		t.Fatalf("toob_confirm_boot() failed hardware GPREGRET/SRAM confirmation: %s", confirmLine)
	}
	t.Logf("Phase 3b PASS: Confirmed Zephyr v2.0.0 (%s) & verified rotated NVS credential!", confirmLine)

	// Warm-reboot to prove Stage 1 consumes GPREGRET/confirm nonce + commits v2.0.0 (tent=0, gpreg=0x00)!
	h.writeAll([]byte("REBOOT\n"))
	bootV2CommLine, off := h.waitForLinePrefixSince(off, "[ZEPHYR] BOOT ver=2.0.0 ", 20*time.Second)
	bootV2Comm := parseKVFields(bootV2CommLine)
	if bootV2Comm["tent"] != "0" || bootV2Comm["svn"] != "2" || bootV2Comm["gpreg"] != "0x00" {
		t.Fatalf("expected committed Zephyr v2.0.0 (tent=0, gpreg=0x00), got: %s", bootV2CommLine)
	}

	// 3e. Verify 204 No Content check-in uses rotated token & bumps X-Toob-Seq to 2!
	noopStartOff := h.markOffset()
	h.writeAll([]byte("OTA_CHECKIN\n"))
	postNoopReq, _ := readUARTHTTPRequest(t, h, noopStartOff, 10*time.Second)
	assertHeaderContains(t, postNoopReq.headers, "Authorization: Bearer "+rotatedTokenHex)
	assertHeaderContains(t, postNoopReq.headers, "X-Toob-Seq: 2")
	noopDoneOff := sendUARTHTTPResponse(t, h, 204, 0, nil, 256)
	noopResLine, off := h.waitForLinePrefixSince(noopDoneOff, "[ZEPHYR] OTA_CHECKIN ", 8*time.Second)
	if !strings.Contains(noopResLine, "result=0xE1101CAE") {
		t.Fatalf("expected 204 No Content to return TOOB_ERR_NOT_FOUND (0xE1101CAE), got: %s", noopResLine)
	}

	// =========================================================================
	// PHASE 4: Stage Unconfirmed bad_v3 (v3.0.0) -> Hardware NRF_WDT Bite -> Automatic Rollback to v2.0.0
	// =========================================================================
	t.Log("Phase 4: Staging unconfirmed Zephyr bad_v3 (v3.0.0) via sdk/os_client & verifying NRF_WDT rollback to v2.0.0...")
	bundleBadV3 := buildFullTrailerBundle(t, art.signer, 1, art.zephyrBadV3, 3, 3)
	manifestBadV3 := encodeTCI1Manifest(t, rotatedTokKey, deviceIDArr, 3, 3, bundleBadV3, "/v1/blobs/zephyr_bad_v3.tbm1", nil)

	v3ReqStartOff := h.markOffset()
	h.writeAll([]byte("OTA_CHECKIN\n"))
	postV3Req, _ := readUARTHTTPRequest(t, h, v3ReqStartOff, 10*time.Second)
	assertHeaderContains(t, postV3Req.headers, "Authorization: Bearer "+rotatedTokenHex)
	assertHeaderContains(t, postV3Req.headers, "X-Toob-Seq: 3")

	v3GetWaitOff := sendUARTHTTPResponse(t, h, 200, 0, manifestBadV3, 256)
	getV3Req, _ := readUARTHTTPRequest(t, h, v3GetWaitOff, 10*time.Second)
	if getV3Req.method != "GET" || getV3Req.url != "http://ota.toob.local/v1/blobs/zephyr_bad_v3.tbm1" {
		t.Fatalf("unexpected bad_v3 GET request: %+v", getV3Req)
	}
	v3BootWaitOff := sendUARTHTTPResponse(t, h, 200, 0, bundleBadV3, 256)

	// Prove Zephyr bad_v3 (v3.0.0) actually boots in TENTATIVE mode and starves NRF_WDT
	badV3Line, off := h.waitForLinePrefixSince(v3BootWaitOff, "[ZEPHYR] BOOT ver=3.0.0 ", 30*time.Second)
	badV3KV := parseKVFields(badV3Line)
	if badV3KV["tent"] != "1" || badV3KV["svn"] != "3" || badV3KV["mode"] != "UNCONFIRMED_WDT_STARVE" {
		t.Fatalf("unexpected bad_v3 boot banner: %s", badV3Line)
	}
	t.Logf("Observed tentative Zephyr bad_v3 boot (starving NRF_WDT): %s", badV3Line)

	// Wait across NRF_WDT timeouts (max_retries=2 -> 3 tentative attempts x ~2s WDT + Stage 1 swap back)
	rbV2Line, off := h.waitForLinePrefixSince(off, "[ZEPHYR] BOOT ver=2.0.0 ", 45*time.Second)
	rbV2KV := parseKVFields(rbV2Line)
	if rbV2KV["vtor"] != "0x00038100" || rbV2KV["tent"] != "0" || rbV2KV["reset"] != "3" || rbV2KV["svn"] != "3" || rbV2KV["handoff"] != "OK" {
		t.Fatalf("expected rolled-back Zephyr v2.0.0 (vtor=0x00038100, tent=0, reset=3 WDT, monotonic svn=3, handoff=OK), got: %s", rbV2Line)
	}
	t.Logf("Phase 4 PASS: Hardware NRF_WDT triggered automatic Stage 1 rollback to Zephyr v2.0.0: %s", rbV2Line)

	// Verify NVS credentials in storage_partition survived the full swap + WDT rollback untouched!
	h.writeAll([]byte("CRED\n"))
	credAfterRBLine, off := h.waitForLinePrefixSince(off, "[ZEPHYR] CRED ", 8*time.Second)
	credAfterRBKV := parseKVFields(credAfterRBLine)
	if credAfterRBKV["status"] != "OK" || credAfterRBKV["seq"] != "3" || credAfterRBKV["token"] != rotatedTokenHex {
		t.Fatalf("Flash NVS credential corrupted across WDT rollback: %s", credAfterRBLine)
	}

	// Verify UICR OTP state and BPROT blocked operations counter via Renode Monitor
	uicrAfterPath := filepath.Join(tmp, "uicr_after.bin")
	monOut := h.saveUicrAndQueryBlocked(uicrAfterPath)
	uicrAfter, err := os.ReadFile(uicrAfterPath)
	if err != nil {
		t.Fatalf("read saved uicr_after.bin: %v", err)
	}
	if !bytes.Equal(uicrAfter[uicrOffKey0:uicrOffKey0+32], art.rootPubKey) {
		t.Fatalf("UICR Root Key 0 mismatch")
	}
	if !bytes.Equal(uicrAfter[uicrOffKey1:uicrOffKey1+32], art.rootPubKey) {
		t.Fatalf("UICR Rotation Key 1 was not burned into CUSTOMER[8..15]")
	}
	if gotDSLC := binary.LittleEndian.Uint32(uicrAfter[uicrOffDSLC : uicrOffDSLC+4]); gotDSLC != 0xFFFFFFFE {
		t.Fatalf("UICR CUSTOMER[16] DSLC = 0x%08X, want 0xFFFFFFFE", gotDSLC)
	}
	if gotLock := binary.LittleEndian.Uint32(uicrAfter[uicrOffLock : uicrOffLock+4]); gotLock != 0xFFFFFFF7 {
		t.Fatalf("UICR CUSTOMER[19] lock word = 0x%08X, want 0xFFFFFFF7", gotLock)
	}
	if strings.Contains(monOut, "0x00000000") && !strings.Contains(monOut, "0x00000002") {
		t.Fatalf("expected powerBprot.BlockedOperations >= 2 from BPROT_CHECK, Monitor output:\n%s", monOut)
	}
	_ = off
}
