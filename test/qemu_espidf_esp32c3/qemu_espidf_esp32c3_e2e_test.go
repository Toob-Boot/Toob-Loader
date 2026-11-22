package qemu_espidf_esp32c3_test

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
	flashSizeBytes = 4 * 1024 * 1024
	efuseSizeBytes = 2048

	// Partition offsets matching test/qemu_espidf_esp32c3/device.toml & partitions.csv
	offStage0      = 0x000000
	offStage1A     = 0x008000
	offStage1B     = 0x028000
	offPartTable   = 0x048000
	offAppSlot0    = 0x050000
	offStagingSlot = 0x110000
	offRecoveryOS  = 0x1D0000

	// ESP32-C3 eFuse shadow offsets relative to EFUSE_RD_WR_DIS_REG (+0x02C)
	efuseOffMAC  = 0x18 // Block 1: EFUSE_RD_MAC_SPI_SYS_0
	efuseOffUser = 0x50 // Block 3: EFUSE_RD_USR_DATA0, byte 0 = DSLC
	efuseOffKey0 = 0x70 // Block 4: EFUSE_RD_KEY0_DATA0
	efuseOffKey1 = 0x90 // Block 5: EFUSE_RD_KEY1_DATA0

	// Device identity matching test/qemu_espidf_esp32c3/device.toml
	testVendorID  = 0x0001
	testProductID = 0x0044
	testHWRev     = 1

	// RFC 8032 Test Vector 1 root signing seed (matches `toob sign stage1 --mock`)
	rootSeedHex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"

	// Provisioning protocol constants
	bootStatusOK   = uint32(0x55AA55AA)
	provCmdBurnKey = 0x01
	provCmdSetDSLC = 0x02
	provCmdReadID  = 0x06
	provCmdReboot  = 0xFF
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

func resolveBuildRoot() string {
	if env := os.Getenv("TOOB_ESPIDF_BUILD_ROOT"); env != "" {
		return env
	}
	return `D:\ToobStorage\tmp_build\r2_espidf`
}

func resolveQEMUBinary(t *testing.T) string {
	t.Helper()
	if env := os.Getenv("TOOB_QEMU_RISCV32"); env != "" {
		if _, err := os.Stat(env); err == nil {
			return env
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("UserHomeDir: %v", err)
	}
	exe := "qemu-system-riscv32"
	if runtime.GOOS == "windows" {
		exe += ".exe"
	}
	cand := filepath.Join(home, ".toob", "tools", "qemu-esp", "qemu", "bin", exe)
	if _, err := os.Stat(cand); err != nil {
		t.Skipf("QEMU binary not found at %s (set TOOB_QEMU_RISCV32 to override)", cand)
	}
	return cand
}

func makeRunDir(t *testing.T) string {
	t.Helper()
	base := filepath.Join(resolveBuildRoot(), "qemu_runs")
	if err := os.MkdirAll(base, 0o755); err != nil {
		return t.TempDir()
	}
	dir, err := os.MkdirTemp(base, "run-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(dir)
	})
	return dir
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
		"-machine", "esp32c3",
		"-accel", "tcg,tb-size=32",
		"-nographic",
		"-serial", fmt.Sprintf("tcp:127.0.0.1:%d", port),
		"-monitor", "none",
		"-drive", fmt.Sprintf("file=%s,if=mtd,format=raw", flashPath),
		"-drive", fmt.Sprintf("file=%s,if=none,format=raw,id=efuse", efusePath),
		"-global", "driver=nvram.esp32c3.efuse,property=drive,value=efuse",
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
			h.t.Fatalf("timeout (%v) waiting for %q after offset %d.\nFull UART log:\n%s",
				timeout, string(needle), offset, string(h.snapshot()))
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

func (h *qemuHarness) readLineSince(offset int, timeout time.Duration) (string, int) {
	h.t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		h.mu.Lock()
		data := h.rxBuf.Bytes()
		if offset < len(data) {
			if nl := bytes.IndexByte(data[offset:], '\n'); nl >= 0 {
				raw := string(data[offset : offset+nl])
				nextOff := offset + nl + 1
				h.mu.Unlock()
				return strings.TrimRight(raw, "\r"), nextOff
			}
		}
		h.mu.Unlock()

		rem := time.Until(deadline)
		if rem <= 0 {
			h.t.Fatalf("timeout (%v) reading line after offset %d.\nFull UART log:\n%s",
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

type firmwareArtifacts struct {
	stage0ESP    []byte
	stage1Signed []byte
	recoveryBin  []byte
	partTableBin []byte
	appV1        []byte
	appV2        []byte
	appBadV3     []byte
	signer       tbm1.Signer
	rootPubKey   []byte
}

func loadArtifacts(t *testing.T) firmwareArtifacts {
	t.Helper()
	root := resolveBuildRoot()
	mustRead := func(rel string) []byte {
		t.Helper()
		p := filepath.Join(root, rel)
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("missing build artifact %s (run scripts/run_qemu_espidf_e2e.ps1 first): %v", p, err)
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
		stage0ESP:    mustRead(filepath.Join("boot_build", "toob_stage0.esp.bin")),
		stage1Signed: mustRead(filepath.Join("boot_build", "toob_stage1.signed.bin")),
		recoveryBin:  mustRead(filepath.Join("boot_build", "toob_recovery.bin")),
		partTableBin: mustRead(filepath.Join("apps", "partition-table.bin")),
		appV1:        mustRead(filepath.Join("apps", "app_v1.toob")),
		appV2:        mustRead(filepath.Join("apps", "app_v2.toob")),
		appBadV3:     mustRead(filepath.Join("apps", "app_bad_v3.toob")),
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

func encodeCheckinManifestTCI1(
	t *testing.T,
	tokenKey [32]byte,
	deviceID [32]byte,
	seqEcho uint64,
	remoteSVN, remoteBuild, totalSize uint32,
	sha256Sum [32]byte,
	blobPath string,
	rotatedToken []byte,
) []byte {
	t.Helper()
	var asgnID [16]byte
	asgnID[0] = 0xCA
	asgnID[1] = 0xFE
	binary.LittleEndian.PutUint32(asgnID[12:16], remoteSVN)

	m := tci1.Manifest{
		TargetSlot:    tci1.SlotApp,
		SVN:           remoteSVN,
		RemoteBuild:   remoteBuild,
		TotalSize:     totalSize,
		SHA256:        sha256Sum,
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

type tunneledHTTPRequest struct {
	method      string
	url         string
	rangeOffset uint32
	headers     []string
	body        []byte
}

func readTunneledHTTPRequest(t *testing.T, h *qemuHarness, offset int, timeout time.Duration) (tunneledHTTPRequest, int) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var req tunneledHTTPRequest
	inReq := false

	for {
		rem := time.Until(deadline)
		if rem <= 0 {
			t.Fatalf("timeout waiting for tunneled HTTP request.\nFull UART log:\n%s", string(h.snapshot()))
		}
		line, next := h.readLineSince(offset, rem)
		offset = next

		if !inReq {
			idx := strings.Index(line, "@@HTREQ ")
			if idx < 0 {
				continue
			}
			fields := strings.Fields(line[idx+len("@@HTREQ "):])
			if len(fields) < 5 {
				t.Fatalf("malformed @@HTREQ line: %q", line)
			}
			rng, err := strconv.ParseUint(fields[2], 10, 32)
			if err != nil {
				t.Fatalf("parse range_offset in %q: %v", line, err)
			}
			req.method = fields[0]
			req.url = fields[1]
			req.rangeOffset = uint32(rng)
			inReq = true
			continue
		}

		if line == "@@HTEND" {
			return req, offset
		}
		if strings.HasPrefix(line, "@@HTHDR ") {
			req.headers = append(req.headers, strings.TrimPrefix(line, "@@HTHDR "))
			continue
		}
		if strings.HasPrefix(line, "@@HTBODY ") {
			b, err := hex.DecodeString(strings.TrimPrefix(line, "@@HTBODY "))
			if err != nil {
				t.Fatalf("decode @@HTBODY hex: %v", err)
			}
			req.body = append(req.body, b...)
		}
	}
}

func sendTunneledHTTPResponse(t *testing.T, h *qemuHarness, offset int, statusCode uint16, body []byte, chunkSize int) int {
	t.Helper()
	respHdr := fmt.Sprintf("@@HTRESP %d 0\r\n", statusCode)
	h.writeAll([]byte(respHdr))

	waitNextOrAbort := func(cur int) int {
		deadline := time.Now().Add(15 * time.Second)
		for {
			rem := time.Until(deadline)
			if rem <= 0 {
				t.Fatalf("timeout waiting for @@HTNEXT.\nUART log:\n%s", string(h.snapshot()))
			}
			line, next := h.readLineSince(cur, rem)
			cur = next
			if strings.Contains(line, "@@HTABORT") {
				t.Fatalf("guest aborted HTTP stream early!\nUART log:\n%s", string(h.snapshot()))
			}
			if strings.Contains(line, "@@HTNEXT") {
				return cur
			}
		}
	}

	for pos := 0; pos < len(body); pos += chunkSize {
		offset = waitNextOrAbort(offset)
		end := min(pos+chunkSize, len(body))
		dataLine := fmt.Sprintf("@@HTDATA %s\r\n", hex.EncodeToString(body[pos:end]))
		h.writeAll([]byte(dataLine))
	}

	offset = waitNextOrAbort(offset)
	h.writeAll([]byte("@@HTDONE\r\n"))
	return offset
}

func serveOSClientOTA(
	t *testing.T,
	h *qemuHarness,
	offset int,
	expectedToken []byte,
	expectedSeq uint64,
	remoteSVN uint32,
	blobPath string,
	bundle []byte,
	rotatedToken []byte,
) int {
	t.Helper()

	h.writeAll([]byte("OTA http://ota.toob.local\n"))
	offset = h.waitForStringSince(offset, "[ESPIDF-APP] OTA_START url=http://ota.toob.local", 5*time.Second)

	// 1. Expect POST /v1/devices/<64-hex-dice-id>/checkin with TDR1 boot diag & Bearer auth
	postReq, offset := readTunneledHTTPRequest(t, h, offset, 10*time.Second)
	if postReq.method != "POST" {
		t.Fatalf("expected checkin POST, got %s (%s)", postReq.method, postReq.url)
	}
	if !strings.HasPrefix(postReq.url, "http://ota.toob.local/v1/devices/") || !strings.HasSuffix(postReq.url, "/checkin") {
		t.Fatalf("unexpected checkin URL: %q", postReq.url)
	}
	devHex := strings.TrimSuffix(strings.TrimPrefix(postReq.url, "http://ota.toob.local/v1/devices/"), "/checkin")
	if len(devHex) != 64 {
		t.Fatalf("expected 64-hex DICE device_id in checkin URL, got %q (len %d)", devHex, len(devHex))
	}

	wantAuth := "Authorization: Bearer " + hex.EncodeToString(expectedToken)
	wantSeq := fmt.Sprintf("X-Toob-Seq: %d", expectedSeq)
	hasAuth, hasSeq, hasOctetType := false, false, false
	for _, hdr := range postReq.headers {
		switch hdr {
		case wantAuth:
			hasAuth = true
		case wantSeq:
			hasSeq = true
		case "Content-Type: application/octet-stream":
			hasOctetType = true
		}
	}
	if !hasAuth || !hasSeq || !hasOctetType {
		t.Fatalf("checkin headers mismatch: got=%v, wantAuth=%q, wantSeq=%q",
			postReq.headers, wantAuth, wantSeq)
	}
	rep, err := tdr1.Parse(postReq.body)
	if err != nil {
		t.Fatalf("expected valid TDR1 telemetry body from toob_get_boot_diag_wire, got err=%v (%x)", err, postReq.body)
	}
	if rep.CheckinSeq != expectedSeq {
		t.Fatalf("TDR1 CheckinSeq = %d, want %d", rep.CheckinSeq, expectedSeq)
	}

	rawDevID, err := hex.DecodeString(devHex)
	if err != nil || len(rawDevID) != 32 {
		t.Fatalf("decode devHex %q: %v", devHex, err)
	}
	var devID [32]byte
	var tokKey [32]byte
	copy(devID[:], rawDevID)
	copy(tokKey[:], expectedToken)

	// Keep each @@HTDATA frame <= 115 wire bytes (< 128B ESP32-C3 UART0 RX FIFO)
	// so QEMU TCP bursts can never overflow the hardware FIFO under host CPU load.
	sum := sha256.Sum256(bundle)
	manifestTCI1 := encodeCheckinManifestTCI1(t, tokKey, devID, expectedSeq, remoteSVN, remoteSVN*100, uint32(len(bundle)), sum, blobPath, rotatedToken)
	offset = sendTunneledHTTPResponse(t, h, offset, 200, manifestTCI1, 52)

	// 2. Expect GET http://ota.toob.local<blobPath> and stream signed TBM1 bundle in 52B chunks
	getReq, offset := readTunneledHTTPRequest(t, h, offset, 10*time.Second)
	if getReq.method != "GET" || getReq.url != "http://ota.toob.local"+blobPath {
		t.Fatalf("unexpected blob GET request: %s %s", getReq.method, getReq.url)
	}
	offset = sendTunneledHTTPResponse(t, h, offset, 200, bundle, 52)
	return offset
}

func writeInitialFlash(t *testing.T, dir string, art firmwareArtifacts) string {
	t.Helper()
	flash := bytes.Repeat([]byte{0xFF}, flashSizeBytes)
	copy(flash[offStage0:], art.stage0ESP)
	copy(flash[offStage1A:], art.stage1Signed)
	copy(flash[offStage1B:], art.stage1Signed)
	copy(flash[offPartTable:], art.partTableBin)
	copy(flash[offAppSlot0:], art.appV1)
	copy(flash[offRecoveryOS:], art.recoveryBin)

	flashPath := filepath.Join(dir, "flash.bin")
	if err := os.WriteFile(flashPath, flash, 0o644); err != nil {
		t.Fatalf("write flash.bin: %v", err)
	}
	return flashPath
}

func TestQEMUESPIDF_ESP32C3_FullLifecycle_DirectXIP_NVS_OSClientOTA_WDTRollback(t *testing.T) {
	art := loadArtifacts(t)
	runDir := makeRunDir(t)
	flashPath := writeInitialFlash(t, runDir, art)

	// Factory eFuse: MAC (Block 1) + primary Root Key 0 (Block 4), DSLC == 0x00 (unprovisioned)
	efuse := make([]byte, efuseSizeBytes)
	expectedMAC := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x61}
	copy(efuse[efuseOffMAC:], expectedMAC)
	copy(efuse[efuseOffKey0:], art.rootPubKey)

	efusePath := filepath.Join(runDir, "efuse.bin")
	if err := os.WriteFile(efusePath, efuse, 0o644); err != nil {
		t.Fatalf("write efuse.bin: %v", err)
	}

	h := startQEMU(t, flashPath, efusePath, 180*time.Second)
	defer h.stop()

	// =========================================================================
	// PHASE 1: COBS Provisioning + Stage 0 -> Stage 1 (MMU Remap) -> ESP-IDF v6.1 app_main() v1.0.0
	// =========================================================================
	t.Log("Phase 1: Factory COBS provisioning + Direct-XIP boot into ESP-IDF v6.1 FreeRTOS app_main() (v1.0.0)...")
	off := h.waitForStringSince(0, "[S0] Signature verification PASSED!", 8*time.Second)
	off = h.waitForSince(off, cobsEncode([]byte("PROV")), 8*time.Second)

	h.writeAll(buildProvFrame(provCmdReadID, nil))
	stFrame, off := h.readCOBSFrameSince(off, 5*time.Second)
	if len(stFrame) != 4 || binary.LittleEndian.Uint32(stFrame) != bootStatusOK {
		t.Fatalf("PROV_CMD_READ_ID status = %x, want %08x", stFrame, bootStatusOK)
	}
	uidFrame, off := h.readCOBSFrameSince(off, 5*time.Second)
	if !bytes.Equal(uidFrame, expectedMAC) {
		t.Fatalf("PROV_CMD_READ_ID MAC = %x, want %x", uidFrame, expectedMAC)
	}

	burnPayload := append([]byte{0x01}, art.rootPubKey...)
	h.writeAll(buildProvFrame(provCmdBurnKey, burnPayload))
	stFrame, off = h.readCOBSFrameSince(off, 5*time.Second)
	if len(stFrame) != 4 || binary.LittleEndian.Uint32(stFrame) != bootStatusOK {
		t.Fatalf("PROV_CMD_BURN_KEY status = %x", stFrame)
	}

	h.writeAll(buildProvFrame(provCmdSetDSLC, []byte{0x01}))
	stFrame, off = h.readCOBSFrameSince(off, 5*time.Second)
	if len(stFrame) != 4 || binary.LittleEndian.Uint32(stFrame) != bootStatusOK {
		t.Fatalf("PROV_CMD_SET_DSLC status = %x", stFrame)
	}

	h.writeAll(buildProvFrame(provCmdReboot, nil))
	stFrame, off = h.readCOBSFrameSince(off, 5*time.Second)
	if len(stFrame) != 4 || binary.LittleEndian.Uint32(stFrame) != bootStatusOK {
		t.Fatalf("PROV_CMD_REBOOT status = %x", stFrame)
	}

	off = h.waitForStringSince(off, "[ESPIDF-APP] BOOT ver=1.0.0 slot=0 part=0xA fail_cnt=1 svn=0 outcome=0", 15*time.Second)
	off = h.waitForStringSince(off, "tasks_ok=1", 3*time.Second)
	t.Log("Phase 1 PASS: Stage 0 -> Stage 1 (MMU Remap) -> Real ESP-IDF v6.1 FreeRTOS app_main() v1.0.0 booted with tasks_ok=1!")

	// =========================================================================
	// PHASE 2: Boot Diag + Real nvs_flash ("toob_sys") Enrollment + Confirm + sdk/os_client TBM1 OTA (v1 -> v2)
	// =========================================================================
	t.Log("Phase 2: Verifying toob_get_boot_diag(), nvs_flash ('toob_sys') credential persistence, toob_confirm_boot(), and sdk/os_client OTA v1 -> v2...")

	h.writeAll([]byte("DIAG\n"))
	off = h.waitForStringSince(off, "[ESPIDF-APP] DIAG status=OK svn=0 outcome=0 edge=1 key=0 wire_len=", 5*time.Second)

	initialToken := bytes.Repeat([]byte{0xA1, 0xB2, 0xC3, 0xD4}, 8) // 32 bytes
	rotatedToken := bytes.Repeat([]byte{0x5E, 0x6F, 0x70, 0x81}, 8) // 32 bytes

	h.writeAll([]byte("ENROLL " + hex.EncodeToString(initialToken) + "\n"))
	off = h.waitForStringSince(off, "[ESPIDF-APP] ENROLL status=OK seq=0 token_prefix=a1b2c3d4", 5*time.Second)

	// Factory Slot 0 is already TOOB_STATE_COMMITTED (CRIT-25 zero-wear no-op: status=OK, rtc_match=0)
	h.writeAll([]byte("CONFIRM\n"))
	off = h.waitForStringSince(off, "[ESPIDF-APP] CONFIRM status=OK rtc_match=0", 5*time.Second)

	bundleV2 := buildFullTrailerBundle(t, art.signer, 1, art.appV2, 2, 2)
	off = serveOSClientOTA(t, h, off, initialToken, 1, 2, "/v1/blobs/app_v2.tbm1", bundleV2, rotatedToken)

	// =========================================================================
	// PHASE 3: Stage 1 Swaps MMU & Boots ESP-IDF v2.0.0 -> Confirm -> Read v1's NVS Credentials!
	// =========================================================================
	t.Log("Phase 3: Waiting for Stage 1 MMU swap into ESP-IDF v2.0.0, confirming boot, and reading v1's rotated NVS credentials...")
	off = h.waitForStringSince(off, "[ESPIDF-APP] BOOT ver=2.0.0 slot=1 part=0xA fail_cnt=0 svn=2 outcome=1", 20*time.Second)
	off = h.waitForStringSince(off, "tasks_ok=1", 3*time.Second)

	// Verify v2.0.0 reads back the rotated token + incremented checkin_seq=1 persisted in nvs_flash by v1.0.0!
	h.writeAll([]byte("CRED\n"))
	off = h.waitForStringSince(off, "[ESPIDF-APP] CRED status=OK seq=1 token_prefix=5e6f7081", 5*time.Second)

	// Tentative OTA Slot 1 writes boot_nonce to RTC 0x50001FC0 + Mailbox (status=OK, rtc_match=1)
	h.writeAll([]byte("CONFIRM\n"))
	off = h.waitForStringSince(off, "[ESPIDF-APP] CONFIRM status=OK rtc_match=1", 5*time.Second)

	h.writeAll([]byte("REBOOT\n"))
	off = h.waitForStringSince(off, "[ESPIDF-APP] BOOT ver=2.0.0 slot=1 part=0xA fail_cnt=0 svn=2", 15*time.Second)
	off = h.waitForStringSince(off, "tasks_ok=1", 3*time.Second)
	t.Log("Phase 3 PASS: ESP-IDF v2.0.0 booted in Slot 1, confirmed boot (RTC + Mailbox), and verified v1's NVS credentials across OTA & reboot!")

	// =========================================================================
	// PHASE 4: Stage bad_v3 -> Unconfirmed FreeRTOS Hang -> TIMG0 MWDT Reset -> Automatic Rollback to v2.0.0!
	// =========================================================================
	t.Log("Phase 4: Staging bad_v3 (skips toob_confirm_boot() & halts TIMG0 MWDT feed) via sdk/os_client...")
	bundleBadV3 := buildFullTrailerBundle(t, art.signer, 1, art.appBadV3, 3, 3)
	off = serveOSClientOTA(t, h, off, rotatedToken, 2, 3, "/v1/blobs/app_bad_v3.tbm1", bundleBadV3, nil)

	// Stage 1 swaps MMU to Slot 0 tentatively and boots bad_v3 (3.0.0)
	off = h.waitForStringSince(off, "[ESPIDF-APP] BOOT ver=3.0.0 slot=0 part=0xA fail_cnt=0 svn=3 outcome=1", 20*time.Second)
	off = h.waitForStringSince(off, "[ESPIDF-APP] SIMULATING_WDT_HANG", 5*time.Second)

	// Hardware TIMG0 MWDT resets the SoC (`TG0WDT_SYS_RST` -> immediate_crash_rst),
	// so Stage 1 immediately reverts MMU to confirmed ESP-IDF v2.0.0 in Slot 1 while
	// anti-rollback TMR keeps monotonic app_svn=3 and boot_diag records outcome=3 (reverted) & fail_cnt=1.
	off = h.waitForStringSince(off, "[ESPIDF-APP] BOOT ver=2.0.0 slot=1 part=0xA fail_cnt=1 svn=3 outcome=3", 45*time.Second)
	off = h.waitForStringSince(off, "tasks_ok=1", 3*time.Second)

	h.writeAll([]byte("DIAG\n"))
	off = h.waitForStringSince(off, "[ESPIDF-APP] DIAG status=OK svn=3 outcome=3", 5*time.Second)

	h.writeAll([]byte("CRED\n"))
	_ = h.waitForStringSince(off, "[ESPIDF-APP] CRED status=OK seq=2 token_prefix=5e6f7081", 5*time.Second)
	t.Log("Phase 4 PASS: Hardware TIMG0 MWDT triggered reset & Stage 1 rolled back automatically to confirmed ESP-IDF v2.0.0 (monotonic svn=3, Slot 1) with NVS seq=2 intact!")
}
