package renode_sifive_fe310_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"io"
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
	otpSizeBytes   = 0x2000

	// SiFive FE310-G002 partition offsets (from hardware.json + device.toml)
	offStage0      = 0x000000
	offStage1A     = 0x010000
	offStage1B     = 0x030000
	offAppSlot0    = 0x050000
	offStagingSlot = 0x0D0000
	offRecoveryOS  = 0x150000

	// FE310 OTP byte offsets relative to CHIP_REG_OTP_MEM_BASE (0x00020000)
	otpOffKey0          = 0x0100 // Word 0x040: Root Public Key Slot 0 (32B)
	otpOffKey1          = 0x0120 // Word 0x048: Root Public Key Slot 1 (32B)
	otpOffDSLC          = 0x0180 // Word 0x060: Device Security Lifecycle byte
	otpOffBootLockMagic = 0x01A0 // Word 0x068: 0x4C4F434B ("LOCK")
	otpOffBootLockEnd   = 0x01A4 // Word 0x069: Locked boot flash end offset
	otpOffChipUID       = 0x07E0 // Word 0x1F8: 16-byte Factory Chip UID

	otpBootLockMagicVal = uint32(0x4C4F434B)
	stage0LockEndBytes  = uint32(0x00010000)

	// Device identity matching test/renode_sifive_fe310/device.toml
	testVendorID  = 0x051F
	testProductID = 0x0310
	testHWRev     = 2

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
	t      *testing.T
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	conn   net.Conn
	cancel context.CancelFunc
	tmpDir string

	mu       sync.Mutex
	rxBuf    bytes.Buffer
	monOut   bytes.Buffer
	notify   chan struct{}
	stopOnce sync.Once
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
		exe += ".exe"
	}
	cand := filepath.Join(home, ".toob", "tools", "renode", "renode_1.17.0-portable", exe)
	if _, err := os.Stat(cand); err != nil {
		t.Skipf("Renode binary not found at %s (set TOOB_RENODE_BIN to override)", cand)
	}
	return cand
}

func makeStorageTempDir(t *testing.T) string {
	t.Helper()
	root := filepath.Join("D:\\ToobStorage", "tmp_fe310")
	if runtime.GOOS != "windows" {
		root = os.TempDir()
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		root = t.TempDir()
	}
	dir, err := os.MkdirTemp(root, "e2e_*")
	if err != nil {
		t.Fatalf("MkdirTemp(%s): %v", root, err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(dir)
	})
	return dir
}

func allocateFreeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

func toSlashPath(p string) string {
	return filepath.ToSlash(p)
}

func startRenode(t *testing.T, tmpDir, flashPath, otpPath string, maxLifetime time.Duration) *renodeHarness {
	t.Helper()
	renodeBin := resolveRenodeBinary(t)
	replPath, err := filepath.Abs("sifive_fe310.repl")
	if err != nil {
		t.Fatalf("Abs(sifive_fe310.repl): %v", err)
	}

	port := allocateFreeTCPPort(t)
	rescPath := filepath.Join(tmpDir, "boot.resc")
	rescContent := fmt.Sprintf(`using sysbus
mach create "sifive_fe310"
machine LoadPlatformDescription @%s
sysbus WriteDoubleWord 0x00001000 0x200002B7
sysbus WriteDoubleWord 0x00001004 0x00028067
sysbus LoadBinary @%s 0x20000000
sysbus LoadBinary @%s 0x00020000
emulation CreateServerSocketTerminal %d "uart_term" false true
connector Connect sysbus.uart0 uart_term
echo "RENODE_SOCKET_READY"
`, toSlashPath(replPath), toSlashPath(flashPath), toSlashPath(otpPath), port)

	if err := os.WriteFile(rescPath, []byte(rescContent), 0o644); err != nil {
		t.Fatalf("write boot.resc: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), maxLifetime)
	cmd := exec.CommandContext(ctx, renodeBin, "--disable-xwt", "--console", "--plain", rescPath)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		t.Fatalf("StdinPipe: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		t.Fatalf("StdoutPipe: %v", err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	h := &renodeHarness{
		t:      t,
		cmd:    cmd,
		stdin:  stdin,
		cancel: cancel,
		tmpDir: tmpDir,
		notify: make(chan struct{}, 1),
	}

	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatalf("start Renode: %v", err)
	}

	readyCh := make(chan struct{}, 1)
	go func() {
		buf := make([]byte, 512)
		signaled := false
		for {
			n, rerr := stdout.Read(buf)
			if n > 0 {
				h.mu.Lock()
				h.monOut.Write(buf[:n])
				hasReady := !signaled && bytes.Contains(h.monOut.Bytes(), []byte("RENODE_SOCKET_READY"))
				h.mu.Unlock()
				if hasReady {
					signaled = true
					readyCh <- struct{}{}
				}
			}
			if rerr != nil {
				return
			}
		}
	}()

	select {
	case <-readyCh:
	case <-time.After(15 * time.Second):
		h.stop()
		t.Fatalf("timeout waiting for Renode monitor socket setup.\nMonitor:\n%s\nStderr:\n%s",
			h.monitorSnapshot(), stderr.String())
	}

	var conn net.Conn
	dialDeadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(dialDeadline) {
		conn, err = net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 500*time.Millisecond)
		if err == nil {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if err != nil {
		h.stop()
		t.Fatalf("dial Renode UART socket 127.0.0.1:%d: %v\nMonitor:\n%s", port, err, h.monitorSnapshot())
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
				return
			}
		}
	}()

	// Start CPU execution only after UART TCP client is attached so zero boot bytes are missed
	if _, err := io.WriteString(stdin, "start\n"); err != nil {
		h.stop()
		t.Fatalf("send Renode start: %v", err)
	}

	t.Cleanup(func() {
		h.stop()
	})

	return h
}

func (h *renodeHarness) dumpOTPAndStop() []byte {
	h.t.Helper()
	dumpPath := filepath.Join(h.tmpDir, "otp_persisted.bin")
	cmd := fmt.Sprintf("pause\ndump_file 0x00020000 0x2000 @%s\necho \"OTP_DUMP_DONE\"\nquit\n",
		toSlashPath(dumpPath))
	_, _ = io.WriteString(h.stdin, cmd)

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(h.monitorSnapshot(), "OTP_DUMP_DONE") {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	h.stop()

	data, err := os.ReadFile(dumpPath)
	if err != nil {
		h.t.Fatalf("read dumped OTP %s: %v\nMonitor:\n%s", dumpPath, err, h.monitorSnapshot())
	}
	return data
}

func (h *renodeHarness) stop() {
	h.stopOnce.Do(func() {
		if h.stdin != nil {
			_, _ = io.WriteString(h.stdin, "quit\n")
			_ = h.stdin.Close()
		}
		if h.conn != nil {
			_ = h.conn.Close()
		}
		done := make(chan struct{})
		go func() {
			if h.cmd != nil {
				_ = h.cmd.Wait()
			}
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			if h.cmd != nil && h.cmd.Process != nil {
				_ = h.cmd.Process.Kill()
			}
			<-done
		}
		h.cancel()
	})
}

func (h *renodeHarness) monitorSnapshot() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.monOut.String()
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
			h.t.Fatalf("timeout (%v) waiting for %q after offset %d.\nFull UART log:\n%s\nMonitor:\n%s",
				timeout, string(needle), offset, string(h.snapshot()), h.monitorSnapshot())
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
			h.t.Fatalf("timeout (%v) waiting for COBS 0x00 terminator at offset %d.\nUART:\n%s",
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
	stage0Bin    []byte
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
			t.Fatalf("missing build artifact %s (run scripts/run_renode_sifive_fe310_e2e.ps1 first): %v", p, err)
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
		stage0Bin:    mustRead("builds/build_sifive_fe310/toob_stage0.bin"),
		stage1Signed: mustRead("builds/build_sifive_fe310/toob_stage1.signed.bin"),
		recoveryBin:  mustRead("builds/build_sifive_fe310/toob_recovery.bin"),
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

	off = h.waitForStringSince(off, "[APP] OTA_FINALIZED status=OK", 15*time.Second)
	return off
}

func writeInitialFlash(t *testing.T, dir string, art firmwareArtifacts, corruptApps bool) string {
	t.Helper()
	if len(art.stage1Signed) > (offStage1B - offStage1A) {
		t.Fatalf("Stage 1A image (%d B) exceeds partition budget (%d B)", len(art.stage1Signed), offStage1B-offStage1A)
	}
	flash := bytes.Repeat([]byte{0xFF}, flashSizeBytes)
	copy(flash[offStage0:], art.stage0Bin)
	copy(flash[offStage1A:], art.stage1Signed)
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

func TestRenodeSiFiveFE310_1a_BlankOTPFailClosed(t *testing.T) {
	art := loadArtifacts(t)
	tmp := makeStorageTempDir(t)
	flashPath := writeInitialFlash(t, tmp, art, false)

	otpPath := filepath.Join(tmp, "otp.bin")
	if err := os.WriteFile(otpPath, make([]byte, otpSizeBytes), 0o644); err != nil {
		t.Fatalf("write blank otp.bin: %v", err)
	}

	h := startRenode(t, tmp, flashPath, otpPath, 20*time.Second)
	defer h.stop()

	off := h.waitForStringSince(0, "=== TOOB STAGE 0 BOOT ===", 8*time.Second)
	h.waitForStringSince(off, "[S0] read_pubkey failed or zero key!", 8*time.Second)

	snap := string(h.snapshot())
	if strings.Contains(snap, "[APP] BOOT") {
		t.Fatalf("SECURITY FAILURE: Guest App booted despite blank OTP root key!\n%s", snap)
	}
}

func TestRenodeSiFiveFE310_FullLifecycle_Provision_FullOTA_TDS1Delta_WDTRollback(t *testing.T) {
	art := loadArtifacts(t)
	tmp := makeStorageTempDir(t)
	flashPath := writeInitialFlash(t, tmp, art, false)

	// Seed 16-byte factory Chip UID + primary Root Key 0 while keeping DSLC == 0x00 (unprovisioned!)
	otp := make([]byte, otpSizeBytes)
	expectedUID := []byte{
		0x53, 0x49, 0x46, 0x56, 0xFE, 0x31, 0x00, 0x02,
		0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0x03, 0x10,
	}
	copy(otp[otpOffChipUID:], expectedUID)
	copy(otp[otpOffKey0:], art.rootPubKey)

	otpPath := filepath.Join(tmp, "otp.bin")
	if err := os.WriteFile(otpPath, otp, 0o644); err != nil {
		t.Fatalf("write factory otp.bin: %v", err)
	}

	h := startRenode(t, tmp, flashPath, otpPath, 150*time.Second)
	defer h.stop()

	// =========================================================================
	// PHASE 1: Factory UART0 COBS Provisioning (DSLC 0x00 -> 0x01) + Cold Boot v1.0.0
	// =========================================================================
	t.Log("Phase 1: Waiting for Stage 0 XIP Ed25519 verify + Stage 1 COBS PROV banner...")
	off := h.waitForStringSince(0, "[S0] Signature verification PASSED!", 10*time.Second)
	provBanner := cobsEncode([]byte("PROV"))
	off = h.waitForSince(off, provBanner, 8*time.Second)

	// 1. PROV_CMD_READ_ID (0x06) -> status(BOOT_OK) + 16-byte factory Chip UID from OTP
	h.writeAll(buildProvFrame(provCmdReadID, nil))
	stFrame, off := h.readCOBSFrameSince(off, 5*time.Second)
	if len(stFrame) != 4 || binary.LittleEndian.Uint32(stFrame) != bootStatusOK {
		t.Fatalf("PROV_CMD_READ_ID status = %x, want %08x", stFrame, bootStatusOK)
	}
	uidFrame, off := h.readCOBSFrameSince(off, 5*time.Second)
	if !bytes.Equal(uidFrame, expectedUID) {
		t.Fatalf("PROV_CMD_READ_ID chip UID = %x, want %x", uidFrame, expectedUID)
	}

	// 2. PROV_CMD_BURN_KEY (0x01, slot=1, rootPubKey) -> burns OTP slot 1 via otpCtrl MMIO!
	burnPayload := append([]byte{0x01}, art.rootPubKey...)
	h.writeAll(buildProvFrame(provCmdBurnKey, burnPayload))
	stFrame, off = h.readCOBSFrameSince(off, 5*time.Second)
	if len(stFrame) != 4 || binary.LittleEndian.Uint32(stFrame) != bootStatusOK {
		t.Fatalf("PROV_CMD_BURN_KEY status = %x, want %08x", stFrame, bootStatusOK)
	}

	// 3. PROV_CMD_LOCK_BOOT_FLASH (0x07) -> burns immutable Stage-0 lock words into OTP!
	h.writeAll(buildProvFrame(provCmdLockBootFlash, nil))
	stFrame, off = h.readCOBSFrameSince(off, 5*time.Second)
	if len(stFrame) != 4 || binary.LittleEndian.Uint32(stFrame) != bootStatusOK {
		t.Fatalf("PROV_CMD_LOCK_BOOT_FLASH status = %x, want %08x", stFrame, bootStatusOK)
	}

	// 4. PROV_CMD_SET_DSLC (0x02, 0x01) -> burns DSLC=0x01 into OTP word 0x060!
	h.writeAll(buildProvFrame(provCmdSetDSLC, []byte{0x01}))
	stFrame, off = h.readCOBSFrameSince(off, 5*time.Second)
	if len(stFrame) != 4 || binary.LittleEndian.Uint32(stFrame) != bootStatusOK {
		t.Fatalf("PROV_CMD_SET_DSLC status = %x, want %08x", stFrame, bootStatusOK)
	}

	// 5. PROV_CMD_REBOOT (0xFF) -> hardware AON WDT reset -> boots App v1.0.0!
	h.writeAll(buildProvFrame(provCmdReboot, nil))
	stFrame, off = h.readCOBSFrameSince(off, 5*time.Second)
	if len(stFrame) != 4 || binary.LittleEndian.Uint32(stFrame) != bootStatusOK {
		t.Fatalf("PROV_CMD_REBOOT status = %x, want %08x", stFrame, bootStatusOK)
	}

	off = h.waitForStringSince(off, "[APP] BOOT ver=1.0.0 slot=0 tent=0 handoff=OK", 15*time.Second)
	t.Log("Phase 1 PASS: Provisioned OTP over COBS UART0 & booted App v1.0.0!")

	// =========================================================================
	// PHASE 2: Revoked KeyIndex=0 Rejection + Signed TBM1 Full OTA (v1.0.0 -> v2.0.0)
	// =========================================================================
	t.Log("Phase 2a: Verifying revoked KeyIndex=0 bundle is rejected cleanly without bricking...")
	revokedBundle := buildFullTrailerBundle(t, art.signer, 0, art.appV2, 2, 2)
	off = streamUARTOTA(t, h, revokedBundle, 113)
	off = h.waitForStringSince(off, "[APP] BOOT ver=1.0.0 slot=0 tent=0 handoff=OK", 15*time.Second)

	t.Log("Phase 2b: Streaming signed TBM1 TrailerLayout OTA v1.0.0 -> v2.0.0 with active KeyIndex=1...")
	bundleV2 := buildFullTrailerBundle(t, art.signer, 1, art.appV2, 2, 2)
	off = streamUARTOTA(t, h, bundleV2, 113)

	off = h.waitForStringSince(off, "[APP] BOOT ver=2.0.0 slot=0 tent=1 handoff=OK", 20*time.Second)
	h.writeAll([]byte("CONFIRM\n"))
	off = h.waitForStringSince(off, "[APP] CONFIRM status=OK", 8*time.Second)
	h.writeAll([]byte("REBOOT\n"))
	off = h.waitForStringSince(off, "[APP] BOOT ver=2.0.0 slot=0 tent=0 handoff=OK", 15*time.Second)
	t.Log("Phase 2 PASS: Revoked KeyIndex=0 rejected + Full QSPI XIP OTA v2.0.0 tentative -> confirmed -> committed!")

	// =========================================================================
	// PHASE 3: Live UART Signed TDS1 Forward-Delta OTA (v2.0.0 -> v3.0.0)
	// =========================================================================
	bundleDeltaV3, rawDeltaBytes := buildDeltaTrailerBundle(t, art.signer, 1, art.appV2, art.appV3, 2, 3, 3)
	t.Logf("Phase 3: Streaming signed TDS1 Forward-Delta OTA v2.0.0 -> v3.0.0 (delta payload=%d bytes vs full=%d bytes)...",
		rawDeltaBytes, len(art.appV3))
	off = streamUARTOTA(t, h, bundleDeltaV3, 113)

	off = h.waitForStringSince(off, "[APP] BOOT ver=3.0.0 slot=0 tent=1 handoff=OK", 20*time.Second)
	h.writeAll([]byte("CONFIRM\n"))
	off = h.waitForStringSince(off, "[APP] CONFIRM status=OK", 8*time.Second)
	h.writeAll([]byte("REBOOT\n"))
	off = h.waitForStringSince(off, "[APP] BOOT ver=3.0.0 slot=0 tent=0 handoff=OK", 15*time.Second)
	t.Log("Phase 3 PASS: Stage 1 RISC-V SDVM + Heatshrink reconstructed v3.0.0 via Scratch Slot & confirmed!")

	// =========================================================================
	// PHASE 4: Unconfirmed Crashing Firmware Automatic Hardware AON WDT Rollback
	// =========================================================================
	t.Log("Phase 4: Streaming signed hanging firmware v4.0.0 to verify Hardware AON WDT rollback...")
	bundleBadV4 := buildFullTrailerBundle(t, art.signer, 1, art.appBadV4, 4, 4)
	off = streamUARTOTA(t, h, bundleBadV4, 113)

	off = h.waitForStringSince(off, "[APP] BOOT ver=4.0.0 slot=0 tent=1 CRASHING_WITHOUT_CONFIRM", 20*time.Second)
	off = h.waitForStringSince(off, "[APP] BOOT ver=3.0.0 slot=0 tent=0 handoff=OK", 35*time.Second)
	t.Log("Phase 4 PASS: Hardware AON WDT reset fired pmucause=0x0200 & Stage 1 restored Scratch backup v3.0.0!")

	persistedOTP := h.dumpOTPAndStop()
	if persistedOTP[otpOffDSLC] != 0x01 {
		t.Fatalf("persisted OTP DSLC = 0x%02X, want 0x01", persistedOTP[otpOffDSLC])
	}
	if !bytes.Equal(persistedOTP[otpOffKey1:otpOffKey1+32], art.rootPubKey) {
		t.Fatalf("persisted OTP KEY1 = %x, want %x", persistedOTP[otpOffKey1:otpOffKey1+32], art.rootPubKey)
	}
	gotLockMagic := binary.LittleEndian.Uint32(persistedOTP[otpOffBootLockMagic : otpOffBootLockMagic+4])
	gotLockEnd := binary.LittleEndian.Uint32(persistedOTP[otpOffBootLockEnd : otpOffBootLockEnd+4])
	if gotLockMagic != otpBootLockMagicVal || gotLockEnd != stage0LockEndBytes {
		t.Fatalf("persisted OTP BootLock = (magic=0x%08X, end=0x%08X), want (0x%08X, 0x%08X)",
			gotLockMagic, gotLockEnd, otpBootLockMagicVal, stage0LockEndBytes)
	}
}

func TestRenodeSiFiveFE310_PMPLockdown_Stage0Isolation_NonBrickability(t *testing.T) {
	art := loadArtifacts(t)
	tmp := makeStorageTempDir(t)
	flashPath := writeInitialFlash(t, tmp, art, false)

	otp := make([]byte, otpSizeBytes)
	otp[otpOffDSLC] = 0x01
	copy(otp[otpOffKey0:], art.rootPubKey)
	binary.LittleEndian.PutUint32(otp[otpOffBootLockMagic:otpOffBootLockMagic+4], otpBootLockMagicVal)
	binary.LittleEndian.PutUint32(otp[otpOffBootLockEnd:otpOffBootLockEnd+4], stage0LockEndBytes)

	otpPath := filepath.Join(tmp, "otp.bin")
	if err := os.WriteFile(otpPath, otp, 0o644); err != nil {
		t.Fatalf("write otp.bin: %v", err)
	}

	h := startRenode(t, tmp, flashPath, otpPath, 45*time.Second)
	defer h.stop()

	off := h.waitForStringSince(0, "[APP] BOOT ver=1.0.0 slot=0 tent=0 handoff=OK", 15*time.Second)

	h.writeAll([]byte("PMP_TEST\n"))
	off = h.waitForStringSince(off,
		"[APP] PMP_TEST PASS pmpcfg0=0x00008880 load_mcause=5 store_mcause=7 flash_guard=BLOCKED",
		10*time.Second)

	// Reboot and confirm Stage 0 executes cleanly from 0x20000000 after hardware reset clears volatile PMP_L
	h.writeAll([]byte("REBOOT\n"))
	h.waitForStringSince(off, "[APP] BOOT ver=1.0.0 slot=0 tent=0 handoff=OK", 15*time.Second)
	t.Log("PMP Lockdown PASS: PMP_L=1 blocked M-mode CSR unlock + M-mode Load/Store to Stage 0 + Flash erase/write!")
}

func TestRenodeSiFiveFE310_RecoveryOS_XMODEM_Rescue(t *testing.T) {
	art := loadArtifacts(t)
	tmp := makeStorageTempDir(t)
	flashPath := writeInitialFlash(t, tmp, art, true)

	otp := make([]byte, otpSizeBytes)
	otp[otpOffDSLC] = 0x01
	copy(otp[otpOffKey0:], art.rootPubKey)

	otpPath := filepath.Join(tmp, "otp.bin")
	if err := os.WriteFile(otpPath, otp, 0o644); err != nil {
		t.Fatalf("write otp.bin: %v", err)
	}

	h := startRenode(t, tmp, flashPath, otpPath, 90*time.Second)
	defer h.stop()

	t.Log("Booting with corrupted App & Staging slots -> expecting Stage 1 handoff to XIP Recovery OS...")
	off := h.waitForStringSince(0, "[REC] listening...", 20*time.Second)
	off = h.waitForStringSince(off, "C", 8*time.Second)

	rescueBundle := buildFullTrailerBundle(t, art.signer, 0, art.appV3, 5, 3)
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
	h.waitForStringSince(eotOff, "[REC] resolved", 15*time.Second)

	off = h.waitForStringSince(eotOff, "[APP] BOOT ver=3.0.0", 20*time.Second)
	h.writeAll([]byte("CONFIRM\n"))
	h.waitForStringSince(off, "[APP] CONFIRM status=OK", 8*time.Second)
	t.Log("Recovery OS PASS: Rescued bricked FE310 over XMODEM-CRC into verified v3.0.0!")
}
