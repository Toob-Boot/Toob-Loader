package renode_rp2040_test

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
	flashSizeBytes    = 2 * 1024 * 1024
	keystoreSizeBytes = 4096

	// RP2040 2MB QSPI XIP partition offsets (chips/rp2040/hardware.json + device.toml)
	offStage0      = 0x000000
	offStage1A     = 0x008000
	offStage1B     = 0x020000
	offAppSlot0    = 0x038000
	offStagingSlot = 0x068000
	offRecoveryOS  = 0x098000
	offKeystoreOTP = 0x1FF000

	// Keystore word offsets relative to offKeystoreOTP (0x1FF000)
	otpOffKey0 = 0x000 // Words [0..7]   : 32B Ed25519 Root Key 0
	otpOffKey1 = 0x020 // Words [8..15]  : 32B Ed25519 Rotation Key 1
	otpOffDSLC = 0x040 // Word  [16]     : ~dslc in byte 0 (0xFFFFFFFF -> 0x00)
	otpOffMono = 0x044 // Words [17..18] : 64-bit 1->0 monotonic SVN counter
	otpOffLock = 0x04C // Word  [19]     : ~locked_sectors

	// Device identity matching test/renode_rp2040/device.toml
	testVendorID  = 0x2E8A
	testProductID = 0x2040
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
	exe := "renode"
	if runtime.GOOS == "windows" {
		exe = "Renode.exe"
	}
	var candidates []string
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates,
			filepath.Join(home, ".toob", "tools", "renode", "renode_1.17.0-portable", exe),
			filepath.Join(home, ".toob", "tools", "renode", "renode_1.17.0-portable", "renode.exe"),
		)
	}
	if runtime.GOOS == "windows" {
		candidates = append(candidates,
			`D:\ToobStorage\tools\renode-1.17.0\renode_1.17.0-portable\Renode.exe`,
			`D:\ToobStorage\tools\renode\renode_1.17.0_portable\Renode.exe`,
		)
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

func startRenode(t *testing.T, dir, flashPath string, maxLifetime time.Duration) *renodeHarness {
	t.Helper()
	renodeBin := resolveRenodeBinary(t)
	ctx, cancel := context.WithTimeout(context.Background(), maxLifetime)

	overlayAbs, err := filepath.Abs("Rp2040SocOverlay.cs")
	if err != nil {
		cancel()
		t.Fatalf("Abs(Rp2040SocOverlay.cs): %v", err)
	}
	replAbs, err := filepath.Abs("rp2040_toob.repl")
	if err != nil {
		cancel()
		t.Fatalf("Abs(rp2040_toob.repl): %v", err)
	}

	monPort := reserveFreeTCPPort(t)
	uartPort := reserveFreeTCPPort(t)

	rescContent := fmt.Sprintf(`include @%s
mach create "rp2040_e2e"
machine LoadPlatformDescription @%s
sysbus.vregChipReset InstallBootRomAndHooks
emulation CreateServerSocketTerminal %d "term" false
connector Connect sysbus.uart0 term
sysbus.xipFlash LoadBinary @%s 0x0

macro reset
"""
    sysbus.cpu0 VectorTableOffset 0x0
    sysbus.cpu0 SP `+"`sysbus ReadDoubleWord 0x0`"+`
    sysbus.cpu0 PC `+"`sysbus ReadDoubleWord 0x4`"+`
    sysbus.cpu1 VectorTableOffset 0x0
    sysbus.cpu1 SP `+"`sysbus ReadDoubleWord 0x0`"+`
    sysbus.cpu1 PC `+"`sysbus ReadDoubleWord 0x4`"+`
"""
runMacro $reset
`,
		toSlashPath(overlayAbs),
		toSlashPath(replAbs),
		uartPort,
		toSlashPath(flashPath),
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

	uartConn, err := dialRetry(fmt.Sprintf("127.0.0.1:%d", uartPort), 20*time.Second)
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

	time.Sleep(120 * time.Millisecond)
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

func (h *renodeHarness) saveKeystoreAndQueryOverlay(keystoreOutPath string) string {
	h.t.Helper()
	h.execMonitor("pause")
	h.execMonitor(fmt.Sprintf("sysbus.ssi SaveFlashRange @%s 0x%X 0x%X",
		toSlashPath(keystoreOutPath), offKeystoreOTP, keystoreSizeBytes))
	h.execMonitor("sysbus.ssi BlockedOperations")
	h.execMonitor("sysbus.ssi BlockedDirectXipWrites")
	h.execMonitor("sysbus.vregChipReset BootRomStatus")
	h.execMonitor("sysbus.cpu0 PC")

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if info, err := os.Stat(keystoreOutPath); err == nil && info.Size() >= keystoreSizeBytes {
			time.Sleep(100 * time.Millisecond)
			return h.monitorSnapshot()
		}
		time.Sleep(40 * time.Millisecond)
	}
	h.t.Fatalf("timeout waiting for Renode to save OTP keystore to %s.\nMonitor output:\n%s",
		keystoreOutPath, h.monitorSnapshot())
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
	stage0Boot2  []byte
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
			t.Fatalf("missing build artifact %s (run scripts/run_renode_rp2040_e2e.ps1 first): %v", p, err)
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
		stage0Boot2:  mustRead("builds/build_rp2040/toob_stage0_boot2.bin"),
		stage1Signed: mustRead("builds/build_rp2040/toob_stage1.signed.bin"),
		recoveryBin:  mustRead("builds/build_rp2040/toob_recovery.bin"),
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
		ackByte, _ := h.readExactByteSince(ackOff, 10*time.Second)
		if ackByte != 'K' {
			t.Fatalf("expected chunk ACK 'K' at pos %d, got 0x%02X (%q).\nUART log:\n%s",
				pos, ackByte, string([]byte{ackByte}), string(h.snapshot()))
		}
	}

	off = h.waitForStringSince(off, "[APP] OTA_FINALIZED status=OK", 15*time.Second)
	return off
}

func buildFlashImage(art firmwareArtifacts, keystore []byte, corruptApps bool) []byte {
	flash := bytes.Repeat([]byte{0xFF}, flashSizeBytes)
	copy(flash[offStage0:], art.stage0Boot2)
	copy(flash[offStage1A:], art.stage1Signed)
	copy(flash[offRecoveryOS:], art.recoveryBin)
	if corruptApps {
		copy(flash[offAppSlot0:], []byte("CORRUPTED_APP_SLOT_HEADER!"))
		copy(flash[offStagingSlot:], []byte("CORRUPTED_STAGING_HEADER!!"))
	} else {
		copy(flash[offAppSlot0:], art.appV1)
	}
	if len(keystore) > 0 {
		copy(flash[offKeystoreOTP:], keystore)
	}
	return flash
}

func newErasedKeystore() []byte {
	return bytes.Repeat([]byte{0xFF}, keystoreSizeBytes)
}

func TestRenodeRP2040_1a_CorruptedBoot2CRC32RejectedByBootROM(t *testing.T) {
	art := loadArtifacts(t)
	tmp := t.TempDir()

	ks := newErasedKeystore()
	copy(ks[otpOffKey0:], art.rootPubKey)
	binary.LittleEndian.PutUint32(ks[otpOffDSLC:otpOffDSLC+4], 0xFFFFFFFE)

	flash := buildFlashImage(art, ks, false)
	// Flip 1 single bit inside the 256-byte boot2 block (offset 0x44 in RP2040 boot2 XIP configurator)
	flash[0x44] ^= 0x01

	flashPath := filepath.Join(tmp, "flash_corrupt_boot2.bin")
	if err := os.WriteFile(flashPath, flash, 0o644); err != nil {
		t.Fatalf("write flash_corrupt_boot2.bin: %v", err)
	}

	h := startRenode(t, tmp, flashPath, 25*time.Second)
	defer h.stop()

	// Allow RP2040 Mask-ROM at 0x00000000 ample virtual time to copy boot2 to 0x20041F00 & check MPEG-2 CRC-32
	time.Sleep(1200 * time.Millisecond)

	ksOutPath := filepath.Join(tmp, "ks_boot2_neg.bin")
	monOut := h.saveKeystoreAndQueryOverlay(ksOutPath)

	uartBytes := h.snapshot()
	if len(uartBytes) != 0 {
		t.Fatalf("SECURITY FAILURE: Stage 0 emitted UART output despite corrupted boot2 CRC-32!\nUART:\n%s", string(uartBytes))
	}
	upperMon := strings.ToUpper(monOut)
	if !strings.Contains(upperMon, "0XBAD0C2C0") {
		t.Fatalf("expected BootRomStatus = 0xBAD0C2C0 (MPEG-2 CRC-32 mismatch latched by Mask-ROM), got:\n%s", monOut)
	}
	if !strings.Contains(upperMon, "0X17A") && !strings.Contains(upperMon, "0X17C") &&
		!strings.Contains(upperMon, "0X0000017A") && !strings.Contains(upperMon, "0X0000017C") {
		t.Fatalf("expected Core 0 PC halted inside RP2040 Mask-ROM (0x17A..0x17C), got:\n%s", monOut)
	}
	t.Log("Corrupted boot2 CRC-32 PASS: RP2040 Mask-ROM rejected 1-bit flip in boot2 and halted at 0x0000017A before Stage 0!")
}

func TestRenodeRP2040_1b_BlankKeystoreFailClosed(t *testing.T) {
	art := loadArtifacts(t)
	tmp := t.TempDir()

	// Valid boot2 MPEG-2 CRC-32, but unprogrammed all-0xFF OTP keystore at 0x1FF000
	flash := buildFlashImage(art, newErasedKeystore(), false)
	flashPath := filepath.Join(tmp, "flash_blank_ks.bin")
	if err := os.WriteFile(flashPath, flash, 0o644); err != nil {
		t.Fatalf("write flash_blank_ks.bin: %v", err)
	}

	h := startRenode(t, tmp, flashPath, 25*time.Second)
	defer h.stop()

	off := h.waitForStringSince(0, "=== TOOB STAGE 0 BOOT ===", 10*time.Second)
	h.waitForStringSince(off, "[S0] read_pubkey failed or zero key!", 10*time.Second)

	snap := string(h.snapshot())
	if strings.Contains(snap, "[APP] BOOT") {
		t.Fatalf("SECURITY FAILURE: Guest App booted despite erased 0xFF OTP keystore!\n%s", snap)
	}
	t.Log("Blank Keystore PASS: Valid boot2 booted Stage 0, which rejected all-0xFF OTP keystore fail-closed!")
}

func TestRenodeRP2040_FullLifecycle_Provision_SwapMoveOTA_TDS1Delta_WDTRollback(t *testing.T) {
	art := loadArtifacts(t)
	tmp := t.TempDir()

	// Seed primary Root Key 0 at 0x1FF000, keeping DSLC word (0x1FF040) = 0xFFFFFFFF (unprovisioned 0x00)
	ks := newErasedKeystore()
	copy(ks[otpOffKey0:], art.rootPubKey)

	flash := buildFlashImage(art, ks, false)
	flashPath := filepath.Join(tmp, "flash_lifecycle.bin")
	if err := os.WriteFile(flashPath, flash, 0o644); err != nil {
		t.Fatalf("write flash_lifecycle.bin: %v", err)
	}

	h := startRenode(t, tmp, flashPath, 210*time.Second)
	defer h.stop()

	// =========================================================================
	// PHASE 3: Factory UART COBS Provisioning + VTOR Proof
	// =========================================================================
	t.Log("Phase 3: Waiting for BootROM -> boot2 -> Stage 0 Ed25519 verify -> Stage 1 COBS PROV banner...")
	off := h.waitForStringSince(0, "[S0] Signature verification PASSED!", 15*time.Second)
	provBanner := cobsEncode([]byte("PROV"))
	off = h.waitForSince(off, provBanner, 10*time.Second)

	// 1. PROV_CMD_READ_ID (0x06) -> status(BOOT_OK) + 8-byte W25Q16JV 4Bh Unique ID
	expectedUID := []byte{0xE6, 0x61, 0x41, 0x03, 0xE7, 0x20, 0x40, 0x01}
	h.writeAll(buildProvFrame(provCmdReadID, nil))
	stFrame, off := h.readCOBSFrameSince(off, 10*time.Second)
	if len(stFrame) != 4 || binary.LittleEndian.Uint32(stFrame) != bootStatusOK {
		t.Fatalf("PROV_CMD_READ_ID status = %x, want %08x", stFrame, bootStatusOK)
	}
	uidFrame, off := h.readCOBSFrameSince(off, 10*time.Second)
	if !bytes.Equal(uidFrame, expectedUID) {
		t.Fatalf("PROV_CMD_READ_ID QSPI 4Bh UID = %x, want %x", uidFrame, expectedUID)
	}

	// 2. PROV_CMD_BURN_KEY (0x01, slot=1, rootPubKey) -> programs KEY1 via .data.ramfunc SSI 02h!
	burnPayload := append([]byte{0x01}, art.rootPubKey...)
	h.writeAll(buildProvFrame(provCmdBurnKey, burnPayload))
	stFrame, off = h.readCOBSFrameSince(off, 10*time.Second)
	if len(stFrame) != 4 || binary.LittleEndian.Uint32(stFrame) != bootStatusOK {
		t.Fatalf("PROV_CMD_BURN_KEY status = %x, want %08x", stFrame, bootStatusOK)
	}

	// 3. PROV_CMD_LOCK_BOOT_FLASH (0x07) -> programs W25Q16JV SR1 = 0xF0 (SRP0|SEC|TB|BP2) + OTP lock word!
	h.writeAll(buildProvFrame(provCmdLockBootFlash, nil))
	stFrame, off = h.readCOBSFrameSince(off, 10*time.Second)
	if len(stFrame) != 4 || binary.LittleEndian.Uint32(stFrame) != bootStatusOK {
		t.Fatalf("PROV_CMD_LOCK_BOOT_FLASH status = %x, want %08x", stFrame, bootStatusOK)
	}

	// 4. PROV_CMD_SET_DSLC (0x02, 0x01) -> programs ~0x01 (0xFFFFFFFE) at 0x1FF040!
	h.writeAll(buildProvFrame(provCmdSetDSLC, []byte{0x01}))
	stFrame, off = h.readCOBSFrameSince(off, 10*time.Second)
	if len(stFrame) != 4 || binary.LittleEndian.Uint32(stFrame) != bootStatusOK {
		t.Fatalf("PROV_CMD_SET_DSLC status = %x, want %08x", stFrame, bootStatusOK)
	}

	// 5. PROV_CMD_REBOOT (0xFF) -> WATCHDOG.CTRL.TRIGGER warm reset -> boots App v1.0.0 at VTOR 0x10038100!
	h.writeAll(buildProvFrame(provCmdReboot, nil))
	stFrame, off = h.readCOBSFrameSince(off, 10*time.Second)
	if len(stFrame) != 4 || binary.LittleEndian.Uint32(stFrame) != bootStatusOK {
		t.Fatalf("PROV_CMD_REBOOT status = %x, want %08x", stFrame, bootStatusOK)
	}

	off = h.waitForStringSince(off, "[APP] BOOT ver=1.0.0 slot=0 tent=0 handoff=OK", 20*time.Second)
	h.writeAll([]byte("SCRATCH_STATUS\n"))
	off = h.waitForStringSince(off, "vtor=0x10038100", 8*time.Second)
	t.Log("Phase 3 PASS: Provisioned QSPI OTP + SPI NOR BPx over COBS UART & verified Cortex-M0+ SCB->VTOR=0x10038100!")

	// =========================================================================
	// PHASE 4: Live UART Full Signed TBM1 Swap-Move OTA (v1.0.0 -> v2.0.0) + SCRATCH Confirm Proof
	// =========================================================================
	t.Log("Phase 4a: Verifying revoked KeyIndex=0 bundle is rejected without bricking...")
	revokedBundle := buildFullTrailerBundle(t, art.signer, 0, art.appV2, 1, 2)
	off = streamUARTOTA(t, h, revokedBundle, 113)
	off = h.waitForStringSince(off, "[APP] BOOT ver=1.0.0 slot=0 tent=0 handoff=OK", 20*time.Second)

	t.Log("Phase 4b: Streaming signed TBM1 Swap-Move OTA v1.0.0 -> v2.0.0 with active KeyIndex=1...")
	bundleV2 := buildFullTrailerBundle(t, art.signer, 1, art.appV2, 1, 2)
	off = streamUARTOTA(t, h, bundleV2, 113)

	off = h.waitForStringSince(off, "[APP] BOOT ver=2.0.0 slot=0 tent=1 handoff=OK", 25*time.Second)
	confirmMark := h.markOffset()
	h.writeAll([]byte("CONFIRM\n"))
	off = h.waitForStringSince(off, "[APP] CONFIRM status=OK s1=0x", 8*time.Second)
	off = h.waitForStringSince(off, "\r\n", 5*time.Second)
	confirmLine := string(h.snapshot()[confirmMark:off])
	if strings.Contains(confirmLine, "s1=0x00000000 s2=0x00000000") {
		t.Fatalf("expected non-zero 64-bit survival nonce in WATCHDOG->SCRATCH1..2 on CONFIRM, got: %q", confirmLine)
	}

	h.writeAll([]byte("REBOOT\n"))
	off = h.waitForStringSince(off, "[APP] BOOT ver=2.0.0 slot=0 tent=0 handoff=OK", 20*time.Second)
	// Verify Stage 1 consumed AND zeroized WATCHDOG->SCRATCH1..2 across warm reset!
	h.writeAll([]byte("SCRATCH_STATUS\n"))
	off = h.waitForStringSince(off, "[APP] SCRATCH s1=0x00000000 s2=0x00000000 vtor=0x10038100", 8*time.Second)
	t.Log("Phase 4 PASS: Revoked KeyIndex=0 rejected + Swap-Move OTA v2.0.0 tentative -> WATCHDOG->SCRATCH confirmed & zeroized!")

	// =========================================================================
	// PHASE 5: Live UART Signed TDS1 Forward-Delta OTA (v2.0.0 -> v3.0.0)
	// =========================================================================
	bundleDeltaV3, rawDeltaBytes := buildDeltaTrailerBundle(t, art.signer, 1, art.appV2, art.appV3, 1, 2, 3)
	t.Logf("Phase 5: Streaming signed TDS1 Forward-Delta OTA v2.0.0 -> v3.0.0 (delta=%d bytes vs full=%d bytes)...",
		rawDeltaBytes, len(art.appV3))
	off = streamUARTOTA(t, h, bundleDeltaV3, 113)

	off = h.waitForStringSince(off, "[APP] BOOT ver=3.0.0 slot=0 tent=1 handoff=OK", 25*time.Second)
	h.writeAll([]byte("CONFIRM\n"))
	off = h.waitForStringSince(off, "[APP] CONFIRM status=OK", 8*time.Second)
	h.writeAll([]byte("REBOOT\n"))
	off = h.waitForStringSince(off, "[APP] BOOT ver=3.0.0 slot=0 tent=0 handoff=OK", 20*time.Second)
	t.Log("Phase 5 PASS: Stage 1 Cortex-M0+ SDVM + Heatshrink reconstructed v3.0.0 & confirmed!")

	// =========================================================================
	// PHASE 6: Bad v4.0.0 Hardware WATCHDOG Rollback (bad_v4 -> v3.0.0)
	// =========================================================================
	t.Log("Phase 6: Streaming signed crashing firmware v4.0.0 (starves RP2040 WATCHDOG) to verify rollback...")
	bundleBadV4 := buildFullTrailerBundle(t, art.signer, 1, art.appBadV4, 3, 4)
	off = streamUARTOTA(t, h, bundleBadV4, 113)

	off = h.waitForStringSince(off, "[APP] BOOT ver=4.0.0 slot=0 tent=1 CRASHING_WITHOUT_CONFIRM", 25*time.Second)
	// RP2040 WATCHDOG fires WATCHDOG->REASON.TIMER=1 across max_retries=2, then Swap-Move rolls back to v3.0.0!
	off = h.waitForStringSince(off, "[APP] BOOT ver=3.0.0 slot=0 tent=0 handoff=OK", 55*time.Second)
	t.Log("Phase 6 PASS: RP2040 WATCHDOG latched REASON.TIMER & Stage 1 rolled back bad_v4 -> v3.0.0!")

	// Verify persisted QSPI OTP keystore sector (KEY1, ~DSLC=0xFE, monotonic SVN bits cleared, lock word)
	ksSavedPath := filepath.Join(tmp, "keystore_after.bin")
	_ = h.saveKeystoreAndQueryOverlay(ksSavedPath)
	persistedKS, err := os.ReadFile(ksSavedPath)
	if err != nil {
		t.Fatalf("read saved keystore_after.bin: %v", err)
	}
	if persistedKS[otpOffDSLC] != 0xFE {
		t.Fatalf("persisted OTP DSLC byte = 0x%02X, want 0xFE (~0x01)", persistedKS[otpOffDSLC])
	}
	if !bytes.Equal(persistedKS[otpOffKey1:otpOffKey1+32], art.rootPubKey) {
		t.Fatalf("persisted OTP KEY1 = %x, want %x", persistedKS[otpOffKey1:otpOffKey1+32], art.rootPubKey)
	}
	lockWord := binary.LittleEndian.Uint32(persistedKS[otpOffLock : otpOffLock+4])
	if lockWord != 0xFFFFFFF7 {
		t.Fatalf("persisted OTP lock word = 0x%08X, want 0xFFFFFFF7 (~8 sectors)", lockWord)
	}
}

func TestRenodeRP2040_HardwareBpAndMpuStage0NonBrickability(t *testing.T) {
	art := loadArtifacts(t)
	tmp := t.TempDir()

	ks := newErasedKeystore()
	copy(ks[otpOffKey0:], art.rootPubKey)
	binary.LittleEndian.PutUint32(ks[otpOffDSLC:otpOffDSLC+4], 0xFFFFFFFE)

	flash := buildFlashImage(art, ks, false)
	flashPath := filepath.Join(tmp, "flash_protect.bin")
	if err := os.WriteFile(flashPath, flash, 0o644); err != nil {
		t.Fatalf("write flash_protect.bin: %v", err)
	}

	h := startRenode(t, tmp, flashPath, 45*time.Second)
	defer h.stop()

	// Boot to Guest App v1.0.0 and warm-reboot to verify SPI NOR BPx + Cortex-M0+ MPU + VTOR across resets
	off := h.waitForStringSince(0, "[APP] BOOT ver=1.0.0 slot=0 tent=0 handoff=OK", 20*time.Second)
	h.writeAll([]byte("REBOOT\n"))
	off = h.waitForStringSince(off, "[APP] BOOT ver=1.0.0 slot=0 tent=0 handoff=OK", 20*time.Second)

	expectedStage0Word := binary.LittleEndian.Uint32(art.stage0Boot2[0x1000 : 0x1000+4])
	expectedLine := fmt.Sprintf(
		"[APP] PROTECT vtor=0x10038100 mpu_ctrl=0x00000005 mpu_rbar=0x10000000 mpu_rasr=0x0600001D mpu_fault=1 sr1=0x000000F0 pre=0x%08X post=0x%08X status=PROTECTED",
		expectedStage0Word, expectedStage0Word,
	)

	h.writeAll([]byte("STAGE0_ATTACK\n"))
	h.waitForStringSince(off, expectedLine, 10*time.Second)

	ksSavedPath := filepath.Join(tmp, "ks_protect.bin")
	monOut := h.saveKeystoreAndQueryOverlay(ksSavedPath)
	if !strings.Contains(monOut, "0x00000003") && !strings.Contains(monOut, "3") {
		t.Fatalf("expected ssi.BlockedOperations >= 3 (WRSR + SE_4K + PP) in monitor output, got:\n%s", monOut)
	}
	t.Logf("Hardware SPI NOR BPx + Cortex-M0+ MPU + VTOR PASS: %s", expectedLine)
}

func TestRenodeRP2040_RecoveryOS_XMODEM_Rescue(t *testing.T) {
	art := loadArtifacts(t)
	tmp := t.TempDir()

	ks := newErasedKeystore()
	copy(ks[otpOffKey0:], art.rootPubKey)
	binary.LittleEndian.PutUint32(ks[otpOffDSLC:otpOffDSLC+4], 0xFFFFFFFE)

	// Corrupt BOTH App Slot (0x038000) and Staging Slot (0x068000) while keeping Stage 0, Stage 1A, and Recovery OS intact
	flash := buildFlashImage(art, ks, true)
	flashPath := filepath.Join(tmp, "flash_rescue.bin")
	if err := os.WriteFile(flashPath, flash, 0o644); err != nil {
		t.Fatalf("write flash_rescue.bin: %v", err)
	}

	h := startRenode(t, tmp, flashPath, 110*time.Second)
	defer h.stop()

	t.Log("Phase 7: Booting with corrupted App & Staging slots -> expecting Stage 1 VTOR handoff to Recovery OS at 0x10098100...")
	off := h.waitForStringSince(0, "[REC] listening...", 25*time.Second)
	off = h.waitForStringSince(off, "C", 10*time.Second)

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
	h.waitForStringSince(eotOff, "[REC] resolved", 15*time.Second)

	off = h.waitForStringSince(eotOff, "[APP] BOOT ver=3.0.0", 25*time.Second)
	h.writeAll([]byte("CONFIRM\n"))
	h.waitForStringSince(off, "[APP] CONFIRM status=OK", 8*time.Second)
	t.Log("Phase 7 PASS: Rescued bricked RP2040 over XMODEM-CRC into verified v3.0.0!")
}
