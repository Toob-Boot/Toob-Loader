package qemu_corstone300_test

import (
	"bufio"
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
	flashBaseSecure = uint32(0x11000000)
	itcmBaseSecure  = uint32(0x10000000)
	otpBaseSecure   = uint32(0x3007E000)

	flashSizeBytes = 2 * 1024 * 1024 // 2 MiB (512 x 4 KB MPC-guarded sectors at 0x11000000 S / 0x01000000 NS)
	otpSizeBytes   = 0x220           // 512B OTP (+0x000) + Lock Magic/Size/SlotLocks (+0x200..+0x21F)

	// OTP layout relative to 0x3007E000 (corstone300_otp/otp_real.c)
	otpOffKey0      = 0x000
	otpOffKey1      = 0x020
	otpOffDSLC      = 0x080
	otpOffMono      = 0x0A0
	otpOffLockMagic = 0x200
	otpOffLockSize  = 0x204
	otpOffLockSlots = 0x208

	otpLockMagicExpected = uint32(0x4C4F434B)

	// Device identity matching test/qemu_corstone300/device.toml
	testVendorID  = 0x043B
	testProductID = 0x0547
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

var cDefineHexOrDecRe = regexp.MustCompile(`(?m)^\s*#define\s+([A-Z0-9_]+)\s+\(?((?:0x[0-9a-fA-F]+|\d+))[uUlL]*\)?`)

type partitionOffsets struct {
	stage0   uint32
	stage1A  uint32
	stage1B  uint32
	appSlot  uint32
	staging  uint32
	recovery uint32
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

type qemuHarness struct {
	t             *testing.T
	cmd           *exec.Cmd
	containerName string
	doneCh        chan error
	uart          net.Conn
	mon           net.Conn
	gdbPort       int
	cancel        context.CancelFunc
	outLog        *syncBuffer
	monBuf        bytes.Buffer
	monLock       sync.Mutex

	mu     sync.Mutex
	rxBuf  bytes.Buffer
	notify chan struct{}
}

func useDockerLinuxQemu() (string, bool) {
	if runtime.GOOS != "windows" || os.Getenv("TOOB_QEMU_ARM_NATIVE") == "1" {
		return "", false
	}
	const winCheck = `D:\ToobStorage\tools\qemu-arm\linux-x64\xpack-qemu-arm-9.2.4-1\bin\qemu-system-arm`
	const containerBin = `/mnt/d/tools/qemu-arm/linux-x64/xpack-qemu-arm-9.2.4-1/bin/qemu-system-arm`
	if _, err := os.Stat(winCheck); err != nil {
		return "", false
	}
	if _, err := exec.LookPath("docker"); err != nil {
		return "", false
	}
	return containerBin, true
}

func resolveQemuBinary(t *testing.T) string {
	t.Helper()
	if env := os.Getenv("TOOB_QEMU_ARM_BIN"); env != "" {
		if _, err := os.Stat(env); err == nil {
			return env
		}
	}
	if runtime.GOOS == "windows" {
		candidates := []string{
			`D:\ToobStorage\tools\qemu-arm\xpack-qemu-arm-9.2.4-1\bin\qemu-system-arm.exe`,
			`D:\ToobStorage\tools\qemu-arm\qemu-system-arm.exe`,
		}
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				return c
			}
		}
	}
	if path, err := exec.LookPath("qemu-system-arm"); err == nil {
		return path
	}
	t.Skip("qemu-system-arm not found (set TOOB_QEMU_ARM_BIN)")
	return ""
}

func resolveBuildRoot() string {
	if env := os.Getenv("TOOB_CORSTONE300_BUILD_ROOT"); env != "" {
		if _, err := os.Stat(env); err == nil {
			return env
		}
	}
	if runtime.GOOS == "windows" {
		const dBuild = `D:\ToobStorage\tmp_build\w3d_corstone300`
		if _, err := os.Stat(dBuild); err == nil {
			return dBuild
		}
	}
	return "builds"
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
		time.Sleep(30 * time.Millisecond)
	}
	return nil, lastErr
}

func dialMonitorReady(addr string, timeout time.Duration) (net.Conn, []byte, error) {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 300*time.Millisecond)
		if err != nil {
			lastErr = err
			time.Sleep(40 * time.Millisecond)
			continue
		}
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			_ = tcpConn.SetNoDelay(true)
		}
		_ = conn.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
		var acc bytes.Buffer
		tmp := make([]byte, 256)
		ready := false
		for time.Now().Before(deadline) {
			n, rerr := conn.Read(tmp)
			if n > 0 {
				acc.Write(tmp[:n])
				if bytes.Contains(acc.Bytes(), []byte("(qemu)")) {
					ready = true
					break
				}
			}
			if rerr != nil {
				lastErr = rerr
				break
			}
		}
		if ready {
			_ = conn.SetReadDeadline(time.Time{})
			return conn, acc.Bytes(), nil
		}
		_ = conn.Close()
		time.Sleep(40 * time.Millisecond)
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("timed out waiting for (qemu) monitor prompt on %s", addr)
	}
	return nil, nil, lastErr
}

func gdbExchangePacket(conn net.Conn, reader *bufio.Reader, payload string) (string, error) {
	var csum byte
	for i := 0; i < len(payload); i++ {
		csum += payload[i]
	}
	pkt := fmt.Sprintf("$%s#%02x", payload, csum)
	if _, err := conn.Write([]byte(pkt)); err != nil {
		return "", err
	}
	for {
		b, err := reader.ReadByte()
		if err != nil {
			return "", err
		}
		if b == '$' {
			break
		}
	}
	var resp strings.Builder
	for {
		b, err := reader.ReadByte()
		if err != nil {
			return "", err
		}
		if b == '#' {
			_, _ = reader.ReadByte()
			_, _ = reader.ReadByte()
			break
		}
		resp.WriteByte(b)
	}
	_, _ = conn.Write([]byte("+"))
	return resp.String(), nil
}

func gdbSendPacket(conn net.Conn, reader *bufio.Reader, payload string) error {
	resp, err := gdbExchangePacket(conn, reader, payload)
	if err != nil {
		return err
	}
	if resp != "OK" {
		return fmt.Errorf("unexpected GDB response %q", resp)
	}
	return nil
}

func (h *qemuHarness) gdbWriteRegion(conn net.Conn, reader *bufio.Reader, baseAddr uint32, data []byte) {
	h.t.Helper()
	const chunkBytes = 1024
	hexBuf := make([]byte, chunkBytes*2)
	for off := 0; off < len(data); off += chunkBytes {
		end := min(off+chunkBytes, len(data))
		slice := data[off:end]
		nHex := hex.Encode(hexBuf, slice)
		cmd := fmt.Sprintf("M%x,%x:%s", baseAddr+uint32(off), len(slice), string(hexBuf[:nHex]))
		if err := gdbSendPacket(conn, reader, cmd); err != nil {
			h.t.Fatalf("gdbWriteRegion at 0x%08X+0x%X failed: %v\nQEMU output:\n%s", baseAddr, off, err, h.outLog.String())
		}
	}
}

func startQemu(t *testing.T, flashImage, otpImage []byte, maxLifetime time.Duration) *qemuHarness {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), maxLifetime)

	uartPort := reserveFreeTCPPort(t)
	monPort := reserveFreeTCPPort(t)
	gdbPort := reserveFreeTCPPort(t)

	containerBin, viaDocker := useDockerLinuxQemu()
	bindHost := "127.0.0.1"
	if viaDocker {
		bindHost = "0.0.0.0"
	}

	qemuArgs := []string{
		"-M", "mps3-an547",
		"-accel", "tcg,tb-size=32",
		"-action", "watchdog=reset",
		"-S",
		"-nographic",
		"-chardev", fmt.Sprintf("socket,id=ser0,host=%s,port=%d,server=on,wait=off,nodelay=on,telnet=off", bindHost, uartPort),
		"-serial", "chardev:ser0",
		"-chardev", fmt.Sprintf("socket,id=mon0,host=%s,port=%d,server=on,wait=off,nodelay=on,telnet=off", bindHost, monPort),
		"-mon", "chardev=mon0,mode=readline",
		"-chardev", fmt.Sprintf("socket,id=gdb0,host=%s,port=%d,server=on,wait=off,nodelay=on,telnet=off", bindHost, gdbPort),
		"-gdb", "chardev:gdb0",
	}

	var cmd *exec.Cmd
	var containerName string
	if viaDocker {
		containerName = fmt.Sprintf("toob-corstone300-%d-%d", os.Getpid(), monPort)
		dockerArgs := []string{
			"run", "--rm",
			"--name", containerName,
			"-p", fmt.Sprintf("127.0.0.1:%d:%d", uartPort, uartPort),
			"-p", fmt.Sprintf("127.0.0.1:%d:%d", monPort, monPort),
			"-p", fmt.Sprintf("127.0.0.1:%d:%d", gdbPort, gdbPort),
			"-v", "D:/ToobStorage:/mnt/d",
			"takt-linux:latest",
			containerBin,
		}
		dockerArgs = append(dockerArgs, qemuArgs...)
		cmd = exec.CommandContext(ctx, "docker", dockerArgs...)
	} else {
		qemuBin := resolveQemuBinary(t)
		cmd = exec.CommandContext(ctx, qemuBin, qemuArgs...)
	}

	outLog := &syncBuffer{}
	cmd.Stdout = outLog
	cmd.Stderr = outLog

	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatalf("start QEMU: %v", err)
	}
	doneCh := make(chan error, 1)
	go func() {
		doneCh <- cmd.Wait()
	}()

	cleanupEarly := func() {
		cancel()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		if containerName != "" {
			_ = exec.Command("docker", "rm", "-f", containerName).Run()
		}
		<-doneCh
	}

	monConn, initMonBytes, err := dialMonitorReady(fmt.Sprintf("127.0.0.1:%d", monPort), 45*time.Second)
	if err != nil {
		cleanupEarly()
		t.Fatalf("connect QEMU monitor (%d): %v\nQEMU output:\n%s", monPort, err, outLog.String())
	}

	uartConn, err := dialRetry(fmt.Sprintf("127.0.0.1:%d", uartPort), 10*time.Second)
	if err != nil {
		_ = monConn.Close()
		cleanupEarly()
		t.Fatalf("connect QEMU UART0 (%d): %v\nQEMU output:\n%s", uartPort, err, outLog.String())
	}

	gdbConn, err := dialRetry(fmt.Sprintf("127.0.0.1:%d", gdbPort), 10*time.Second)
	if err != nil {
		_ = uartConn.Close()
		_ = monConn.Close()
		cleanupEarly()
		t.Fatalf("connect QEMU GDB stub (%d): %v\nQEMU output:\n%s", gdbPort, err, outLog.String())
	}

	h := &qemuHarness{
		t:             t,
		cmd:           cmd,
		containerName: containerName,
		doneCh:        doneCh,
		uart:          uartConn,
		mon:           monConn,
		gdbPort:       gdbPort,
		cancel:        cancel,
		outLog:        outLog,
		notify:        make(chan struct{}, 1),
	}
	h.monBuf.Write(initMonBytes)

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

	// Populate persistent RAM-backed Code-Flash (0x11000000), Secure ITCM Boot Vectors (0x10000000),
	// and Secure OTP Bank (0x3007E000) via GDB RSP so warm SYSRESETREQ & Watchdog resets never overwrite state!
	_ = gdbConn.SetDeadline(time.Now().Add(30 * time.Second))
	gdbReader := bufio.NewReaderSize(gdbConn, 4096)
	_, _ = gdbConn.Write([]byte("+"))
	h.gdbWriteRegion(gdbConn, gdbReader, itcmBaseSecure, flashImage[:64])
	h.gdbWriteRegion(gdbConn, gdbReader, flashBaseSecure, flashImage)
	h.gdbWriteRegion(gdbConn, gdbReader, otpBaseSecure, otpImage)
	_ = gdbConn.Close()

	time.Sleep(40 * time.Millisecond)
	h.execMonitor("system_reset")
	time.Sleep(40 * time.Millisecond)
	h.execMonitor("cont")

	return h
}

func (h *qemuHarness) execMonitor(cmdLine string) {
	h.t.Helper()
	if h.mon == nil {
		return
	}
	if _, err := h.mon.Write([]byte(cmdLine + "\r\n")); err != nil {
		h.t.Fatalf("QEMU monitor write %q failed: %v\nQEMU stderr:\n%s", cmdLine, err, h.outLog.String())
	}
}

func (h *qemuHarness) monitorSnapshot() string {
	h.monLock.Lock()
	defer h.monLock.Unlock()
	return h.monBuf.String()
}

func (h *qemuHarness) readSecureMemory(addr uint32, size int) []byte {
	h.t.Helper()
	h.execMonitor("stop")
	time.Sleep(40 * time.Millisecond)
	// Reset halted Cortex-M55 back into ARMv8.1-M Secure state (without executing instruction 0)
	// so GDB debug reads pass Secure IDAU/SAU attribution over internal SSE-300 DTCM (0x3007E000).
	h.execMonitor("system_reset")
	time.Sleep(40 * time.Millisecond)

	gdbConn, err := dialRetry(fmt.Sprintf("127.0.0.1:%d", h.gdbPort), 5*time.Second)
	if err != nil {
		h.t.Fatalf("reconnect QEMU GDB stub (%d): %v", h.gdbPort, err)
	}
	defer gdbConn.Close()
	_ = gdbConn.SetDeadline(time.Now().Add(10 * time.Second))
	gdbReader := bufio.NewReaderSize(gdbConn, 4096)
	_, _ = gdbConn.Write([]byte("+"))

	out := make([]byte, 0, size)
	const chunkBytes = 256
	for off := 0; off < size; off += chunkBytes {
		take := min(chunkBytes, size-off)
		resp, rerr := gdbExchangePacket(gdbConn, gdbReader, fmt.Sprintf("m%x,%x", addr+uint32(off), take))
		if rerr != nil {
			h.t.Fatalf("GDB read 0x%08X+%d failed: %v", addr, off, rerr)
		}
		chunk, herr := hex.DecodeString(resp)
		if herr != nil || len(chunk) != take {
			h.t.Fatalf("GDB read 0x%08X+%d returned %q (err=%v)", addr, off, resp, herr)
		}
		out = append(out, chunk...)
	}
	return out
}

func (h *qemuHarness) stop() {
	if h.mon != nil {
		_, _ = h.mon.Write([]byte("quit\r\n"))
		_ = h.mon.Close()
		h.mon = nil
	}
	if h.uart != nil {
		_ = h.uart.Close()
		h.uart = nil
	}
	if h.doneCh != nil {
		select {
		case <-h.doneCh:
			h.doneCh = nil
			h.cancel()
			return
		case <-time.After(1200 * time.Millisecond):
		}
	}
	h.cancel()
	if h.cmd != nil && h.cmd.Process != nil {
		_ = h.cmd.Process.Kill()
	}
	if h.containerName != "" {
		_ = exec.Command("docker", "rm", "-f", h.containerName).Run()
		h.containerName = ""
	}
	if h.doneCh != nil {
		<-h.doneCh
		h.doneCh = nil
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
			h.t.Fatalf("timeout (%v) waiting for %q after offset %d.\nUART0 log:\n%s\nMonitor log:\n%s\nQEMU stderr:\n%s",
				timeout, string(needle), offset, string(h.snapshot()), h.monitorSnapshot(), h.outLog.String())
		}
		select {
		case <-h.notify:
		case <-time.After(min(rem, 40*time.Millisecond)):
		}
	}
}

func (h *qemuHarness) waitForStringSince(offset int, s string, timeout time.Duration) int {
	return h.waitForSince(offset, []byte(s), timeout)
}

func (h *qemuHarness) readExactByteSince(offset int, timeout time.Duration) (byte, int) {
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
			h.t.Fatalf("timeout (%v) reading byte at offset %d.\nUART0 log:\n%s",
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
			h.t.Fatalf("timeout (%v) waiting for COBS 0x00 terminator at offset %d.\nUART0 log:\n%s",
				timeout, offset, string(h.snapshot()))
		}
		select {
		case <-h.notify:
		case <-time.After(min(rem, 25*time.Millisecond)):
		}
	}
}

func (h *qemuHarness) writeAll(b []byte) {
	h.t.Helper()
	const sliceBytes = 64
	for pos := 0; pos < len(b); pos += sliceBytes {
		end := min(pos+sliceBytes, len(b))
		if _, err := h.uart.Write(b[pos:end]); err != nil {
			h.t.Fatalf("UART0 TCP write failed: %v", err)
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
	offsets      partitionOffsets
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

func parseGeneratedOffsets(t *testing.T, buildRoot string) partitionOffsets {
	t.Helper()
	defs := map[string]uint32{}
	for _, rel := range []string{
		"build_corstone300/generated/boot_layout.h",
		"build_corstone300/generated/generated_boot_config.h",
	} {
		raw, err := os.ReadFile(filepath.Join(buildRoot, rel))
		if err != nil {
			continue
		}
		for _, m := range cDefineHexOrDecRe.FindAllStringSubmatch(string(raw), -1) {
			v, perr := strconv.ParseUint(m[2], 0, 32)
			if perr == nil {
				defs[m[1]] = uint32(v)
			}
		}
	}

	mustOff := func(candidates ...string) uint32 {
		for _, k := range candidates {
			if abs, ok := defs[k]; ok {
				if abs >= flashBaseSecure {
					return abs - flashBaseSecure
				}
				return abs
			}
		}
		t.Fatalf("missing layout macro %v in generated headers (have keys: %d)", candidates, len(defs))
		return 0
	}

	return partitionOffsets{
		stage0:   mustOff("CHIP_STAGE0_ABS_ADDR"),
		stage1A:  mustOff("CHIP_STAGE1A_ABS_ADDR", "CHIP_STAGE1_A_ABS_ADDR", "CHIP_STAGE1_SLOT_A_ABS_ADDR", "CHIP_STAGE1_ABS_ADDR"),
		stage1B:  mustOff("CHIP_STAGE1B_ABS_ADDR", "CHIP_STAGE1_B_ABS_ADDR", "CHIP_STAGE1_SLOT_B_ABS_ADDR"),
		appSlot:  mustOff("CHIP_APP_SLOT_ABS_ADDR"),
		staging:  mustOff("CHIP_STAGING_SLOT_ABS_ADDR"),
		recovery: mustOff("CHIP_RECOVERY_OS_ABS_ADDR", "CHIP_RECOVERY_SLOT_ABS_ADDR"),
	}
}

func loadArtifacts(t *testing.T) firmwareArtifacts {
	t.Helper()
	buildRoot := resolveBuildRoot()
	mustRead := func(rel string) []byte {
		t.Helper()
		p, err := filepath.Abs(filepath.Join(buildRoot, rel))
		if err != nil {
			t.Fatalf("Abs(%s): %v", rel, err)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("missing build artifact %s (run scripts/run_qemu_corstone300_e2e.ps1 first): %v", p, err)
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
		offsets:      parseGeneratedOffsets(t, buildRoot),
		stage0Raw:    mustRead("build_corstone300/toob_stage0.bin"),
		stage1Signed: mustRead("build_corstone300/toob_stage1.signed.bin"),
		recoveryBin:  mustRead("build_corstone300/toob_recovery.bin"),
		appV1:        mustRead("apps/app_v1.toob"),
		appV2:        mustRead("apps/app_v2.toob"),
		appV3:        mustRead("apps/app_v3.toob"),
		appBadV4:     mustRead("apps/app_bad_v4.toob"),
		signer:       signer,
		rootPubKey:   append([]byte(nil), signer.Public()...),
	}
}

func buildFlashImage(art firmwareArtifacts, corruptApps bool) []byte {
	flash := bytes.Repeat([]byte{0xFF}, flashSizeBytes)
	copy(flash[art.offsets.stage0:], art.stage0Raw)
	copy(flash[art.offsets.stage1A:], art.stage1Signed)
	copy(flash[art.offsets.stage1B:], art.stage1Signed)
	copy(flash[art.offsets.recovery:], art.recoveryBin)
	if corruptApps {
		copy(flash[art.offsets.appSlot:], []byte("CORRUPTED_CORSTONE300_APP_SLOT!"))
		copy(flash[art.offsets.staging:], []byte("CORRUPTED_CORSTONE300_STAGING!!"))
	} else {
		copy(flash[art.offsets.appSlot:], art.appV1)
	}
	return flash
}

func newErasedOtp() []byte {
	return bytes.Repeat([]byte{0xFF}, otpSizeBytes)
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

func streamUARTOTA(t *testing.T, h *qemuHarness, bundle []byte, chunkSize int) int {
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
			t.Fatalf("expected chunk ACK 'K' at pos %d, got 0x%02X.\nUART0 log:\n%s",
				pos, ackByte, string(h.snapshot()))
		}
	}

	off = h.waitForStringSince(off, "[APP] OTA_FINALIZED status=OK", 15*time.Second)
	return off
}

func TestQemuCorstone300_01_BlankOtpFailClosed(t *testing.T) {
	art := loadArtifacts(t)
	flash := buildFlashImage(art, false)
	otp := newErasedOtp()

	h := startQemu(t, flash, otp, 60*time.Second)
	defer h.stop()

	off := h.waitForStringSince(0, "=== TOOB STAGE 0 BOOT ===", 10*time.Second)
	h.waitForStringSince(off, "[S0] read_pubkey failed or zero key!", 10*time.Second)

	snap := string(h.snapshot())
	if strings.Contains(snap, "[APP] BOOT") {
		t.Fatalf("SECURITY FAILURE: Non-Secure Guest App booted despite blank 0xFF OTP!\n%s", snap)
	}
	t.Log("Proof 1 PASS: Blank 0xFF Secure OTP rejected fail-closed inside ARMv8.1-M Secure Stage 0!")
}

func TestQemuCorstone300_02_to_06_TrustZoneFullLifecycle(t *testing.T) {
	art := loadArtifacts(t)
	flash := buildFlashImage(art, false)

	// Seed primary Root Key 0 in Secure OTP while keeping DSLC == 0 (unprovisioned)
	otp := newErasedOtp()
	copy(otp[otpOffKey0:], art.rootPubKey)
	otp[otpOffLockSlots+0] = 0x00

	h := startQemu(t, flash, otp, 210*time.Second)
	defer h.stop()

	var off int

	// =========================================================================
	// PROOF 2: COBS UART0 Provisioning (UID, Ed25519 Root Key 1, Lock, DSLC, Reboot)
	// =========================================================================
	t.Run("02_COBSUARTProvisioning", func(t *testing.T) {
		off = h.waitForStringSince(0, "[S0] Signature verification PASSED!", 12*time.Second)
		provBanner := cobsEncode([]byte("PROV"))
		off = h.waitForSince(off, provBanner, 10*time.Second)

		// 1. PROV_CMD_READ_ID (0x06) -> status(BOOT_OK) + 12-byte SSE-300 SYSINFO Silicon/FPGA UID
		h.writeAll(buildProvFrame(provCmdReadID, nil))
		stFrame, nextOff := h.readCOBSFrameSince(off, 8*time.Second)
		off = nextOff
		if len(stFrame) != 4 || binary.LittleEndian.Uint32(stFrame) != bootStatusOK {
			t.Fatalf("PROV_CMD_READ_ID status = %x, want %08x", stFrame, bootStatusOK)
		}
		uidFrame, nextOff := h.readCOBSFrameSince(off, 8*time.Second)
		off = nextOff
		if len(uidFrame) != 12 {
			t.Fatalf("PROV_CMD_READ_ID UID len = %d, want 12 (%x)", len(uidFrame), uidFrame)
		}
		if bytes.Equal(uidFrame, make([]byte, 12)) || bytes.Equal(uidFrame, bytes.Repeat([]byte{0xFF}, 12)) {
			t.Fatalf("PROV_CMD_READ_ID returned degenerate UID: %x", uidFrame)
		}
		t.Logf("SSE-300 SYSINFO 96-bit UID = %x", uidFrame)

		// 2. PROV_CMD_BURN_KEY (0x01, slot=1, rootPubKey)
		burnPayload := append([]byte{0x01}, art.rootPubKey...)
		h.writeAll(buildProvFrame(provCmdBurnKey, burnPayload))
		stFrame, off = h.readCOBSFrameSince(off, 8*time.Second)
		if len(stFrame) != 4 || binary.LittleEndian.Uint32(stFrame) != bootStatusOK {
			t.Fatalf("PROV_CMD_BURN_KEY status = %x, want %08x", stFrame, bootStatusOK)
		}

		// 3. PROV_CMD_LOCK_BOOT_FLASH (0x07) -> locks immutable Stage-0 flash in Secure OTP!
		h.writeAll(buildProvFrame(provCmdLockBootFlash, nil))
		stFrame, off = h.readCOBSFrameSince(off, 8*time.Second)
		if len(stFrame) != 4 || binary.LittleEndian.Uint32(stFrame) != bootStatusOK {
			t.Fatalf("PROV_CMD_LOCK_BOOT_FLASH status = %x, want %08x", stFrame, bootStatusOK)
		}

		// 4. PROV_CMD_SET_DSLC (0x02, 0x01) -> burns 3-byte TMR 0xFE into Secure OTP!
		h.writeAll(buildProvFrame(provCmdSetDSLC, []byte{0x01}))
		stFrame, off = h.readCOBSFrameSince(off, 8*time.Second)
		if len(stFrame) != 4 || binary.LittleEndian.Uint32(stFrame) != bootStatusOK {
			t.Fatalf("PROV_CMD_SET_DSLC status = %x, want %08x", stFrame, bootStatusOK)
		}

		// 5. PROV_CMD_REBOOT (0xFF) -> hardware S32K Watchdog resets SoC -> BXNS into Non-Secure v1.0.0!
		h.writeAll(buildProvFrame(provCmdReboot, nil))
		stFrame, off = h.readCOBSFrameSince(off, 8*time.Second)
		if len(stFrame) != 4 || binary.LittleEndian.Uint32(stFrame) != bootStatusOK {
			t.Fatalf("PROV_CMD_REBOOT status = %x, want %08x", stFrame, bootStatusOK)
		}

		off = h.waitForStringSince(off, "[APP] BOOT ver=1.0.0 ns_pc=0x010", 20*time.Second)
		off = h.waitForStringSince(off, "slot=0 tent=0 handoff=OK", 5*time.Second)
		t.Log("Proof 2 PASS: COBS UART0 Provisioning complete & booted Cortex-M55 Non-Secure App v1.0.0!")
	})

	// =========================================================================
	// PROOF 3: Live ARMv8.1-M TrustZone VTOR_S -> SAU/MPC -> VTOR_NS (BXNS) & Stage-0 Isolation
	// =========================================================================
	t.Run("03_TrustZoneBXNSHandoffAndStage0Isolation", func(t *testing.T) {
		// Verify warm SYSRESETREQ from Non-Secure App transitions cleanly through Secure Stage 0/1 back to Non-Secure!
		h.writeAll([]byte("REBOOT\n"))
		off = h.waitForStringSince(off, "[APP] BOOT ver=1.0.0 ns_pc=0x010", 15*time.Second)
		off = h.waitForStringSince(off, "slot=0 tent=0 handoff=OK", 5*time.Second)

		// Trigger live Non-Secure attacks against Secure Stage 0 (0x11000000 & 0x01000000) and Secure OTP (0x3007E000)!
		probeStart := h.markOffset()
		h.writeAll([]byte("TEST_TZ_ISOLATION\n"))
		off = h.waitForStringSince(probeStart, "[TZ_PROOF] SECURE_FAULT AUVIOL=1", 8*time.Second)
		off = h.waitForStringSince(off, "[TZ_PROOF] SECURE_FAULT AUVIOL=1", 8*time.Second)
		off = h.waitForStringSince(off, "[TZ_PROOF] SECURE_FAULT AUVIOL=1", 8*time.Second)
		off = h.waitForStringSince(
			off,
			"[APP] TZ_ISOLATION ns_pc=1 sau_raz=1 s0_read_blocked=1 s0_write_blocked=1 otp_read_blocked=1 leak_bytes=0 fault_cnt=3",
			8*time.Second,
		)
		t.Log("Proof 3 PASS: Live BXNS Non-Secure execution + 3x synchronous SecureFault AUVIOL=1 + zero data leak verified!")
	})

	// =========================================================================
	// PROOF 4: Full Signed TBM1 OTA (v1.0.0 -> v2.0.0) across Non-Secure/Secure Boundary
	// =========================================================================
	t.Run("04_FullSignedOTA_V1ToV2", func(t *testing.T) {
		// First prove revoked KeyIndex=0 bundle is rejected without bricking Non-Secure v1.0.0
		revokedBundle := buildFullTrailerBundle(t, art.signer, 0, art.appV2, 1, 2)
		off = streamUARTOTA(t, h, revokedBundle, 113)
		off = h.waitForStringSince(off, "[APP] BOOT ver=1.0.0 ns_pc=0x010", 18*time.Second)
		off = h.waitForStringSince(off, "slot=0 tent=0 handoff=OK", 5*time.Second)

		// Now stream valid KeyIndex=1 signed TBM1 bundle v2.0.0
		bundleV2 := buildFullTrailerBundle(t, art.signer, 1, art.appV2, 1, 2)
		off = streamUARTOTA(t, h, bundleV2, 113)

		off = h.waitForStringSince(off, "[APP] BOOT ver=2.0.0 ns_pc=0x010", 20*time.Second)
		off = h.waitForStringSince(off, "slot=0 tent=1 handoff=OK", 5*time.Second)

		h.writeAll([]byte("CONFIRM\n"))
		off = h.waitForStringSince(off, "[APP] CONFIRM status=OK", 8*time.Second)
		h.writeAll([]byte("REBOOT\n"))
		off = h.waitForStringSince(off, "[APP] BOOT ver=2.0.0 ns_pc=0x010", 18*time.Second)
		off = h.waitForStringSince(off, "slot=0 tent=0 handoff=OK", 5*time.Second)
		t.Log("Proof 4 PASS: Revoked KeyIndex=0 rejected + Full Signed TBM1 OTA v1.0.0 -> v2.0.0 swapped, BXNSed & confirmed!")
	})

	// =========================================================================
	// PROOF 5: ~136B TDS1 Forward-Delta OTA (v2.0.0 -> v3.0.0) across TrustZone Boundary
	// =========================================================================
	t.Run("05_ForwardDeltaOTA_V2ToV3", func(t *testing.T) {
		bundleDeltaV3, rawDeltaBytes := buildDeltaTrailerBundle(t, art.signer, 1, art.appV2, art.appV3, 1, 2, 3)
		t.Logf("TDS1 forward-delta payload = %d bytes (vs %d-byte full image)", rawDeltaBytes, len(art.appV3))
		if rawDeltaBytes > 256 {
			t.Fatalf("expected compact ~136B TDS1 delta patch, got %d bytes", rawDeltaBytes)
		}
		off = streamUARTOTA(t, h, bundleDeltaV3, 113)

		off = h.waitForStringSince(off, "[APP] BOOT ver=3.0.0 ns_pc=0x010", 22*time.Second)
		off = h.waitForStringSince(off, "slot=0 tent=1 handoff=OK", 5*time.Second)

		h.writeAll([]byte("CONFIRM\n"))
		off = h.waitForStringSince(off, "[APP] CONFIRM status=OK", 8*time.Second)
		h.writeAll([]byte("REBOOT\n"))
		off = h.waitForStringSince(off, "[APP] BOOT ver=3.0.0 ns_pc=0x010", 18*time.Second)
		off = h.waitForStringSince(off, "slot=0 tent=0 handoff=OK", 5*time.Second)
		t.Logf("Proof 5 PASS: %d-byte TDS1 Forward-Delta OTA reconstructed v3.0.0 in Secure Stage 1, BXNSed & confirmed!", rawDeltaBytes)
	})

	// =========================================================================
	// PROOF 6: Hardware S32K Watchdog Rollback (bad_v4 -> v3.0.0) + Secure OTP Audit
	// =========================================================================
	t.Run("06_WatchdogRollback_BadV4ToV3", func(t *testing.T) {
		bundleBadV4 := buildFullTrailerBundle(t, art.signer, 1, art.appBadV4, 3, 4)
		off = streamUARTOTA(t, h, bundleBadV4, 113)

		off = h.waitForStringSince(off, "[APP] BOOT ver=4.0.0 ns_pc=0x010", 20*time.Second)
		off = h.waitForStringSince(off, "slot=0 tent=1 CRASHING_WITHOUT_CONFIRM", 5*time.Second)

		// Hardware S32K Watchdog fires 1st timeout -> Secure Stage 1 NMI latches syndrome -> 2nd timeout resets SoC -> rolls back to v3.0.0!
		off = h.waitForStringSince(off, "[APP] BOOT ver=3.0.0 ns_pc=0x010", 30*time.Second)
		off = h.waitForStringSince(off, "slot=0 tent=0 handoff=OK", 5*time.Second)

		// Inspect persisted Secure OTP physical memory at 0x3007E000 via QEMU Secure GDB RSP
		persistedOtp := h.readSecureMemory(otpBaseSecure, otpSizeBytes)
		if !bytes.Equal(persistedOtp[otpOffKey1:otpOffKey1+32], art.rootPubKey) {
			t.Fatalf("persisted Secure OTP KEY1 = %x, want %x", persistedOtp[otpOffKey1:otpOffKey1+32], art.rootPubKey)
		}
		for i := range 3 {
			if persistedOtp[otpOffDSLC+i] != 0xFE {
				t.Fatalf("persisted Secure OTP DSLC TMR[%d] = 0x%02X, want 0xFE", i, persistedOtp[otpOffDSLC+i])
			}
		}
		lockMagic := binary.LittleEndian.Uint32(persistedOtp[otpOffLockMagic : otpOffLockMagic+4])
		if lockMagic != otpLockMagicExpected {
			t.Fatalf("persisted Secure OTP Lock Magic = 0x%08X, want 0x%08X", lockMagic, otpLockMagicExpected)
		}
		if persistedOtp[otpOffLockSlots+1] != 0x00 {
			t.Fatalf("persisted Secure OTP Slot 1 lock = 0x%02X, want 0x00", persistedOtp[otpOffLockSlots+1])
		}
		t.Log("Proof 6 PASS: Hardware S32K Watchdog rolled back unconfirmed Non-Secure bad_v4 -> v3.0.0 & Secure OTP verified!")
	})
}

func TestQemuCorstone300_07_XMODEMRecoveryOSRescue(t *testing.T) {
	art := loadArtifacts(t)
	flash := buildFlashImage(art, true)

	otp := newErasedOtp()
	copy(otp[otpOffKey0:], art.rootPubKey)
	otp[otpOffLockSlots+0] = 0x00
	otp[otpOffDSLC+0] = 0xFE
	otp[otpOffDSLC+1] = 0xFE
	otp[otpOffDSLC+2] = 0xFE

	h := startQemu(t, flash, otp, 120*time.Second)
	defer h.stop()

	t.Log("Booting with corrupted Active App & Staging slots -> expecting Secure-State VTOR handoff to Recovery OS...")
	off := h.waitForStringSince(0, "[REC] listening...", 20*time.Second)
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
				t.Fatalf("Recovery OS returned XMODEM NAK on block %d/%d.\nUART0 log:\n%s",
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

	off = h.waitForStringSince(eotOff, "[APP] BOOT ver=3.0.0 ns_pc=0x010", 25*time.Second)
	off = h.waitForStringSince(off, "slot=0 tent=1 handoff=OK", 5*time.Second)

	h.writeAll([]byte("CONFIRM\n"))
	h.waitForStringSince(off, "[APP] CONFIRM status=OK", 8*time.Second)
	t.Log("Proof 7 PASS: XMODEM-CRC Recovery OS rescued bricked Corstone-300 across Secure -> Non-Secure BXNS into v3.0.0!")
}
