package provision

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"math"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/toob-boot/toob/internal/cobs"
)

// mockDevice emulates the C bootloader UART responder in boot_provisioning.c
// and boot_cobs.c (emitting [0x00, <cobs>, 0x00] frames and optional "PROV" banner).
type mockDevice struct {
	rxBuf       bytes.Buffer
	txBuf       bytes.Buffer
	rawWireLog  bytes.Buffer
	uid         []byte
	lastKeySlot uint8
	lastKey     []byte
	lockedOff   uint32
	lockedSize  uint32
	lockedCount int
	dslc        byte
}

func newMockDevice(withBanner bool) *mockDevice {
	m := &mockDevice{
		uid: []byte{0x60, 0x55, 0xF9, 0x11, 0x22, 0x33},
	}
	if withBanner {
		m.sendWireFrame([]byte("PROV"))
	}
	return m
}

func (m *mockDevice) sendWireFrame(payload []byte) {
	m.txBuf.WriteByte(0x00)
	m.txBuf.Write(cobs.Encode(payload))
}

func (m *mockDevice) Read(p []byte) (int, error) {
	return m.txBuf.Read(p)
}

func (m *mockDevice) Write(p []byte) (int, error) {
	m.rawWireLog.Write(p)
	m.rxBuf.Write(p)
	for {
		data := m.rxBuf.Bytes()
		idx := bytes.IndexByte(data, 0x00)
		if idx < 0 {
			break
		}
		rawFrame := data[:idx]
		m.rxBuf.Next(idx + 1)
		if len(rawFrame) == 0 {
			continue
		}

		decoded, err := cobs.Decode(rawFrame)
		if err != nil || len(decoded) < 5 {
			m.respondStatus(BootErrInvalidArg)
			continue
		}

		payloadLen := len(decoded) - 4
		expectedCRC := crc32.ChecksumIEEE(decoded[:payloadLen])
		actualCRC := binary.LittleEndian.Uint32(decoded[payloadLen:])
		if expectedCRC != actualCRC {
			m.respondStatus(BootErrVerify)
			continue
		}

		cmd := decoded[0]
		cmdPayload := decoded[1:payloadLen]
		switch cmd {
		case CmdReadID:
			m.respondStatus(BootOK)
			m.sendWireFrame(m.uid)
		case CmdBurnKey:
			if len(cmdPayload) < 2 || len(cmdPayload)-1 > MaxPublicKeyBytes {
				m.respondStatus(BootErrInvalidArg)
				continue
			}
			m.lastKeySlot = cmdPayload[0]
			m.lastKey = append([]byte(nil), cmdPayload[1:]...)
			m.respondStatus(BootOK)
		case CmdSetDSLC:
			if len(cmdPayload) != 1 || cmdPayload[0] == 0x00 || cmdPayload[0] == 0xFF {
				m.respondStatus(BootErrInvalidArg)
				continue
			}
			m.dslc = cmdPayload[0]
			m.respondStatus(BootOK)
		case CmdSetProtection:
			if len(cmdPayload) != 4 {
				m.respondStatus(BootErrInvalidArg)
				continue
			}
			m.respondStatus(BootOK)
		case CmdEnableSB, CmdEnableFE, CmdReboot:
			m.respondStatus(BootOK)
		case CmdLockBootFlash:
			switch len(cmdPayload) {
			case 0:
				m.lockedOff = 0
				m.lockedSize = 0x8000
				m.lockedCount++
				m.respondStatus(BootOK)
			case 8:
				off := binary.LittleEndian.Uint32(cmdPayload[0:4])
				sz := binary.LittleEndian.Uint32(cmdPayload[4:8])
				if sz == 0 || math.MaxUint32-off < sz {
					m.respondStatus(BootErrInvalidArg)
					continue
				}
				m.lockedOff = off
				m.lockedSize = sz
				m.lockedCount++
				m.respondStatus(BootOK)
			default:
				m.respondStatus(BootErrInvalidArg)
			}
		default:
			m.respondStatus(BootErrNotSupported)
		}
	}
	return len(p), nil
}

func (m *mockDevice) respondStatus(code uint32) {
	var resp [4]byte
	binary.LittleEndian.PutUint32(resp[:], code)
	m.sendWireFrame(resp[:])
}

func TestProvisioningProtocol(t *testing.T) {
	for _, tc := range []struct {
		name       string
		withBanner bool
	}{
		{"with PROV announcement banner", true},
		{"without PROV announcement banner", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dev := newMockDevice(tc.withBanner)
			client := NewClient(dev)

			uid, err := client.ReadChipUID()
			if err != nil {
				t.Fatalf("ReadChipUID failed: %v", err)
			}
			expectedUID := []byte{0x60, 0x55, 0xF9, 0x11, 0x22, 0x33}
			if !bytes.Equal(uid, expectedUID) {
				t.Fatalf("UID mismatch: got %x, want %x", uid, expectedUID)
			}

			devID := DeriveDeviceID(uid, MockRootPublicKey)
			if devID == [32]byte{} {
				t.Fatal("Device ID derivation returned all zeroes")
			}

			if err := client.BurnPublicKey(0, MockRootPublicKey); err != nil {
				t.Fatalf("BurnPublicKey failed: %v", err)
			}
			if err := client.SetProtection(0x00000001); err != nil {
				t.Fatalf("SetProtection failed: %v", err)
			}
			if err := client.EnableSecureBoot(); err != nil {
				t.Fatalf("EnableSecureBoot failed: %v", err)
			}
			if err := client.EnableFlashEncryption(); err != nil {
				t.Fatalf("EnableFlashEncryption failed: %v", err)
			}
			if err := client.LockBootFlash(); err != nil {
				t.Fatalf("LockBootFlash failed: %v", err)
			}
			if dev.lockedCount != 1 || dev.lockedSize != 0x8000 {
				t.Fatalf("unexpected default lock state: count=%d size=0x%X", dev.lockedCount, dev.lockedSize)
			}
			if err := client.LockBootFlashRange(0x08000000, 0x00008000); err != nil {
				t.Fatalf("LockBootFlashRange failed: %v", err)
			}
			if dev.lockedCount != 2 || dev.lockedOff != 0x08000000 || dev.lockedSize != 0x8000 {
				t.Fatalf("unexpected custom lock range: off=0x%08X size=0x%X", dev.lockedOff, dev.lockedSize)
			}
			if err := client.SetDSLC(0x01); err != nil {
				t.Fatalf("SetDSLC failed: %v", err)
			}
			if dev.dslc != 0x01 {
				t.Fatalf("expected DSLC 0x01, got 0x%02X", dev.dslc)
			}
			if err := client.Reboot(); err != nil {
				t.Fatalf("Reboot failed: %v", err)
			}
		})
	}
}

func TestSyncDrainsBootBannerAndFlushesPartialRXState(t *testing.T) {
	dev := newMockDevice(false)
	// Simulate partial Stage-0 UART RX garbage sitting in the target's COBS receiver,
	// plus 512 bytes of ASCII ROM boot-banner noise + PROV banner in the host RX FIFO.
	dev.rxBuf.WriteString("PARTIAL_UART_GARBAGE")
	dev.txBuf.WriteString("ESP-ROM:esp32c6-20220919\r\nBuild:Sep 19 2022\r\nrst:0x1 (POWERON)\r\n")
	dev.txBuf.WriteString(strings.Repeat("BOOT_BANNER_LINE_EXCEEDING_256_BYTES_", 10))
	dev.sendWireFrame([]byte("PROV"))

	client := NewClient(dev)
	if err := client.Sync(); err != nil {
		t.Fatalf("Sync() failed on noisy boot stream: %v", err)
	}
	rawTx := dev.rawWireLog.Bytes()
	if len(rawTx) == 0 || rawTx[0] != 0x00 {
		t.Fatalf("expected Sync() to transmit leading 0x00 delimiter first, got %x", rawTx)
	}

	uid, err := client.ReadChipUID()
	if err != nil {
		t.Fatalf("ReadChipUID after Sync() failed: %v", err)
	}
	if !bytes.Equal(uid, dev.uid) {
		t.Fatalf("UID mismatch after Sync(): got %x, want %x", uid, dev.uid)
	}
}

func TestSyncExceedsDrainBudget(t *testing.T) {
	var noisy bytes.Buffer
	noisy.Write(bytes.Repeat([]byte("A"), MaxSyncDrainBytes+64))
	client := NewClient(&splitRW{r: &noisy, w: io.Discard})
	err := client.Sync()
	if err == nil || !strings.Contains(err.Error(), "drain budget") {
		t.Fatalf("expected Sync() drain budget error, got %v", err)
	}
}

type silentSerialMock struct {
	deadline time.Time
}

func (s *silentSerialMock) SetReadDeadline(t time.Time) error {
	s.deadline = t
	return nil
}

func (s *silentSerialMock) Read(_ []byte) (int, error) {
	if !s.deadline.IsZero() && time.Now().After(s.deadline) {
		return 0, os.ErrDeadlineExceeded
	}
	time.Sleep(5 * time.Millisecond)
	if !s.deadline.IsZero() && time.Now().After(s.deadline) {
		return 0, os.ErrDeadlineExceeded
	}
	return 0, nil
}

func (s *silentSerialMock) Write(p []byte) (int, error) {
	return len(p), nil
}

func TestSilentBoardTimeoutEnforced(t *testing.T) {
	silent := &silentSerialMock{}
	client := NewClientWithTimeout(silent, 35*time.Millisecond)

	start := time.Now()
	err := client.Sync()
	elapsed := time.Since(start)
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expected os.ErrDeadlineExceeded from Sync() on silent board, got %v", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("Sync() took %s instead of respecting 35ms timeout", elapsed)
	}

	start = time.Now()
	_, err = client.ReadChipUID()
	elapsed = time.Since(start)
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expected os.ErrDeadlineExceeded from ReadChipUID() on silent board, got %v", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("ReadChipUID() took %s instead of respecting 35ms timeout", elapsed)
	}
}

func TestSendFrameMaxWireFrameBodyLimit(t *testing.T) {
	var tx bytes.Buffer
	client := NewClient(&splitRW{r: &bytes.Buffer{}, w: &tx})

	// 252-byte payload + 1-byte cmd + 4-byte CRC32 = 257 raw bytes -> >256 COBS body bytes.
	oversizedPayload := bytes.Repeat([]byte{0x42}, 252)
	err := client.sendFrame(CmdBurnKey, oversizedPayload)
	if err == nil || !strings.Contains(err.Error(), "MaxWireFrameBody") {
		t.Fatalf("expected MaxWireFrameBody error, got %v", err)
	}
	if tx.Len() != 0 {
		t.Fatalf("expected 0 bytes transmitted on oversized frame, got %d", tx.Len())
	}
}

func TestBurnPublicKeyValidationAndVariableLengths(t *testing.T) {
	var tx bytes.Buffer
	rejectClient := NewClient(&splitRW{r: &bytes.Buffer{}, w: &tx})

	// Empty, all-zero, wrong-length Ed25519 slot 0, and >128B keys must fail before transmitting.
	badInputs := []struct {
		slot uint8
		algo string
		key  []byte
	}{
		{0, "", nil},
		{0, "", make([]byte, 32)},
		{0, "", bytes.Repeat([]byte{0xAA}, 64)},
		{1, "", make([]byte, 64)},
		{1, "", bytes.Repeat([]byte{0xAA}, 8)},
		{1, "", bytes.Repeat([]byte{0xAA}, MaxPublicKeyBytes+1)},
		{0, "ed25519", bytes.Repeat([]byte{0xAA}, 48)},
		{1, "unknown-algo", MockRootPublicKey},
	}
	for i, tc := range badInputs {
		if err := rejectClient.BurnPublicKeyWithAlgorithm(tc.slot, tc.algo, tc.key); err == nil {
			t.Fatalf("case %d: expected error for slot=%d algo=%q len=%d", i, tc.slot, tc.algo, len(tc.key))
		}
		if tx.Len() != 0 {
			t.Fatalf("case %d: transmitted %d bytes before failing validation", i, tx.Len())
		}
	}

	// Valid variable-length PQC/custom slot keys succeed cleanly up to MaxPublicKeyBytes (128B).
	dev := newMockDevice(true)
	client := NewClient(dev)
	pqcAnchor64 := bytes.Repeat([]byte{0x5A}, 64)
	if err := client.BurnPublicKey(1, pqcAnchor64); err != nil {
		t.Fatalf("BurnPublicKey(slot=1, 64B PQC anchor) failed: %v", err)
	}
	if dev.lastKeySlot != 1 || !bytes.Equal(dev.lastKey, pqcAnchor64) {
		t.Fatalf("unexpected burned key: slot=%d len=%d", dev.lastKeySlot, len(dev.lastKey))
	}

	custom128 := bytes.Repeat([]byte{0x3C}, MaxPublicKeyBytes)
	if err := client.BurnPublicKeyWithAlgorithm(2, "custom", custom128); err != nil {
		t.Fatalf("BurnPublicKeyWithAlgorithm(slot=2, 128B custom) failed: %v", err)
	}
	if dev.lastKeySlot != 2 || !bytes.Equal(dev.lastKey, custom128) {
		t.Fatalf("unexpected burned custom key: slot=%d len=%d", dev.lastKeySlot, len(dev.lastKey))
	}

	mlDSA48 := bytes.Repeat([]byte{0x7E}, 48)
	if err := client.BurnPublicKeyWithAlgorithm(0, "ml-dsa-65", mlDSA48); err != nil {
		t.Fatalf("BurnPublicKeyWithAlgorithm(slot=0, ml-dsa-65 48B) failed: %v", err)
	}
}

type errWriter struct {
	err error
}

func (e errWriter) Write(_ []byte) (int, error) { return 0, e.err }

func TestRebootPropagatesWriteError(t *testing.T) {
	wantErr := errors.New("serial cable unplugged")
	client := NewClient(&splitRW{r: &bytes.Buffer{}, w: errWriter{err: wantErr}})
	err := client.Reboot()
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected Reboot() to propagate write error %v, got %v", wantErr, err)
	}
}

func TestOpenSerialValidation(t *testing.T) {
	if _, err := OpenSerial("", DefaultBaudRate, DefaultReadTimeout); err == nil {
		t.Fatal("expected error for empty serial port name")
	}
	if _, err := OpenSerial("COM3\x00bad", DefaultBaudRate, DefaultReadTimeout); err == nil {
		t.Fatal("expected error for NUL byte in serial port name")
	}
	if _, err := OpenSerial("COM3", 0, DefaultReadTimeout); err == nil {
		t.Fatal("expected error for zero baud rate")
	}
	if _, err := OpenSerial("COM3", DefaultBaudRate, 0); err == nil {
		t.Fatal("expected error for non-positive readTimeout")
	}
	if _, err := OpenSerial("COM254", DefaultBaudRate, 50*time.Millisecond); err == nil {
		t.Fatal("expected error opening non-existent serial port COM254")
	}
}

func TestProvisioningTrailingZeroPayloadsAndSyncBytes(t *testing.T) {
	for _, wantUID := range [][]byte{
		{0x00},
		{0x60, 0x55, 0xF9, 0x11, 0x22, 0x00},
		{0x00, 0xAA, 0x00, 0x00},
	} {
		dev := newMockDevice(false)
		dev.uid = wantUID
		dev.txBuf.Write([]byte{0x00, 0x00, 0x00})
		dev.sendWireFrame([]byte("PROV"))
		dev.txBuf.Write([]byte{0x00, 0x00})

		client := NewClient(dev)
		gotUID, err := client.ReadChipUID()
		if err != nil {
			t.Fatalf("ReadChipUID(%x) failed: %v", wantUID, err)
		}
		if !bytes.Equal(gotUID, wantUID) {
			t.Fatalf("UID trailing-zero mismatch: got %x, want %x", gotUID, wantUID)
		}
	}

	dev := newMockDevice(true)
	client := NewClient(dev)
	var maskWithTrailingZeroCRC uint32
	found := false
	for cand := uint32(1); cand < 100000; cand++ {
		var msg [5]byte
		msg[0] = CmdSetProtection
		binary.LittleEndian.PutUint32(msg[1:5], cand)
		crc := crc32.ChecksumIEEE(msg[:])
		if (crc >> 24) == 0x00 {
			maskWithTrailingZeroCRC = cand
			found = true
			break
		}
	}
	if !found {
		t.Fatal("failed to find SetProtection bitmask whose LE CRC32 ends in 0x00")
	}
	if err := client.SetProtection(maskWithTrailingZeroCRC); err != nil {
		t.Fatalf("SetProtection(0x%08X) with trailing-zero CRC32 failed: %v", maskWithTrailingZeroCRC, err)
	}
}

func TestProvisioningPROVBannerOnlySkippedOnce(t *testing.T) {
	var wire bytes.Buffer
	var okBytes [4]byte
	binary.LittleEndian.PutUint32(okBytes[:], BootOK)

	wire.WriteByte(0x00)
	wire.Write(cobs.Encode([]byte("PROV")))
	wire.WriteByte(0x00)
	wire.Write(cobs.Encode(okBytes[:]))
	wire.WriteByte(0x00)
	wire.Write(cobs.Encode([]byte("PROV")))

	rw := &splitRW{r: &wire, w: io.Discard}
	client := NewClient(rw)
	if err := client.EnableSecureBoot(); err != nil {
		t.Fatalf("first command should skip initial PROV banner: %v", err)
	}
	err := client.EnableFlashEncryption()
	var stErr *StatusError
	if !errors.As(err, &stErr) || stErr.Code != 0x564F5250 {
		t.Fatalf("expected rogue second PROV frame to fail with StatusError 0x564F5250, got %v", err)
	}
}

type splitRW struct {
	r io.Reader
	w io.Writer
}

func (s *splitRW) Read(p []byte) (int, error)  { return s.r.Read(p) }
func (s *splitRW) Write(p []byte) (int, error) { return s.w.Write(p) }

func TestSetDSLCAndLockBootFlashClientValidation(t *testing.T) {
	var txCapture bytes.Buffer
	client := NewClient(&splitRW{r: &bytes.Buffer{}, w: &txCapture})

	for _, badDSLC := range []byte{0x00, 0xFF} {
		if err := client.SetDSLC(badDSLC); err == nil {
			t.Fatalf("SetDSLC(0x%02X) must be rejected client-side", badDSLC)
		}
		if txCapture.Len() != 0 {
			t.Fatalf("SetDSLC(0x%02X) transmitted %d bytes before failing", badDSLC, txCapture.Len())
		}
	}

	for _, badRange := range [][2]uint32{
		{0x00000000, 0},
		{0xFFFFF000, 0x1000},
		{0xFFFFFFFF, 1},
		{0x80000000, 0x80000000},
	} {
		if err := client.LockBootFlashRange(badRange[0], badRange[1]); err == nil {
			t.Fatalf("LockBootFlashRange(0x%X, 0x%X) must be rejected client-side", badRange[0], badRange[1])
		}
		if txCapture.Len() != 0 {
			t.Fatalf("LockBootFlashRange(0x%X, 0x%X) transmitted %d bytes before failing", badRange[0], badRange[1], txCapture.Len())
		}
	}

	dev := newMockDevice(true)
	validClient := NewClient(dev)
	if err := validClient.LockBootFlashRange(0xFFFFF000, 0x0FFF); err != nil {
		t.Fatalf("expected boundary LockBootFlashRange(0xFFFFF000, 0x0FFF) to succeed, got %v", err)
	}
}

func TestProvisioningTamperAndStatusDecoding(t *testing.T) {
	dev := newMockDevice(true)
	client := NewClient(dev)
	if err := client.sendFrame(0x42, []byte{0x01, 0x02}); err != nil {
		t.Fatalf("sendFrame failed: %v", err)
	}
	err := client.recvStatus()
	var stErr *StatusError
	if !errors.As(err, &stErr) || stErr.Code != BootErrNotSupported {
		t.Fatalf("expected StatusError(BootErrNotSupported), got %v", err)
	}
	if !strings.Contains(stErr.Error(), "BOOT_ERR_NOT_SUPPORTED") || !strings.Contains(stErr.Error(), "0xE8282828") {
		t.Fatalf("unexpected StatusError message: %s", stErr.Error())
	}

	allCodes := map[uint32]string{
		BootOK:                   "BOOT_OK",
		BootErrFlash:             "BOOT_ERR_FLASH",
		BootErrFlashAlign:        "BOOT_ERR_FLASH_ALIGN",
		BootErrFlashBounds:       "BOOT_ERR_FLASH_BOUNDS",
		BootErrCrypto:            "BOOT_ERR_CRYPTO",
		BootErrVerify:            "BOOT_ERR_VERIFY",
		BootErrTimeout:           "BOOT_ERR_TIMEOUT",
		BootErrPower:             "BOOT_ERR_POWER",
		BootErrNotSupported:      "BOOT_ERR_NOT_SUPPORTED",
		BootErrInvalidArg:        "BOOT_ERR_INVALID_ARG",
		BootErrState:             "BOOT_ERR_STATE",
		BootErrFlashNotErased:    "BOOT_ERR_FLASH_NOT_ERASED",
		BootErrCounterExhausted:  "BOOT_ERR_COUNTER_EXHAUSTED",
		BootErrDefer:             "BOOT_ERR_DEFER",
		BootErrECCHardfault:      "BOOT_ERR_ECC_HARDFAULT",
		BootErrFlashHW:           "BOOT_ERR_FLASH_HW",
		BootErrNotFound:          "BOOT_ERR_NOT_FOUND",
		BootErrWDTTrigger:        "BOOT_ERR_WDT_TRIGGER",
		BootErrInvalidState:      "BOOT_ERR_INVALID_STATE",
		BootErrWALFull:           "BOOT_ERR_WAL_FULL",
		BootErrWALLocked:         "BOOT_ERR_WAL_LOCKED",
		BootRecoveryRequested:    "BOOT_RECOVERY_REQUESTED",
		BootErrABIMismatch:       "BOOT_ERR_ABI_MISMATCH",
		BootErrDowngrade:         "BOOT_ERR_DOWNGRADE",
		BootErrDeviceLocked:      "BOOT_ERR_DEVICE_LOCKED",
		BootErrCmdReplay:         "BOOT_ERR_CMD_REPLAY",
		BootErrCmdDeviceMismatch: "BOOT_ERR_CMD_DEVICE_MISMATCH",
		BootErrManifestCorrupt:   "BOOT_ERR_MANIFEST_CORRUPT",
		BootErrManifestVersion:   "BOOT_ERR_MANIFEST_VERSION",
		BootErrManifestProduct:   "BOOT_ERR_MANIFEST_PRODUCT",
	}
	if len(allCodes) != 30 {
		t.Fatalf("duplicate boot_status_t constant value detected: map has %d entries, want 30", len(allCodes))
	}
	for code, wantName := range allCodes {
		if got := StatusName(code); got != wantName {
			t.Errorf("StatusName(0x%08X) = %q, want %q", code, got, wantName)
		}
		if code != BootOK {
			msg := (&StatusError{Code: code}).Error()
			if !strings.Contains(msg, wantName) {
				t.Errorf("StatusError(0x%08X).Error() = %q, missing %q", code, msg, wantName)
			}
		}
	}
	if got := (&StatusError{Code: 0xDEADBEEF}).Error(); !strings.Contains(got, "0xDEADBEEF") {
		t.Errorf("unexpected unknown StatusError format: %q", got)
	}
}

func FuzzProvisionClientUntrustedWire(f *testing.F) {
	var okStatus [4]byte
	binary.LittleEndian.PutUint32(okStatus[:], BootOK)
	validReadIDStream := append([]byte{0x00}, cobs.Encode([]byte("PROV"))...)
	validReadIDStream = append(validReadIDStream, 0x00)
	validReadIDStream = append(validReadIDStream, cobs.Encode(okStatus[:])...)
	validReadIDStream = append(validReadIDStream, 0x00)
	validReadIDStream = append(validReadIDStream, cobs.Encode([]byte{0x11, 0x22, 0x00})...)

	f.Add(validReadIDStream)
	f.Add([]byte{})
	f.Add([]byte{0x00, 0x00, 0x00})
	f.Add(bytes.Repeat([]byte{0xFF}, 1100))
	f.Add([]byte{0x00, 0x05, 'P', 'R', 'O', 'V', 0x00, 0x05, 0x39, 0x39, 0x39, 0xE9, 0x00})

	f.Fuzz(func(_ *testing.T, wire []byte) {
		if len(wire) > 8192 {
			return
		}
		c1 := NewClient(&splitRW{r: bytes.NewReader(wire), w: io.Discard})
		_, _ = c1.ReadChipUID()

		c2 := NewClient(&splitRW{r: bytes.NewReader(wire), w: io.Discard})
		_ = c2.Sync()
		_ = c2.BurnPublicKey(0, MockRootPublicKey)
		_ = c2.LockBootFlash()
		_ = c2.SetDSLC(0x01)
	})
}
