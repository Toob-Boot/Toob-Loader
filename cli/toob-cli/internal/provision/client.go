package provision

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"math"
	"os"
	"strings"
	"time"

	"github.com/toob-boot/toob/internal/cobs"
)

// Opcodes matching toobloader/core/include/boot_provisioning.h.
const (
	CmdSync          byte = 0x00
	CmdBurnKey       byte = 0x01
	CmdSetDSLC       byte = 0x02
	CmdSetProtection byte = 0x03
	CmdEnableSB      byte = 0x04
	CmdEnableFE      byte = 0x05
	CmdReadID        byte = 0x06
	CmdLockBootFlash byte = 0x07
	CmdReboot        byte = 0xFF
)

// Wire protocol sizing limits matching toobloader/core/boot_provisioning.c.
const (
	// MaxWireFrameBody is PROV_RX_MAX_SIZE (maximum COBS-encoded frame body excluding 0x00 delimiters).
	MaxWireFrameBody = 256
	// MaxPublicKeyBytes is PROV_KEY_MAX_SIZE (maximum key material payload accepted by Stage-1 provisioning).
	MaxPublicKeyBytes = 128
	// Ed25519PublicKeyBytes is the canonical RFC 8032 Ed25519 public key length.
	Ed25519PublicKeyBytes = 32
	// MinCustomPublicKeyBytes is the minimum length accepted for non-Ed25519 custom/PQC key anchor slots.
	MinCustomPublicKeyBytes = 16
	// MaxSyncDrainBytes bounds pre-sync ASCII boot-banner noise drained during Sync().
	MaxSyncDrainBytes = 4096

	maxConsecutiveEmptyReads = 1000
)

// Boot status codes matching common/include/boot_types.h 1:1 (CRIT-32a).
const (
	BootOK uint32 = 0x55AA55AA

	// HAL Errors
	BootErrFlash            uint32 = 0xE1A1A1A1
	BootErrFlashAlign       uint32 = 0xE2B2B2B2
	BootErrFlashBounds      uint32 = 0xE3C3C3C3
	BootErrCrypto           uint32 = 0xE4D4D4D4
	BootErrVerify           uint32 = 0xE5E5E5E5
	BootErrTimeout          uint32 = 0xE6F6F6F6
	BootErrPower            uint32 = 0xE7171717
	BootErrNotSupported     uint32 = 0xE8282828
	BootErrNotSupp          uint32 = BootErrNotSupported
	BootErrInvalidArg       uint32 = 0xE9393939
	BootErrState            uint32 = 0xEA4A4A4A
	BootErrFlashNotErased   uint32 = 0xEB5B5B5B
	BootErrCounterExhausted uint32 = 0xEC6C6C6C
	BootErrDefer            uint32 = 0xEC7C7C7C
	BootErrECCHardfault     uint32 = 0xED7D7D7D
	BootErrFlashHW          uint32 = 0xEE8E8E8E

	// Core State-Machine Errors
	BootErrNotFound       uint32 = 0xF1818181
	BootErrWDTTrigger     uint32 = 0xF2929292
	BootErrInvalidState   uint32 = 0xF3A3A3A3
	BootErrWALFull        uint32 = 0xF4B4B4B4
	BootErrWALLocked      uint32 = 0xF5C5C5C5
	BootRecoveryRequested uint32 = 0xF6D6D6D6
	BootErrABIMismatch    uint32 = 0xF7E7E7E7
	BootErrDowngrade      uint32 = 0xF8F8F8F8

	// Cloud Command Errors
	BootErrDeviceLocked      uint32 = 0xF9090909
	BootErrCmdReplay         uint32 = 0xFA1A1A1A
	BootErrCmdDeviceMismatch uint32 = 0xFB2B2B2B

	// TBM1 Manifest Errors
	BootErrManifestCorrupt uint32 = 0xFC3C3C3C
	BootErrManifestVersion uint32 = 0xFC4D4D4D
	BootErrManifestProduct uint32 = 0xFC5E5E5E
)

var provBanner = []byte("PROV")

// StatusName returns the symbolic boot_status_t name from common/include/boot_types.h,
// or "" when code does not match a defined status constant.
func StatusName(code uint32) string {
	switch code {
	case BootOK:
		return "BOOT_OK"
	case BootErrFlash:
		return "BOOT_ERR_FLASH"
	case BootErrFlashAlign:
		return "BOOT_ERR_FLASH_ALIGN"
	case BootErrFlashBounds:
		return "BOOT_ERR_FLASH_BOUNDS"
	case BootErrCrypto:
		return "BOOT_ERR_CRYPTO"
	case BootErrVerify:
		return "BOOT_ERR_VERIFY"
	case BootErrTimeout:
		return "BOOT_ERR_TIMEOUT"
	case BootErrPower:
		return "BOOT_ERR_POWER"
	case BootErrNotSupported:
		return "BOOT_ERR_NOT_SUPPORTED"
	case BootErrInvalidArg:
		return "BOOT_ERR_INVALID_ARG"
	case BootErrState:
		return "BOOT_ERR_STATE"
	case BootErrFlashNotErased:
		return "BOOT_ERR_FLASH_NOT_ERASED"
	case BootErrCounterExhausted:
		return "BOOT_ERR_COUNTER_EXHAUSTED"
	case BootErrDefer:
		return "BOOT_ERR_DEFER"
	case BootErrECCHardfault:
		return "BOOT_ERR_ECC_HARDFAULT"
	case BootErrFlashHW:
		return "BOOT_ERR_FLASH_HW"
	case BootErrNotFound:
		return "BOOT_ERR_NOT_FOUND"
	case BootErrWDTTrigger:
		return "BOOT_ERR_WDT_TRIGGER"
	case BootErrInvalidState:
		return "BOOT_ERR_INVALID_STATE"
	case BootErrWALFull:
		return "BOOT_ERR_WAL_FULL"
	case BootErrWALLocked:
		return "BOOT_ERR_WAL_LOCKED"
	case BootRecoveryRequested:
		return "BOOT_RECOVERY_REQUESTED"
	case BootErrABIMismatch:
		return "BOOT_ERR_ABI_MISMATCH"
	case BootErrDowngrade:
		return "BOOT_ERR_DOWNGRADE"
	case BootErrDeviceLocked:
		return "BOOT_ERR_DEVICE_LOCKED"
	case BootErrCmdReplay:
		return "BOOT_ERR_CMD_REPLAY"
	case BootErrCmdDeviceMismatch:
		return "BOOT_ERR_CMD_DEVICE_MISMATCH"
	case BootErrManifestCorrupt:
		return "BOOT_ERR_MANIFEST_CORRUPT"
	case BootErrManifestVersion:
		return "BOOT_ERR_MANIFEST_VERSION"
	case BootErrManifestProduct:
		return "BOOT_ERR_MANIFEST_PRODUCT"
	default:
		return ""
	}
}

// StatusError wraps a non-BootOK bootloader status code.
type StatusError struct {
	Code uint32
}

func (e *StatusError) Error() string {
	if name := StatusName(e.Code); name != "" {
		return fmt.Sprintf("provision: bootloader rejected command with status %s (0x%08X)", name, e.Code)
	}
	return fmt.Sprintf("provision: bootloader rejected command with status 0x%08X", e.Code)
}

type readDeadliner interface {
	SetReadDeadline(t time.Time) error
}

// Client coordinates factory provisioning over a stream (serial port, pipe, etc.).
type Client struct {
	rw         io.ReadWriter
	timeout    time.Duration
	statusSeen bool
}

// NewClient creates a new provisioning client with DefaultReadTimeout.
func NewClient(rw io.ReadWriter) *Client {
	return &Client{
		rw:      rw,
		timeout: DefaultReadTimeout,
	}
}

// NewClientWithTimeout creates a provisioning client with an explicit per-operation timeout.
func NewClientWithTimeout(rw io.ReadWriter, timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = DefaultReadTimeout
	}
	return &Client{
		rw:      rw,
		timeout: timeout,
	}
}

// SetTimeout updates the per-operation read/sync timeout on the client.
func (c *Client) SetTimeout(timeout time.Duration) {
	if timeout > 0 {
		c.timeout = timeout
	}
}

func (c *Client) effectiveTimeout() time.Duration {
	if c.timeout <= 0 {
		return DefaultReadTimeout
	}
	return c.timeout
}

func (c *Client) applyReadDeadline(deadline time.Time) func() {
	dl, ok := c.rw.(readDeadliner)
	if !ok {
		return func() {}
	}
	_ = dl.SetReadDeadline(deadline)
	return func() {
		_ = dl.SetReadDeadline(time.Time{})
	}
}

func writeAll(w io.Writer, data []byte) error {
	if w == nil {
		return errors.New("provision: nil transport writer")
	}
	total := 0
	for total < len(data) {
		n, err := w.Write(data[total:])
		if n > 0 {
			total += n
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

// sendFrame formats [cmd][payload][crc32 LE], applies COBS encoding, validates
// that the COBS body fits PROV_RX_MAX_SIZE (256 bytes), and transmits it.
func (c *Client) sendFrame(cmd byte, payload []byte) error {
	msg := make([]byte, 1+len(payload)+4)
	msg[0] = cmd
	copy(msg[1:], payload)

	crc := crc32.ChecksumIEEE(msg[:1+len(payload)])
	binary.LittleEndian.PutUint32(msg[1+len(payload):], crc)

	encoded := cobs.Encode(msg)
	bodyLen := len(encoded) - 1
	if bodyLen > MaxWireFrameBody {
		return fmt.Errorf("provision: encoded frame body (%d bytes) exceeds MaxWireFrameBody (%d bytes)",
			bodyLen, MaxWireFrameBody)
	}
	return writeAll(c.rw, encoded)
}

// Sync flushes any partial Stage-0 UART RX state with a leading 0x00 delimiter,
// sends a COBS sync probe, and drains pre-sync ASCII boot-banner noise within
// a bounded byte and time budget until the bootloader ACK frame arrives.
func (c *Client) Sync() error {
	timeout := c.effectiveTimeout()
	deadline := time.Now().Add(timeout)
	clearDeadline := c.applyReadDeadline(deadline)
	defer clearDeadline()

	// Leading 0x00 flushes any partial UART RX noise accumulated before host attach.
	if err := writeAll(c.rw, []byte{0x00}); err != nil {
		return fmt.Errorf("send sync delimiter: %w", err)
	}
	if err := c.sendFrame(CmdSync, nil); err != nil {
		return fmt.Errorf("send sync probe: %w", err)
	}

	var frameBuf []byte
	var single [1]byte
	oversized := false
	drainedBytes := 0
	emptyReads := 0

	for {
		if time.Now().After(deadline) {
			return fmt.Errorf("provision: sync timed out after %s: %w", timeout, os.ErrDeadlineExceeded)
		}

		n, err := c.rw.Read(single[:])
		if n > 0 {
			emptyReads = 0
			drainedBytes++
			if drainedBytes > MaxSyncDrainBytes {
				return fmt.Errorf("provision: sync exceeded %d-byte boot-noise drain budget", MaxSyncDrainBytes)
			}

			b := single[0]
			if b == 0x00 {
				if !oversized && len(frameBuf) > 0 {
					if decoded, decErr := cobs.Decode(frameBuf); decErr == nil && len(decoded) == 4 {
						code := binary.LittleEndian.Uint32(decoded)
						if code == BootOK || code == BootErrNotSupported {
							c.statusSeen = true
							return nil
						}
					}
				}
				frameBuf = frameBuf[:0]
				oversized = false
				continue
			}

			if !oversized {
				if len(frameBuf) >= MaxWireFrameBody {
					oversized = true
					frameBuf = frameBuf[:0]
				} else {
					frameBuf = append(frameBuf, b)
				}
			}
		}

		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				return fmt.Errorf("provision: sync timed out after %s: %w", timeout, err)
			}
			return fmt.Errorf("provision: sync failed waiting for ACK: %w", err)
		}
		if n == 0 {
			emptyReads++
			if emptyReads > maxConsecutiveEmptyReads {
				return io.ErrNoProgress
			}
		}
	}
}

// recvFrame reads bytes until a non-empty 0x00-delimited COBS frame is received,
// skipping leading/consecutive 0x00 sync markers emitted by boot_cobs_send_frame (CRIT-32b)
// while enforcing Client.timeout and MaxWireFrameBody.
func (c *Client) recvFrame() ([]byte, error) {
	if c.rw == nil {
		return nil, errors.New("provision: nil transport reader")
	}

	timeout := c.effectiveTimeout()
	deadline := time.Now().Add(timeout)
	clearDeadline := c.applyReadDeadline(deadline)
	defer clearDeadline()

	var buf []byte
	var single [1]byte
	emptyReads := 0

	for {
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("provision: timed out waiting for frame after %s: %w", timeout, os.ErrDeadlineExceeded)
		}

		n, err := c.rw.Read(single[:])
		if n > 0 {
			emptyReads = 0
			if single[0] == 0x00 {
				if len(buf) == 0 {
					continue
				}
				return cobs.Decode(buf)
			}
			buf = append(buf, single[0])
			if len(buf) > MaxWireFrameBody {
				return nil, errors.New("provision: frame exceeded maximum allowed length")
			}
		}
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				return nil, fmt.Errorf("provision: timed out waiting for frame after %s: %w", timeout, err)
			}
			return nil, err
		}
		if n == 0 {
			emptyReads++
			if emptyReads > maxConsecutiveEmptyReads {
				return nil, io.ErrNoProgress
			}
		}
	}
}

// recvStatus reads a 4-byte LE status response frame, transparently skipping
// a buffered "PROV" announcement banner at most once before the first status (CRIT-32c).
func (c *Client) recvStatus() error {
	frame, err := c.recvFrame()
	if err != nil {
		return fmt.Errorf("read status frame: %w", err)
	}
	if !c.statusSeen {
		c.statusSeen = true
		if bytes.Equal(frame, provBanner) {
			frame, err = c.recvFrame()
			if err != nil {
				return fmt.Errorf("read status frame after PROV banner: %w", err)
			}
		}
	}
	if len(frame) != 4 {
		return fmt.Errorf("invalid status frame length: expected 4, got %d", len(frame))
	}

	statusCode := binary.LittleEndian.Uint32(frame)
	if statusCode != BootOK {
		return &StatusError{Code: statusCode}
	}
	return nil
}

// ReadChipUID requests the silicon hardware UID/MAC address from the target.
func (c *Client) ReadChipUID() ([]byte, error) {
	if err := c.sendFrame(CmdReadID, nil); err != nil {
		return nil, fmt.Errorf("send ReadID: %w", err)
	}

	if err := c.recvStatus(); err != nil {
		return nil, err
	}

	uidFrame, err := c.recvFrame()
	if err != nil {
		return nil, fmt.Errorf("read UID frame: %w", err)
	}
	if len(uidFrame) == 0 {
		return nil, errors.New("received empty UID from device")
	}
	return uidFrame, nil
}

func isAllZeroBytes(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

func validatePublicKeyForSlot(keyIndex uint8, algorithm string, pubKey []byte) error {
	if len(pubKey) == 0 {
		return errors.New("provision: public key must not be empty")
	}
	if len(pubKey) > MaxPublicKeyBytes {
		return fmt.Errorf("provision: public key length (%d bytes) exceeds maximum %d bytes", len(pubKey), MaxPublicKeyBytes)
	}
	if isAllZeroBytes(pubKey) {
		return errors.New("provision: refusing to burn all-zero public key")
	}

	algo := strings.ToLower(strings.TrimSpace(algorithm))
	switch algo {
	case "":
		if keyIndex == 0 && len(pubKey) != Ed25519PublicKeyBytes {
			return fmt.Errorf("provision: Ed25519 root public key for slot 0 must be %d bytes, got %d",
				Ed25519PublicKeyBytes, len(pubKey))
		}
		if keyIndex > 0 && len(pubKey) < MinCustomPublicKeyBytes {
			return fmt.Errorf("provision: public key for slot %d must be at least %d bytes, got %d",
				keyIndex, MinCustomPublicKeyBytes, len(pubKey))
		}
	case "ed25519":
		if len(pubKey) != Ed25519PublicKeyBytes {
			return fmt.Errorf("provision: Ed25519 public key must be %d bytes, got %d", Ed25519PublicKeyBytes, len(pubKey))
		}
	case "ecdsa-p256", "p256":
		if len(pubKey) != 32 && len(pubKey) != 64 && len(pubKey) != 65 {
			return fmt.Errorf("provision: ECDSA-P256 public key/digest must be 32, 64, or 65 bytes, got %d", len(pubKey))
		}
	case "ed448":
		if len(pubKey) != 57 {
			return fmt.Errorf("provision: Ed448 public key must be 57 bytes, got %d", len(pubKey))
		}
	case "pqc", "ml-dsa-65", "sha256", "sha384", "sha512":
		if len(pubKey) != 32 && len(pubKey) != 48 && len(pubKey) != 64 {
			return fmt.Errorf("provision: %s public key anchor must be 32, 48, or 64 bytes, got %d", algo, len(pubKey))
		}
	case "custom":
		if len(pubKey) < MinCustomPublicKeyBytes {
			return fmt.Errorf("provision: custom public key must be between %d and %d bytes, got %d",
				MinCustomPublicKeyBytes, MaxPublicKeyBytes, len(pubKey))
		}
	default:
		return fmt.Errorf("provision: unsupported public key algorithm %q", algorithm)
	}
	return nil
}

// BurnPublicKey burns a public key into the specified eFuse/OTP slot.
// Slot 0 enforces the 32-byte Ed25519 root key length; secondary slots (1..255)
// accept algorithm-appropriate PQC/custom key anchors (16..128 bytes).
func (c *Client) BurnPublicKey(keyIndex uint8, pubKey []byte) error {
	return c.BurnPublicKeyWithAlgorithm(keyIndex, "", pubKey)
}

// BurnPublicKeyWithAlgorithm burns a public key validated against an explicit
// algorithm profile ("ed25519", "ecdsa-p256", "ed448", "ml-dsa-65", "pqc", "custom").
func (c *Client) BurnPublicKeyWithAlgorithm(keyIndex uint8, algorithm string, pubKey []byte) error {
	if err := validatePublicKeyForSlot(keyIndex, algorithm, pubKey); err != nil {
		return err
	}
	payload := make([]byte, 1+len(pubKey))
	payload[0] = keyIndex
	copy(payload[1:], pubKey)

	if err := c.sendFrame(CmdBurnKey, payload); err != nil {
		return fmt.Errorf("send BurnKey: %w", err)
	}
	return c.recvStatus()
}

// SetDSLC writes the Device Security Life Cycle state (e.g. 0x01 = PROVISIONED).
// Rejects 0x00 (unprovisioned DEVELOPMENT) and 0xFF (irreversible decommission) client-side (CRIT-31).
func (c *Client) SetDSLC(dslc byte) error {
	if dslc == 0x00 {
		return errors.New("provision: invalid DSLC value 0x00 (unprovisioned DEVELOPMENT state)")
	}
	if dslc == 0xFF {
		return errors.New("provision: refusing DSLC value 0xFF (permanently decommissions/bricks device)")
	}
	if err := c.sendFrame(CmdSetDSLC, []byte{dslc}); err != nil {
		return fmt.Errorf("send SetDSLC: %w", err)
	}
	return c.recvStatus()
}

// SetProtection writes hardware protection bits (e.g., JTAG disable).
func (c *Client) SetProtection(bitmask uint32) error {
	payload := make([]byte, 4)
	binary.LittleEndian.PutUint32(payload, bitmask)

	if err := c.sendFrame(CmdSetProtection, payload); err != nil {
		return fmt.Errorf("send SetProtection: %w", err)
	}
	return c.recvStatus()
}

// EnableSecureBoot enables hardware secure boot.
func (c *Client) EnableSecureBoot() error {
	if err := c.sendFrame(CmdEnableSB, nil); err != nil {
		return fmt.Errorf("send EnableSB: %w", err)
	}
	return c.recvStatus()
}

// EnableFlashEncryption enables hardware transparent flash encryption.
func (c *Client) EnableFlashEncryption() error {
	if err := c.sendFrame(CmdEnableFE, nil); err != nil {
		return fmt.Errorf("send EnableFE: %w", err)
	}
	return c.recvStatus()
}

// LockBootFlash write-protects the default immutable Stage 0 boot flash region (0-byte payload).
func (c *Client) LockBootFlash() error {
	if err := c.sendFrame(CmdLockBootFlash, nil); err != nil {
		return fmt.Errorf("send LockBootFlash: %w", err)
	}
	return c.recvStatus()
}

// LockBootFlashRange write-protects an explicit [offset, offset+size) flash range (8-byte LE payload).
func (c *Client) LockBootFlashRange(offset, size uint32) error {
	if size == 0 {
		return errors.New("provision: lock boot flash size must be greater than zero")
	}
	if uint64(offset)+uint64(size) > math.MaxUint32 {
		return fmt.Errorf("provision: lock boot flash range [0x%08X..0x%X) overflows uint32",
			offset, uint64(offset)+uint64(size))
	}
	var payload [8]byte
	binary.LittleEndian.PutUint32(payload[0:4], offset)
	binary.LittleEndian.PutUint32(payload[4:8], size)

	if err := c.sendFrame(CmdLockBootFlash, payload[:]); err != nil {
		return fmt.Errorf("send LockBootFlashRange: %w", err)
	}
	return c.recvStatus()
}

// Reboot commands the device to reboot into the provisioned OS.
func (c *Client) Reboot() error {
	if err := c.sendFrame(CmdReboot, nil); err != nil {
		return fmt.Errorf("send Reboot: %w", err)
	}
	return c.recvStatus()
}

// DeriveDeviceID deterministically derives the 32-byte Device ID from chip UID and Root Pubkey:
// SHA-256(chipUID || rootPubkey || "toob-device-id-v1")
func DeriveDeviceID(chipUID, rootPubkey []byte) [32]byte {
	h := sha256.New()
	h.Write(chipUID)
	h.Write(rootPubkey)
	h.Write([]byte("toob-device-id-v1"))
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// MockRootPublicKey is the RFC 8032 Test Vector 1 Root Public Key (matches efuse_mock.c).
var MockRootPublicKey = []byte{
	0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
	0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
	0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
	0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
}

// MockRootPrivateKeySeedHex is the RFC 8032 TV1 seed matching MockRootPublicKey.
const MockRootPrivateKeySeedHex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
