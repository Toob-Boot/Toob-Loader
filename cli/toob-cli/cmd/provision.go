package cmd

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/toob-boot/toob/internal/manifest"
	"github.com/toob-boot/toob/internal/provision"
	"github.com/toob-boot/toob/internal/ui"
)

type provisionCommonOpts struct {
	port         string
	baud         uint32
	hardwarePath string
	timeout      time.Duration
	yes          bool
}

func registerProvisionCommonFlags(c *cobra.Command, opts *provisionCommonOpts, withYes bool) {
	c.Flags().StringVarP(&opts.port, "port", "p", "", "Serial device path (e.g. COM3, /dev/ttyACM0) (required)")
	c.Flags().Uint32Var(&opts.baud, "baud", 0, "Serial baud rate (defaults to 115200)")
	c.Flags().StringVar(&opts.hardwarePath, "hardware", "", "Optional hardware.json path for validation context")
	c.Flags().DurationVar(&opts.timeout, "timeout", provision.DefaultReadTimeout, "Serial response read timeout")
	_ = c.MarkFlagRequired("port")
	if withYes {
		c.Flags().BoolVarP(&opts.yes, "yes", "y", false, "Confirm irreversible hardware fuse/flash writes without prompting")
	}
}

func openProvisionClient(opts provisionCommonOpts) (*provision.Client, func(), error) {
	baud, err := resolveProvisionBaud(opts.baud, opts.hardwarePath)
	if err != nil {
		return nil, nil, err
	}

	rw, err := provision.OpenSerial(opts.port, baud, opts.timeout)
	if err != nil {
		return nil, nil, fmt.Errorf("open serial port %s at %d baud: %w", opts.port, baud, err)
	}

	client := provision.NewClientWithTimeout(rw, opts.timeout)
	if syncErr := client.Sync(); syncErr != nil {
		_ = rw.Close()
		return nil, nil, fmt.Errorf("synchronize provisioning protocol on %s: %w", opts.port, syncErr)
	}

	cleanup := func() {
		if closeErr := rw.Close(); closeErr != nil {
			ui.Warn("Failed to close serial port %s: %v", opts.port, closeErr)
		}
	}
	return client, cleanup, nil
}

func resolveProvisionBaud(explicit uint32, hardwarePath string) (uint32, error) {
	if hardwarePath != "" {
		if _, err := manifest.ParseHardwareJSON(filepath.Clean(hardwarePath)); err != nil {
			return 0, fmt.Errorf("read hardware metadata %s: %w", hardwarePath, err)
		}
	}
	if explicit != 0 {
		return explicit, nil
	}
	return provision.DefaultBaudRate, nil
}

func newProvisionCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "provision",
		Short: "Provision hardware root-of-trust keys, eFuses, and flash locks over serial",
	}

	c.AddCommand(
		newProvisionReadIDCmd(),
		newProvisionBurnKeyCmd(),
		newProvisionSetDSLCCmd(),
		newProvisionLockBootFlashCmd(),
		newProvisionFullCmd(),
	)
	return c
}

func newProvisionReadIDCmd() *cobra.Command {
	var (
		common provisionCommonOpts
		keyArg string
		mock   bool
	)

	c := &cobra.Command{
		Use:   "read-id",
		Short: "Read target silicon UID and derive the Toob device ID",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if !mock && strings.TrimSpace(keyArg) == "" {
				return errors.New("either --key <pubkey-hex-or-file> or --mock is required to derive DeviceID")
			}

			pub, err := loadProvisionPubKey(keyArg, mock)
			if err != nil {
				return err
			}

			client, cleanup, err := openProvisionClient(common)
			if err != nil {
				return err
			}
			defer cleanup()

			uid, err := client.ReadChipUID()
			if err != nil {
				return fmt.Errorf("read chip UID: %w", err)
			}

			devID := provision.DeriveDeviceID(uid, pub)

			ui.Info("Chip UID:  %x", uid)
			ui.Success("Device ID: %x", devID)
			return nil
		},
	}

	registerProvisionCommonFlags(c, &common, false)
	c.Flags().StringVar(&keyArg, "key", "", "Ed25519 root public key (64 hex chars or file path)")
	c.Flags().BoolVar(&mock, "mock", false, "Derive DeviceID using deterministic development mock root key")
	c.MarkFlagsMutuallyExclusive("mock", "key")
	return c
}

func newProvisionBurnKeyCmd() *cobra.Command {
	var (
		common    provisionCommonOpts
		slot      uint8
		keyArg    string
		mock      bool
		algorithm string
	)

	c := &cobra.Command{
		Use:   "burn-key",
		Short: "Burn an immutable Ed25519 root public key hash into device OTP/eFuses",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if !mock && strings.TrimSpace(keyArg) == "" {
				return errors.New("either --key <pubkey-hex-or-file> or --mock is required")
			}
			pub, err := loadProvisionPubKey(keyArg, mock)
			if err != nil {
				return err
			}

			warnMockKeyIfNeeded(mock)
			ui.Warn("IRREVERSIBLE ACTION: burning root public key into slot %d on %s", slot, common.port)
			if confErr := confirmIrreversible(common.yes, fmt.Sprintf("Permanently burn root public key into OTP slot %d on %s?", slot, common.port)); confErr != nil {
				return confErr
			}

			client, cleanup, err := openProvisionClient(common)
			if err != nil {
				return err
			}
			defer cleanup()

			if strings.TrimSpace(algorithm) != "" {
				err = client.BurnPublicKeyWithAlgorithm(slot, algorithm, pub)
			} else {
				err = client.BurnPublicKey(slot, pub)
			}
			if err != nil {
				return fmt.Errorf("burn public key: %w", err)
			}

			ui.Success("Burned root public key to OTP slot %d", slot)
			return nil
		},
	}

	registerProvisionCommonFlags(c, &common, true)
	c.Flags().Uint8Var(&slot, "slot", 0, "OTP key slot index")
	c.Flags().StringVar(&keyArg, "key", "", "Ed25519 root public key (64 hex chars or file path)")
	c.Flags().BoolVar(&mock, "mock", false, "Burn deterministic development mock public key (NEVER FOR PRODUCTION)")
	c.Flags().StringVar(&algorithm, "algorithm", "", "Explicit algorithm profile (ed25519, ecdsa-p256, ed448, ml-dsa-65, pqc, custom)")
	c.MarkFlagsMutuallyExclusive("mock", "key")
	return c
}

func newProvisionSetDSLCCmd() *cobra.Command {
	var (
		common provisionCommonOpts
		value  uint32
	)

	c := &cobra.Command{
		Use:   "set-dslc",
		Short: "Advance device security lifecycle state (DSLC)",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if value > math.MaxUint8 {
				return fmt.Errorf("--value %d exceeds 8-bit DSLC range (0..255)", value)
			}

			ui.Warn("IRREVERSIBLE ACTION: advancing device security lifecycle (DSLC=%d) on %s", value, common.port)
			if err := confirmIrreversible(common.yes, fmt.Sprintf("Permanently set DSLC state to %d on %s?", value, common.port)); err != nil {
				return err
			}

			client, cleanup, err := openProvisionClient(common)
			if err != nil {
				return err
			}
			defer cleanup()

			if err := client.SetDSLC(byte(value)); err != nil {
				return fmt.Errorf("set DSLC: %w", err)
			}

			ui.Success("Device lifecycle state advanced to %d", value)
			return nil
		},
	}

	registerProvisionCommonFlags(c, &common, true)
	c.Flags().Uint32Var(&value, "value", 0, "Target DSLC lifecycle code (required)")
	_ = c.MarkFlagRequired("value")
	return c
}

func newProvisionLockBootFlashCmd() *cobra.Command {
	var (
		common provisionCommonOpts
		offset uint32
		size   uint32
		full   bool
	)

	c := &cobra.Command{
		Use:   "lock-boot-flash",
		Short: "Write-protect bootloader flash sectors or full boot flash region",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			hasRange := cmd.Flags().Changed("offset") || cmd.Flags().Changed("size")
			if !full && !hasRange {
				return errors.New("specify --full or both --offset and --size")
			}
			if hasRange && size == 0 {
				return errors.New("--size must be non-zero when locking a flash range")
			}

			ui.Warn("IRREVERSIBLE ACTION: locking boot flash on %s", common.port)
			if err := confirmIrreversible(common.yes, fmt.Sprintf("Permanently write-protect boot flash on %s?", common.port)); err != nil {
				return err
			}

			client, cleanup, err := openProvisionClient(common)
			if err != nil {
				return err
			}
			defer cleanup()

			if hasRange {
				if err := client.LockBootFlashRange(offset, size); err != nil {
					return fmt.Errorf("lock boot flash range [0x%X..0x%X): %w", offset, offset+size, err)
				}
				ui.Success("Locked boot flash range [0x%X, size=0x%X)", offset, size)
				return nil
			}

			if err := client.LockBootFlash(); err != nil {
				return fmt.Errorf("lock boot flash: %w", err)
			}
			ui.Success("Locked full boot flash region")
			return nil
		},
	}

	registerProvisionCommonFlags(c, &common, true)
	c.Flags().Uint32Var(&offset, "offset", 0, "Flash range start byte offset")
	c.Flags().Uint32Var(&size, "size", 0, "Flash range length in bytes")
	c.Flags().BoolVar(&full, "full", false, "Lock full bootloader flash region")
	c.MarkFlagsMutuallyExclusive("full", "offset")
	return c
}

func newProvisionFullCmd() *cobra.Command {
	var (
		common       provisionCommonOpts
		slot         uint8
		keyArg       string
		mock         bool
		dslc         uint32
		secureBoot   bool
		flashEncrypt bool
		lockFlash    bool
		reboot       bool
	)

	c := &cobra.Command{
		Use:   "full",
		Short: "Execute full factory provisioning sequence (key burn, lifecycle, protections, flash lock)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !mock && strings.TrimSpace(keyArg) == "" {
				return errors.New("either --key <pubkey-hex-or-file> or --mock is required")
			}
			if dslc > math.MaxUint8 {
				return fmt.Errorf("--dslc %d exceeds 8-bit range (0..255)", dslc)
			}
			pub, err := loadProvisionPubKey(keyArg, mock)
			if err != nil {
				return err
			}

			warnMockKeyIfNeeded(mock)
			ui.Warn("Provisioning summary on %s: burn-key(slot=%d), secure-boot=%v, flash-encrypt=%v, lock-boot-flash=%v, dslc=%d",
				common.port, slot, secureBoot, flashEncrypt, lockFlash, dslc)
			if confErr := confirmIrreversible(common.yes, "Proceed with permanent hardware provisioning? This cannot be undone."); confErr != nil {
				return confErr
			}

			client, cleanup, err := openProvisionClient(common)
			if err != nil {
				return err
			}
			defer cleanup()

			if err := client.BurnPublicKey(slot, pub); err != nil {
				return fmt.Errorf("burn root public key: %w", err)
			}
			if cmd.Flags().Changed("dslc") {
				if err := client.SetDSLC(byte(dslc)); err != nil {
					return fmt.Errorf("set DSLC: %w", err)
				}
			}
			if secureBoot {
				if err := client.EnableSecureBoot(); err != nil {
					return fmt.Errorf("enable secure boot: %w", err)
				}
			}
			if flashEncrypt {
				if err := client.EnableFlashEncryption(); err != nil {
					return fmt.Errorf("enable flash encryption: %w", err)
				}
			}
			if lockFlash {
				if err := client.LockBootFlash(); err != nil {
					return fmt.Errorf("lock boot flash: %w", err)
				}
			}
			if reboot {
				if err := client.Reboot(); err != nil {
					return fmt.Errorf("reboot target: %w", err)
				}
			}

			ui.Success("Full device provisioning completed on %s", common.port)
			return nil
		},
	}

	registerProvisionCommonFlags(c, &common, true)
	c.Flags().Uint8Var(&slot, "slot", 0, "OTP key slot index")
	c.Flags().StringVar(&keyArg, "key", "", "Ed25519 root public key (64 hex chars or file path)")
	c.Flags().BoolVar(&mock, "mock", false, "Provision using deterministic development mock public key (DEV ONLY)")
	c.Flags().Uint32Var(&dslc, "dslc", 0, "Target device lifecycle state (0..255)")
	c.Flags().BoolVar(&secureBoot, "secure-boot", true, "Enable hardware secure boot verification")
	c.Flags().BoolVar(&flashEncrypt, "flash-encrypt", false, "Enable hardware flash encryption")
	c.Flags().BoolVar(&lockFlash, "lock-boot-flash", false, "Lock bootloader flash sectors after provisioning")
	c.Flags().BoolVar(&reboot, "reboot", true, "Reboot target device after provisioning completes")
	c.MarkFlagsMutuallyExclusive("mock", "key")
	return c
}

func warnMockKeyIfNeeded(mock bool) {
	if mock {
		ui.Warn("WARNING: --mock burns a PUBLICLY KNOWN development key! NEVER use --mock on production hardware.")
	}
}

func loadProvisionPubKey(keyArg string, mock bool) (ed25519.PublicKey, error) {
	if mock {
		return ed25519.PublicKey(slices.Clone(provision.MockRootPublicKey)), nil
	}
	trimmed := strings.TrimSpace(keyArg)
	if len(trimmed) == ed25519.PublicKeySize*2 || strings.HasPrefix(trimmed, "0x") {
		if pub, err := parseEd25519PubHex(trimmed); err == nil {
			return pub, nil
		}
	}
	raw, err := os.ReadFile(filepath.Clean(trimmed))
	if err != nil {
		return nil, fmt.Errorf("read public key file %s: %w", trimmed, err)
	}
	return parseEd25519PubHex(strings.TrimSpace(string(raw)))
}
