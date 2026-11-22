package cmd

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/toob-boot/toob/internal/provision"
	"github.com/toob-boot/toob/internal/ui"
)

var (
	provPortFlag           string
	provMockFlag           bool
	provKeyHexFlag         string
	provSlotFlag           uint8
	provEnableSBFlag       bool
	provEnableFEFlag       bool
	provLockBootFlashFlag  bool
	provProtectionBitsFlag uint32
	provRebootFlag         bool
)

var provisionCmd = &cobra.Command{
	Use:   "provision",
	Short: "Factory provisioning of target devices via UART wire protocol",
	Long: `Communicates with a device in factory DEVELOPMENT state (DSLC == 0x00)
to read hardware UID, burn root keys into eFuses, enable hardware security,
and transition lifecycle state to PROVISIONED.`,
}

var provReadIDCmd = &cobra.Command{
	Use:   "read-id",
	Short: "Read chip silicon UID and print derived Device ID",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, closer, err := openProvisionClient()
		if err != nil {
			return err
		}
		if closer != nil {
			defer closer.Close()
		}

		uid, err := client.ReadChipUID()
		if err != nil {
			return fmt.Errorf("read chip UID: %w", err)
		}

		pubKey := provision.MockRootPublicKey
		if provKeyHexFlag != "" {
			k, err := hex.DecodeString(strings.TrimSpace(provKeyHexFlag))
			if err != nil || len(k) != 32 {
				return errors.New("invalid 32-byte hex public key for device ID derivation")
			}
			pubKey = k
		}

		devID := provision.DeriveDeviceID(uid, pubKey)

		ui.Success("Successfully queried silicon identity")
		fmt.Printf("Silicon UID / MAC:   %s\n", hex.EncodeToString(uid))
		fmt.Printf("Derived Device ID:   %s\n", hex.EncodeToString(devID[:]))
		return nil
	},
}

var provBurnKeyCmd = &cobra.Command{
	Use:   "burn-key",
	Short: "Burn an Ed25519 root public key into device eFuse slot",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, closer, err := openProvisionClient()
		if err != nil {
			return err
		}
		if closer != nil {
			defer closer.Close()
		}

		pubKey, err := resolvePubKey()
		if err != nil {
			return err
		}

		if err := client.BurnPublicKey(provSlotFlag, pubKey); err != nil {
			return fmt.Errorf("burn public key: %w", err)
		}

		ui.Success("Burned root public key into eFuse Slot %d", provSlotFlag)
		return nil
	},
}

var provFullCmd = &cobra.Command{
	Use:   "full",
	Short: "Run full end-to-end factory provisioning pipeline",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, closer, err := openProvisionClient()
		if err != nil {
			return err
		}
		if closer != nil {
			defer closer.Close()
		}

		pubKey, err := resolvePubKey()
		if err != nil {
			return err
		}

		ui.Step("1/5 Querying Hardware Identity")
		uid, err := client.ReadChipUID()
		if err != nil {
			return fmt.Errorf("query UID: %w", err)
		}
		devID := provision.DeriveDeviceID(uid, pubKey)
		ui.Success("Silicon UID: %s | Device-ID: %s", hex.EncodeToString(uid), hex.EncodeToString(devID[:]))

		ui.Step("2/5 Burning Root Public Key")
		if err := client.BurnPublicKey(provSlotFlag, pubKey); err != nil {
			return fmt.Errorf("burn root key: %w", err)
		}
		ui.Success("Root public key burned to eFuse Slot %d", provSlotFlag)

		ui.Step("3/5 Configuring Hardware Security")
		if provEnableSBFlag {
			if err := client.EnableSecureBoot(); err != nil {
				return fmt.Errorf("enable secure boot: %w", err)
			}
			ui.Success("Hardware Secure Boot enabled")
		}
		if provEnableFEFlag {
			if err := client.EnableFlashEncryption(); err != nil {
				return fmt.Errorf("enable flash encryption: %w", err)
			}
			ui.Success("Hardware Flash Encryption enabled")
		}
		if provProtectionBitsFlag != 0 {
			if err := client.SetProtection(provProtectionBitsFlag); err != nil {
				return fmt.Errorf("set protection bits: %w", err)
			}
			ui.Success("Protection bits (0x%08X) burned", provProtectionBitsFlag)
		}
		if provLockBootFlashFlag {
			if err := client.LockBootFlash(); err != nil {
				return fmt.Errorf("lock boot flash: %w", err)
			}
			ui.Success("Immutable Stage 0 boot flash permanently locked")
		}

		ui.Step("4/5 Finalizing Device Lifecycle (DSLC -> PROVISIONED)")
		if err := client.SetDSLC(0x01); err != nil {
			return fmt.Errorf("set DSLC: %w", err)
		}
		ui.Success("DSLC set to 0x01 (PROVISIONED) — Provisioning permanently locked")

		if provRebootFlag {
			ui.Step("5/5 Rebooting Target")
			if err := client.Reboot(); err != nil {
				var stErr *provision.StatusError
				if errors.As(err, &stErr) {
					return fmt.Errorf("reboot target: %w", err)
				}
			}
			ui.Success("Target rebooted into OS")
		} else {
			ui.Tip("Device is provisioned. Power-cycle or reset device to boot into OS.")
		}

		return nil
	},
}

func resolvePubKey() ([]byte, error) {
	if provMockFlag {
		return provision.MockRootPublicKey, nil
	}
	if provKeyHexFlag != "" {
		b, err := hex.DecodeString(strings.TrimSpace(provKeyHexFlag))
		if err != nil {
			return nil, fmt.Errorf("invalid hex in --key: %w", err)
		}
		if len(b) != 32 {
			return nil, fmt.Errorf("public key must be 32 bytes, got %d", len(b))
		}
		return b, nil
	}
	return nil, errors.New("must specify --mock or --key <hex>")
}

func openProvisionClient() (*provision.Client, io.Closer, error) {
	if provPortFlag == "" {
		return nil, nil, errors.New("missing required --port flag (e.g., --port COM3 or --port /dev/ttyUSB0)")
	}

	// Format port for Windows COM naming if needed
	portPath := provPortFlag
	if strings.HasPrefix(strings.ToUpper(portPath), "COM") && len(portPath) > 4 {
		portPath = "\\\\.\\" + portPath
	}

	f, err := os.OpenFile(portPath, os.O_RDWR, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("open serial port %s: %w", provPortFlag, err)
	}

	return provision.NewClient(f), f, nil
}

func init() {
	provisionCmd.PersistentFlags().StringVarP(&provPortFlag, "port", "p", "", "Serial port path (e.g. COM3 or /dev/ttyUSB0)")
	provisionCmd.PersistentFlags().BoolVar(&provMockFlag, "mock", false, "Use mock keys (RFC 8032 TV1)")
	provisionCmd.PersistentFlags().StringVar(&provKeyHexFlag, "key", "", "Hex-encoded 32-byte Ed25519 root public key")
	provisionCmd.PersistentFlags().Uint8Var(&provSlotFlag, "slot", 0, "eFuse key slot (0 to 5, default 0)")

	provFullCmd.Flags().BoolVar(&provEnableSBFlag, "secure-boot", true, "Enable hardware secure boot")
	provFullCmd.Flags().BoolVar(&provEnableFEFlag, "flash-encryption", true, "Enable transparent flash encryption")
	provFullCmd.Flags().BoolVar(&provLockBootFlashFlag, "lock-boot-flash", false, "Permanently write-protect immutable Stage 0 boot flash")
	provFullCmd.Flags().Uint32Var(&provProtectionBitsFlag, "protection-bits", 0, "Extra protection bitmask to burn")
	provFullCmd.Flags().BoolVar(&provRebootFlag, "reboot", true, "Reboot device immediately after provisioning")

	provisionCmd.AddCommand(provReadIDCmd)
	provisionCmd.AddCommand(provBurnKeyCmd)
	provisionCmd.AddCommand(provFullCmd)

	rootCmd.AddCommand(provisionCmd)
}
