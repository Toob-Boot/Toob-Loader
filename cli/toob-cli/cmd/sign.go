package cmd

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"

	"github.com/Toob-Boot/Toob-Loader/toob-go-lib/build"
	"github.com/Toob-Boot/Toob-Loader/toob-go-lib/tbm1"
	"github.com/spf13/cobra"
	"github.com/toob-boot/toob/internal/paths"
	"github.com/toob-boot/toob/internal/provision"
	"github.com/toob-boot/toob/internal/ui"
)

const (
	toobImageHeaderLen  = 20
	toobImageMagic      = 0x544F4F42 // "TOOB"
	toobStage1SVNMagic  = 0x31534254 // "TBS1"
	ed25519SignatureLen = 64
)

var (
	signMockFlag     bool
	signKeyFileFlag  string
	signKeyHexFlag   string
	signOutFlag      string
	signEntryFlag    uint32
	stage1SVNFlag    uint32
	signChipFlag     string
	signHardwareFlag string

	bundleDeviceFlag    string
	bundleBaseFlag      string
	bundleBaseSVNFlag   uint32
	bundleCompressFlag  bool
	bundleRDeltaOldFlag string
	bundleTrailerFlag   bool
	bundleVendorFlag    uint16
	bundleProductFlag   uint16
	bundleHWRevMinFlag  uint16
	bundleHWRevMaxFlag  uint16
	bundleSVNFlag       uint32
	bundleVerMajorFlag  uint16
	bundleVerMinorFlag  uint16
	bundleVerPatchFlag  uint16
	bundleKeyIndexFlag  uint8
)

var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign firmware manifests, bundles, images, or generate signing keys",
	Long: `The sign command signs TBM1 update manifests and bundles with Ed25519 signatures,
packs BootROM Stage 0 images declaratively from hardware.json, prepends bootloader
image headers, and generates cryptographic keypairs.

When --mock is passed, the RFC 8032 Test Vector 1 development key is used,
which matches the default public key built into the efuse_mock hardware driver.`,
}

var signManifestCmd = &cobra.Command{
	Use:   "manifest <manifest.bin>",
	Short: "Sign a TBM1 v2 manifest package",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		inPath := args[0]
		data, err := os.ReadFile(inPath)
		if err != nil {
			return fmt.Errorf("read manifest file: %w", err)
		}
		if len(data) < ed25519SignatureLen {
			return errors.New("manifest data is too short")
		}

		signer, err := resolveSigner()
		if err != nil {
			return err
		}

		sig, err := tbm1.SignBlock(data, signer)
		if err != nil {
			return fmt.Errorf("sign manifest block: %w", err)
		}

		signedData := make([]byte, len(data))
		copy(signedData, data)
		copy(signedData[len(signedData)-ed25519SignatureLen:], sig)

		outPath := inPath
		if signOutFlag != "" {
			outPath = signOutFlag
		}

		if err := os.WriteFile(outPath, signedData, 0644); err != nil {
			return fmt.Errorf("write signed manifest: %w", err)
		}

		pubKeyHex := hex.EncodeToString(signer.Public())
		ui.Success("Signed TBM1 manifest -> %s", outPath)
		ui.Tip("Signer Public Key (Slot 0): %s", pubKeyHex)
		return nil
	},
}

func validateToobImage(label string, b []byte) error {
	if len(b) <= toobImageHeaderLen {
		return fmt.Errorf("%s (%d bytes) is too small to contain a 20-byte Toob image header and payload", label, len(b))
	}
	if uint64(len(b)) > math.MaxUint32 {
		return fmt.Errorf("%s exceeds uint32 size limit", label)
	}
	if gotMagic := binary.LittleEndian.Uint32(b[0:4]); gotMagic != toobImageMagic {
		return fmt.Errorf("%s is missing the 'TOOB' image header magic (got 0x%08X, want 0x%08X); run 'toob sign image' first",
			label, gotMagic, toobImageMagic)
	}
	if hdrSize := binary.LittleEndian.Uint32(b[4:8]); hdrSize != uint32(len(b)) {
		return fmt.Errorf("%s header image_size (%d) does not match file length (%d)", label, hdrSize, len(b))
	}
	return nil
}

func isRemappableExecModel(model string) bool {
	switch strings.ToLower(strings.TrimSpace(model)) {
	case "xip_remap", "bank_swap", "relocatable":
		return true
	}
	return false
}

func loadOptionalChipManifestForDevice(chip string) *build.ChipManifest {
	hwPath, err := resolveChipHardwareJSON(chip, "")
	if err != nil {
		return nil
	}
	cmPath := filepath.Join(filepath.Dir(hwPath), "chip_manifest.json")
	raw, err := os.ReadFile(cmPath)
	if err != nil {
		return nil
	}
	var cm build.ChipManifest
	if json.Unmarshal(raw, &cm) != nil {
		return nil
	}
	return &cm
}

func validateBundleAgainstDevice(cmd *cobra.Command, dt *build.DeviceToml, devicePath string) (vendorID, productID, hwRevMin, hwRevMax uint16, err error) {
	if dt.Identity.VendorID == 0 || dt.Identity.VendorID == 0xFFFF {
		return 0, 0, 0, 0, fmt.Errorf("%s must define a valid non-zero [identity] vendor_id", devicePath)
	}
	if dt.Identity.ProductID == 0 || dt.Identity.ProductID == 0xFFFF {
		return 0, 0, 0, 0, fmt.Errorf("%s must define a valid non-zero [identity] product_id", devicePath)
	}

	vendorID = dt.Identity.VendorID
	if cmd.Flags().Changed("vendor") {
		if bundleVendorFlag != dt.Identity.VendorID {
			return 0, 0, 0, 0, fmt.Errorf("--vendor (0x%04X) does not match %s [identity] vendor_id (0x%04X)",
				bundleVendorFlag, devicePath, dt.Identity.VendorID)
		}
		vendorID = bundleVendorFlag
	}

	productID = dt.Identity.ProductID
	if cmd.Flags().Changed("product") {
		if bundleProductFlag != dt.Identity.ProductID {
			return 0, 0, 0, 0, fmt.Errorf("--product (0x%04X) does not match %s [identity] product_id (0x%04X)",
				bundleProductFlag, devicePath, dt.Identity.ProductID)
		}
		productID = bundleProductFlag
	}

	hwRevMin = dt.Identity.HwRev
	if cmd.Flags().Changed("hw-rev-min") {
		hwRevMin = bundleHWRevMinFlag
	}
	hwRevMax = dt.Identity.HwRev
	if cmd.Flags().Changed("hw-rev-max") {
		hwRevMax = bundleHWRevMaxFlag
	}
	if dt.Identity.HwRev < hwRevMin || dt.Identity.HwRev > hwRevMax {
		return 0, 0, 0, 0, fmt.Errorf("%s [identity] hw_rev (%d) falls outside [--hw-rev-min=%d .. --hw-rev-max=%d]",
			devicePath, dt.Identity.HwRev, hwRevMin, hwRevMax)
	}

	cm := loadOptionalChipManifestForDevice(dt.Device.Chip)
	var caps *build.SlotCapabilities
	if cm != nil {
		caps = cm.SlotCapabilities
	}

	transport := strings.ToLower(strings.TrimSpace(dt.BootConfig.TransportProvider))
	if transport == "" && caps != nil {
		switch {
		case caps.SlotCount >= 2 && isRemappableExecModel(caps.ExecModel):
			transport = "pointer"
		case caps.SlotCount >= 2:
			transport = "oneway"
		case caps.HasScratch:
			transport = "swapscratch"
		default:
			transport = "swapmove"
		}
	}
	backup := strings.ToLower(strings.TrimSpace(dt.BootConfig.BackupMode))
	if transport == "oneway" && backup == "" {
		backup = "full"
	}

	if bundleBaseFlag != "" {
		if !dt.Partitions.EnableDeltas {
			return 0, 0, 0, 0, fmt.Errorf("refusing to sign forward-delta bundle: partitions.enable_deltas is false in %s", devicePath)
		}
		if dt.Features.Delta != nil && !*dt.Features.Delta {
			return 0, 0, 0, 0, fmt.Errorf("refusing to sign forward-delta bundle: features.delta is false in %s", devicePath)
		}
		if dt.Partitions.ScratchSize > 0 && dt.Partitions.ScratchSize < dt.Partitions.AppSize {
			return 0, 0, 0, 0, fmt.Errorf("refusing to sign forward-delta bundle: partitions.scratch_size (%d) < partitions.app_size (%d) in %s",
				dt.Partitions.ScratchSize, dt.Partitions.AppSize, devicePath)
		}
		if transport != "" && transport != "pointer" && caps != nil && !caps.HasScratch && dt.Partitions.ScratchSize == 0 {
			return 0, 0, 0, 0, fmt.Errorf("refusing to sign forward-delta bundle [HIGH-33]: transport '%s' on chip '%s' has no scratch partition",
				transport, dt.Device.Chip)
		}
	}

	if bundleCompressFlag {
		if dt.Features.Compression != nil && !*dt.Features.Compression {
			return 0, 0, 0, 0, fmt.Errorf("refusing to sign compressed bundle: features.compression is false in %s", devicePath)
		}
		hasAllocatedScratch := dt.Partitions.ScratchSize > 0 ||
			(dt.Partitions.EnableDeltas && transport != "" && transport != "pointer" && (caps == nil || caps.HasScratch))
		if transport == "oneway" && backup == "full" && !hasAllocatedScratch {
			return 0, 0, 0, 0, fmt.Errorf("refusing to sign compressed bundle [HIGH-33]: oneway transport with full backup and no scratch partition rejects compressed streams in %s",
				devicePath)
		}
	}

	if transport == "oneway" && backup == "reverse_delta" && bundleRDeltaOldFlag == "" {
		return 0, 0, 0, 0, fmt.Errorf("refusing to sign bundle: boot_config.backup_mode = 'reverse_delta' in %s requires --rdelta-old <previous.toob>",
			devicePath)
	}

	return vendorID, productID, hwRevMin, hwRevMax, nil
}

var signBundleCmd = &cobra.Command{
	Use:   "bundle <image.toob>",
	Short: "Assemble and Ed25519-sign a complete TBM1 v2 update bundle",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if bundleBaseFlag != "" && bundleCompressFlag {
			return errors.New("--base (TDS1 forward delta) and --compress (Heatshrink) are mutually exclusive")
		}
		if cmd.Flags().Changed("base-svn") && bundleBaseFlag == "" {
			return errors.New("--base-svn requires --base <base.toob>")
		}

		vendorID := bundleVendorFlag
		productID := bundleProductFlag
		hwRevMin := bundleHWRevMinFlag
		hwRevMax := bundleHWRevMaxFlag

		var dt *build.DeviceToml
		if bundleDeviceFlag != "" {
			var err error
			dt, err = build.ParseToml(bundleDeviceFlag)
			if err != nil {
				return fmt.Errorf("parse --device manifest %s: %w", bundleDeviceFlag, err)
			}
			vendorID, productID, hwRevMin, hwRevMax, err = validateBundleAgainstDevice(cmd, dt, bundleDeviceFlag)
			if err != nil {
				return err
			}
		}

		if vendorID == 0 || vendorID == 0xFFFF {
			return errors.New("--vendor must be non-zero and not 0xFFFF (reserved)")
		}
		if productID == 0 || productID == 0xFFFF {
			return errors.New("--product must be non-zero and not 0xFFFF (reserved)")
		}
		if hwRevMin > hwRevMax {
			return fmt.Errorf("--hw-rev-min (%d) must not exceed --hw-rev-max (%d)", hwRevMin, hwRevMax)
		}

		inPath := args[0]
		installed, err := os.ReadFile(inPath)
		if err != nil {
			return fmt.Errorf("read installed image: %w", err)
		}
		if err := validateToobImage("installed image", installed); err != nil {
			return err
		}

		signer, err := resolveSigner()
		if err != nil {
			return err
		}

		var baseBytes []byte
		if bundleBaseFlag != "" {
			baseBytes, err = os.ReadFile(bundleBaseFlag)
			if err != nil {
				return fmt.Errorf("read --base image: %w", err)
			}
			if err := validateToobImage("--base image", baseBytes); err != nil {
				return err
			}
		}

		var rdeltaOldBytes []byte
		if bundleRDeltaOldFlag != "" {
			rdeltaOldBytes, err = os.ReadFile(bundleRDeltaOldFlag)
			if err != nil {
				return fmt.Errorf("read --rdelta-old image: %w", err)
			}
			if err := validateToobImage("--rdelta-old image", rdeltaOldBytes); err != nil {
				return err
			}
		}

		if dt != nil && dt.Partitions.AppSize > 0 {
			appBudget := uint64(dt.Partitions.AppSize)
			if uint64(len(installed)) > appBudget {
				return fmt.Errorf("installed image (%d bytes) exceeds partitions.app_size (%d bytes) in %s",
					len(installed), dt.Partitions.AppSize, bundleDeviceFlag)
			}
			if uint64(len(baseBytes)) > appBudget {
				return fmt.Errorf("--base image (%d bytes) exceeds partitions.app_size (%d bytes) in %s",
					len(baseBytes), dt.Partitions.AppSize, bundleDeviceFlag)
			}
			if uint64(len(rdeltaOldBytes)) > appBudget {
				return fmt.Errorf("--rdelta-old image (%d bytes) exceeds partitions.app_size (%d bytes) in %s",
					len(rdeltaOldBytes), dt.Partitions.AppSize, bundleDeviceFlag)
			}
		}

		bundle, err := tbm1.PackBundle(tbm1.PackOptions{
			Installed:     installed,
			TargetSlot:    tbm1.SlotApp,
			Base:          baseBytes,
			BaseSVN:       bundleBaseSVNFlag,
			Compress:      bundleCompressFlag,
			ReverseOld:    rdeltaOldBytes,
			TrailerLayout: bundleTrailerFlag,
			VendorID:      vendorID,
			ProductID:     productID,
			HWRevMin:      hwRevMin,
			HWRevMax:      hwRevMax,
			SVN:           bundleSVNFlag,
			VerMajor:      bundleVerMajorFlag,
			VerMinor:      bundleVerMinorFlag,
			VerPatch:      bundleVerPatchFlag,
			KeyIndex:      bundleKeyIndexFlag,
		}, signer)
		if err != nil {
			return err
		}

		outPath := inPath + ".tbm1"
		if signOutFlag != "" {
			outPath = signOutFlag
		}
		if err := os.WriteFile(outPath, bundle, 0644); err != nil {
			return fmt.Errorf("write TBM1 bundle: %w", err)
		}

		ui.Success("Packed & signed TBM1 bundle (%d bytes) -> %s", len(bundle), outPath)
		ui.Tip("SVN: %d, Signer Public Key: %s", bundleSVNFlag, hex.EncodeToString(signer.Public()))
		return nil
	},
}

var signImageCmd = &cobra.Command{
	Use:   "image <app.bin>",
	Short: "Prepend Toob image header to an application binary",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		inPath := args[0]
		rawBin, err := os.ReadFile(inPath)
		if err != nil {
			return fmt.Errorf("read app binary: %w", err)
		}
		if len(rawBin) == 0 {
			return errors.New("application binary is empty")
		}
		if uint64(len(rawBin)) > math.MaxUint32-toobImageHeaderLen-3 {
			return errors.New("application binary exceeds uint32 image_size limit")
		}

		if pad := (4 - (len(rawBin) % 4)) % 4; pad > 0 {
			padded := make([]byte, len(rawBin)+pad)
			copy(padded, rawBin)
			for i := len(rawBin); i < len(padded); i++ {
				padded[i] = 0xFF
			}
			rawBin = padded
		}

		entryOffset := uint32(toobImageHeaderLen)
		if cmd.Flags().Changed("entry") {
			if signEntryFlag < toobImageHeaderLen {
				return fmt.Errorf("--entry (0x%X) must not point inside the 20-byte Toob image header (>= 0x14)", signEntryFlag)
			}
			entryOffset = signEntryFlag
		}

		header := make([]byte, toobImageHeaderLen)
		totalSize := uint32(toobImageHeaderLen + len(rawBin))
		binary.LittleEndian.PutUint32(header[0:4], toobImageMagic)
		binary.LittleEndian.PutUint32(header[4:8], totalSize)
		binary.LittleEndian.PutUint32(header[8:12], entryOffset)

		fp := sha256.Sum256(rawBin)
		copy(header[12:20], fp[:8])

		combined := make([]byte, 0, int(totalSize))
		combined = append(combined, header...)
		combined = append(combined, rawBin...)

		outPath := inPath + ".toob"
		if signOutFlag != "" {
			outPath = signOutFlag
		}

		if err := os.WriteFile(outPath, combined, 0644); err != nil {
			return fmt.Errorf("write tagged image: %w", err)
		}

		ui.Success("Prepend Toob header (20 bytes) -> %s", outPath)
		ui.Tip("Total image size: %d bytes, Entry offset: 0x%08X", totalSize, entryOffset)
		return nil
	},
}

var signKeygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate a new Ed25519 signing keypair",
	RunE: func(cmd *cobra.Command, args []string) error {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return fmt.Errorf("generate key: %w", err)
		}

		seed := priv.Seed()
		seedHex := hex.EncodeToString(seed)
		pubHex := hex.EncodeToString(pub)

		if signOutFlag != "" {
			if err := os.WriteFile(signOutFlag, []byte(seedHex+"\n"), 0600); err != nil {
				return fmt.Errorf("save private key: %w", err)
			}
			ui.Success("Saved private key seed -> %s", signOutFlag)
		}

		fmt.Println("==================================================")
		fmt.Println("   New Ed25519 Signing Keypair Generated")
		fmt.Println("==================================================")
		fmt.Printf("Seed (Secret Key, 32B): %s\n", seedHex)
		fmt.Printf("Public Key (eFuse Slot): %s\n", pubHex)
		fmt.Println("==================================================")
		ui.Tip("Keep the seed confidential. Burn the public key into eFuse slot 0.")
		return nil
	},
}

func resolveSigner() (tbm1.Signer, error) {
	if signMockFlag {
		seedBytes, _ := hex.DecodeString(provision.MockRootPrivateKeySeedHex)
		priv := ed25519.NewKeyFromSeed(seedBytes)
		return tbm1.NewLocalSigner(priv)
	}

	if signKeyHexFlag != "" {
		trimmed := strings.TrimSpace(signKeyHexFlag)
		keyBytes, err := hex.DecodeString(trimmed)
		if err != nil {
			return nil, fmt.Errorf("invalid hex in --key-hex: %w", err)
		}
		if len(keyBytes) == 32 {
			priv := ed25519.NewKeyFromSeed(keyBytes)
			return tbm1.NewLocalSigner(priv)
		} else if len(keyBytes) == 64 {
			return tbm1.NewLocalSigner(ed25519.PrivateKey(keyBytes))
		}
		return nil, fmt.Errorf("private key hex must be 32 bytes (seed) or 64 bytes (full), got %d bytes", len(keyBytes))
	}

	if signKeyFileFlag != "" {
		content, err := os.ReadFile(signKeyFileFlag)
		if err != nil {
			return nil, fmt.Errorf("read key file: %w", err)
		}
		trimmed := strings.TrimSpace(string(content))
		keyBytes, err := hex.DecodeString(trimmed)
		if err == nil && (len(keyBytes) == 32 || len(keyBytes) == 64) {
			if len(keyBytes) == 32 {
				return tbm1.NewLocalSigner(ed25519.NewKeyFromSeed(keyBytes))
			}
			return tbm1.NewLocalSigner(ed25519.PrivateKey(keyBytes))
		}
		if len(content) == 32 {
			return tbm1.NewLocalSigner(ed25519.NewKeyFromSeed(content))
		} else if len(content) == 64 {
			return tbm1.NewLocalSigner(ed25519.PrivateKey(content))
		}
		return nil, errors.New("key file must contain 32 or 64 raw bytes, or 64/128 hex characters")
	}

	return nil, errors.New("must specify --mock, --key-file, or --key-hex to sign")
}

var signStage1Cmd = &cobra.Command{
	Use:   "stage1 <toob_stage1.bin>",
	Short: "Prepend Toob header and append Ed25519 signature for a Stage 1 bank",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		inPath := args[0]
		rawBin, err := os.ReadFile(inPath)
		if err != nil {
			return fmt.Errorf("read stage1 binary: %w", err)
		}
		if len(rawBin) == 0 {
			return errors.New("stage1 binary is empty")
		}
		if !cmd.Flags().Changed("entry") {
			return errors.New("--entry (Stage 1 execution address, e.g. 0x40390000 or 0x40820000) is required")
		}
		if signEntryFlag < toobImageHeaderLen {
			return fmt.Errorf("--entry (0x%X) must be a valid Stage 1 execution address (>= 0x14)", signEntryFlag)
		}
		if uint64(len(rawBin)) > math.MaxUint32-toobImageHeaderLen-ed25519SignatureLen-3 {
			return errors.New("stage1 binary exceeds uint32 image_size limit")
		}

		if pad := (4 - (len(rawBin) % 4)) % 4; pad > 0 {
			padded := make([]byte, len(rawBin)+pad)
			copy(padded, rawBin)
			for i := len(rawBin); i < len(padded); i++ {
				padded[i] = 0xFF
			}
			rawBin = padded
		}

		signer, err := resolveSigner()
		if err != nil {
			return err
		}

		header := make([]byte, toobImageHeaderLen)
		binary.LittleEndian.PutUint32(header[0:4], toobImageMagic)
		binary.LittleEndian.PutUint32(header[4:8], uint32(len(rawBin)))
		binary.LittleEndian.PutUint32(header[8:12], signEntryFlag)
		binary.LittleEndian.PutUint32(header[12:16], toobStage1SVNMagic)
		binary.LittleEndian.PutUint32(header[16:20], stage1SVNFlag)

		msg := make([]byte, 0, toobImageHeaderLen+len(rawBin)+ed25519SignatureLen)
		msg = append(msg, header...)
		msg = append(msg, rawBin...)

		digest := sha256.Sum256(msg)
		sig, err := signer.Sign(digest[:])
		if err != nil {
			return fmt.Errorf("sign stage1 digest: %w", err)
		}
		msg = append(msg, sig...)

		outPath := inPath + ".signed"
		if signOutFlag != "" {
			outPath = signOutFlag
		}
		if err := os.WriteFile(outPath, msg, 0644); err != nil {
			return fmt.Errorf("write signed stage1: %w", err)
		}

		ui.Success("Signed Stage 1 bank (%d bytes) -> %s", len(msg), outPath)
		ui.Tip("Entry: 0x%08X, SVN: %d, Signer Public Key: %s", signEntryFlag, stage1SVNFlag, hex.EncodeToString(signer.Public()))
		return nil
	},
}

func resolveChipHardwareJSON(chip, explicitPath string) (string, error) {
	if explicitPath != "" {
		return explicitPath, nil
	}
	chipNorm := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(chip)), "-", "")
	if chipNorm == "" {
		return "", errors.New("specify either --hardware <path/to/hardware.json> or --chip <chip>")
	}

	if regDir, err := paths.RegistryDir(); err == nil && regDir != "" {
		cand := filepath.Join(regDir, "chips", chipNorm, "hardware.json")
		if _, statErr := os.Stat(cand); statErr == nil {
			return cand, nil
		}
	}
	if cwd, err := os.Getwd(); err == nil {
		curr := cwd
		for {
			cand := filepath.Join(curr, "toob-infra", "registry", "packages", "chips", chipNorm, "hardware.json")
			if _, statErr := os.Stat(cand); statErr == nil {
				return cand, nil
			}
			parent := filepath.Dir(curr)
			if parent == curr {
				break
			}
			curr = parent
		}
	}
	return "", fmt.Errorf("cannot locate hardware.json for chip %q (pass --hardware explicitly or set TOOB_REGISTRY_DIR)", chip)
}

var signStage0Cmd = &cobra.Command{
	Use:     "stage0 <toob_stage0.elf>",
	Aliases: []string{"esp-stage0"},
	Short:   "Pack a Stage 0 ELF into a BootROM-loadable image driven by hardware.json",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		inPath := args[0]
		hwPath, err := resolveChipHardwareJSON(signChipFlag, signHardwareFlag)
		if err != nil {
			return err
		}
		img, err := build.PackStage0FromHardwareJSON(inPath, hwPath)
		if err != nil {
			return err
		}
		outPath := inPath + ".rom.bin"
		if signOutFlag != "" {
			outPath = signOutFlag
		}
		if err := os.WriteFile(outPath, img, 0644); err != nil {
			return fmt.Errorf("write Stage 0 BootROM image: %w", err)
		}
		ui.Success("Packed Stage 0 BootROM image (%d bytes, %s) -> %s", len(img), filepath.Base(hwPath), outPath)
		return nil
	},
}

func init() {
	signCmd.PersistentFlags().BoolVar(&signMockFlag, "mock", false, "Use RFC 8032 TV1 test key matching efuse_mock")
	signCmd.PersistentFlags().StringVar(&signKeyFileFlag, "key-file", "", "Path to private key or seed file")
	signCmd.PersistentFlags().StringVar(&signKeyHexFlag, "key-hex", "", "Hex-encoded 32-byte seed or 64-byte private key")
	signCmd.PersistentFlags().StringVarP(&signOutFlag, "out", "o", "", "Output path for the signed artifact")

	signImageCmd.Flags().Uint32Var(&signEntryFlag, "entry", 0, "Execution entry point offset in image (default 20)")
	signStage1Cmd.Flags().Uint32Var(&signEntryFlag, "entry", 0, "Execution entry point address for Stage 1")
	signStage1Cmd.Flags().Uint32Var(&stage1SVNFlag, "svn", 1, "Authenticated Stage 1 Security Version Number (SVN)")
	signStage0Cmd.Flags().StringVar(&signChipFlag, "chip", "", "Target chip package name (resolves chips/<chip>/hardware.json)")
	signStage0Cmd.Flags().StringVar(&signHardwareFlag, "hardware", "", "Explicit path to hardware.json")

	signBundleCmd.Flags().StringVar(&bundleDeviceFlag, "device", "", "Optional path to device.toml for sign-time identity, budget, and transport coherence checks")
	signBundleCmd.Flags().StringVar(&bundleBaseFlag, "base", "", "Base firmware image (.toob) to emit a TDS1 forward delta")
	signBundleCmd.Flags().Uint32Var(&bundleBaseSVNFlag, "base-svn", 0, "Expected installed base SVN when emitting a TDS1 forward delta")
	signBundleCmd.Flags().BoolVar(&bundleCompressFlag, "compress", false, "Compress primary image with Heatshrink (mutually exclusive with --base)")
	signBundleCmd.Flags().StringVar(&bundleRDeltaOldFlag, "rdelta-old", "", "Previous firmware image (.toob) to embed Region 6 TDS1 reverse delta")
	signBundleCmd.Flags().BoolVar(&bundleTrailerFlag, "trailer", true, "Emit Zero-Copy TrailerLayout bundle")
	signBundleCmd.Flags().Uint16Var(&bundleVendorFlag, "vendor", 0x0001, "Device vendor_id")
	signBundleCmd.Flags().Uint16Var(&bundleProductFlag, "product", 0x0042, "Device product_id")
	signBundleCmd.Flags().Uint16Var(&bundleHWRevMinFlag, "hw-rev-min", 1, "Minimum hw_rev")
	signBundleCmd.Flags().Uint16Var(&bundleHWRevMaxFlag, "hw-rev-max", 1, "Maximum hw_rev")
	signBundleCmd.Flags().Uint32Var(&bundleSVNFlag, "svn", 1, "Security Version Number (SVN)")
	signBundleCmd.Flags().Uint16Var(&bundleVerMajorFlag, "ver-major", 1, "Firmware major version")
	signBundleCmd.Flags().Uint16Var(&bundleVerMinorFlag, "ver-minor", 0, "Firmware minor version")
	signBundleCmd.Flags().Uint16Var(&bundleVerPatchFlag, "ver-patch", 0, "Firmware patch version")
	signBundleCmd.Flags().Uint8Var(&bundleKeyIndexFlag, "key-index", 0, "Root public key slot index")

	signCmd.AddCommand(signManifestCmd)
	signCmd.AddCommand(signBundleCmd)
	signCmd.AddCommand(signImageCmd)
	signCmd.AddCommand(signStage1Cmd)
	signCmd.AddCommand(signStage0Cmd)
	signCmd.AddCommand(signKeygenCmd)

	rootCmd.AddCommand(signCmd)
}
