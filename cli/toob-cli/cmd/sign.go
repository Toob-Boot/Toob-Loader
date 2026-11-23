package cmd

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	build "github.com/Toob-Boot/Toob-Loader/toob-go-lib/build"
	"github.com/Toob-Boot/Toob-Loader/toob-go-lib/tbm1"
	"github.com/toob-boot/toob/internal/signing"
	"github.com/toob-boot/toob/internal/ui"
)

func newSignCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "sign",
		Short: "Sign firmware images, TBM1 manifests, Stage-0/OTA bundles, TCC1 commands, and KDMs",
	}

	c.AddCommand(
		newSignManifestCmd(),
		newSignImageCmd(),
		newSignStage0Cmd(),
		newSignStage1Cmd(),
		newSignBundleCmd(),
		newSignKeygenCmd(),
		newSignTCC1Cmd(),
		newSignKDMCmd(),
	)
	return c
}

func registerKeyFlags(c *cobra.Command, keyFile, keyHex *string, mock *bool) {
	c.Flags().StringVarP(keyFile, "key-file", "k", "", "Path to Ed25519 private key file (hex or PEM/PKCS#8)")
	c.Flags().StringVar(keyHex, "key-hex", "", "Raw Ed25519 private key in hex")
	c.Flags().BoolVar(mock, "mock", false, "Sign using deterministic development mock root key (DEV ONLY)")
	c.MarkFlagsMutuallyExclusive("mock", "key-file", "key-hex")
}

func newSignManifestCmd() *cobra.Command {
	var (
		inPath  string
		outPath string
		keyFile string
		keyHex  string
		mock    bool
	)

	c := &cobra.Command{
		Use:   "manifest [in] [out]",
		Short: "Sign an unsigned TBM1 v2 manifest block",
		Args:  cobra.MaximumNArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			if inPath == "" && len(args) >= 1 {
				inPath = args[0]
			}
			if outPath == "" && len(args) >= 2 {
				outPath = args[1]
			}
			if inPath == "" {
				return errors.New("input manifest path is required (--in or positional argument)")
			}
			if outPath == "" {
				outPath = inPath
			}

			signer, err := signing.LoadSigner(signing.KeySource{
				Mock:    mock,
				KeyFile: keyFile,
				KeyHex:  keyHex,
			})
			if err != nil {
				return err
			}
			defer signer.Zeroise()

			pubHex, err := signing.SignManifest(inPath, outPath, signer)
			if err != nil {
				return fmt.Errorf("sign manifest: %w", err)
			}

			ui.Success("Signed TBM1 manifest -> %s (pubkey=%s)", outPath, shortID(pubHex, 16))
			return nil
		},
	}

	c.Flags().StringVarP(&inPath, "in", "i", "", "Input unsigned manifest block path")
	c.Flags().StringVarP(&outPath, "out", "o", "", "Output signed manifest block path")
	registerKeyFlags(c, &keyFile, &keyHex, &mock)
	return c
}

func newSignImageCmd() *cobra.Command {
	return newSignImageCommand("image", "Sign a raw firmware/bootloader binary with a Toob image header", "app")
}

func newSignStage1Cmd() *cobra.Command {
	return newSignImageCommand("stage1", "Sign a Stage-1 bootloader binary image", "stage1")
}

func newSignImageCommand(use, short, defaultRole string) *cobra.Command {
	var (
		inPath            string
		outPath           string
		payloadPath       string
		chip              string
		hardwarePath      string
		headerOffset      uint32
		entryRaw          string
		entryPoint        uint32
		roleStr           string
		stage1SVN         uint32
		execModel         string
		baseFingerprint   string
		requireBaseDigest bool
		keyFile           string
		keyHex            string
		mock              bool
		keyIndex          uint8
		unsigned          bool
	)

	c := &cobra.Command{
		Use:   use + " [in]",
		Short: short,
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if inPath == "" && len(args) == 1 {
				inPath = args[0]
			}
			if inPath == "" {
				return errors.New("input binary path is required (--in or positional argument)")
			}
			if outPath == "" {
				outPath = inPath + ".signed"
			}

			role, err := signing.ParseImageRole(roleStr)
			if err != nil {
				return err
			}
			if unsigned {
				if role.IsStage1() {
					return fmt.Errorf("--unsigned is not permitted for Stage-1 role %s", role)
				}
				if mock || strings.TrimSpace(keyFile) != "" || strings.TrimSpace(keyHex) != "" {
					return errors.New("--unsigned cannot be combined with --mock, --key-file, or --key-hex")
				}
				if keyIndex != 0 {
					return errors.New("--unsigned cannot be combined with non-zero --key-index")
				}
			}

			var hdrOffPtr *uint32
			if cmd.Flags().Changed("header-offset") {
				hdrOffPtr = &headerOffset
			}

			if rawEntry := strings.TrimSpace(entryRaw); rawEntry != "" {
				trimmed := strings.TrimRight(rawEntry, "uUlL")
				entryVal, entryErr := build.ParseU64Literal(trimmed)
				if entryErr != nil {
					return fmt.Errorf("invalid --entry %q: %w", entryRaw, entryErr)
				}
				if entryVal > math.MaxUint32 {
					return fmt.Errorf("--entry %q exceeds 32-bit unsigned range", entryRaw)
				}
				entryPoint = uint32(entryVal)
				if hdrOffPtr == nil &&
					strings.TrimSpace(chip) == "" &&
					strings.TrimSpace(hardwarePath) == "" &&
					entryPoint >= signing.ToobImageHeaderLen &&
					entryPoint <= 0x1000 &&
					entryPoint%4 == 0 {
					off := entryPoint
					hdrOffPtr = &off
				}
			}

			if role.IsStage1() && !cmd.Flags().Changed("stage1-svn") {
				stage1SVN = 1
			}

			var baseFP *[32]byte
			if baseFingerprint != "" {
				decoded, decErr := decodeHexBytes32(baseFingerprint, "base-fingerprint")
				if decErr != nil {
					return decErr
				}
				var arr [32]byte
				copy(arr[:], decoded)
				baseFP = &arr
			}

			var payload []byte
			if payloadPath != "" {
				payload, err = os.ReadFile(filepath.Clean(payloadPath))
				if err != nil {
					return fmt.Errorf("read payload %s: %w", payloadPath, err)
				}
			}

			var signer tbm1.Signer
			if !unsigned {
				localSigner, loadErr := signing.LoadSigner(signing.KeySource{
					Mock:    mock,
					KeyFile: keyFile,
					KeyHex:  keyHex,
				})
				if loadErr != nil {
					return loadErr
				}
				defer localSigner.Zeroise()
				signer = localSigner
			}

			res, err := signing.SignImage(signing.ImageOptions{
				InPath:                 inPath,
				OutPath:                outPath,
				Payload:                payload,
				Chip:                   chip,
				HardwarePath:           hardwarePath,
				HeaderOffset:           hdrOffPtr,
				EntryPoint:             entryPoint,
				Role:                   role,
				Stage1SVN:              stage1SVN,
				ExecModel:              execModel,
				BaseFingerprint:        baseFP,
				RequireBaseFingerprint: requireBaseDigest,
				KeyIndex:               keyIndex,
				Unsigned:               unsigned,
			}, signer)
			if err != nil {
				return fmt.Errorf("sign image: %w", err)
			}

			if unsigned {
				ui.Success("Built unsigned %s image -> %s (%d bytes)", res.Role, res.OutPath, res.ImageSize)
			} else {
				ui.Success("Signed %s image -> %s (%d bytes)", res.Role, res.OutPath, res.ImageSize)
			}
			return nil
		},
	}

	c.Flags().StringVarP(&inPath, "in", "i", "", "Input raw binary path")
	c.Flags().StringVarP(&outPath, "out", "o", "", "Output signed binary path")
	c.Flags().StringVar(&payloadPath, "payload", "", "Optional explicit raw payload file")
	c.Flags().StringVar(&chip, "chip", "", "Target chip identifier (for declarative header offset resolution)")
	c.Flags().StringVar(&hardwarePath, "hardware", "", "Path to declarative hardware.json")
	c.Flags().Uint32Var(&headerOffset, "header-offset", 0, "Override Toob image header byte offset")
	c.Flags().StringVar(&entryRaw, "entry", "", "Image entry offset/address (hex or decimal; implies --header-offset on XIP when no --chip/--hardware/--header-offset is set)")
	c.Flags().Uint32Var(&entryPoint, "entry-point", 0, "Override image entrypoint address")
	c.MarkFlagsMutuallyExclusive("entry", "entry-point")
	c.Flags().StringVar(&roleStr, "role", defaultRole, "Image role (app, recovery, stage1, stage1a, stage1b, netcore)")
	c.Flags().Uint32Var(&stage1SVN, "stage1-svn", 0, "Stage-1 security version number")
	c.Flags().StringVar(&execModel, "exec-model", "", "Execution model override (xip or ram)")
	c.Flags().StringVar(&baseFingerprint, "base-fingerprint", "", "Expected 32-byte SHA-256 base fingerprint hex")
	c.Flags().BoolVar(&requireBaseDigest, "require-base-fingerprint", false, "Require base fingerprint matching")
	c.Flags().Uint8Var(&keyIndex, "key-index", 0, "OTP root key slot index recorded in TSIG trailer")
	c.Flags().BoolVar(&unsigned, "unsigned", false, "Build non-Stage-1 image header without TSIG signature trailer (DEV/TEST ONLY)")
	registerKeyFlags(c, &keyFile, &keyHex, &mock)
	c.MarkFlagsMutuallyExclusive("unsigned", "mock", "key-file", "key-hex")
	return c
}

func newSignStage0Cmd() *cobra.Command {
	var (
		elfPath      string
		outPath      string
		chip         string
		hardwarePath string
		packagesDir  string
	)

	c := &cobra.Command{
		Use:   "stage0 [elf]",
		Short: "Pack a Stage-0 ELF with declarative bootrom headers",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if elfPath == "" && len(args) == 1 {
				elfPath = args[0]
			}
			if elfPath == "" {
				return errors.New("input Stage-0 ELF path is required (--elf or positional argument)")
			}
			if outPath == "" {
				return errors.New("--out is required")
			}

			res, err := signing.PackStage0(signing.Stage0Options{
				ELFPath:      elfPath,
				OutPath:      outPath,
				Chip:         chip,
				HardwarePath: hardwarePath,
				PackagesDir:  packagesDir,
			})
			if err != nil {
				return fmt.Errorf("pack Stage-0 image: %w", err)
			}

			ui.Success("Packed Stage-0 image -> %s (%d bytes)", res.OutPath, res.Size)
			return nil
		},
	}

	c.Flags().StringVarP(&elfPath, "elf", "i", "", "Input Stage-0 ELF path")
	c.Flags().StringVarP(&outPath, "out", "o", "", "Output Stage-0 packed binary path (required)")
	c.Flags().StringVar(&chip, "chip", "", "Target chip identifier")
	c.Flags().StringVar(&hardwarePath, "hardware", "", "Path to hardware.json")
	c.Flags().StringVar(&packagesDir, "packages-dir", "", "Override HAL packages directory")
	return c
}

func newSignBundleCmd() *cobra.Command {
	var (
		opts           signing.BundleOptions
		roleStr        string
		target         uint8
		reverseOldPath string
		sbomDigestHex  string
		deviceBindHex  string
		keyFile        string
		keyHex         string
		mock           bool
	)

	c := &cobra.Command{
		Use:   "bundle [installed-bin] [out-bundle]",
		Short: "Pack and sign an OTA/recovery TBM1 v2 bundle",
		Args:  cobra.MaximumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if opts.InstalledPath == "" && len(args) >= 1 {
				opts.InstalledPath = args[0]
			}
			if opts.OutPath == "" && len(args) >= 2 {
				opts.OutPath = args[1]
			}
			if opts.InstalledPath == "" {
				return errors.New("input installed image is required (--in or positional argument)")
			}
			if opts.OutPath == "" {
				return errors.New("output bundle path is required (--out or positional argument)")
			}

			role, err := signing.ParseImageRole(roleStr)
			if err != nil {
				return err
			}
			opts.Role = role

			if cmd.Flags().Changed("target-slot") {
				opts.TargetSlot = &target
			}
			if reverseOldPath != "" {
				revData, readErr := os.ReadFile(filepath.Clean(reverseOldPath))
				if readErr != nil {
					return fmt.Errorf("read reverse-delta base %s: %w", reverseOldPath, readErr)
				}
				opts.ReverseOld = revData
			}
			if sbomDigestHex != "" {
				sbomBytes, decErr := decodeHexBytes32(sbomDigestHex, "sbom-digest")
				if decErr != nil {
					return decErr
				}
				opts.SBOMDigest = sbomBytes
			}
			if deviceBindHex != "" {
				bindBytes, decErr := decodeHexBytes32(deviceBindHex, "device-bind")
				if decErr != nil {
					return decErr
				}
				opts.DeviceBind = bindBytes
			}

			signer, err := signing.LoadSigner(signing.KeySource{
				Mock:    mock,
				KeyFile: keyFile,
				KeyHex:  keyHex,
			})
			if err != nil {
				return err
			}
			defer signer.Zeroise()

			res, err := signing.SignBundle(opts, signer)
			if err != nil {
				return fmt.Errorf("sign bundle: %w", err)
			}

			ui.Success("Signed TBM1 bundle -> %s (%d bytes, slot=%d)", res.OutPath, len(res.Data), res.TargetSlot)
			return nil
		},
	}

	c.Flags().StringVarP(&opts.InstalledPath, "in", "i", "", "Path to signed installed binary")
	c.Flags().StringVar(&opts.InstalledPath, "installed", "", "Alias for --in")
	c.Flags().StringVarP(&opts.OutPath, "out", "o", "", "Output bundle path")
	c.Flags().StringVar(&roleStr, "role", "app", "Target image role (app, recovery, stage1a, stage1b, netcore)")
	c.Flags().Uint8Var(&target, "target-slot", 0, "Target flash slot index override")
	c.Flags().StringVar(&opts.BasePath, "base", "", "Optional base binary for delta compression")
	c.Flags().Uint32Var(&opts.BaseSVN, "base-svn", 0, "Base firmware SVN for delta updates")
	c.Flags().BoolVar(&opts.Compress, "compress", true, "Enable Heatshrink compression in TBM1 trailer")
	c.Flags().StringVar(&reverseOldPath, "reverse-old", "", "Path to old image for reverse-delta recovery generation")
	c.Flags().StringVarP(&opts.DeviceTomlPath, "manifest", "m", "", "Path to device.toml for declarative layout parameters")
	c.Flags().StringVar(&opts.Chip, "chip", "", "Target chip identifier")
	c.Flags().StringVar(&opts.HardwarePath, "hardware", "", "Path to hardware.json")
	c.Flags().StringVar(&opts.CoreDir, "core-dir", "", "Override Core SDK path")
	c.Flags().Uint32Var(&opts.SectorSize, "sector-size", 0, "Flash sector size override")
	c.Flags().Uint32Var(&opts.StagingBudget, "staging-budget", 0, "Staging partition size budget override")
	c.Flags().StringVar(&opts.TransportProvider, "transport", "", "Transport mode override")
	c.Flags().BoolVar(&opts.Flat, "flat", false, "Emit flat TBM1 container instead of trailer layout")
	c.Flags().Uint16Var(&opts.VendorID, "vendor-id", 0, "16-bit vendor ID")
	c.Flags().Uint16Var(&opts.ProductID, "product-id", 0, "16-bit product ID")
	c.Flags().Uint16Var(&opts.HWRevMin, "hw-rev-min", 0, "Minimum hardware revision")
	c.Flags().Uint16Var(&opts.HWRevMax, "hw-rev-max", 0, "Maximum hardware revision")
	c.Flags().Uint8Var(&opts.KeyIndex, "key-index", 0, "Signing key slot index")
	c.Flags().Uint32Var(&opts.KeyEpoch, "key-epoch", 0, "Signing key anti-rollback epoch")
	c.Flags().Uint32Var(&opts.SVN, "svn", 0, "Application security version number")
	c.Flags().Uint32Var(&opts.Stage1SVN, "stage1-svn", 0, "Minimum required Stage-1 SVN")
	c.Flags().Uint32Var(&opts.BuildNumber, "build-number", 0, "Monotonic build number")
	c.Flags().Uint16Var(&opts.VerMajor, "ver-major", 0, "Semantic major version")
	c.Flags().Uint16Var(&opts.VerMinor, "ver-minor", 0, "Semantic minor version")
	c.Flags().Uint16Var(&opts.VerPatch, "ver-patch", 0, "Semantic patch version")
	c.Flags().Uint16Var(&opts.BootRetryLimit, "boot-retry-limit", 0, "Boot attempt limit before rollback")
	c.Flags().StringVar(&sbomDigestHex, "sbom-digest", "", "Hex SHA-256 digest of attached SBOM")
	c.Flags().StringVar(&deviceBindHex, "device-bind", "", "Hex device binding ID (32 bytes)")
	c.Flags().StringVar(&opts.PQCAlgo, "pqc-algo", "", "Post-quantum signature algorithm (e.g. ml_dsa_65)")
	c.Flags().StringVar(&opts.PQCPubkeyPath, "pqc-pubkey", "", "Path to PQC public key binary")
	c.Flags().StringVar(&opts.PQCSigPath, "pqc-sig", "", "Path to PQC detached signature binary")
	registerKeyFlags(c, &keyFile, &keyHex, &mock)
	return c
}

func newSignKeygenCmd() *cobra.Command {
	var (
		privOut   string
		pubOut    string
		overwrite bool
	)

	c := &cobra.Command{
		Use:   "keygen",
		Short: "Generate a fresh Ed25519 root/release signing keypair",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			pubHex, err := signing.GenerateKeypair(privOut, pubOut, overwrite)
			if err != nil {
				return fmt.Errorf("generate signing keypair: %w", err)
			}
			ui.Success("Generated Ed25519 keypair:")
			ui.Info("Private key: %s (mode 0600, never printed)", privOut)
			ui.Info("Public key:  %s", pubOut)
			ui.Info("Pubkey hex:  %s", pubHex)
			return nil
		},
	}

	c.Flags().StringVar(&privOut, "priv", "toob-signing.priv.hex", "Private key output path")
	c.Flags().StringVar(&pubOut, "pub", "toob-signing.pub.hex", "Public key output path")
	c.Flags().BoolVar(&overwrite, "overwrite", false, "Overwrite existing key files")
	return c
}

func newSignTCC1Cmd() *cobra.Command {
	tccCmd := &cobra.Command{
		Use:   "tcc1",
		Short: "Sign and verify TCC1 cloud commands",
	}

	var (
		cmdCode     uint8
		flags       uint16
		counterMin  uint32
		issuedAt    uint32
		deviceIDHex string
		paramsHex   string
		outPath     string
		keyFile     string
		keyHex      string
		mock        bool
	)

	signCmd := &cobra.Command{
		Use:   "sign",
		Short: "Sign a TCC1 command frame",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if outPath == "" {
				return errors.New("--out is required")
			}

			var devID [32]byte
			if deviceIDHex != "" {
				dec, decErr := decodeHexBytes32(deviceIDHex, "device-id")
				if decErr != nil {
					return decErr
				}
				copy(devID[:], dec)
			}

			var params []byte
			if paramsHex != "" {
				dec, decErr := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(paramsHex), "0x"))
				if decErr != nil {
					return fmt.Errorf("invalid --params-hex: %w", decErr)
				}
				params = dec
			}

			signer, err := signing.LoadSigner(signing.KeySource{
				Mock:    mock,
				KeyFile: keyFile,
				KeyHex:  keyHex,
			})
			if err != nil {
				return err
			}
			defer signer.Zeroise()

			frame, err := signing.SignCloudCommand(signing.TCC1Options{
				Command:    signing.CloudCommand(cmdCode),
				Flags:      flags,
				CounterMin: counterMin,
				IssuedAt:   issuedAt,
				DeviceID:   devID,
				Params:     params,
			}, signer)
			if err != nil {
				return fmt.Errorf("sign TCC1 command: %w", err)
			}
			if err := os.WriteFile(filepath.Clean(outPath), frame, 0o600); err != nil {
				return fmt.Errorf("write TCC1 frame %s: %w", outPath, err)
			}
			ui.Success("Signed TCC1 command frame -> %s (%d bytes)", outPath, len(frame))
			return nil
		},
	}

	signCmd.Flags().StringVarP(&outPath, "out", "o", "", "Output signed TCC1 frame path (required)")
	signCmd.Flags().Uint8Var(&cmdCode, "command", 0, "TCC1 command opcode")
	signCmd.Flags().Uint16Var(&flags, "flags", 0, "TCC1 flags field")
	signCmd.Flags().Uint32Var(&counterMin, "counter-min", 0, "Monotonic minimum sequence counter")
	signCmd.Flags().Uint32Var(&issuedAt, "issued-at", 0, "Unix timestamp when command was issued")
	signCmd.Flags().StringVar(&deviceIDHex, "device-id", "", "Target 32-byte device ID hex")
	signCmd.Flags().StringVar(&paramsHex, "params-hex", "", "Optional hex-encoded command parameter bytes")
	registerKeyFlags(signCmd, &keyFile, &keyHex, &mock)

	var (
		inPath    string
		pubKeyHex string
	)
	verifyCmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify a TCC1 command frame signature",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			frame, err := os.ReadFile(filepath.Clean(inPath))
			if err != nil {
				return fmt.Errorf("read TCC1 frame %s: %w", inPath, err)
			}
			pub, err := parseEd25519PubHex(pubKeyHex)
			if err != nil {
				return err
			}
			if err := signing.VerifyCloudCommand(frame, pub); err != nil {
				return fmt.Errorf("verify TCC1 command: %w", err)
			}
			ui.Success("TCC1 signature valid (%s)", inPath)
			return nil
		},
	}
	verifyCmd.Flags().StringVarP(&inPath, "in", "i", "", "Input TCC1 frame path (required)")
	verifyCmd.Flags().StringVar(&pubKeyHex, "pubkey", "", "Ed25519 public key hex (required)")
	_ = verifyCmd.MarkFlagRequired("in")
	_ = verifyCmd.MarkFlagRequired("pubkey")

	tccCmd.AddCommand(signCmd, verifyCmd)
	return tccCmd
}

func newSignKDMCmd() *cobra.Command {
	kdmCmd := &cobra.Command{
		Use:   "kdm",
		Short: "Sign and verify Key Delegation Manifests (KDM)",
	}

	var (
		seqNum         uint32
		delegatePubHex string
		outPath        string
		keyFile        string
		keyHex         string
		mock           bool
	)

	signCmd := &cobra.Command{
		Use:   "sign",
		Short: "Sign a Key Delegation Manifest",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if outPath == "" {
				return errors.New("--out is required")
			}
			newPub, err := decodeHexBytes32(delegatePubHex, "delegate-pubkey")
			if err != nil {
				return err
			}

			signer, err := signing.LoadSigner(signing.KeySource{
				Mock:    mock,
				KeyFile: keyFile,
				KeyHex:  keyHex,
			})
			if err != nil {
				return err
			}
			defer signer.Zeroise()

			blob, err := signing.SignKDM(signing.KDMOptions{
				SequenceNumber: seqNum,
				NewCloudPubkey: newPub,
			}, signer)
			if err != nil {
				return fmt.Errorf("sign KDM: %w", err)
			}
			if err := os.WriteFile(filepath.Clean(outPath), blob, 0o600); err != nil {
				return fmt.Errorf("write KDM %s: %w", outPath, err)
			}
			ui.Success("Signed KDM -> %s (%d bytes)", outPath, len(blob))
			return nil
		},
	}

	signCmd.Flags().StringVarP(&outPath, "out", "o", "", "Output KDM file path (required)")
	signCmd.Flags().StringVar(&delegatePubHex, "delegate-pubkey", "", "Delegated Ed25519 public key hex (required)")
	signCmd.Flags().Uint32Var(&seqNum, "sequence", 0, "Monotonic key delegation sequence number")
	registerKeyFlags(signCmd, &keyFile, &keyHex, &mock)
	_ = signCmd.MarkFlagRequired("delegate-pubkey")

	var (
		inPath    string
		pubKeyHex string
	)
	verifyCmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify a Key Delegation Manifest",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			blob, err := os.ReadFile(filepath.Clean(inPath))
			if err != nil {
				return fmt.Errorf("read KDM %s: %w", inPath, err)
			}
			pub, err := parseEd25519PubHex(pubKeyHex)
			if err != nil {
				return err
			}
			if err := signing.VerifyKDM(blob, pub); err != nil {
				return fmt.Errorf("verify KDM: %w", err)
			}
			ui.Success("KDM signature valid (%s)", inPath)
			return nil
		},
	}
	verifyCmd.Flags().StringVarP(&inPath, "in", "i", "", "Input KDM file path (required)")
	verifyCmd.Flags().StringVar(&pubKeyHex, "pubkey", "", "Root Ed25519 public key hex (required)")
	_ = verifyCmd.MarkFlagRequired("in")
	_ = verifyCmd.MarkFlagRequired("pubkey")

	kdmCmd.AddCommand(signCmd, verifyCmd)
	return kdmCmd
}

func parseEd25519PubHex(raw string) (ed25519.PublicKey, error) {
	b, err := decodeHexBytes32(raw, "pubkey")
	if err != nil {
		return nil, err
	}
	return ed25519.PublicKey(b), nil
}

func decodeHexBytes32(raw, label string) ([]byte, error) {
	cleaned := strings.TrimPrefix(strings.TrimSpace(raw), "0x")
	b, err := hex.DecodeString(cleaned)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("--%s must be %d hex characters (%d bytes)", label, ed25519.PublicKeySize*2, ed25519.PublicKeySize)
	}
	return b, nil
}
