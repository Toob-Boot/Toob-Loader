package signing

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Toob-Boot/Toob-Loader/toob-go-lib/build"
	"github.com/Toob-Boot/Toob-Loader/toob-go-lib/tbm1"
	"github.com/toob-boot/toob/internal/manifest"
	"github.com/toob-boot/toob/internal/registry"
)

const (
	// MLDSA65Algorithm is the Toob PQC identifier matching crypto_manifest.json.
	MLDSA65Algorithm = "ml_dsa_65"
	// MLDSA65PublicKeySize is the FIPS 204 ML-DSA-65 public key size in bytes.
	MLDSA65PublicKeySize = 1952
	// MLDSA65SignatureSize is the FIPS 204 ML-DSA-65 signature size in bytes.
	MLDSA65SignatureSize = 3309
)

// Stage0Options configures hardware-validated BootROM Stage-0 ELF packing.
type Stage0Options struct {
	ELFPath      string
	OutPath      string
	Chip         string
	HardwarePath string
	CacheDir     string
	Cache        *registry.Cache
	PackagesDir  string
}

// Stage0PackResult summarizes a packed BootROM Stage-0 image.
type Stage0PackResult struct {
	OutPath string
	Chip    string
	Size    int
	Data    []byte
}

// BundleOptions configures declarative TBM1 v2 bundle construction, signing, and verification.
type BundleOptions struct {
	Installed     []byte
	InstalledPath string
	OutPath       string

	Role       ImageRole
	TargetSlot *uint8

	Base       []byte
	BasePath   string
	BaseSVN    uint32
	Compress   bool
	ReverseOld []byte

	DeviceTomlPath    string
	Chip              string
	HardwarePath      string
	CacheDir          string
	Cache             *registry.Cache
	CoreDir           string
	SectorSize        uint32
	StagingBudget     uint32
	TransportProvider string
	Flat              bool

	VendorID       uint16
	ProductID      uint16
	HWRevMin       uint16
	HWRevMax       uint16
	KeyIndex       uint8
	KeyEpoch       uint32
	SVN            uint32
	Stage1SVN      uint32
	BuildNumber    uint32
	VerMajor       uint16
	VerMinor       uint16
	VerPatch       uint16
	BootRetryLimit uint16
	SBOMDigest     []byte
	DeviceBind     []byte

	PQCAlgo       string
	PQCPubkey     []byte
	PQCPubkeyPath string
	PQCSig        []byte
	PQCSigPath    string
}

// BundleResult summarizes a built, self-verified, budget-checked TBM1 v2 bundle.
type BundleResult struct {
	OutPath           string
	TargetSlot        uint8
	Role              ImageRole
	SectorSize        uint32
	TransportProvider string
	StagingBudget     uint32
	PQCAlgorithm      string
	Data              []byte
}

// PackStage0 resolves hardware/chip metadata fail-fast (rejecting corrupt or missing
// chip_manifest.json) and packs a Stage-0 ELF using Toob-Boot's declarative BootROM packer.
func PackStage0(opts Stage0Options) (*Stage0PackResult, error) {
	elfTrim := strings.TrimSpace(opts.ELFPath)
	if elfTrim == "" {
		return nil, errors.New("stage0 ELF path must not be empty")
	}
	cleanELF := filepath.Clean(elfTrim)
	info, err := os.Stat(cleanELF)
	if err != nil {
		return nil, fmt.Errorf("stat stage0 ELF %s: %w", cleanELF, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("stage0 ELF %s is not a regular file", cleanELF)
	}

	if strings.TrimSpace(opts.Chip) == "" && strings.TrimSpace(opts.HardwarePath) == "" {
		return nil, errors.New("PackStage0 requires Chip or HardwarePath")
	}

	chipCtx, err := resolveChipContext(opts.Chip, opts.HardwarePath, opts.CacheDir, opts.PackagesDir, opts.Cache)
	if err != nil {
		return nil, err
	}

	var packed []byte
	if chipCtx.PackagesDir != "" {
		packed, err = manifest.PackStage0ELFWithPackagesDir(cleanELF, chipCtx.Hardware, chipCtx.PackagesDir)
	} else {
		packed, err = manifest.PackStage0FromHardwareJSON(cleanELF, chipCtx.HardwarePath)
	}
	if err != nil {
		return nil, fmt.Errorf("pack Stage-0 ELF: %w", err)
	}
	if len(packed) == 0 {
		return nil, errors.New("packed Stage-0 image is empty")
	}

	if strings.TrimSpace(opts.OutPath) != "" {
		if err := writeFileAtomic(opts.OutPath, packed, 0o644, true); err != nil {
			return nil, fmt.Errorf("write packed Stage-0 image: %w", err)
		}
	}

	chipName := strings.TrimSpace(opts.Chip)
	if chipName == "" && chipCtx.Hardware != nil {
		chipName = chipCtx.Hardware.ChipFamily
	}

	return &Stage0PackResult{
		OutPath: opts.OutPath,
		Chip:    chipName,
		Size:    len(packed),
		Data:    packed,
	}, nil
}

// SignBundle builds, signs, self-verifies, and budget-checks a TBM1 v2 update bundle
// using declarative device, flash sector, transport, and PQC metadata.
func SignBundle(opts BundleOptions, signer tbm1.Signer) (*BundleResult, error) {
	if signer == nil {
		return nil, errors.New("signer must not be nil")
	}

	targetSlot, role, err := resolveBundleSlotAndRole(opts.Role, opts.TargetSlot)
	if err != nil {
		return nil, err
	}

	installed, err := loadOptionalPayload(opts.Installed, opts.InstalledPath, "installed image")
	if err != nil {
		return nil, err
	}
	if len(installed) == 0 {
		return nil, errors.New("non-empty Installed image or InstalledPath is required")
	}

	baseImg, err := loadOptionalPayload(opts.Base, opts.BasePath, "base image")
	if err != nil {
		return nil, err
	}
	if len(baseImg) > 0 && opts.Compress {
		return nil, errors.New("base image (TDS1 delta) and Heatshrink compression are mutually exclusive")
	}

	dt, err := parseOptionalDeviceToml(opts.DeviceTomlPath)
	if err != nil {
		return nil, err
	}

	chipName := strings.TrimSpace(opts.Chip)
	if chipName == "" && dt != nil {
		chipName = strings.TrimSpace(dt.Device.Chip)
	}

	chipCtx, err := resolveChipContext(chipName, opts.HardwarePath, opts.CacheDir, "", opts.Cache)
	if err != nil {
		return nil, err
	}

	var hw *manifest.HardwareJson
	var cm *manifest.ChipManifest
	if chipCtx != nil {
		hw = chipCtx.Hardware
		cm = chipCtx.ChipManifest
	}

	if validateErr := validateManifestContextIfAvailable(opts, dt, chipCtx); validateErr != nil {
		return nil, validateErr
	}

	if roleErr := validateRoleAgainstExecModel(role, effectiveExecModel("", cm)); roleErr != nil {
		return nil, roleErr
	}

	sectorSize, err := resolveBundleSectorSize(opts.SectorSize, hw)
	if err != nil {
		return nil, err
	}

	transportProvider, err := resolveAndValidateTransport(opts.TransportProvider, dt, len(baseImg) > 0, opts.Compress)
	if err != nil {
		return nil, err
	}

	stagingBudget, err := resolveStagingBudget(dt, hw, cm, sectorSize, transportProvider, opts.StagingBudget)
	if err != nil {
		return nil, err
	}

	stage1SVN := opts.Stage1SVN
	if stage1SVN == 0 && dt != nil {
		stage1SVN = dt.BootConfig.Stage1Svn
	}
	if s1Err := validateStage1BundleConsistency(targetSlot, stage1SVN, installed); s1Err != nil {
		return nil, s1Err
	}

	pqcAlgo, pqcPub, pqcSig, err := resolveAndValidatePQC(opts, dt, cm)
	if err != nil {
		return nil, err
	}

	m := buildTBM1Manifest(opts, dt, targetSlot, sectorSize, stage1SVN, installed, baseImg, pqcPub, pqcSig)
	pkg, err := tbm1.Build(m, signer)
	if err != nil {
		return nil, fmt.Errorf("build TBM1 bundle: %w", err)
	}

	storedPrimary := installed
	if len(pkg.Payloads) > 0 && pkg.Payloads[0].Data != nil {
		storedPrimary = pkg.Payloads[0].Data
	}

	var bundle []byte
	if opts.Flat {
		bundle, err = pkg.AssembleFlat([][]byte{storedPrimary})
	} else {
		bundle, err = pkg.AssembleTrailer([][]byte{storedPrimary})
	}
	if err != nil {
		return nil, fmt.Errorf("assemble TBM1 bundle: %w", err)
	}

	if err := selfVerifyAssembledBundle(bundle, opts.Flat, pkg.TotalLen, signer); err != nil {
		return nil, err
	}

	if stagingBudget > 0 && uint64(len(bundle)) > uint64(stagingBudget) {
		return nil, fmt.Errorf("signed bundle size %d bytes exceeds staging budget %d bytes", len(bundle), stagingBudget)
	}

	if strings.TrimSpace(opts.OutPath) != "" {
		if err := writeFileAtomic(opts.OutPath, bundle, 0o644, true); err != nil {
			return nil, fmt.Errorf("write TBM1 bundle: %w", err)
		}
	}

	return &BundleResult{
		OutPath:           opts.OutPath,
		TargetSlot:        targetSlot,
		Role:              role,
		SectorSize:        sectorSize,
		TransportProvider: transportProvider,
		StagingBudget:     stagingBudget,
		PQCAlgorithm:      pqcAlgo,
		Data:              bundle,
	}, nil
}

func resolveBundleSlotAndRole(roleOpt ImageRole, slotOpt *uint8) (uint8, ImageRole, error) {
	if strings.TrimSpace(string(roleOpt)) != "" {
		parsedRole, err := ParseImageRole(string(roleOpt))
		if err != nil {
			return 0, "", err
		}
		mappedSlot, err := parsedRole.TargetSlot()
		if err != nil {
			return 0, "", err
		}
		if slotOpt != nil && *slotOpt != mappedSlot {
			return 0, "", fmt.Errorf("explicit TargetSlot %d conflicts with Role %s (slot %d)", *slotOpt, parsedRole, mappedSlot)
		}
		return mappedSlot, parsedRole, nil
	}

	if slotOpt == nil {
		return 0, "", errors.New("bundle Role or TargetSlot must be explicitly specified (refusing silent SlotApp fallback)")
	}

	switch *slotOpt {
	case tbm1.SlotApp:
		return tbm1.SlotApp, RoleApp, nil
	case tbm1.SlotNetcore:
		return tbm1.SlotNetcore, RoleNetcore, nil
	case tbm1.SlotRecovery:
		return tbm1.SlotRecovery, RoleRecovery, nil
	case tbm1.SlotStage1:
		return tbm1.SlotStage1, RoleStage1, nil
	default:
		return 0, "", fmt.Errorf("unsupported TBM1 TargetSlot %d (expected 0..3)", *slotOpt)
	}
}

func loadOptionalPayload(raw []byte, path, label string) ([]byte, error) {
	if len(raw) > 0 && strings.TrimSpace(path) != "" {
		return nil, fmt.Errorf("%s bytes and path are mutually exclusive", label)
	}
	if len(raw) > 0 {
		return raw, nil
	}
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	data, err := readFileBounded(path, maxFirmwareFileBytes)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", label, err)
	}
	return data, nil
}

func parseOptionalDeviceToml(path string) (*manifest.DeviceToml, error) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return nil, nil
	}
	dt, err := manifest.ParseToml(filepath.Clean(trimmed))
	if err != nil {
		return nil, fmt.Errorf("parse device.toml %s: %w", trimmed, err)
	}
	return dt, nil
}

func validateManifestContextIfAvailable(opts BundleOptions, dt *manifest.DeviceToml, chipCtx *resolvedChipContext) error {
	coreDir := strings.TrimSpace(opts.CoreDir)
	if coreDir == "" || dt == nil || chipCtx == nil || chipCtx.HardwarePath == "" {
		return nil
	}

	var cmPath string
	if chipCtx.ChipManifest != nil && chipCtx.ChipDir != "" {
		cmPath = filepath.Join(chipCtx.ChipDir, "chip_manifest.json")
	}

	outDir := os.TempDir()
	if strings.TrimSpace(opts.OutPath) != "" {
		outDir = filepath.Dir(filepath.Clean(opts.OutPath))
	}

	_, err := manifest.LoadSilent(manifest.Inputs{
		Device:           dt,
		ProjectDir:       filepath.Dir(filepath.Clean(opts.DeviceTomlPath)),
		HardwarePath:     chipCtx.HardwarePath,
		ChipManifestPath: cmPath,
		CoreDir:          filepath.Clean(coreDir),
		OutDir:           outDir,
	})
	if err != nil {
		return fmt.Errorf("manifest context validation failed: %w", err)
	}
	return nil
}

func resolveBundleSectorSize(explicit uint32, hw *manifest.HardwareJson) (uint32, error) {
	if explicit != 0 {
		if explicit&(explicit-1) != 0 || explicit > tbm1.MaxSectorSize {
			return 0, fmt.Errorf("explicit sector_size %d must be a power of two <= %d", explicit, tbm1.MaxSectorSize)
		}
	}

	if hw != nil {
		hwMaxSector, err := resolveFlashSectorSize(hw)
		if err != nil {
			return 0, err
		}
		if explicit == 0 {
			return hwMaxSector, nil
		}
		if explicit < hwMaxSector {
			return 0, fmt.Errorf("explicit sector_size %d is smaller than chip max flash sector_size %d", explicit, hwMaxSector)
		}
		return explicit, nil
	}

	if explicit == 0 {
		return 0, errors.New("flash sector_size cannot be resolved without Chip, HardwarePath, or explicit SectorSize")
	}
	return explicit, nil
}

func resolveAndValidateTransport(explicit string, dt *manifest.DeviceToml, useDelta, useCompress bool) (string, error) {
	tp := strings.ToLower(strings.TrimSpace(explicit))
	if tp == "" && dt != nil {
		tp = strings.ToLower(strings.TrimSpace(dt.BootConfig.TransportProvider))
	}

	if tp != "" {
		switch build.Transport(tp) {
		case build.TransportPointer,
			build.TransportOneway,
			build.TransportSwapScratch,
			build.TransportSwapMove,
			build.TransportSwapOffset:
		default:
			return "", fmt.Errorf("unsupported transport_provider %q", tp)
		}
	} else if dt != nil {
		return "", errors.New("device.toml boot_config.transport_provider must not be empty")
	}

	if dt != nil {
		if useDelta && dt.Features.Delta != nil && !*dt.Features.Delta {
			return "", errors.New("TDS1 delta requested, but device.toml disables features.delta")
		}
		if useCompress && dt.Features.Compression != nil && !*dt.Features.Compression {
			return "", errors.New("Heatshrink compression requested, but device.toml disables features.compression")
		}
	}
	return tp, nil
}

func resolveStagingBudget(dt *manifest.DeviceToml, hw *manifest.HardwareJson, cm *manifest.ChipManifest, sectorSize uint32, transport string, explicitBudget uint32) (uint32, error) {
	var derived uint64

	if hw != nil {
		flashTotal, err := resolveFlashTotalBytes(hw)
		if err != nil {
			return 0, err
		}

		if dt != nil {
			computed, err := computeDeviceStagingBudget(dt, hw, cm, sectorSize, transport, flashTotal)
			if err != nil {
				return 0, err
			}
			derived = computed
		} else if explicitRegion, ok := findNamedStagingRegion(hw); ok {
			derived = explicitRegion
		} else {
			derived = flashTotal
		}
	}

	if explicitBudget > 0 {
		if derived == 0 || uint64(explicitBudget) < derived {
			derived = uint64(explicitBudget)
		}
	}

	if derived > uint64(^uint32(0)) {
		return 0, fmt.Errorf("staging budget %d overflows uint32", derived)
	}
	return uint32(derived), nil
}

func computeDeviceStagingBudget(dt *manifest.DeviceToml, hw *manifest.HardwareJson, cm *manifest.ChipManifest, sectorSize uint32, transport string, flashTotal uint64) (uint64, error) {
	align := uint64(sectorSize)
	if uint64(hw.Flash.AppAlignment) > align {
		align = uint64(hw.Flash.AppAlignment)
	}

	stage1Slots := uint64(1)
	if cm != nil && cm.SlotCapabilities != nil && cm.SlotCapabilities.SlotCount >= 2 {
		stage1Slots = 2
	}

	stage0, err := alignUpU64(uint64(dt.Partitions.Stage0Size), uint64(sectorSize))
	if err != nil {
		return 0, err
	}
	stage1Single, err := alignUpU64(uint64(dt.Partitions.Stage1Size), uint64(sectorSize))
	if err != nil {
		return 0, err
	}
	scratch, err := alignUpU64(uint64(dt.Partitions.ScratchSize), uint64(sectorSize))
	if err != nil {
		return 0, err
	}
	recovery, err := alignUpU64(uint64(dt.Partitions.RecoverySize), uint64(sectorSize))
	if err != nil {
		return 0, err
	}
	netcore, err := alignUpU64(uint64(dt.Partitions.NetcoreSize), uint64(sectorSize))
	if err != nil {
		return 0, err
	}
	wal := uint64(dt.Partitions.WalSectors) * uint64(sectorSize)
	fixed := stage0 + stage1Single*stage1Slots + scratch + recovery + netcore + wal

	if fixed >= flashTotal {
		return 0, fmt.Errorf("fixed device.toml partitions (%d bytes) exceed chip flash (%d bytes)", fixed, flashTotal)
	}

	isSwapMove := transport == string(build.TransportSwapMove)
	spare := uint64(0)
	if isSwapMove {
		spare = uint64(sectorSize)
	}

	if dt.Partitions.AppSize > 0 {
		appBudget, alignErr := alignUpU64(uint64(dt.Partitions.AppSize), align)
		if alignErr != nil {
			return 0, alignErr
		}
		stagingBudget := appBudget + spare
		if fixed+appBudget+stagingBudget > flashTotal {
			return 0, fmt.Errorf("device.toml app + staging budgets (%d + %d + %d fixed) exceed chip flash (%d bytes)", appBudget, stagingBudget, fixed, flashTotal)
		}
		return stagingBudget, nil
	}

	metaReserve := uint64(0)
	if dt.Partitions.WalSectors == 0 {
		metaReserve = uint64(minMetadataSectors) * uint64(sectorSize)
	}
	if fixed+metaReserve+spare >= flashTotal {
		return 0, fmt.Errorf("insufficient flash remaining (%d bytes) for app and staging slots", flashTotal)
	}

	remaining := flashTotal - fixed - metaReserve - spare
	half := (remaining / 2 / align) * align
	if half == 0 {
		return 0, errors.New("computed zero staging budget from remaining flash")
	}
	return half + spare, nil
}

func findNamedStagingRegion(hw *manifest.HardwareJson) (uint64, bool) {
	for _, r := range hw.Flash.Regions {
		if strings.EqualFold(strings.TrimSpace(r.Name), "staging") {
			sz := uint64(r.Size)
			if sz == 0 && r.SectorSize > 0 && r.Count > 0 {
				sz = uint64(r.SectorSize) * uint64(r.Count)
			}
			if sz > 0 {
				return sz, true
			}
		}
	}
	return 0, false
}

func validateStage1BundleConsistency(targetSlot uint8, stage1SVN uint32, installed []byte) error {
	if targetSlot != tbm1.SlotStage1 {
		return nil
	}
	if stage1SVN == 0 {
		return errors.New("stage1_svn must be >= 1 for Stage-1 bundles")
	}
	if len(installed) >= ToobImageHeaderLen && binary.LittleEndian.Uint32(installed[0:4]) == ToobImageMagic {
		svnMagic := binary.LittleEndian.Uint32(installed[12:16])
		if svnMagic != ToobStage1SVNMagic {
			return fmt.Errorf("Stage-1 image header has invalid SVN magic 0x%08x (expected 0x%08x)", svnMagic, ToobStage1SVNMagic)
		}
		imgSVN := binary.LittleEndian.Uint32(installed[16:20])
		if imgSVN != stage1SVN {
			return fmt.Errorf("bundle stage1_svn (%d) disagrees with Stage-1 image header SVN (%d)", stage1SVN, imgSVN)
		}
	}
	return nil
}

func resolveAndValidatePQC(opts BundleOptions, dt *manifest.DeviceToml, cm *manifest.ChipManifest) (string, []byte, []byte, error) {
	algo := strings.ToLower(strings.TrimSpace(opts.PQCAlgo))
	if algo == "" && dt != nil {
		algo = strings.ToLower(strings.TrimSpace(dt.Crypto.Pqc))
	}
	if algo == "" && cm != nil && cm.Crypto != nil {
		algo = strings.ToLower(strings.TrimSpace(cm.Crypto.Pqc))
	}

	pqcPub, err := loadOptionalPayload(opts.PQCPubkey, opts.PQCPubkeyPath, "PQC public key")
	if err != nil {
		return "", nil, nil, err
	}
	pqcSig, err := loadOptionalPayload(opts.PQCSig, opts.PQCSigPath, "PQC signature")
	if err != nil {
		return "", nil, nil, err
	}

	hasPub := len(pqcPub) > 0
	hasSig := len(pqcSig) > 0
	if hasPub != hasSig {
		return "", nil, nil, errors.New("PQCPubkey and PQCSig must be provided together")
	}

	if algo == "" || algo == "none" {
		if hasPub {
			return "", nil, nil, errors.New("detached PQC signature supplied when PQC algorithm is disabled")
		}
		return "none", nil, nil, nil
	}

	if !hasPub || !hasSig {
		return "", nil, nil, fmt.Errorf("PQC algorithm %q is enabled: detached PQCPubkey and PQCSig are required", algo)
	}
	if isAllZero(pqcPub) || isAllZero(pqcSig) {
		return "", nil, nil, errors.New("PQC public key and signature must not be all zeros")
	}
	if algo == MLDSA65Algorithm {
		if len(pqcPub) != MLDSA65PublicKeySize {
			return "", nil, nil, fmt.Errorf("ml_dsa_65 public key must be %d bytes, got %d", MLDSA65PublicKeySize, len(pqcPub))
		}
		if len(pqcSig) != MLDSA65SignatureSize {
			return "", nil, nil, fmt.Errorf("ml_dsa_65 signature must be %d bytes, got %d", MLDSA65SignatureSize, len(pqcSig))
		}
	}
	return algo, pqcPub, pqcSig, nil
}

func buildTBM1Manifest(
	opts BundleOptions,
	dt *manifest.DeviceToml,
	targetSlot uint8,
	sectorSize uint32,
	stage1SVN uint32,
	installed, baseImg, pqcPub, pqcSig []byte,
) tbm1.Manifest {
	vendorID := opts.VendorID
	productID := opts.ProductID
	hwRevMin := opts.HWRevMin
	hwRevMax := opts.HWRevMax
	if dt != nil {
		if vendorID == 0 {
			vendorID = dt.Identity.VendorID
		}
		if productID == 0 {
			productID = dt.Identity.ProductID
		}
		if hwRevMin == 0 && hwRevMax == 0 && dt.Identity.HwRev != 0 {
			hwRevMin = dt.Identity.HwRev
			hwRevMax = dt.Identity.HwRev
		}
	}

	img := tbm1.Image{
		TargetSlot: targetSlot,
		CompAlg:    tbm1.CompNone,
		DeltaAlg:   tbm1.DeltaNone,
		Installed:  installed,
		VerMajor:   opts.VerMajor,
		VerMinor:   opts.VerMinor,
		VerPatch:   opts.VerPatch,
	}
	if len(baseImg) > 0 {
		img.DeltaAlg = tbm1.DeltaTDS1
		img.Base = baseImg
		img.BaseSVN = opts.BaseSVN
	} else if opts.Compress {
		img.CompAlg = tbm1.CompHeatshrink
	}

	var rdeltas []tbm1.ReverseDelta
	if len(opts.ReverseOld) > 0 {
		rdeltas = append(rdeltas, tbm1.ReverseDelta{
			TargetSlot: targetSlot,
			DeltaAlg:   tbm1.DeltaTDS1,
			OldImage:   opts.ReverseOld,
		})
	}

	return tbm1.Manifest{
		VendorID:       vendorID,
		ProductID:      productID,
		HWRevMin:       hwRevMin,
		HWRevMax:       hwRevMax,
		KeyIndex:       opts.KeyIndex,
		KeyEpoch:       opts.KeyEpoch,
		SVN:            opts.SVN,
		Stage1SVN:      stage1SVN,
		BuildNumber:    opts.BuildNumber,
		FwVerMajor:     opts.VerMajor,
		FwVerMinor:     opts.VerMinor,
		FwVerPatch:     opts.VerPatch,
		BootRetryLimit: opts.BootRetryLimit,
		SBOMDigest:     bytes.Clone(opts.SBOMDigest),
		AutoSBOM:       len(opts.SBOMDigest) == 0,
		DeviceBind:     bytes.Clone(opts.DeviceBind),
		PQCSig:         pqcSig,
		PQCPubkey:      pqcPub,
		ReverseDeltas:  rdeltas,
		TrailerLayout:  !opts.Flat,
		SectorSize:     sectorSize,
		Images:         []tbm1.Image{img},
	}
}

func selfVerifyAssembledBundle(bundle []byte, flat bool, totalManifestLen uint32, signer tbm1.Signer) error {
	pub := signer.Public()
	if flat {
		if len(bundle) < int(totalManifestLen) {
			return fmt.Errorf("flat bundle truncated (%d < %d)", len(bundle), totalManifestLen)
		}
		if err := tbm1.VerifyBlock(bundle[:totalManifestLen], pub); err != nil {
			return fmt.Errorf("self-verify flat TBM1 manifest: %w", err)
		}
		return nil
	}

	off, length, err := tbm1.ParseTrailerLocator(bundle)
	if err != nil {
		return fmt.Errorf("parse bundle TrailerLocator: %w", err)
	}
	end := uint64(off) + uint64(length)
	if end > uint64(len(bundle)) {
		return fmt.Errorf("bundle TrailerLocator out of bounds [%d..%d) for size %d", off, end, len(bundle))
	}
	if err := tbm1.VerifyBlock(bundle[off:end], pub); err != nil {
		return fmt.Errorf("self-verify trailer TBM1 manifest: %w", err)
	}
	return nil
}
