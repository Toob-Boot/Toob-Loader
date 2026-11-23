package manifest

import (
	build "github.com/Toob-Boot/Toob-Loader/toob-go-lib/build"
	"github.com/toob-boot/toob/internal/ui"
)

// uiLogger routes build pipeline messages to the CLI output.
type uiLogger struct{}

func (uiLogger) Info(format string, args ...any)    { ui.Info(format, args...) }
func (uiLogger) Success(format string, args ...any) { ui.Success(format, args...) }
func (uiLogger) Warn(format string, args ...any)    { ui.Warn(format, args...) }
func (uiLogger) Step(format string, args ...any)    { ui.Step(format, args...) }

// Type aliases to toob-go-lib/build.
type (
	HexUint32             = build.HexUint32
	DeviceToml            = build.DeviceToml
	HardwareJson          = build.HardwareJson //nolint:staticcheck // ST1003: mirrors toob-go-lib/build.HardwareJson and internal/ports
	HardwareJSON          = build.HardwareJson
	FlashSpec             = build.FlashSpec
	FlashRegion           = build.FlashRegion
	MemorySpec            = build.MemorySpec
	ReservedRamRegion     = build.ReservedRamRegion //nolint:staticcheck // ST1003: mirrors toob-go-lib/build.ReservedRamRegion
	ReservedRAMRegion     = build.ReservedRamRegion
	RegisterBlock         = build.RegisterBlock
	ResetCauseCode        = build.ResetCauseCode
	ResetCauses           = build.ResetCauses
	ChipManifest          = build.ChipManifest
	ChipSources           = build.ChipSources
	ChipCrypto            = build.ChipCrypto
	ChipRecovery          = build.ChipRecovery
	RecoveryCrypto        = build.RecoveryCrypto
	SlotCapabilities      = build.SlotCapabilities
	DriverManifest        = build.DriverManifest
	CryptoFootprint       = build.CryptoFootprint
	CryptoManifest        = build.CryptoManifest
	ArchManifest          = build.ArchManifest
	BootromImageSpec      = build.BootromImageSpec
	BootromHeaderSpec     = build.BootromHeaderSpec
	BootromSegmentSpec    = build.BootromSegmentSpec
	BootromFieldSpec      = build.BootromFieldSpec
	BootromPatchSpec      = build.BootromPatchSpec
	BootromTrailerOp      = build.BootromTrailerOp
	Provenance            = build.Provenance
	StringOrSlice         = build.StringOrSlice
	ReferenceBuildContext = build.ReferenceBuildContext
	CompilerFlags         = build.CompilerFlags
	Coprocessor           = build.Coprocessor
	MultiCore             = build.MultiCore

	Inputs          = build.Inputs
	Context         = build.Context
	Result          = build.Result
	ResolvedConfig  = build.ResolvedConfig
	PartitionLayout = build.PartitionLayout
	PartitionSlot   = build.PartitionSlot
	SlotKind        = build.SlotKind
	AllocationGap   = build.AllocationGap
	Transport       = build.Transport
	BackupMode      = build.BackupMode
	BudgetReport    = build.BudgetReport
	Logger          = build.Logger
	NopLogger       = build.NopLogger
)

// Constant aliases to toob-go-lib/build.
const (
	SlotBoot     = build.SlotBoot
	SlotApp      = build.SlotApp
	SlotSystem   = build.SlotSystem
	SlotReserved = build.SlotReserved

	TransportPointer     = build.TransportPointer
	TransportOneway      = build.TransportOneway
	TransportSwapScratch = build.TransportSwapScratch
	TransportSwapMove    = build.TransportSwapMove
	TransportSwapOffset  = build.TransportSwapOffset

	BackupUnset        = build.BackupUnset
	BackupNone         = build.BackupNone
	BackupFull         = build.BackupFull
	BackupReverseDelta = build.BackupReverseDelta

	BootromLayoutFlat      = build.BootromLayoutFlat
	BootromLayoutSegmented = build.BootromLayoutSegmented
)

// Function aliases to toob-go-lib/build.
var (
	ParseToml                    = build.ParseToml
	ParseHardwareJSON            = build.ParseHardwareJSON
	PackStage0ELF                = build.PackStage0ELF
	PackStage0FromHardwareJSON   = build.PackStage0FromHardwareJSON
	PackStage0ELFWithPackagesDir = build.PackStage0ELFWithPackagesDir
	CheckBudget                  = build.CheckBudget
	CheckBudgetWithLayout        = build.CheckBudgetWithLayout
	Generate                     = build.Generate
	ValidateName                 = build.ValidateName
	ValidatePackageRef           = build.ValidatePackageRef
	AuditProvenance              = build.AuditProvenance
	VerifyHardwareProvenance     = build.VerifyHardwareProvenance
	HasVerificationFailures      = build.HasVerificationFailures
	FormatVerificationErrors     = build.FormatVerificationErrors
)

// Load reads all build inputs and binds the CLI logger to the pipeline.
func Load(in Inputs) (*Context, error) { return build.Load(in, uiLogger{}) }

// LoadSilent reads all build inputs using a no-op logger without terminal output.
func LoadSilent(in Inputs) (*Context, error) { return build.Load(in, build.NopLogger{}) }
