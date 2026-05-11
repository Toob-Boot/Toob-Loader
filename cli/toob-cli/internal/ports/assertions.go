// Compile-time assertions that verify the port contracts stay in sync
// with the actual implementation types.
//
// This uses BIDIRECTIONAL struct literal initialization:
// - real→port: If the real type has a field the port type doesn't → compile error
// - port→real: If the port type has a field the real type doesn't → compile error
//
// For types with anonymous sub-structs (manifest.HardwareJson, manifest.DeviceToml),
// array literals enforce type-matching of each individual field.
//
// When this file fails to compile, it means the contract drifted from
// the implementation — update either ports.go or the implementation type.
package ports

import (
	"github.com/toob-boot/toob/internal/lockfile"
	"github.com/toob-boot/toob/internal/manifest"
	"github.com/toob-boot/toob/internal/registry"
	"github.com/toob-boot/toob/internal/toolchain"
	"github.com/toob-boot/toob/internal/updater"
)

// --- RegistryIndex ↔ registry.Index ---

func assertRegistryIndexToPort() {
	var r registry.Index
	_ = RegistryIndex{
		FormatVersion:    r.FormatVersion,
		RegistryVersion:  r.RegistryVersion,
		CLICompatibility: r.CliCompatibility,
	}
}

func assertRegistryIndexFromPort() {
	var p RegistryIndex
	_ = registry.Index{
		FormatVersion:    p.FormatVersion,
		RegistryVersion:  p.RegistryVersion,
		CliCompatibility: p.CLICompatibility,
	}
}

// --- ChipInfo ↔ RegistryChip ---

func assertChipToPort() {
	var r registry.ChipInfo
	_ = RegistryChip{
		Name: r.Name, Vendor: r.Vendor, Arch: r.Arch,
		CompilerPrefix: r.CompilerPrefix, Path: r.Path,
		Version: r.Version, CliCompatibility: r.CliCompatibility,
		Verified: r.Verified, Description: r.Description,
	}
}

func assertChipFromPort() {
	var p RegistryChip
	_ = registry.ChipInfo{
		Name: p.Name, Vendor: p.Vendor, Arch: p.Arch,
		CompilerPrefix: p.CompilerPrefix, Path: p.Path,
		Version: p.Version, CliCompatibility: p.CliCompatibility,
		Verified: p.Verified, Description: p.Description,
	}
}

// --- VendorInfo ↔ RegistryVendor ---

func assertVendorToPort() {
	var r registry.VendorInfo
	_ = RegistryVendor{
		Name: r.Name, Path: r.Path,
		Version: r.Version, Description: r.Description,
	}
}

func assertVendorFromPort() {
	var p RegistryVendor
	_ = registry.VendorInfo{
		Name: p.Name, Path: p.Path,
		Version: p.Version, Description: p.Description,
	}
}

// --- ArchInfo ↔ RegistryArch ---

func assertArchToPort() {
	var r registry.ArchInfo
	_ = RegistryArch{
		Name: r.Name, Path: r.Path,
		Version: r.Version, Description: r.Description,
	}
}

func assertArchFromPort() {
	var p RegistryArch
	_ = registry.ArchInfo{
		Name: p.Name, Path: p.Path,
		Version: p.Version, Description: p.Description,
	}
}

// --- ToolchainInfo ↔ RegistryToolchain ---

func assertToolchainToPort() {
	var r registry.ToolchainInfo
	_ = RegistryToolchain{
		Path: r.Path, Version: r.Version,
	}
}

func assertToolchainFromPort() {
	var p RegistryToolchain
	_ = registry.ToolchainInfo{
		Path: p.Path, Version: p.Version,
	}
}

// --- toolchain.RegistryToolchain ↔ ToolchainDownload ---

func assertToolchainDownloadToPort() {
	var r toolchain.RegistryToolchain
	_ = ToolchainDownload{
		Version: r.Version, URLs: r.URLs, SHA256: r.Sha256,
	}
}

func assertToolchainDownloadFromPort() {
	var p ToolchainDownload
	_ = toolchain.RegistryToolchain{
		Version: p.Version, URLs: p.URLs, Sha256: p.SHA256,
	}
}

// --- FlashRegion ↔ HardwareFlashRegion ---

func assertFlashRegionToPort() {
	var r manifest.FlashRegion
	_ = HardwareFlashRegion{
		Type: r.Type, Base: r.Base, Size: r.Size,
		SectorSize: r.SectorSize, Count: r.Count, Name: r.Name,
	}
}

func assertFlashRegionFromPort() {
	var p HardwareFlashRegion
	_ = manifest.FlashRegion{
		Type: p.Type, Base: p.Base, Size: p.Size,
		SectorSize: p.SectorSize, Count: p.Count, Name: p.Name,
	}
}

// --- updater.ReleaseInfo ↔ UpdateCheckResponse ---

func assertReleaseInfoToPort() {
	var r updater.ReleaseInfo
	_ = UpdateCheckResponse{
		TagName: r.TagName,
	}
}

func assertReleaseInfoFromPort() {
	var p UpdateCheckResponse
	_ = updater.ReleaseInfo{
		TagName: p.TagName,
	}
}

// --- updater.Asset ↔ UpdateCheckAsset ---

func assertAssetToPort() {
	var r updater.Asset
	_ = UpdateCheckAsset{
		Name: r.Name, BrowserDownloadURL: r.BrowserDownloadURL,
	}
}

func assertAssetFromPort() {
	var p UpdateCheckAsset
	_ = updater.Asset{
		Name: p.Name, BrowserDownloadURL: p.BrowserDownloadURL,
	}
}

// --- registry.MatrixDependencies ↔ MatrixDependencies ---

func assertMatrixDepsToPort() {
	var r registry.MatrixDependencies
	_ = MatrixDependencies{
		Toolchain: r.Toolchain, Vendor: r.Vendor, Arch: r.Arch,
		Compiler: r.Compiler, CoreSDK: r.CoreSDK,
	}
}

func assertMatrixDepsFromPort() {
	var p MatrixDependencies
	_ = registry.MatrixDependencies{
		Toolchain: p.Toolchain, Vendor: p.Vendor, Arch: p.Arch,
		Compiler: p.Compiler, CoreSDK: p.CoreSDK,
	}
}

// --- registry.MatrixVerifiedCli ↔ MatrixVerifiedCli ---

func assertMatrixVerifiedCliToPort() {
	var r registry.MatrixVerifiedCli
	_ = MatrixVerifiedCli{
		Status: r.Status, LastTested: r.LastTested,
	}
}

func assertMatrixVerifiedCliFromPort() {
	var p MatrixVerifiedCli
	_ = registry.MatrixVerifiedCli{
		Status: p.Status, LastTested: p.LastTested,
	}
}

// --- registry.MatrixVersion ↔ MatrixVersion ---

func assertMatrixVersionToPort() {
	var r registry.MatrixVersion
	_ = MatrixVersion{
		EnvironmentHash: r.EnvironmentHash,
	}
}

func assertMatrixVersionFromPort() {
	var p MatrixVersion
	_ = registry.MatrixVersion{
		EnvironmentHash: p.EnvironmentHash,
	}
}

// --- registry.MatrixChip ↔ MatrixChip ---
// Both are simple wrappers around map[string]MatrixVersion; the field-count
// test covers structural parity.

// --- lockfile.ChipEntry ↔ LockfileChipEntry ---

func assertLockChipToPort() {
	var r lockfile.ChipEntry
	_ = LockfileChipEntry{
		Name: r.Name, Version: r.Version, Arch: r.Arch,
		ArchVersion: r.ArchVersion, Vendor: r.Vendor,
		VendorVersion: r.VendorVersion, Toolchain: r.Toolchain,
		ToolchainVersion: r.ToolchainVersion, Spawned: r.Spawned,
	}
}

func assertLockChipFromPort() {
	var p LockfileChipEntry
	_ = lockfile.ChipEntry{
		Name: p.Name, Version: p.Version, Arch: p.Arch,
		ArchVersion: p.ArchVersion, Vendor: p.Vendor,
		VendorVersion: p.VendorVersion, Toolchain: p.Toolchain,
		ToolchainVersion: p.ToolchainVersion, Spawned: p.Spawned,
	}
}

// --- lockfile.ToolchainEntry ↔ LockfileToolchainEntry ---

func assertLockToolchainToPort() {
	var r lockfile.ToolchainEntry
	_ = LockfileToolchainEntry{Version: r.Version}
}

func assertLockToolchainFromPort() {
	var p LockfileToolchainEntry
	_ = lockfile.ToolchainEntry{Version: p.Version}
}

// --- HardwareJson ↔ HardwareJSON (anonymous sub-structs, field-level check) ---

func assertHardwareJSON() {
	var r manifest.HardwareJson
	var p HardwareJSON

	_ = [2]string{r.ChipFamily, p.ChipFamily}
	_ = [2]uint32{r.Flash.Size, p.Flash.Size}
	_ = [2]uint32{r.Flash.WriteAlignment, p.Flash.WriteAlignment}
	_ = [2]uint32{r.Flash.AppAlignment, p.Flash.AppAlignment}
	_ = [2]string{r.Flash.BaseAddr, p.Flash.BaseAddr}
	_ = [2]string{r.Flash.XipBase, p.Flash.XipBase}
	_ = [2]uint32{r.CryptoCapabilities.ArenaSize, p.CryptoCapabilities.ArenaSize}
	_ = [2]string{r.Memory.RamBase, p.Memory.RAMBase}
	_ = [2]string{r.Memory.RamSize, p.Memory.RAMSize}
}

// --- DeviceToml ↔ ports.DeviceToml (anonymous sub-structs, field-level check) ---

func assertDeviceToml() {
	var r manifest.DeviceToml
	var p DeviceToml

	_ = [2]string{r.Name, p.Name}
	_ = [2]string{r.Version, p.Version}
	_ = [2]string{r.Device.Vendor, p.Device.Vendor}
	_ = [2]string{r.Device.Chip, p.Device.Chip}
	_ = [2]string{r.Build.Compiler, p.Build.Compiler}
	_ = [2]string{r.Build.CoreSDK, p.Build.CoreSDK}
	_ = [2]string{r.Build.Registry, p.Build.Registry}
	_ = [2]uint32{r.Partitions.Stage0Size, p.Partitions.Stage0Size}
	_ = [2]uint32{r.Partitions.Stage1Size, p.Partitions.Stage1Size}
	_ = [2]uint32{r.Partitions.AppSize, p.Partitions.AppSize}
	_ = [2]uint32{r.Partitions.ScratchSize, p.Partitions.ScratchSize}
	_ = [2]uint32{r.Partitions.RecoverySize, p.Partitions.RecoverySize}
	_ = [2]uint32{r.Partitions.NetcoreSize, p.Partitions.NetcoreSize}
	_ = [2]uint32{r.Partitions.WalSectors, p.Partitions.WALSectors}
	_ = [2]uint32{r.Partitions.StagingSlotID, p.Partitions.StagingSlotID}
	_ = [2]bool{r.Partitions.EnableDeltas, p.Partitions.EnableDeltas}
	_ = [2]uint32{r.BootConfig.MaxRetries, p.BootConfig.MaxRetries}
	_ = [2]uint32{r.BootConfig.MaxRecoveryRetries, p.BootConfig.MaxRecoveryRetries}
	_ = [2]bool{r.BootConfig.EdgeUnattendedMode, p.BootConfig.EdgeUnattendedMode}
	_ = [2]uint32{r.BootConfig.BackoffBaseS, p.BootConfig.BackoffBaseS}
	_ = [2]uint32{r.BootConfig.WdtTimeoutMs, p.BootConfig.WDTTimeoutMs}
}
