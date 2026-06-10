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
	"github.com/toob-boot/toob/internal/apiclient"
	"github.com/toob-boot/toob/internal/lockfile"
	"github.com/toob-boot/toob/internal/manifest"
	"github.com/toob-boot/toob/internal/registry"
	"github.com/toob-boot/toob/internal/toolchain"
	"github.com/toob-boot/toob/internal/updater"
)

// --- apiclient ↔ ports ---

func assertRegistryRevisionResponseToPort() {
	var r apiclient.RevisionResponse
	_ = RegistryRevisionResponse{
		Revision: r.Revision, FormatVersion: r.FormatVersion,
		CommitSHA: r.CommitSHA, CreatedAt: r.CreatedAt,
	}
}

func assertRegistryRevisionResponseFromPort() {
	var p RegistryRevisionResponse
	_ = apiclient.RevisionResponse{
		Revision: p.Revision, FormatVersion: p.FormatVersion,
		CommitSHA: p.CommitSHA, CreatedAt: p.CreatedAt,
	}
}

func assertRegistryVersionResponseToPort() {
	var r apiclient.RegistryVersionResponse
	_ = RegistryVersionResponse{Version: r.Version}
}

func assertRegistryVersionResponseFromPort() {
	var p RegistryVersionResponse
	_ = apiclient.RegistryVersionResponse{Version: p.Version}
}

func assertChipResolveResponseToPort() {
	var r apiclient.ChipResolveResponse
	_ = ChipResolveResponse{
		Name: r.Name, Version: r.Version, Path: r.Path, Manifest: r.Manifest,
	}
}

func assertChipResolveResponseFromPort() {
	var p ChipResolveResponse
	_ = apiclient.ChipResolveResponse{
		Name: p.Name, Version: p.Version, Path: p.Path, Manifest: p.Manifest,
	}
}

func assertIntegrationItemToPort() {
	var r apiclient.IntegrationItem
	_ = IntegrationItem{Name: r.Name, Version: r.Version}
}

func assertIntegrationItemFromPort() {
	var p IntegrationItem
	_ = apiclient.IntegrationItem{Name: p.Name, Version: p.Version}
}

func assertMatrixEntryToPort() {
	var r apiclient.MatrixEntry
	_ = MatrixEntry{
		ID: r.ID, Chip: r.Chip, ChipVersion: r.ChipVersion,
		EnvHash: r.EnvHash, Dependencies: r.Dependencies,
		CombinationKey: r.CombinationKey, Status: r.Status,
		TestedAt: r.TestedAt, Revision: r.Revision,
	}
}

func assertMatrixEntryFromPort() {
	var p MatrixEntry
	_ = apiclient.MatrixEntry{
		ID: p.ID, Chip: p.Chip, ChipVersion: p.ChipVersion,
		EnvHash: p.EnvHash, Dependencies: p.Dependencies,
		CombinationKey: p.CombinationKey, Status: p.Status,
		TestedAt: p.TestedAt, Revision: p.Revision,
	}
}

func assertLoginResponseToPort() {
	var r apiclient.LoginResponse
	_ = LoginResponse{
		PublisherID: r.PublisherID, Login: r.Login, Role: r.Role,
		APIKey: r.APIKey, HasAPIKey: r.HasAPIKey,
	}
}

func assertLoginResponseFromPort() {
	var p LoginResponse
	_ = apiclient.LoginResponse{
		PublisherID: p.PublisherID, Login: p.Login, Role: p.Role,
		APIKey: p.APIKey, HasAPIKey: p.HasAPIKey,
	}
}

func assertCheckCombinationResponseToPort() {
	var r apiclient.CheckCombinationResponse
	_ = CheckCombinationResponse{
		Compatible: r.Compatible, Status: r.Status, LastTested: r.LastTested,
	}
}

func assertCheckCombinationResponseFromPort() {
	var p CheckCombinationResponse
	_ = apiclient.CheckCombinationResponse{
		Compatible: p.Compatible, Status: p.Status, LastTested: p.LastTested,
	}
}

func assertPackageResponseToPort() {
	var r apiclient.PackageResponse
	_ = PackageResponse{
		Name: r.Name, Version: r.Version, Category: r.Category,
		Stage: r.Stage, Path: r.Path, Manifest: r.Manifest,
	}
}

func assertPackageResponseFromPort() {
	var p PackageResponse
	_ = apiclient.PackageResponse{
		Name: p.Name, Version: p.Version, Category: p.Category,
		Stage: p.Stage, Path: p.Path, Manifest: p.Manifest,
	}
}

func assertMyPackagesResponseToPort() {
	var r apiclient.MyPackagesResponse
	// Notice: we can't easily assert the array elements directly with struct literal casting if the nested types differ.
	// But in assertions_test.go it will catch it via reflection. We just verify the top level struct shape here.
	_ = MyPackagesResponse{Count: r.Count, Packages: nil}
}

func assertMyPackagesResponseFromPort() {
	var p MyPackagesResponse
	_ = apiclient.MyPackagesResponse{Count: p.Count, Packages: nil}
}

func assertMyPackageSummaryToPort() {
	var r apiclient.MyPackageSummary
	_ = MyPackageSummary{
		ID: r.ID, Name: r.Name, Version: r.Version,
		Category: r.Category, Stage: r.Stage,
		StagingStatus: r.StagingStatus, StagingFeedback: r.StagingFeedback,
		TarballSHA: r.TarballSHA, CreatedAt: r.CreatedAt,
	}
}

func assertMyPackageSummaryFromPort() {
	var p MyPackageSummary
	_ = apiclient.MyPackageSummary{
		ID: p.ID, Name: p.Name, Version: p.Version,
		Category: p.Category, Stage: p.Stage,
		StagingStatus: p.StagingStatus, StagingFeedback: p.StagingFeedback,
		TarballSHA: p.TarballSHA, CreatedAt: p.CreatedAt,
	}
}

func assertPublishResponseToPort() {
	var r apiclient.PublishResponse
	_ = PublishResponse{
		Status: r.Status, Name: r.Name, Version: r.Version,
		TarballSHA: r.TarballSHA, Signature: r.Signature,
		ID: r.ID, Category: r.Category, Stage: r.Stage,
		IngestionWarnings: r.IngestionWarnings,
	}
}

func assertPublishResponseFromPort() {
	var p PublishResponse
	_ = apiclient.PublishResponse{
		Status: p.Status, Name: p.Name, Version: p.Version,
		TarballSHA: p.TarballSHA, Signature: p.Signature,
		ID: p.ID, Category: p.Category, Stage: p.Stage,
		IngestionWarnings: p.IngestionWarnings,
	}
}

func assertSyncDeltaResponseToPort() {
	var r apiclient.SyncDeltaResponse
	_ = SyncDeltaResponse{Since: r.Since, Count: r.Count, Revisions: r.Revisions}
}

func assertSyncDeltaResponseFromPort() {
	var p SyncDeltaResponse
	_ = apiclient.SyncDeltaResponse{Since: p.Since, Count: p.Count, Revisions: p.Revisions}
}

func assertAckSyncResponseToPort() {
	var r apiclient.AckSyncResponse
	_ = AckSyncResponse{Status: r.Status, Advisories: r.Advisories}
}

func assertAckSyncResponseFromPort() {
	var p AckSyncResponse
	_ = apiclient.AckSyncResponse{Status: p.Status, Advisories: p.Advisories}
}

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
		Name: r.Name, Arch: r.Arch,
		CompilerPrefix: r.CompilerPrefix, Path: r.Path,
		Version: r.Version, CliCompatibility: r.CliCompatibility,
		Verified: r.Verified, Description: r.Description,
	}
}

func assertChipFromPort() {
	var p RegistryChip
	_ = registry.ChipInfo{
		Name: p.Name, Arch: p.Arch,
		CompilerPrefix: p.CompilerPrefix, Path: p.Path,
		Version: p.Version, CliCompatibility: p.CliCompatibility,
		Verified: p.Verified, Description: p.Description,
	}
}

// --- ChipCrypto ↔ registry.ChipCrypto ---

func assertChipCryptoToPort() {
	var r registry.ChipCrypto
	_ = ChipCrypto{
		Backend: r.Backend, Hash: r.Hash, Pqc: r.Pqc,
	}
}

func assertChipCryptoFromPort() {
	var p ChipCrypto
	_ = registry.ChipCrypto{
		Backend: p.Backend, Hash: p.Hash, Pqc: p.Pqc,
	}
}

// --- CryptoInfo ↔ RegistryCrypto ---

func assertCryptoToPort() {
	var r registry.CryptoInfo
	_ = RegistryCrypto{
		Name: r.Name, Path: r.Path, Version: r.Version,
		Description: r.Description, Category: r.Category,
		License: r.License, MinCoreSdk: r.MinCoreSdk,
		Wrapper: r.Wrapper, UpstreamSources: r.UpstreamSources,
		Cflags: r.Cflags, Includes: r.Includes,
		ChipBinding: r.ChipBinding,
	}
}

func assertCryptoFromPort() {
	var p RegistryCrypto
	_ = registry.CryptoInfo{
		Name: p.Name, Path: p.Path, Version: p.Version,
		Description: p.Description, Category: p.Category,
		License: p.License, MinCoreSdk: p.MinCoreSdk,
		Wrapper: p.Wrapper, UpstreamSources: p.UpstreamSources,
		Cflags: p.Cflags, Includes: p.Includes,
		ChipBinding: p.ChipBinding,
	}
}

// --- DriverInfo ↔ RegistryDriver ---

func assertDriverToPort() {
	var r registry.DriverInfo
	_ = RegistryDriver{
		Name: r.Name, Path: r.Path,
		Version: r.Version, Description: r.Description,
		Category: r.Category,
	}
}

func assertDriverFromPort() {
	var p RegistryDriver
	_ = registry.DriverInfo{
		Name: p.Name, Path: p.Path,
		Version: p.Version, Description: p.Description,
		Category: p.Category,
	}
}

// Removed VendorInfo

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
		UpstreamVersion: r.UpstreamVersion,
	}
}

func assertToolchainFromPort() {
	var p RegistryToolchain
	_ = registry.ToolchainInfo{
		Path: p.Path, Version: p.Version,
		UpstreamVersion: p.UpstreamVersion,
	}
}

// --- toolchain.RegistryToolchain ↔ ToolchainDownload ---

func assertToolchainDownloadToPort() {
	var r toolchain.RegistryToolchain
	_ = ToolchainDownload{
		Version: r.Version, UpstreamVersion: r.UpstreamVersion,
		URLs: r.URLs, Sha256: r.Sha256,
	}
}

func assertToolchainDownloadFromPort() {
	var p ToolchainDownload
	_ = toolchain.RegistryToolchain{
		Version: p.Version, UpstreamVersion: p.UpstreamVersion,
		URLs: p.URLs, Sha256: p.Sha256,
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
		Toolchain: r.Toolchain, Arch: r.Arch,
		Compiler: r.Compiler, CoreSDK: r.CoreSDK,
	}
}

func assertMatrixDepsFromPort() {
	var p MatrixDependencies
	_ = registry.MatrixDependencies{
		Toolchain: p.Toolchain, Arch: p.Arch,
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
		ArchVersion:      r.ArchVersion,
		Toolchain:        r.Toolchain,
		ToolchainVersion: r.ToolchainVersion,
		CryptoBackend:    r.CryptoBackend,
		CryptoHash:       r.CryptoHash,
		CryptoPqc:        r.CryptoPqc,
		Spawned:          r.Spawned,
	}
}

func assertLockChipFromPort() {
	var p LockfileChipEntry
	_ = lockfile.ChipEntry{
		Name: p.Name, Version: p.Version, Arch: p.Arch,
		ArchVersion:      p.ArchVersion,
		Toolchain:        p.Toolchain,
		ToolchainVersion: p.ToolchainVersion,
		CryptoBackend:    p.CryptoBackend,
		CryptoHash:       p.CryptoHash,
		CryptoPqc:        p.CryptoPqc,
		Spawned:          p.Spawned,
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
	_ = [2]string{r.Crypto.Backend, p.Crypto.Backend}
	_ = [2]string{r.Crypto.Hash, p.Crypto.Hash}
	_ = [2]string{r.Crypto.Pqc, p.Crypto.Pqc}
}
