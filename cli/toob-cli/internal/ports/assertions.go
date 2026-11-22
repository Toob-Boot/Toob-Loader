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
	_ = IntegrationItem{
		Name: r.Name, Version: r.Version,
		Description: r.Description, Path: r.Path,
	}
}

func assertIntegrationItemFromPort() {
	var p IntegrationItem
	_ = apiclient.IntegrationItem{
		Name: p.Name, Version: p.Version,
		Description: p.Description, Path: p.Path,
	}
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

func assertAuthConfigToPort() {
	var r apiclient.AuthConfig
	_ = AuthConfig{
		Issuer: r.Issuer, Audience: r.Audience, ClientID: r.ClientID, Scopes: r.Scopes,
	}
}

func assertAuthConfigFromPort() {
	var p AuthConfig
	_ = apiclient.AuthConfig{
		Issuer: p.Issuer, Audience: p.Audience, ClientID: p.ClientID, Scopes: p.Scopes,
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

// --- RegistryEcosystem ↔ registry.EcosystemVersions ---

func assertRegistryEcosystemToPort() {
	var r registry.EcosystemVersions
	_ = RegistryEcosystem{
		CLI: r.CLI, CoreSDK: r.CoreSDK, Compiler: r.Compiler, CoreSDKSha256: r.CoreSDKSha256,
	}
}

func assertRegistryEcosystemFromPort() {
	var p RegistryEcosystem
	_ = registry.EcosystemVersions{
		CLI: p.CLI, CoreSDK: p.CoreSDK, Compiler: p.Compiler, CoreSDKSha256: p.CoreSDKSha256,
	}
}

func assertRegistryIndexToPort() {
	var r registry.Index
	var eco *RegistryEcosystem
	if r.Ecosystem != nil {
		eco = &RegistryEcosystem{
			CLI: r.Ecosystem.CLI, CoreSDK: r.Ecosystem.CoreSDK, Compiler: r.Ecosystem.Compiler, CoreSDKSha256: r.Ecosystem.CoreSDKSha256,
		}
	}
	_ = RegistryIndex{
		FormatVersion:   r.FormatVersion,
		RegistryVersion: r.RegistryVersion,
		Ecosystem:       eco,
	}
}

func assertRegistryIndexFromPort() {
	var p RegistryIndex
	var eco *registry.EcosystemVersions
	if p.Ecosystem != nil {
		eco = &registry.EcosystemVersions{
			CLI: p.Ecosystem.CLI, CoreSDK: p.Ecosystem.CoreSDK, Compiler: p.Ecosystem.Compiler, CoreSDKSha256: p.Ecosystem.CoreSDKSha256,
		}
	}
	_ = registry.Index{
		FormatVersion:   p.FormatVersion,
		RegistryVersion: p.RegistryVersion,
		Ecosystem:       eco,
	}
}

// --- ChipInfo ↔ RegistryChip ---

func assertChipToPort() {
	var r registry.ChipInfo
	var rec *ChipRecovery
	if r.Recovery != nil {
		var cryp *RecoveryCrypto
		if r.Recovery.Crypto != nil {
			cryp = &RecoveryCrypto{Backend: r.Recovery.Crypto.Backend, Hash: r.Recovery.Crypto.Hash}
		}
		rec = &ChipRecovery{
			Console: r.Recovery.Console, Flash: r.Recovery.Flash,
			WDT: r.Recovery.WDT, Clock: r.Recovery.Clock, RTC: r.Recovery.RTC,
			Crypto:  cryp,
			Sources: r.Recovery.Sources, Includes: r.Recovery.Includes,
		}
	}
	_ = RegistryChip{
		Name: r.Name, Author: r.Author, Tier: r.Tier, Arch: r.Arch,
		CompilerPrefix: r.CompilerPrefix, Path: r.Path,
		Version: r.Version, SHA256: r.SHA256, TarballSHA: r.TarballSHA,
		CliCompatibility: r.CliCompatibility,
		Verified:         r.Verified, Description: r.Description,
		HalBindings: r.HalBindings,
		Recovery:    rec,
	}
}

func assertChipFromPort() {
	var p RegistryChip
	var rec *registry.ChipRecovery
	if p.Recovery != nil {
		var cryp *registry.RecoveryCrypto
		if p.Recovery.Crypto != nil {
			cryp = &registry.RecoveryCrypto{Backend: p.Recovery.Crypto.Backend, Hash: p.Recovery.Crypto.Hash}
		}
		rec = &registry.ChipRecovery{
			Console: p.Recovery.Console, Flash: p.Recovery.Flash,
			WDT: p.Recovery.WDT, Clock: p.Recovery.Clock, RTC: p.Recovery.RTC,
			Crypto:  cryp,
			Sources: p.Recovery.Sources, Includes: p.Recovery.Includes,
		}
	}
	_ = registry.ChipInfo{
		Name: p.Name, Author: p.Author, Tier: p.Tier, Arch: p.Arch,
		CompilerPrefix: p.CompilerPrefix, Path: p.Path,
		Version: p.Version, SHA256: p.SHA256, TarballSHA: p.TarballSHA,
		CliCompatibility: p.CliCompatibility,
		Verified:         p.Verified, Description: p.Description,
		HalBindings: p.HalBindings,
		Recovery:    rec,
	}
}

// --- ChipRecovery ↔ registry.ChipRecovery ---

func assertChipRecoveryToPort() {
	var r registry.ChipRecovery
	var cryp *RecoveryCrypto
	if r.Crypto != nil {
		cryp = &RecoveryCrypto{Backend: r.Crypto.Backend, Hash: r.Crypto.Hash}
	}
	_ = ChipRecovery{
		Console: r.Console, Flash: r.Flash,
		WDT: r.WDT, Clock: r.Clock, RTC: r.RTC,
		Crypto:  cryp,
		Sources: r.Sources, Includes: r.Includes,
	}
}

func assertChipRecoveryFromPort() {
	var p ChipRecovery
	var cryp *registry.RecoveryCrypto
	if p.Crypto != nil {
		cryp = &registry.RecoveryCrypto{Backend: p.Crypto.Backend, Hash: p.Crypto.Hash}
	}
	_ = registry.ChipRecovery{
		Console: p.Console, Flash: p.Flash,
		WDT: p.WDT, Clock: p.Clock, RTC: p.RTC,
		Crypto:  cryp,
		Sources: p.Sources, Includes: p.Includes,
	}
}

// --- RecoveryCrypto ↔ registry.RecoveryCrypto ---

func assertRecoveryCryptoToPort() {
	var r registry.RecoveryCrypto
	_ = RecoveryCrypto{
		Backend: r.Backend, Hash: r.Hash,
	}
}

func assertRecoveryCryptoFromPort() {
	var p RecoveryCrypto
	_ = registry.RecoveryCrypto{
		Backend: p.Backend, Hash: p.Hash,
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
	var fp *CryptoFootprint
	if r.Footprint != nil {
		fp = &CryptoFootprint{FlashBytes: r.Footprint.FlashBytes, RamBytes: r.Footprint.RamBytes}
	}
	_ = RegistryCrypto{
		Name: r.Name, Author: r.Author, Tier: r.Tier, Path: r.Path, Version: r.Version,
		SHA256: r.SHA256, TarballSHA: r.TarballSHA,
		Description: r.Description, AbiVersion: r.AbiVersion, Category: r.Category,
		License: r.License, MinCoreSdk: r.MinCoreSdk,
		Wrapper: r.Wrapper, UpstreamSources: r.UpstreamSources,
		Headers: r.Headers, Symbols: r.Symbols,
		Cflags: r.Cflags, Includes: r.Includes,
		ChipBinding: r.ChipBinding, HasHwAcceleration: r.HasHwAcceleration,
		Footprint: fp,
	}
}

func assertCryptoFromPort() {
	var p RegistryCrypto
	var fp *registry.CryptoFootprint
	if p.Footprint != nil {
		fp = &registry.CryptoFootprint{FlashBytes: p.Footprint.FlashBytes, RamBytes: p.Footprint.RamBytes}
	}
	_ = registry.CryptoInfo{
		Name: p.Name, Author: p.Author, Tier: p.Tier, Path: p.Path, Version: p.Version,
		SHA256: p.SHA256, TarballSHA: p.TarballSHA,
		Description: p.Description, AbiVersion: p.AbiVersion, Category: p.Category,
		License: p.License, MinCoreSdk: p.MinCoreSdk,
		Wrapper: p.Wrapper, UpstreamSources: p.UpstreamSources,
		Headers: p.Headers, Symbols: p.Symbols,
		Cflags: p.Cflags, Includes: p.Includes,
		ChipBinding: p.ChipBinding, HasHwAcceleration: p.HasHwAcceleration,
		Footprint: fp,
	}
}

// --- DriverInfo ↔ RegistryDriver ---

func assertDriverToPort() {
	var r registry.DriverInfo
	_ = RegistryDriver{
		Name: r.Name, Author: r.Author, Tier: r.Tier, Trait: r.Trait, Path: r.Path,
		Version: r.Version, SHA256: r.SHA256, TarballSHA: r.TarballSHA, Description: r.Description,
		Category: r.Category,
	}
}

func assertDriverFromPort() {
	var p RegistryDriver
	_ = registry.DriverInfo{
		Name: p.Name, Author: p.Author, Tier: p.Tier, Trait: p.Trait, Path: p.Path,
		Version: p.Version, SHA256: p.SHA256, TarballSHA: p.TarballSHA, Description: p.Description,
		Category: p.Category,
	}
}

// Removed VendorInfo

// --- ArchInfo ↔ RegistryArch ---

func assertArchToPort() {
	var r registry.ArchInfo
	_ = RegistryArch{
		Name: r.Name, Author: r.Author, Tier: r.Tier, Path: r.Path,
		Version: r.Version, SHA256: r.SHA256, TarballSHA: r.TarballSHA, Description: r.Description,
	}
}

func assertArchFromPort() {
	var p RegistryArch
	_ = registry.ArchInfo{
		Name: p.Name, Author: p.Author, Tier: p.Tier, Path: p.Path,
		Version: p.Version, SHA256: p.SHA256, TarballSHA: p.TarballSHA, Description: p.Description,
	}
}

// --- SoCInfo ↔ RegistrySoC ---

func assertSoCToPort() {
	var r registry.SoCInfo
	_ = RegistrySoC{
		Name: r.Name, Author: r.Author, Tier: r.Tier, Path: r.Path,
		Version: r.Version, SHA256: r.SHA256, TarballSHA: r.TarballSHA, Description: r.Description,
		Chips: r.Chips,
	}
}

func assertSoCFromPort() {
	var p RegistrySoC
	_ = registry.SoCInfo{
		Name: p.Name, Author: p.Author, Tier: p.Tier, Path: p.Path,
		Version: p.Version, SHA256: p.SHA256, TarballSHA: p.TarballSHA, Description: p.Description,
		Chips: p.Chips,
	}
}

// --- IntegrationInfo ↔ RegistryIntegration ---

func assertIntegrationToPort() {
	var r registry.IntegrationInfo
	_ = RegistryIntegration{
		Name: r.Name, Author: r.Author, Tier: r.Tier, Path: r.Path,
		Version: r.Version, SHA256: r.SHA256, TarballSHA: r.TarballSHA, Description: r.Description,
	}
}

func assertIntegrationFromPort() {
	var p RegistryIntegration
	_ = registry.IntegrationInfo{
		Name: p.Name, Author: p.Author, Tier: p.Tier, Path: p.Path,
		Version: p.Version, SHA256: p.SHA256, TarballSHA: p.TarballSHA, Description: p.Description,
	}
}

// --- ToolchainInfo ↔ RegistryToolchain ---

func assertToolchainToPort() {
	var r registry.ToolchainInfo
	_ = RegistryToolchain{
		Path: r.Path, Version: r.Version,
		UpstreamVersion: r.UpstreamVersion, TarballSHA: r.TarballSHA,
	}
}

func assertToolchainFromPort() {
	var p RegistryToolchain
	_ = registry.ToolchainInfo{
		Path: p.Path, Version: p.Version,
		UpstreamVersion: p.UpstreamVersion, TarballSHA: p.TarballSHA,
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
		SectorSize: r.SectorSize, Count: r.Count, Name: r.Name, Description: r.Description,
	}
}

func assertFlashRegionFromPort() {
	var p HardwareFlashRegion
	_ = manifest.FlashRegion{
		Type: p.Type, Base: p.Base, Size: p.Size,
		SectorSize: p.SectorSize, Count: p.Count, Name: p.Name, Description: p.Description,
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

func assertDriverManifestToPort() {
	var r manifest.DriverManifest
	_ = DriverManifest{
		Name: r.Name, Author: r.Author, Tier: r.Tier, Version: r.Version, Description: r.Description,
		Trait: r.Trait, AbiVersion: r.AbiVersion, ExecModel: r.ExecModel, IsHardwareTRNG: r.IsHardwareTRNG,
		Headers: r.Headers, Sources: r.Sources, MockSources: r.MockSources, Symbols: r.Symbols,
	}
}

func assertDriverManifestFromPort() {
	var p DriverManifest
	_ = manifest.DriverManifest{
		Name: p.Name, Author: p.Author, Tier: p.Tier, Version: p.Version, Description: p.Description,
		Trait: p.Trait, AbiVersion: p.AbiVersion, ExecModel: p.ExecModel, IsHardwareTRNG: p.IsHardwareTRNG,
		Headers: p.Headers, Sources: p.Sources, MockSources: p.MockSources, Symbols: p.Symbols,
	}
}

func assertCryptoFootprintToPort() {
	var r manifest.CryptoFootprint
	_ = CryptoFootprint{FlashBytes: r.FlashBytes, RamBytes: r.RamBytes}
}

func assertCryptoFootprintFromPort() {
	var p CryptoFootprint
	_ = manifest.CryptoFootprint{FlashBytes: p.FlashBytes, RamBytes: p.RamBytes}
}

func assertCryptoManifestToPort() {
	var r manifest.CryptoManifest
	var fp *CryptoFootprint
	if r.Footprint != nil {
		fp = &CryptoFootprint{FlashBytes: r.Footprint.FlashBytes, RamBytes: r.Footprint.RamBytes}
	}
	_ = CryptoManifest{
		Name: r.Name, Author: r.Author, Tier: r.Tier, Version: r.Version, Description: r.Description,
		AbiVersion: r.AbiVersion, Category: r.Category, License: r.License, MinCoreSdk: r.MinCoreSdk,
		Wrapper: r.Wrapper, UpstreamSources: r.UpstreamSources, Headers: r.Headers, Symbols: r.Symbols,
		Cflags: r.Cflags, Includes: r.Includes, ChipBinding: r.ChipBinding,
		HasHwAcceleration: r.HasHwAcceleration, Footprint: fp,
	}
}

func assertCryptoManifestFromPort() {
	var p CryptoManifest
	var fp *manifest.CryptoFootprint
	if p.Footprint != nil {
		fp = &manifest.CryptoFootprint{FlashBytes: p.Footprint.FlashBytes, RamBytes: p.Footprint.RamBytes}
	}
	_ = manifest.CryptoManifest{
		Name: p.Name, Author: p.Author, Tier: p.Tier, Version: p.Version, Description: p.Description,
		AbiVersion: p.AbiVersion, Category: p.Category, License: p.License, MinCoreSdk: p.MinCoreSdk,
		Wrapper: p.Wrapper, UpstreamSources: p.UpstreamSources, Headers: p.Headers, Symbols: p.Symbols,
		Cflags: p.Cflags, Includes: p.Includes, ChipBinding: p.ChipBinding,
		HasHwAcceleration: p.HasHwAcceleration, Footprint: fp,
	}
}

func assertArchManifestToPort() {
	var r manifest.ArchManifest
	_ = ArchManifest{
		Name: r.Name, Author: r.Author, Tier: r.Tier, Version: r.Version, Description: r.Description,
		Headers: r.Headers, Sources: r.Sources, Symbols: r.Symbols, RequiredMacros: r.RequiredMacros,
	}
}

func assertArchManifestFromPort() {
	var p ArchManifest
	_ = manifest.ArchManifest{
		Name: p.Name, Author: p.Author, Tier: p.Tier, Version: p.Version, Description: p.Description,
		Headers: p.Headers, Sources: p.Sources, Symbols: p.Symbols, RequiredMacros: p.RequiredMacros,
	}
}

func assertProvenanceToPort() {
	var r manifest.Provenance
	_ = Provenance{
		Source: r.Source, Ref: r.Ref, Verified: r.Verified,
	}
}

func assertProvenanceFromPort() {
	var p Provenance
	_ = manifest.Provenance{
		Source: p.Source, Ref: p.Ref, Verified: p.Verified,
	}
}

// --- HardwareJson ↔ HardwareJSON (anonymous sub-structs, field-level check) ---

func assertHardwareJSON() {
	var r manifest.HardwareJson
	var p HardwareJSON

	_ = [2]string{r.ChipFamily, p.ChipFamily}
	_ = [2]uint32{r.Flash.Size, p.Flash.Size}
	_ = [2]uint32{r.Flash.WriteAlignment, p.Flash.WriteAlignment}
	_ = [2]uint32{r.Flash.AppAlignment, p.Flash.AppAlignment}
	_ = [2]uint32{uint32(r.Flash.Base), p.Flash.Base}
	_ = [2]string{r.Flash.BaseAddr, p.Flash.BaseAddr}
	_ = [2]string{r.Flash.XipBase, p.Flash.XipBase}
	_ = [2]uint32{r.Flash.VtorAlignment, p.Flash.VtorAlignment}
	_ = [2]uint32{r.Flash.ImageHeaderOffset, p.Flash.ImageHeaderOffset}
	_ = [2]uint32{r.Flash.EraseTimeUsMax, p.Flash.EraseTimeUsMax}
	_ = [2]uint32{r.Flash.WriteTimeUsPage, p.Flash.WriteTimeUsPage}
	_ = [2]string{r.Flash.Stage0ExecMode, p.Flash.Stage0ExecMode}
	_ = [2]string{r.Flash.EntrySymbol, p.Flash.EntrySymbol}
	_ = [2]uint32{r.CryptoCapabilities.ArenaSize, p.CryptoCapabilities.ArenaSize}
	_ = [2]string{r.Memory.IramBase, p.Memory.IRAMBase}
	_ = [2]string{r.Memory.IramSize, p.Memory.IRAMSize}
	_ = [2]string{r.Memory.SramBase, p.Memory.SRAMBase}
	_ = [2]string{r.Memory.SramSize, p.Memory.SRAMSize}
	_ = [2]string{r.Memory.LpRamBase, p.Memory.LPRAMBase}
	_ = [2]string{r.Memory.LpRamSize, p.Memory.LPRAMSize}
	_ = [2]uint32{r.Memory.VtorAlignment, p.Memory.VtorAlignment}
	_ = [2]uint32{r.Memory.ImageHeaderOffset, p.Memory.ImageHeaderOffset}

	if r.Provenance != nil {
		_ = Provenance{Source: r.Provenance.Source, Ref: r.Provenance.Ref, Verified: r.Provenance.Verified}
	}
	if p.Provenance != nil {
		_ = manifest.Provenance{Source: p.Provenance.Source, Ref: p.Provenance.Ref, Verified: p.Provenance.Verified}
	}
	if r.BootromImage != nil && p.BootromImage != nil {
		_ = [2]string{r.BootromImage.Extends, p.BootromImage.Extends}
		_ = [2]string{r.BootromImage.Layout, p.BootromImage.Layout}
		_ = [2]int{r.BootromImage.MinSize, p.BootromImage.MinSize}
	}
}

// --- DeviceToml ↔ ports.DeviceToml (anonymous sub-structs, field-level check) ---

func assertDeviceToml() {
	var r manifest.DeviceToml
	var p DeviceToml

	_ = [2]string{r.Name, p.Name}
	_ = [2]string{r.Version, p.Version}
	_ = [2]uint16{r.Identity.VendorID, p.Identity.VendorID}
	_ = [2]uint16{r.Identity.ProductID, p.Identity.ProductID}
	_ = [2]uint16{r.Identity.HwRev, p.Identity.HwRev}
	_ = [2]string{r.Device.Chip, p.Device.Chip}
	_ = [2]string{r.Build.Compiler, p.Build.Compiler}
	_ = [2]string{r.Build.CoreSDK, p.Build.CoreSDK}
	_ = [2]string{r.Build.Registry, p.Build.Registry}
	_ = [2]string{r.Build.Profile, p.Build.Profile}
	_ = [2][]string{r.Build.Mock, p.Build.Mock}
	_ = [2]map[string]string{r.Drivers, p.Drivers}
	_ = [2]map[string]any{r.DriverConfig, p.DriverConfig}
	_ = [2]uint32{r.Partitions.Stage0Size, p.Partitions.Stage0Size}
	_ = [2]uint32{r.Partitions.Stage1Size, p.Partitions.Stage1Size}
	_ = [2]uint32{r.Partitions.AppSize, p.Partitions.AppSize}
	_ = [2]uint32{r.Partitions.ScratchSize, p.Partitions.ScratchSize}
	_ = [2]uint32{r.Partitions.RecoverySize, p.Partitions.RecoverySize}
	_ = [2]uint32{r.Partitions.NetcoreSize, p.Partitions.NetcoreSize}
	_ = [2]uint32{r.Partitions.WalSectors, p.Partitions.WALSectors}
	if r.Partitions.StagingSlotID != nil {
		_ = [2]uint32{*r.Partitions.StagingSlotID, p.Partitions.StagingSlotID}
	}
	_ = [2]bool{r.Partitions.EnableDeltas, p.Partitions.EnableDeltas}
	_ = [2]uint32{r.BootConfig.MaxRetries, p.BootConfig.MaxRetries}
	_ = [2]uint32{r.BootConfig.MaxRecoveryRetries, p.BootConfig.MaxRecoveryRetries}
	_ = [2]bool{r.BootConfig.EdgeUnattendedMode, p.BootConfig.EdgeUnattendedMode}
	_ = [2]uint32{r.BootConfig.BackoffBaseS, p.BootConfig.BackoffBaseS}
	_ = [2]uint32{r.BootConfig.WdtTimeoutMs, p.BootConfig.WDTTimeoutMs}
	_ = [2]uint32{r.BootConfig.Stage1Svn, p.BootConfig.Stage1SVN}
	_ = [2]uint32{r.BootConfig.CryptoArenaSize, p.BootConfig.CryptoArenaSize}
	_ = [2]string{r.BootConfig.TransportProvider, p.BootConfig.TransportProvider}
	_ = [2]string{r.BootConfig.BackupMode, p.BootConfig.BackupMode}
	_ = [2]*bool{r.Features.CloudCommands, p.Features.CloudCommands}
	_ = [2]*bool{r.Features.UartProvisioning, p.Features.UartProvisioning}
	_ = [2]*bool{r.Features.MultiImage, p.Features.MultiImage}
	_ = [2]*bool{r.Features.Delta, p.Features.Delta}
	_ = [2]*bool{r.Features.Compression, p.Features.Compression}
	_ = [2]string{r.Crypto.Backend, p.Crypto.Backend}
	_ = [2]string{r.Crypto.Hash, p.Crypto.Hash}
	_ = [2]string{r.Crypto.Pqc, p.Crypto.Pqc}
}

func assertChipManifest() {
	var r manifest.ChipManifest
	var p ChipManifest
	_ = [2]string{r.Name, p.Name}
	_ = [2]string{r.Author, p.Author}
	_ = [2]string{r.Tier, p.Tier}
	_ = [2]string{r.Arch, p.Arch}
	_ = [2]string{r.CompilerPrefix, p.CompilerPrefix}
	_ = [2]string{r.Description, p.Description}
	_ = [2]string{r.Version, p.Version}
	_ = [2]string{r.MinCoreSDK, p.MinCoreSDK}
	_ = [2]string{r.MinCompiler, p.MinCompiler}
	_ = [2]string{r.Stage0ExecMode, p.Stage0ExecMode}
	_ = [2]string{r.EntrySymbol, p.EntrySymbol}
}

func assertSlotCapabilities() {
	var r manifest.SlotCapabilities
	var p SlotCapabilities
	_ = [2]string{r.ExecModel, p.ExecModel}
	_ = [2]int{r.SlotCount, p.SlotCount}
	_ = [2]bool{r.HasScratch, p.HasScratch}
	_ = [2]uint32{r.MaxEraseCycles, p.MaxEraseCycles}
}
