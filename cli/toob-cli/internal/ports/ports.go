// Package ports defines all boundary contracts for the Toob CLI.
//
// This file is the Single Source of Truth for every interface that
// crosses a component boundary. The protocol.json is derived from
// the struct definitions and tags in this file.
//
// Contract Rules:
//
//	Adding a `port:"required"` field   = BREAKING → bump ProtocolVersion
//	Removing any field                 = BREAKING → bump ProtocolVersion
//	Changing a field type              = BREAKING → bump ProtocolVersion
//	Adding a `port:"optional"` field   = non-breaking
package ports

// ProtocolVersion is the global contract version embedded into every CLI
// binary at compile time. The Compiler Container exposes the same value
// via the Docker label "toob.protocol_version". If they don't match,
// the build is aborted before it starts.
//
// Only incremented for BREAKING changes (new required fields, removed fields,
// type changes). MINOR additions (new optional fields) do NOT require a bump.
const ProtocolVersion = 1

// =============================================================================
// Boundary: CLI → Compiler Container (via Docker)
// =============================================================================

// DockerBuildInput defines what the CLI passes to the Compiler Container.
type DockerBuildInput struct {
	Image       string            `json:"image"        port:"required"` // toob-compiler:v{cli_version}
	Workspace   string            `json:"workspace"    port:"required"` // -v {project_root}:/workspace
	RegistryDir string            `json:"registry_dir" port:"required"` // -v {path}:/root/.toob/registry
	WorkDir     string            `json:"work_dir"     port:"required"` // -w /workspace
	Command     string            `json:"command"      port:"required"` // toob build --native
	Manifest    string            `json:"manifest"     port:"optional"` // --manifest {path}
	BuildDir    string            `json:"build_dir"    port:"optional"` // --build-dir {path}
	ProxyVars   map[string]string `json:"proxy_vars"   port:"optional"` // HTTP_PROXY, HTTPS_PROXY, NO_PROXY
}

// DockerBuildOutput defines what the Compiler Container returns to the CLI.
type DockerBuildOutput struct {
	ExitCode     int    `json:"exit_code"     port:"required"` // 0 = success, non-zero = failure
	Logs         []byte `json:"logs"          port:"required"` // UTF-8 combined stdout+stderr
	Stage0Binary string `json:"stage0_binary" port:"required"` // builds/build_{chip}/toob_stage0.bin
	Stage1Binary string `json:"stage1_binary" port:"required"` // builds/build_{chip}/toob_stage1.bin
	GeneratedDir string `json:"generated_dir" port:"required"` // builds/build_{chip}/generated/
}

// =============================================================================
// Boundary: CLI → Toob Hub API (HTTP)
// =============================================================================

// ResolveRegistryRequest is sent to GET /api/v1/resolve/registry.
type ResolveRegistryRequest struct {
	Version string `json:"version" port:"required"` // "latest" | "0.0.1" | ...
}

// ResolveRegistryResponse is the JSON body returned by the Hub.
type ResolveRegistryResponse struct {
	Version     string `json:"version"      port:"required"`
	DownloadURL string `json:"download_url" port:"required"`
}

// ResolveChipRequest is sent to GET /api/v1/resolve/chip.
type ResolveChipRequest struct {
	Name    string `json:"name"    port:"required"`
	Version string `json:"version" port:"optional"`
}

// ResolveChipResponse is the JSON body returned by the Hub.
type ResolveChipResponse struct {
	Chip                   string `json:"chip"                      port:"required"`
	ChipVersion            string `json:"chip_version"              port:"required"`
	FoundInRegistryVersion string `json:"found_in_registry_version" port:"required"`
	RegistryDownloadURL    string `json:"registry_download_url"     port:"required"`
}

// ResolveEnvironmentRequest is sent to GET /api/v1/resolve/environment.
type ResolveEnvironmentRequest struct {
	Chip       string `json:"chip"        port:"required"`
	CLIVersion string `json:"cli_version" port:"required"`
}

// ResolveEnvironmentResponse is the JSON body returned by the Hub.
type ResolveEnvironmentResponse struct {
	Status              string `json:"status"               port:"required"`
	RecommendedCompiler string `json:"recommended_compiler" port:"required"`
	RecommendedCoreSDK  string `json:"recommended_core_sdk" port:"required"`
}

// HubResolveIntegrationsResponse defines GET /api/v1/resolve/integrations response.
type HubResolveIntegrationsResponse struct {
	Integrations []struct {
		Name    string `json:"name"    port:"required"`
		Version string `json:"version" port:"required"`
	} `json:"integrations" port:"required"`
}

// =============================================================================
// Boundary: CLI → GitHub API
// =============================================================================

// UpdateCheckResponse represents the GitHub Releases API response
// consumed by the CLI updater.
type UpdateCheckResponse struct {
	TagName string              `json:"tag_name" port:"required"`
	Assets  []UpdateCheckAsset  `json:"assets"   port:"required"`
}

// UpdateCheckAsset is a single release asset from GitHub.
type UpdateCheckAsset struct {
	Name               string `json:"name"                 port:"required"`
	BrowserDownloadURL string `json:"browser_download_url" port:"required"`
}

// CoreSDKCloneInput defines the git clone parameters for fetching the Core SDK.
type CoreSDKCloneInput struct {
	RepoURL string `json:"repo_url" port:"required"` // https://github.com/Toob-Boot/Toob-Loader.git
	Ref     string `json:"ref"      port:"required"` // Branch or tag (main, core/v0.0.1)
	Depth   int    `json:"depth"    port:"required"` // Always 1 (shallow clone)
	DestDir string `json:"dest_dir" port:"required"` // Local destination path
}

// =============================================================================
// Boundary: CLI → Registry Files (local disk)
// =============================================================================

// RegistryIndex is the parsed content of registry.json.
type RegistryIndex struct {
	FormatVersion    int                        `json:"format_version"    port:"required"`
	RegistryVersion  string                     `json:"registry_version"  port:"required"`
	CLICompatibility string                     `json:"cli_compatibility" port:"required"`
	Chips            map[string]RegistryChip    `json:"chips"             port:"required"`
	Vendors          map[string]RegistryVendor  `json:"vendors"           port:"required"`
	Archs            map[string]RegistryArch    `json:"archs"             port:"required"`
	Toolchains       map[string]RegistryToolchain `json:"toolchains"      port:"required"`
	Integrations     map[string]RegistryIntegration `json:"integrations"  port:"required"`
}

// RegistryChip is a single chip entry in registry.json.
type RegistryChip struct {
	Name             string `json:"name"              port:"required"`
	Vendor           string `json:"vendor"            port:"required"`
	Arch             string `json:"arch"              port:"required"`
	CompilerPrefix   string `json:"compiler_prefix"   port:"required"`
	Path             string `json:"path"              port:"required"`
	Version          string `json:"version"           port:"required"`
	CliCompatibility string `json:"cli_compatibility" port:"optional"`
	Verified         bool   `json:"verified"          port:"optional"`
	Description      string `json:"description"       port:"optional"`
}

// RegistryVendor is a vendor entry in registry.json.
type RegistryVendor struct {
	Name        string `json:"name"        port:"required"`
	Path        string `json:"path"        port:"required"`
	Version     string `json:"version"     port:"required"`
	Description string `json:"description" port:"optional"`
}

// RegistryArch is an architecture entry in registry.json.
type RegistryArch struct {
	Name        string `json:"name"        port:"required"`
	Path        string `json:"path"        port:"required"`
	Version     string `json:"version"     port:"required"`
	Description string `json:"description" port:"optional"`
}

// RegistryIntegration is an integration entry in registry.json.
type RegistryIntegration struct {
	Name        string `json:"name"        port:"required"`
	Path        string `json:"path"        port:"required"`
	Version     string `json:"version"     port:"required"`
	Description string `json:"description" port:"optional"`
}

// RegistryToolchain defines toolchain download metadata in registry.json.
type RegistryToolchain struct {
	Path            string `json:"path"             port:"optional"`
	Version         string `json:"version"          port:"required"`
	UpstreamVersion string `json:"upstream_version" port:"required"`
}

// ToolchainDownload is the extended toolchain entry used by toolchain/manager.go
// for auto-provisioning. Includes download URLs and checksums per OS/arch.
type ToolchainDownload struct {
	Version string            `json:"version" port:"required"`
	URLs    map[string]string `json:"urls"    port:"required"` // Key: {os}_{arch}
	SHA256  map[string]string `json:"sha256"  port:"required"` // Key: {os}_{arch}
}

// HardwareJSON is the parsed content of chips/{chip}/hardware.json.
type HardwareJSON struct {
	ChipFamily         string             `json:"chip_family"          port:"required"`
	Flash              HardwareFlash      `json:"flash"                port:"required"`
	CryptoCapabilities HardwareCrypto     `json:"crypto_capabilities"  port:"required"`
	Memory             HardwareMemory     `json:"memory"               port:"required"`
}

// HardwareFlash describes the flash geometry of a chip.
type HardwareFlash struct {
	Size           uint32              `json:"size"            port:"required"`
	WriteAlignment uint32             `json:"write_alignment" port:"optional"`
	AppAlignment   uint32             `json:"app_alignment"   port:"optional"`
	BaseAddr       string             `json:"base_addr"       port:"optional"`
	XipBase        string             `json:"xip_base"        port:"optional"`
	Regions        []HardwareFlashRegion `json:"regions"       port:"required"`
}

// HardwareFlashRegion is a single flash region.
type HardwareFlashRegion struct {
	Type       string `json:"type"        port:"required"`
	Base       uint32 `json:"base"        port:"required"`
	Size       uint32 `json:"size"        port:"optional"`
	SectorSize uint32 `json:"sector_size" port:"optional"`
	Count      uint32 `json:"count"       port:"optional"`
	Name       string `json:"name"        port:"optional"`
}

// HardwareCrypto defines crypto capabilities.
type HardwareCrypto struct {
	ArenaSize uint32 `json:"arena_size" port:"required"`
}

// HardwareMemory defines RAM geometry.
type HardwareMemory struct {
	RAMBase string `json:"ram_base" port:"required"`
	RAMSize string `json:"ram_size" port:"required"`
}

// DeviceToml is the parsed content of device.toml (user project manifest).
type DeviceToml struct {
	Name    string          `json:"name"       port:"required"`
	Version string          `json:"version"    port:"optional"`
	Device  DeviceSection   `json:"device"     port:"required"`
	Build   BuildSection    `json:"build"      port:"optional"`
	Partitions PartitionSection `json:"partitions" port:"required"`
	BootConfig BootConfigSection `json:"boot_config" port:"optional"`
}

// DeviceSection identifies the target chip.
type DeviceSection struct {
	Vendor string `json:"vendor" port:"required"`
	Chip   string `json:"chip"   port:"required"`
}

// BuildSection configures the build environment.
type BuildSection struct {
	Compiler string `json:"compiler" port:"optional"` // "latest" | specific version
	CoreSDK  string `json:"core_sdk" port:"optional"` // "main" | tag
	Registry string `json:"registry" port:"optional"` // "latest" | version
}

// PartitionSection defines the flash partition layout.
type PartitionSection struct {
	Stage0Size    uint32 `json:"stage0_size"     port:"required"`
	Stage1Size    uint32 `json:"stage1_size"     port:"required"`
	AppSize       uint32 `json:"app_size"        port:"required"`
	ScratchSize   uint32 `json:"scratch_size"    port:"optional"`
	RecoverySize  uint32 `json:"recovery_size"   port:"optional"`
	NetcoreSize   uint32 `json:"netcore_size"    port:"optional"`
	WALSectors    uint32 `json:"wal_sectors"     port:"optional"`
	StagingSlotID uint32 `json:"staging_slot_id" port:"optional"`
	EnableDeltas  bool   `json:"enable_deltas"   port:"optional"`
}

// BootConfigSection configures bootloader behavior.
type BootConfigSection struct {
	MaxRetries         uint32 `json:"max_retries"          port:"optional"`
	MaxRecoveryRetries uint32 `json:"max_recovery_retries" port:"optional"`
	EdgeUnattendedMode bool   `json:"edge_unattended_mode" port:"optional"`
	BackoffBaseS       uint32 `json:"backoff_base_s"       port:"optional"`
	WDTTimeoutMs       uint32 `json:"wdt_timeout_ms"       port:"optional"`
}

// =============================================================================
// Boundary: Compiler Internal I/O (files expected/produced during build)
// =============================================================================

// CompilerInputFiles defines files the compiler pipeline reads.
type CompilerInputFiles struct {
	SuitCDDL      string `json:"suit_cddl"      port:"required"` // cli/suit/toob_suit.cddl
	TelemetryCDDL string `json:"telemetry_cddl"  port:"required"` // cli/suit/toob_telemetry.cddl
	CMakeLists    string `json:"cmakelists"      port:"required"` // CMakeLists.txt
	ToolchainCMake string `json:"toolchain_cmake" port:"required"` // cmake/toolchain-{arch}.cmake
}

// CompilerOutputFiles defines files the compiler pipeline produces.
type CompilerOutputFiles struct {
	BootSuitC        string `json:"boot_suit_c"        port:"required"` // generated/boot_suit.c
	BootSuitH        string `json:"boot_suit_h"        port:"required"` // generated/boot_suit.h
	TelemetryDecodeC string `json:"telemetry_decode_c"  port:"required"` // generated/toob_telemetry_decode.c
	TelemetryDecodeH string `json:"telemetry_decode_h"  port:"required"` // generated/toob_telemetry_decode.h
	TelemetryEncodeC string `json:"telemetry_encode_c"  port:"required"` // generated/toob_telemetry_encode.c
	TelemetryEncodeH string `json:"telemetry_encode_h"  port:"required"` // generated/toob_telemetry_encode.h
	ManifestHeader   string `json:"manifest_header"    port:"required"` // generated/generated_boot_config.h
	LinkerScripts    string `json:"linker_scripts"     port:"required"` // generated/toob_linker_*.ld
	ConfigCMake      string `json:"config_cmake"       port:"required"` // generated/toob_config.cmake
}

// =============================================================================
// Boundary: Compatibility Matrix (compatibility_matrix.json)
// =============================================================================

// MatrixDependencies defines what a specific chip version depends on.
type MatrixDependencies struct {
	Toolchain string `json:"toolchain"                port:"required"`
	Vendor    string `json:"vendor"                   port:"required"`
	Arch      string `json:"arch"                     port:"required"`
	Compiler  string `json:"compiler_container"       port:"optional"`
	CoreSDK   string `json:"core_sdk"                 port:"optional"`
}

// MatrixVerifiedCli is one CLI version entry in the matrix.
type MatrixVerifiedCli struct {
	Status     string `json:"status"      port:"required"`
	LastTested string `json:"last_tested" port:"required"`
}

// MatrixVersion is a single chip version entry in the matrix.
type MatrixVersion struct {
	EnvironmentHash     string                        `json:"environment_hash"      port:"required"`
	Dependencies        MatrixDependencies            `json:"dependencies"          port:"required"`
	VerifiedCliVersions map[string]MatrixVerifiedCli  `json:"verified_cli_versions" port:"required"`
}

// MatrixChip is a single chip entry in the compatibility matrix.
type MatrixChip struct {
	Versions map[string]MatrixVersion `json:"versions" port:"required"`
}

// =============================================================================
// Boundary: Toob Hub API (resolve/matrix, resolve/combination)
// =============================================================================

// HubResolveMatrixRequest defines GET /api/v1/resolve/matrix query params.
type HubResolveMatrixRequest struct {
	Chip string `json:"chip" port:"optional"` // Filter by chip name; omit for full matrix
}

// HubResolveCombinationRequest defines GET /api/v1/resolve/combination query params.
type HubResolveCombinationRequest struct {
	Chip        string `json:"chip"         port:"required"`
	ChipVersion string `json:"chip_version" port:"optional"`
	CLI         string `json:"cli"          port:"optional"`
	Core        string `json:"core"         port:"optional"`
	Compiler    string `json:"compiler"     port:"optional"`
}

// HubResolveCombinationResponse defines the binary go/no-go validation result.
type HubResolveCombinationResponse struct {
	Compatible bool   `json:"compatible"   port:"required"` // true if VERIFIED
	Status     string `json:"status"       port:"required"` // "VERIFIED" | "UNKNOWN" | error status
	LastTested string `json:"last_tested"  port:"optional"`
}

// =============================================================================
// Boundary: Chip Manifest (chip_manifest.json)
// =============================================================================

// ChipManifest is the parsed content of chips/{chip}/chip_manifest.json.
type ChipManifest struct {
	Vendor         string `json:"vendor"          port:"required"`
	Arch           string `json:"arch"            port:"required"`
	CompilerPrefix string `json:"compiler_prefix" port:"required"`
	Version        string `json:"version"         port:"required"`
}

// =============================================================================
// Boundary: Lockfile (toob.lock — TOML)
// =============================================================================

// LockfileSchema is the in-memory representation of toob.lock.
type LockfileSchema struct {
	RegistryVersion string `json:"registry_version" port:"required"`
	RegistryCommit  string `json:"registry_commit"  port:"required"`
	Compiler        string `json:"compiler"         port:"optional"`
	CoreSDK         string `json:"core_sdk"         port:"optional"`
}

// LockfileChipEntry is a single chip entry in toob.lock.
type LockfileChipEntry struct {
	Name             string `json:"name"              port:"required"`
	Version          string `json:"version"           port:"required"`
	Arch             string `json:"arch"              port:"required"`
	ArchVersion      string `json:"arch_version"      port:"optional"`
	Vendor           string `json:"vendor"            port:"required"`
	VendorVersion    string `json:"vendor_version"    port:"optional"`
	Toolchain        string `json:"toolchain"         port:"optional"`
	ToolchainVersion string `json:"toolchain_version" port:"optional"`
	Spawned          bool   `json:"spawned"           port:"required"`
}

// LockfileToolchainEntry is a toolchain version pinned in toob.lock.
type LockfileToolchainEntry struct {
	Version string `json:"version" port:"required"`
}

// =============================================================================
// Boundary: Compiler Container Manifest (compiler/compiler_manifest.json)
// =============================================================================

// CompilerManifest is the parsed content of compiler/compiler_manifest.json.
// It declaratively tracks all inputs of the compiler container for
// reproducibility and supply-chain traceability.
type CompilerManifest struct {
	FormatVersion   int                  `json:"format_version"   port:"required"`
	CompilerVersion string               `json:"compiler_version" port:"required"`
	ProtocolVersion int                  `json:"protocol_version" port:"required"`
	BaseImage       CompilerBaseImage    `json:"base_image"       port:"required"`
	CLI             CompilerCLIDep       `json:"cli"              port:"required"`
	CoreSDK         CompilerCoreSDKDep   `json:"core_sdk"         port:"required"`
	Registry        CompilerRegistryDep  `json:"registry"         port:"required"`
	SystemPackages  []string             `json:"system_packages"  port:"required"`
	PythonPackages  []string             `json:"python_packages"  port:"required"`
	Scripts         []CompilerScript     `json:"scripts"          port:"optional"`
	Distribution    CompilerDistribution `json:"distribution"     port:"required"`
}

// CompilerBaseImage identifies the container base.
type CompilerBaseImage struct {
	Image  string `json:"image"  port:"required"`
	Source string `json:"source" port:"optional"`
}

// CompilerSourceRef is a traceable reference to a Git repository.
type CompilerSourceRef struct {
	URL      string `json:"url"      port:"required"`
	Ref      string `json:"ref"      port:"required"`
	Artifact string `json:"artifact" port:"optional"`
}

// CompilerCLIDep defines the embedded CLI binary dependency.
type CompilerCLIDep struct {
	Version string            `json:"version" port:"required"`
	Source  CompilerSourceRef `json:"source"  port:"required"`
}

// CompilerCoreSDKDep defines the embedded Core SDK dependency.
type CompilerCoreSDKDep struct {
	Version string            `json:"version" port:"required"`
	Source  CompilerSourceRef `json:"source"  port:"required"`
}

// CompilerRegistryDep defines the pre-cloned HAL registry.
type CompilerRegistryDep struct {
	Source CompilerSourceRef `json:"source" port:"required"`
}

// CompilerScript is a build script bundled into the container.
type CompilerScript struct {
	Name string `json:"name" port:"required"`
	Path string `json:"path" port:"required"`
}

// CompilerDistribution defines the target container registry.
type CompilerDistribution struct {
	Registry   string   `json:"registry"   port:"required"`
	Repository string   `json:"repository" port:"required"`
	Platforms  []string `json:"platforms"   port:"required"`
}
