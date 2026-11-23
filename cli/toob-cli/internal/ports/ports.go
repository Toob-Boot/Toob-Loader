// Package ports defines all external boundary contracts for the Toob CLI.
//
// This file is the Single Source of Truth for every interface that crosses an
// external component boundary (Docker IPC, HTTP APIs, registry.json,
// compatibility_matrix.json, and toob.lock v2). Internal manifest schemas live
// in internal/manifest (re-exported from toob-go-lib/build).
//
// Contract Rules:
//
//	Adding a `port:"required"` field   = BREAKING -> bump ProtocolVersion
//	Removing any field                 = BREAKING -> bump ProtocolVersion
//	Changing a field type              = BREAKING -> bump ProtocolVersion
//	Changing port tag (req <-> opt)    = BREAKING -> bump ProtocolVersion
//	Adding a `port:"optional"` field   = non-breaking (MINOR)
package ports

import (
	"encoding/json"
	"time"
)

// ProtocolVersion is the global contract version embedded into every CLI
// binary at compile time. The Compiler Container exposes the same value
// via the Docker label "toob.protocol_version". If they don't match,
// the build is aborted before it starts.
const ProtocolVersion = 2

// =============================================================================
// Boundary: CLI -> Compiler Container (via Docker)
// =============================================================================

// DockerBuildInput defines what the CLI passes to the Compiler Container.
type DockerBuildInput struct {
	Image         string            `json:"image"                    port:"required"`
	Workspace     string            `json:"workspace"                port:"required"`
	RegistryDir   string            `json:"registry_dir"             port:"required"`
	WorkDir       string            `json:"work_dir"                 port:"required"`
	Command       string            `json:"command"                  port:"required"`
	CommandArgs   []string          `json:"command_args,omitempty"   port:"optional"`
	ToolchainsDir string            `json:"toolchains_dir,omitempty" port:"optional"`
	CoreSDKDir    string            `json:"core_sdk_dir,omitempty"   port:"optional"`
	DevMode       bool              `json:"dev_mode,omitempty"       port:"optional"`
	Manifest      string            `json:"manifest"                 port:"optional"`
	BuildDir      string            `json:"build_dir"                port:"optional"`
	ProxyVars     map[string]string `json:"proxy_vars"               port:"optional"`
}

// DockerBuildOutput defines what the Compiler Container returns to the CLI.
type DockerBuildOutput struct {
	ExitCode     int    `json:"exit_code"     port:"required"`
	Logs         []byte `json:"logs"          port:"required"`
	Stage0Binary string `json:"stage0_binary" port:"required"`
	Stage1Binary string `json:"stage1_binary" port:"required"`
	GeneratedDir string `json:"generated_dir" port:"required"`
}

// =============================================================================
// Boundary: CLI -> Toob Registry API (HTTP)
// =============================================================================

// RegistryRevisionResponse is the JSON body for GET /api/v1/registry/revision.
type RegistryRevisionResponse struct {
	Revision      int64  `json:"revision"            port:"required"`
	FormatVersion int    `json:"format_version"      port:"required"`
	CommitSHA     string `json:"commit_sha"          port:"required"`
	Signature     string `json:"signature,omitempty" port:"optional"`
	CreatedAt     string `json:"created_at"          port:"required"`
}

// ChipResolveResponse is the JSON body for GET /api/v1/resolve/chip.
type ChipResolveResponse struct {
	Name     string          `json:"name"     port:"required"`
	Version  string          `json:"version"  port:"required"`
	Path     string          `json:"path"     port:"required"`
	Manifest json.RawMessage `json:"manifest" port:"required"`
}

// IntegrationItem is a single entry in GET /api/v1/resolve/integrations.
type IntegrationItem struct {
	Name        string `json:"name"        port:"required"`
	Version     string `json:"version"     port:"required"`
	Description string `json:"description" port:"optional"`
	Path        string `json:"path"        port:"optional"`
}

// MatrixEntry represents a compatibility matrix entry returned by the Registry API.
type MatrixEntry struct {
	ID             int64           `json:"id"              port:"required"`
	Chip           string          `json:"chip"            port:"required"`
	ChipVersion    string          `json:"chip_version"    port:"required"`
	EnvHash        string          `json:"env_hash"        port:"required"`
	Dependencies   json.RawMessage `json:"dependencies"    port:"required"`
	CombinationKey string          `json:"combination_key" port:"required"`
	Status         string          `json:"status"          port:"required"`
	TestedAt       *time.Time      `json:"tested_at"       port:"optional"`
	Revision       *int64          `json:"revision"        port:"optional"`
}

// CheckCombinationResponse is the JSON body for GET /api/v1/resolve/combination.
type CheckCombinationResponse struct {
	Compatible bool   `json:"compatible"            port:"required"`
	Status     string `json:"status"                port:"required"`
	LastTested string `json:"last_tested,omitempty" port:"optional"`
}

// PackageResponse is the JSON body for GET /api/v1/package/{name}/{version}.
type PackageResponse struct {
	Name     string          `json:"name"     port:"required"`
	Version  string          `json:"version"  port:"required"`
	Category string          `json:"category" port:"required"`
	Stage    string          `json:"stage"    port:"required"`
	Path     string          `json:"path"     port:"required"`
	Manifest json.RawMessage `json:"manifest" port:"required"`
}

// MyPackageSummary is a summary element returned by GET /api/v1/packages/mine.
type MyPackageSummary struct {
	ID              string `json:"id"                         port:"required"`
	Name            string `json:"name"                       port:"required"`
	Version         string `json:"version"                    port:"required"`
	Category        string `json:"category"                   port:"required"`
	Stage           string `json:"stage"                      port:"required"`
	StagingStatus   string `json:"staging_status,omitempty"   port:"optional"`
	StagingFeedback string `json:"staging_feedback,omitempty" port:"optional"`
	TarballSHA      string `json:"tarball_sha"                port:"required"`
	CreatedAt       string `json:"created_at"                 port:"required"`
}

// MyPackagesResponse is the JSON body for GET /api/v1/packages/mine.
type MyPackagesResponse struct {
	Count    int                `json:"count"    port:"required"`
	Packages []MyPackageSummary `json:"packages" port:"required"`
}

// PublishResponse is the JSON body for POST /api/v1/publish.
type PublishResponse struct {
	Status            string   `json:"status"                       port:"required"`
	ID                string   `json:"id"                           port:"required"`
	Name              string   `json:"name"                         port:"required"`
	Version           string   `json:"version"                      port:"required"`
	Category          string   `json:"category"                     port:"required"`
	Stage             string   `json:"stage"                        port:"required"`
	TarballSHA        string   `json:"tarball_sha"                  port:"required"`
	Signature         string   `json:"signature"                    port:"required"`
	IngestionWarnings []string `json:"ingestion_warnings,omitempty" port:"optional"`
}

// PromoteResponse is the JSON body for POST /api/v1/packages/{category}/{name}/{version}/promote.
type PromoteResponse struct {
	Status  string `json:"status"            port:"required"`
	Name    string `json:"name"              port:"required"`
	Version string `json:"version"           port:"required"`
	JobID   int64  `json:"job_id"            port:"required"`
	Message string `json:"message"           port:"required"`
	Warning string `json:"warning,omitempty" port:"optional"`
}

// CheckNameAvailableResponse is the JSON body for GET /api/v1/packages/check-name.
type CheckNameAvailableResponse struct {
	Available bool   `json:"available"         port:"required"`
	Message   string `json:"message,omitempty" port:"optional"`
}

// UnpublishResponse is the JSON body for DELETE /api/v1/package/{name}/{version}.
type UnpublishResponse struct {
	Status  string `json:"status"  port:"required"`
	Name    string `json:"name"    port:"required"`
	Version string `json:"version" port:"required"`
}

// SearchResult is a single package hit returned by GET /api/v1/search.
type SearchResult struct {
	Name          string `json:"name"                     port:"required"`
	Version       string `json:"version"                  port:"required"`
	Category      string `json:"category"                 port:"required"`
	Description   string `json:"description,omitempty"    port:"optional"`
	Author        string `json:"author,omitempty"         port:"optional"`
	DownloadCount int64  `json:"download_count,omitempty" port:"optional"`
	Downloads     int    `json:"downloads,omitempty"      port:"optional"`
}

// SearchResponse is the JSON body for GET /api/v1/search.
type SearchResponse struct {
	Results []SearchResult `json:"results"         port:"required"`
	HasMore bool           `json:"has_more"        port:"required"`
	Count   int            `json:"count,omitempty" port:"optional"`
}

// AuthConfig is the JSON body for GET /api/v1/auth/config.
type AuthConfig struct {
	Issuer      string   `json:"issuer"       port:"required"`
	Audience    string   `json:"audience"     port:"optional"`
	ClientID    string   `json:"client_id"    port:"required"`
	Scopes      []string `json:"scopes"       port:"required"`
	AccountsURL string   `json:"accounts_url" port:"optional"`
	SettingsURL string   `json:"settings_url" port:"optional"`
}

// Profile is the JSON body for GET /api/v1/me.
type Profile struct {
	ID          string `json:"id"           port:"required"`
	Username    string `json:"username"     port:"required"`
	DisplayName string `json:"display_name" port:"required"`
	Orgs        []struct {
		ID   string `json:"id"   port:"required"`
		Name string `json:"name" port:"required"`
		Role string `json:"role" port:"required"`
	} `json:"orgs" port:"required"`
}

// =============================================================================
// Boundary: CLI -> Admin, Jobs, Namespaces, Organizations & Credentials APIs
// =============================================================================

// AdminJobsStats aggregates job execution counters for admin status reporting.
type AdminJobsStats struct {
	Queued      int     `json:"queued"       port:"required"`
	Running     int     `json:"running"      port:"required"`
	Passed      int     `json:"passed"       port:"required"`
	Failed      int     `json:"failed"       port:"required"`
	Total       int     `json:"total"        port:"required"`
	FailureRate float64 `json:"failure_rate" port:"required"`
}

// AdminDashboardPackage summarizes a staged package on the admin dashboard.
type AdminDashboardPackage struct {
	ID        string    `json:"id"         port:"required"`
	Name      string    `json:"name"       port:"required"`
	Version   string    `json:"version"    port:"required"`
	Category  string    `json:"category"   port:"required"`
	Publisher string    `json:"publisher"  port:"required"`
	CreatedAt time.Time `json:"created_at" port:"required"`
}

// AdminPendingPR represents a pending pull request tracked by the admin API.
type AdminPendingPR struct {
	ID        int64     `json:"id"         port:"required"`
	PRNumber  int       `json:"pr_number"  port:"required"`
	Repo      string    `json:"repo"       port:"required"`
	HeadSHA   string    `json:"head_sha"   port:"required"`
	Status    string    `json:"status"     port:"required"`
	CreatedAt time.Time `json:"created_at" port:"required"`
}

// AdminStatusResponse is the JSON body for GET /api/v1/admin/status.
type AdminStatusResponse struct {
	StagingPackages     []AdminDashboardPackage `json:"staging_packages"      port:"required"`
	PendingPRs          []AdminPendingPR        `json:"pending_prs"           port:"required"`
	ValidationJobsStats AdminJobsStats          `json:"validation_jobs_stats" port:"required"`
	PublishJobsStats    AdminJobsStats          `json:"publish_jobs_stats"    port:"required"`
}

// AdminStagingPackage represents a package awaiting review in the staging queue.
type AdminStagingPackage struct {
	ID              string `json:"id"                         port:"required"`
	Name            string `json:"name"                       port:"required"`
	Version         string `json:"version"                    port:"required"`
	Category        string `json:"category"                   port:"required"`
	PublisherID     string `json:"publisher_id,omitempty"     port:"optional"`
	StagingStatus   string `json:"staging_status,omitempty"   port:"optional"`
	StagingFeedback string `json:"staging_feedback,omitempty" port:"optional"`
	CreatedAt       string `json:"created_at,omitempty"       port:"optional"`
}

// AdminStagingResponse is the JSON body for GET /api/v1/admin/staging.
type AdminStagingResponse struct {
	Packages []AdminStagingPackage `json:"packages" port:"required"`
}

// AdminReleaseResponse is the JSON body for POST /api/v1/admin/release.
type AdminReleaseResponse struct {
	Status       string `json:"status"                  port:"required"`
	RevisionID   int64  `json:"revision_id"             port:"required"`
	Count        int    `json:"count"                   port:"required"`
	MirrorStatus string `json:"mirror_status,omitempty" port:"optional"`
}

// AdminRevokeRequest is the JSON request body for POST /api/v1/admin/revoke.
type AdminRevokeRequest struct {
	Name        string `json:"name"                  port:"required"`
	Version     string `json:"version"               port:"required"`
	Severity    string `json:"severity"              port:"required"`
	Title       string `json:"title"                 port:"required"`
	Description string `json:"description,omitempty" port:"optional"`
}

// AdminRevokeResponse is the JSON body for POST /api/v1/admin/revoke.
type AdminRevokeResponse struct {
	Status             string `json:"status"                  port:"required"`
	AdvisoryID         int64  `json:"advisory_id"             port:"required"`
	AffectedRevisions  int    `json:"affected_revisions"      port:"required"`
	AffectedPublishers int    `json:"affected_publishers"     port:"required"`
	MirrorStatus       string `json:"mirror_status,omitempty" port:"optional"`
}

// AdminMockWebhookRequest is the JSON request body for POST /api/v1/admin/mock-webhook.
type AdminMockWebhookRequest struct {
	Action       string   `json:"action"         port:"required"`
	PRNumber     int      `json:"pr_number"      port:"required"`
	Repo         string   `json:"repo"           port:"required"`
	HeadSHA      string   `json:"head_sha"       port:"required"`
	GitHubUserID int64    `json:"github_user_id" port:"required"`
	Files        []string `json:"files"          port:"required"`
}

// AdminMockWebhookResponse is the JSON body for POST /api/v1/admin/mock-webhook.
type AdminMockWebhookResponse struct {
	Status string `json:"status"           port:"required"`
	JobID  int64  `json:"job_id,omitempty" port:"optional"`
	Reason string `json:"reason,omitempty" port:"optional"`
}

// Namespace represents a claimed package namespace returned by the Registry API.
type Namespace struct {
	ID        string     `json:"id"                  port:"required"`
	TenantID  string     `json:"tenant_id,omitempty" port:"optional"`
	Name      string     `json:"name"                port:"required"`
	CreatedAt time.Time  `json:"created_at"          port:"required"`
	SyncedAt  *time.Time `json:"synced_at,omitempty" port:"optional"`
}

// NamespaceMembership describes an organization member role in a namespace.
type NamespaceMembership struct {
	ID   string `json:"id"   port:"required"`
	Name string `json:"name" port:"required"`
	Role string `json:"role" port:"required"`
}

// PublishJob represents a validation or publish pipeline job record.
type PublishJob struct {
	ID               int64           `json:"id"                      port:"required"`
	PackageID        string          `json:"package_id"              port:"required"`
	PackageName      string          `json:"package_name"            port:"required"`
	PackageVersion   string          `json:"package_version"         port:"required"`
	PublisherID      string          `json:"publisher_id"            port:"required"`
	ReferenceContext json.RawMessage `json:"reference_context"       port:"required"`
	Status           string          `json:"status"                  port:"required"`
	CompilerLog      *string         `json:"compiler_log,omitempty"  port:"optional"`
	ErrorMessage     *string         `json:"error_message,omitempty" port:"optional"`
	ErrorSummary     *string         `json:"error_summary,omitempty" port:"optional"`
	RetryCount       int             `json:"retry_count"             port:"required"`
	CreatedAt        time.Time       `json:"created_at"              port:"required"`
	StartedAt        *time.Time      `json:"started_at,omitempty"    port:"optional"`
	FinishedAt       *time.Time      `json:"finished_at,omitempty"   port:"optional"`
}

// Organization summarizes an identity-api tenant membership.
type Organization struct {
	ID   string `json:"id"   port:"required"`
	Name string `json:"name" port:"required"`
	Role string `json:"role" port:"required"`
	Plan string `json:"plan" port:"required"`
}

// Organizations is the JSON body for GET /api/v1/orgs on accounts API.
type Organizations struct {
	Tenants     []Organization `json:"tenants"      port:"required"`
	Created     int            `json:"created"      port:"required"`
	CreateLimit int            `json:"create_limit" port:"required"`
}

// Invitation represents an organization membership invitation.
type Invitation struct {
	ID        string `json:"id"         port:"required"`
	Email     string `json:"email"      port:"required"`
	Role      string `json:"role"       port:"required"`
	ExpiresAt string `json:"expires_at" port:"required"`
}

// InvitationAcceptance is the JSON response for accepting an organization invite.
type InvitationAcceptance struct {
	Organization Organization `json:"organization" port:"required"`
	Joined       bool         `json:"joined"       port:"required"`
}

// Credential represents an API token or CI credential metadata entry.
type Credential struct {
	ID         string     `json:"id"                     port:"required"`
	TenantID   string     `json:"tenant_id"              port:"required"`
	Kind       string     `json:"kind"                   port:"required"`
	Name       string     `json:"name"                   port:"required"`
	Namespace  string     `json:"namespace,omitempty"    port:"optional"`
	Scopes     []string   `json:"scopes"                 port:"required"`
	Status     string     `json:"status"                 port:"required"`
	CreatedAt  time.Time  `json:"created_at"             port:"required"`
	ExpiresAt  time.Time  `json:"expires_at"             port:"required"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty" port:"optional"`
}

// CredentialRequest is the JSON request body to mint a scoped credential.
type CredentialRequest struct {
	Name          string   `json:"name"                      port:"required"`
	TenantID      string   `json:"tenant_id"                 port:"required"`
	Namespace     string   `json:"namespace,omitempty"       port:"optional"`
	Scopes        []string `json:"scopes"                    port:"required"`
	ExpiresInDays int      `json:"expires_in_days,omitempty" port:"optional"`
}

// CreatedCredential is the JSON response returned once upon creating a credential.
type CreatedCredential struct {
	Credential Credential `json:"credential" port:"required"`
	Token      string     `json:"token"      port:"required"`
}

// =============================================================================
// Boundary: CLI -> registry.json (local cache & remote index)
// =============================================================================

// RegistryEcosystem declares compatible ecosystem component versions in registry.json.
type RegistryEcosystem struct {
	CLI           []string          `json:"cli"                       port:"required"`
	CoreSDK       []string          `json:"core_sdk"                  port:"required"`
	Compiler      []string          `json:"compiler"                  port:"required"`
	CoreSDKSha256 map[string]string `json:"core_sdk_sha256,omitempty" port:"optional"`
}

// RegistryIndex defines the root structure of registry.json.
type RegistryIndex struct {
	FormatVersion   int                            `json:"format_version"   port:"required"`
	RegistryVersion string                         `json:"registry_version" port:"required"`
	Ecosystem       *RegistryEcosystem             `json:"ecosystem"        port:"optional"`
	Chips           map[string]RegistryChip        `json:"chips"            port:"required"`
	Archs           map[string]RegistryArch        `json:"archs"            port:"required"`
	Toolchains      map[string]RegistryToolchain   `json:"toolchains"       port:"required"`
	Integrations    map[string]RegistryIntegration `json:"integrations"   port:"required"`
	Drivers         map[string]RegistryDriver      `json:"drivers"          port:"required"`
	Crypto          map[string]RegistryCrypto      `json:"crypto"           port:"required"`
	SoCs            map[string]RegistrySoC         `json:"socs,omitempty"   port:"optional"`
	Ports           map[string]RegistryPort        `json:"ports,omitempty"  port:"optional"`
}

// RegistryChipSources lists relative source paths for a chip entry in registry.json.
type RegistryChipSources struct {
	Startup  string   `json:"startup"           port:"required"`
	Platform string   `json:"platform"          port:"required"`
	Config   string   `json:"config"            port:"required"`
	Linker   string   `json:"linker"            port:"required"`
	Hardware string   `json:"hardware"          port:"required"`
	Drivers  []string `json:"drivers,omitempty" port:"optional"`
	Extra    []string `json:"extra,omitempty"   port:"optional"`
}

// RegistryChipCrypto defines Stage-1 default crypto slots for a chip entry in registry.json.
type RegistryChipCrypto struct {
	Backend string `json:"backend,omitempty" port:"optional"`
	Hash    string `json:"hash,omitempty"    port:"optional"`
	Pqc     string `json:"pqc,omitempty"     port:"optional"`
}

// RegistryRecoveryCrypto specifies recovery crypto overrides for a chip entry in registry.json.
type RegistryRecoveryCrypto struct {
	Backend string `json:"backend,omitempty" port:"optional"`
	Hash    string `json:"hash,omitempty"    port:"optional"`
}

// RegistryChipRecovery defines recovery defaults for a chip entry in registry.json.
type RegistryChipRecovery struct {
	Console  string                  `json:"console"            port:"required"`
	Flash    string                  `json:"flash"              port:"required"`
	WDT      string                  `json:"wdt,omitempty"      port:"optional"`
	Clock    string                  `json:"clock,omitempty"    port:"optional"`
	RTC      string                  `json:"rtc,omitempty"      port:"optional"`
	Crypto   *RegistryRecoveryCrypto `json:"crypto,omitempty"   port:"optional"`
	Sources  []string                `json:"sources,omitempty"  port:"optional"`
	Includes []string                `json:"includes,omitempty" port:"optional"`
}

// RegistryChip represents a chip entry in registry.json.
type RegistryChip struct {
	Name             string                `json:"name"                   port:"required"`
	Author           string                `json:"author,omitempty"       port:"optional"`
	Tier             string                `json:"tier,omitempty"         port:"optional"`
	Arch             string                `json:"arch"                   port:"required"`
	CompilerPrefix   string                `json:"compiler_prefix"        port:"required"`
	Path             string                `json:"path"                   port:"required"`
	Version          string                `json:"version"                port:"required"`
	SHA256           string                `json:"sha256,omitempty"       port:"optional"`
	TarballSHA       string                `json:"tarball_sha,omitempty"  port:"optional"`
	CliCompatibility string                `json:"cli_compatibility"      port:"required"`
	Description      string                `json:"description,omitempty"  port:"optional"`
	Verified         bool                  `json:"verified"               port:"required"`
	HalBindings      map[string]string     `json:"hal_bindings,omitempty" port:"optional"`
	Sources          *RegistryChipSources  `json:"sources,omitempty"      port:"optional"`
	Includes         []string              `json:"includes,omitempty"     port:"optional"`
	Crypto           *RegistryChipCrypto   `json:"crypto,omitempty"       port:"optional"`
	Recovery         *RegistryChipRecovery `json:"recovery,omitempty"     port:"optional"`
}

// RegistryCryptoFootprint reports optional estimated code and RAM footprint in registry.json.
type RegistryCryptoFootprint struct {
	FlashBytes uint32 `json:"flash_bytes,omitempty" port:"optional"`
	RamBytes   uint32 `json:"ram_bytes,omitempty"   port:"optional"` //nolint:staticcheck // ST1003: mirrors registry.CryptoFootprint.RamBytes field name
}

// RegistryCrypto represents a crypto module entry in registry.json.
type RegistryCrypto struct {
	Name              string                   `json:"name"                        port:"required"`
	Author            string                   `json:"author,omitempty"            port:"optional"`
	Tier              string                   `json:"tier,omitempty"              port:"optional"`
	Path              string                   `json:"path"                        port:"required"`
	Version           string                   `json:"version"                     port:"required"`
	SHA256            string                   `json:"sha256,omitempty"            port:"optional"`
	TarballSHA        string                   `json:"tarball_sha,omitempty"       port:"optional"`
	Description       string                   `json:"description,omitempty"       port:"optional"`
	AbiVersion        string                   `json:"abi_version,omitempty"       port:"optional"`
	Category          []string                 `json:"category"                    port:"required"`
	License           string                   `json:"license,omitempty"           port:"optional"`
	MinCoreSdk        string                   `json:"min_core_sdk,omitempty"      port:"optional"`
	Wrapper           *string                  `json:"wrapper,omitempty"           port:"optional"`
	UpstreamSources   []string                 `json:"upstream_sources,omitempty"  port:"optional"`
	Headers           []string                 `json:"headers,omitempty"           port:"optional"`
	Symbols           map[string]string        `json:"symbols,omitempty"           port:"optional"`
	Cflags            []string                 `json:"cflags,omitempty"            port:"optional"`
	Includes          []string                 `json:"includes,omitempty"          port:"optional"`
	ChipBinding       []string                 `json:"chip_binding,omitempty"      port:"optional"`
	HasHwAcceleration bool                     `json:"has_hw_acceleration,omitempty" port:"optional"`
	Footprint         *RegistryCryptoFootprint `json:"footprint,omitempty"         port:"optional"`
}

// RegistryDriver represents a HAL driver entry in registry.json.
type RegistryDriver struct {
	Name        string `json:"name"                  port:"required"`
	Author      string `json:"author,omitempty"      port:"optional"`
	Tier        string `json:"tier,omitempty"        port:"optional"`
	Trait       string `json:"trait,omitempty"       port:"optional"`
	Path        string `json:"path"                  port:"required"`
	Version     string `json:"version"               port:"required"`
	SHA256      string `json:"sha256,omitempty"      port:"optional"`
	TarballSHA  string `json:"tarball_sha,omitempty" port:"optional"`
	Description string `json:"description,omitempty" port:"optional"`
	Category    string `json:"category,omitempty"    port:"optional"`
}

// RegistryArch represents a CPU architecture entry in registry.json.
type RegistryArch struct {
	Name        string `json:"name"                  port:"required"`
	Author      string `json:"author,omitempty"      port:"optional"`
	Tier        string `json:"tier,omitempty"        port:"optional"`
	Path        string `json:"path"                  port:"required"`
	Version     string `json:"version"               port:"required"`
	SHA256      string `json:"sha256,omitempty"      port:"optional"`
	TarballSHA  string `json:"tarball_sha,omitempty" port:"optional"`
	Description string `json:"description"           port:"required"`
}

// RegistryIntegration represents a target RTOS/build integration in registry.json.
type RegistryIntegration struct {
	Name        string `json:"name"                  port:"required"`
	Author      string `json:"author,omitempty"      port:"optional"`
	Tier        string `json:"tier,omitempty"        port:"optional"`
	Path        string `json:"path"                  port:"required"`
	Version     string `json:"version"               port:"required"`
	SHA256      string `json:"sha256,omitempty"      port:"optional"`
	TarballSHA  string `json:"tarball_sha,omitempty" port:"optional"`
	Description string `json:"description"           port:"required"`
}

// RegistrySoC represents a shared SoC package entry in registry.json.
type RegistrySoC struct {
	Name        string   `json:"name"                  port:"required"`
	Author      string   `json:"author,omitempty"      port:"optional"`
	Tier        string   `json:"tier,omitempty"        port:"optional"`
	Path        string   `json:"path"                  port:"required"`
	Version     string   `json:"version"               port:"required"`
	SHA256      string   `json:"sha256,omitempty"      port:"optional"`
	TarballSHA  string   `json:"tarball_sha,omitempty" port:"optional"`
	Description string   `json:"description,omitempty" port:"optional"`
	Chips       []string `json:"chips,omitempty"       port:"optional"`
}

// RegistryPort represents a hardware platform port package entry in registry.json.
type RegistryPort struct {
	Name        string `json:"name"                  port:"required"`
	Author      string `json:"author,omitempty"      port:"optional"`
	Tier        string `json:"tier,omitempty"        port:"optional"`
	Path        string `json:"path"                  port:"required"`
	Version     string `json:"version"               port:"required"`
	SHA256      string `json:"sha256,omitempty"      port:"optional"`
	TarballSHA  string `json:"tarball_sha,omitempty" port:"optional"`
	Description string `json:"description,omitempty" port:"optional"`
}

// RegistryToolchain represents a compiler toolchain entry in registry.json and toolchains/registry.json.
type RegistryToolchain struct {
	Path            string            `json:"path"                      port:"required"`
	Version         string            `json:"version"                   port:"required"`
	UpstreamVersion string            `json:"upstream_version"          port:"required"`
	TarballSHA      string            `json:"tarball_sha,omitempty"     port:"optional"`
	CompilerBinary  string            `json:"compiler_binary,omitempty" port:"optional"`
	URLs            map[string]string `json:"urls,omitempty"            port:"optional"`
	Sha256          map[string]string `json:"sha256,omitempty"          port:"optional"`
}

// =============================================================================
// Boundary: CLI -> compatibility_matrix.json
// =============================================================================

// MatrixDependencies defines the pinned build dependencies of a matrix entry.
type MatrixDependencies struct {
	Toolchain string `json:"toolchain"                    port:"required"`
	Arch      string `json:"arch"                         port:"required"`
	Compiler  string `json:"compiler_container,omitempty" port:"optional"`
	CoreSDK   string `json:"core_sdk,omitempty"           port:"optional"`
}

// MatrixVerifiedCli holds the verification status for a single CLI version.
type MatrixVerifiedCli struct {
	Status     string `json:"status"      port:"required"`
	LastTested string `json:"last_tested" port:"required"`
}

// MatrixVersion represents one verified configuration snapshot for a chip version.
type MatrixVersion struct {
	EnvironmentHash     string                       `json:"environment_hash"      port:"required"`
	Dependencies        MatrixDependencies           `json:"dependencies"          port:"required"`
	VerifiedCliVersions map[string]MatrixVerifiedCli `json:"verified_cli_versions" port:"required"`
}

// MatrixChip maps chip versions to their verified compatibility snapshots.
type MatrixChip struct {
	Versions map[string]MatrixVersion `json:"versions" port:"required"`
}

// =============================================================================
// Boundary: CLI -> toob.lock (Lockfile v2 — TOML)
// =============================================================================

// LockfileRegistry records the provenance of the registry index used for locking.
type LockfileRegistry struct {
	URL         string `toml:"url,omitempty"          json:"url,omitempty"          port:"optional"`
	Revision    string `toml:"revision,omitempty"     json:"revision,omitempty"     port:"optional"`
	IndexSHA256 string `toml:"index_sha256,omitempty" json:"index_sha256,omitempty" port:"optional"`
	Version     string `toml:"version,omitempty"      json:"version,omitempty"      port:"optional"`
	Commit      string `toml:"commit,omitempty"       json:"commit,omitempty"       port:"optional"`
}

// LockfileEnvironment pins Core SDK and compiler container digests in toob.lock.
type LockfileEnvironment struct {
	CoreSDK        string `toml:"core_sdk,omitempty"        json:"core_sdk,omitempty"        port:"optional"`
	CoreSDKSHA256  string `toml:"core_sdk_sha256,omitempty" json:"core_sdk_sha256,omitempty" port:"optional"`
	Compiler       string `toml:"compiler,omitempty"        json:"compiler,omitempty"        port:"optional"`
	CompilerDigest string `toml:"compiler_digest,omitempty" json:"compiler_digest,omitempty" port:"optional"`
}

// LockfilePackage represents a pinned dependency entry in toob.lock v2 [[package]].
type LockfilePackage struct {
	Category    string `toml:"category"               json:"category"               port:"required"`
	Name        string `toml:"name"                   json:"name"                   port:"required"`
	Version     string `toml:"version"                json:"version"                port:"required"`
	Source      string `toml:"source"                 json:"source"                 port:"required"`
	SHA256      string `toml:"sha256,omitempty"       json:"sha256,omitempty"       port:"optional"`
	BaseVersion string `toml:"base_version,omitempty" json:"base_version,omitempty" port:"optional"`
	BaseSHA256  string `toml:"base_sha256,omitempty"  json:"base_sha256,omitempty"  port:"optional"`
	Trait       string `toml:"trait,omitempty"        json:"trait,omitempty"        port:"optional"`
}

// LockfileChipEntry represents a legacy v1 chip entry retained for migration compatibility.
type LockfileChipEntry struct {
	Name             string `toml:"name"              json:"name"              port:"required"`
	Version          string `toml:"version"           json:"version"           port:"required"`
	Arch             string `toml:"arch"              json:"arch"              port:"required"`
	ArchVersion      string `toml:"arch_version"      json:"arch_version"      port:"optional"`
	Toolchain        string `toml:"toolchain"         json:"toolchain"         port:"optional"`
	ToolchainVersion string `toml:"toolchain_version" json:"toolchain_version" port:"optional"`
	CryptoBackend    string `toml:"crypto_backend"    json:"crypto_backend"    port:"optional"`
	CryptoHash       string `toml:"crypto_hash"       json:"crypto_hash"       port:"optional"`
	CryptoPqc        string `toml:"crypto_pqc"        port:"optional" json:"crypto_pqc"`
	Spawned          bool   `toml:"spawned"           json:"spawned"           port:"required"`
}

// LockfileToolchainEntry pins a toolchain version and per-platform archive checksums.
type LockfileToolchainEntry struct {
	Version string            `toml:"version"          json:"version"          port:"required"`
	SHA256  map[string]string `toml:"sha256,omitempty" json:"sha256,omitempty" port:"optional"`
}

// LockfileTarget records resolved per-chip bindings in toob.lock v2 [targets.<chip>].
type LockfileTarget struct {
	Chip            string            `toml:"chip"                       json:"chip"                       port:"required"`
	Arch            string            `toml:"arch,omitempty"             json:"arch,omitempty"             port:"optional"`
	Toolchain       string            `toml:"toolchain,omitempty"        json:"toolchain,omitempty"        port:"optional"`
	SoC             string            `toml:"soc,omitempty"              json:"soc,omitempty"              port:"optional"`
	Integration     string            `toml:"integration,omitempty"      json:"integration,omitempty"      port:"optional"`
	Drivers         map[string]string `toml:"drivers,omitempty"          json:"drivers,omitempty"          port:"optional"`
	Crypto          map[string]string `toml:"crypto,omitempty"           json:"crypto,omitempty"           port:"optional"`
	RecoveryDrivers map[string]string `toml:"recovery_drivers,omitempty" json:"recovery_drivers,omitempty" port:"optional"`
	RecoveryCrypto  map[string]string `toml:"recovery_crypto,omitempty"  json:"recovery_crypto,omitempty"  port:"optional"`
}

// LockfileV2 is the top-level schema for toob.lock (v2 with v1 migration fields).
type LockfileV2 struct {
	FormatVersion int                               `toml:"format_version,omitempty" json:"format_version,omitempty" port:"optional"`
	Registry      LockfileRegistry                  `toml:"registry"                 json:"registry"                 port:"required"`
	Environment   LockfileEnvironment               `toml:"environment"              json:"environment"              port:"required"`
	Packages      []LockfilePackage                 `toml:"package,omitempty"        json:"package,omitempty"        port:"optional"`
	Chips         []LockfileChipEntry               `toml:"chip,omitempty"           json:"chip,omitempty"           port:"optional"`
	Toolchains    map[string]LockfileToolchainEntry `toml:"toolchains,omitempty"     json:"toolchains,omitempty"     port:"optional"`
	Targets       map[string]LockfileTarget         `toml:"targets,omitempty"        json:"targets,omitempty"        port:"optional"`
}
