// Compile-time assertions verifying every external boundary port contract stays
// in bidirectional sync with its concrete implementation struct.
//
// Each pair performs real -> port AND port -> real conversion so that any
// added, removed, renamed, or type-changed field produces an immediate
// compiler error during `go build` or `go test`.
package ports

import (
	"github.com/toob-boot/toob/internal/apiclient"
	"github.com/toob-boot/toob/internal/lockfile"
	"github.com/toob-boot/toob/internal/registry"
	"github.com/toob-boot/toob/internal/toolchain"
)

// --- Generic slice / map / pointer mapping helpers ---

func mapSlice[A, B any](in []A, fn func(A) B) []B {
	if in == nil {
		return nil
	}
	out := make([]B, len(in))
	for i, v := range in {
		out[i] = fn(v)
	}
	return out
}

func mapMap[K comparable, A, B any](in map[K]A, fn func(A) B) map[K]B {
	if in == nil {
		return nil
	}
	out := make(map[K]B, len(in))
	for k, v := range in {
		out[k] = fn(v)
	}
	return out
}

func mapPtr[A, B any](in *A, fn func(A) B) *B {
	if in == nil {
		return nil
	}
	v := fn(*in)
	return &v
}

// --- apiclient <-> ports ---

func toPortRevisionResponse(r apiclient.RevisionResponse) RegistryRevisionResponse {
	return RegistryRevisionResponse{
		Revision: r.Revision, FormatVersion: r.FormatVersion,
		CommitSHA: r.CommitSHA, Signature: r.Signature, CreatedAt: r.CreatedAt,
	}
}

func fromPortRevisionResponse(p RegistryRevisionResponse) apiclient.RevisionResponse {
	return apiclient.RevisionResponse{
		Revision: p.Revision, FormatVersion: p.FormatVersion,
		CommitSHA: p.CommitSHA, Signature: p.Signature, CreatedAt: p.CreatedAt,
	}
}

func toPortChipResolveResponse(r apiclient.ChipResolveResponse) ChipResolveResponse {
	return ChipResolveResponse{
		Name: r.Name, Version: r.Version, Path: r.Path, Manifest: r.Manifest,
	}
}

func fromPortChipResolveResponse(p ChipResolveResponse) apiclient.ChipResolveResponse {
	return apiclient.ChipResolveResponse{
		Name: p.Name, Version: p.Version, Path: p.Path, Manifest: p.Manifest,
	}
}

func toPortIntegrationItem(r apiclient.IntegrationItem) IntegrationItem {
	return IntegrationItem{
		Name: r.Name, Version: r.Version, Description: r.Description, Path: r.Path,
	}
}

func fromPortIntegrationItem(p IntegrationItem) apiclient.IntegrationItem {
	return apiclient.IntegrationItem{
		Name: p.Name, Version: p.Version, Description: p.Description, Path: p.Path,
	}
}

func toPortMatrixEntry(r apiclient.MatrixEntry) MatrixEntry {
	return MatrixEntry{
		ID: r.ID, Chip: r.Chip, ChipVersion: r.ChipVersion,
		EnvHash: r.EnvHash, Dependencies: r.Dependencies,
		CombinationKey: r.CombinationKey, Status: r.Status,
		TestedAt: r.TestedAt, Revision: r.Revision,
	}
}

func fromPortMatrixEntry(p MatrixEntry) apiclient.MatrixEntry {
	return apiclient.MatrixEntry{
		ID: p.ID, Chip: p.Chip, ChipVersion: p.ChipVersion,
		EnvHash: p.EnvHash, Dependencies: p.Dependencies,
		CombinationKey: p.CombinationKey, Status: p.Status,
		TestedAt: p.TestedAt, Revision: p.Revision,
	}
}

func toPortCheckCombinationResponse(r apiclient.CheckCombinationResponse) CheckCombinationResponse {
	return CheckCombinationResponse{
		Compatible: r.Compatible, Status: r.Status, LastTested: r.LastTested,
	}
}

func fromPortCheckCombinationResponse(p CheckCombinationResponse) apiclient.CheckCombinationResponse {
	return apiclient.CheckCombinationResponse{
		Compatible: p.Compatible, Status: p.Status, LastTested: p.LastTested,
	}
}

func toPortPackageResponse(r apiclient.PackageResponse) PackageResponse {
	return PackageResponse{
		Name: r.Name, Version: r.Version, Category: r.Category,
		Stage: r.Stage, Path: r.Path, Manifest: r.Manifest,
	}
}

func fromPortPackageResponse(p PackageResponse) apiclient.PackageResponse {
	return apiclient.PackageResponse{
		Name: p.Name, Version: p.Version, Category: p.Category,
		Stage: p.Stage, Path: p.Path, Manifest: p.Manifest,
	}
}

func toPortMyPackageSummary(r apiclient.MyPackageSummary) MyPackageSummary {
	return MyPackageSummary{
		ID: r.ID, Name: r.Name, Version: r.Version, Category: r.Category,
		Stage: r.Stage, StagingStatus: r.StagingStatus, StagingFeedback: r.StagingFeedback,
		TarballSHA: r.TarballSHA, CreatedAt: r.CreatedAt,
	}
}

func fromPortMyPackageSummary(p MyPackageSummary) apiclient.MyPackageSummary {
	return apiclient.MyPackageSummary{
		ID: p.ID, Name: p.Name, Version: p.Version, Category: p.Category,
		Stage: p.Stage, StagingStatus: p.StagingStatus, StagingFeedback: p.StagingFeedback,
		TarballSHA: p.TarballSHA, CreatedAt: p.CreatedAt,
	}
}

func toPortMyPackagesResponse(r apiclient.MyPackagesResponse) MyPackagesResponse {
	return MyPackagesResponse{
		Count:    r.Count,
		Packages: mapSlice(r.Packages, toPortMyPackageSummary),
	}
}

func fromPortMyPackagesResponse(p MyPackagesResponse) apiclient.MyPackagesResponse {
	return apiclient.MyPackagesResponse{
		Count:    p.Count,
		Packages: mapSlice(p.Packages, fromPortMyPackageSummary),
	}
}

func toPortPublishResponse(r apiclient.PublishResponse) PublishResponse {
	return PublishResponse{
		Status: r.Status, ID: r.ID, Name: r.Name, Version: r.Version,
		Category: r.Category, Stage: r.Stage, TarballSHA: r.TarballSHA,
		Signature: r.Signature, IngestionWarnings: r.IngestionWarnings,
	}
}

func fromPortPublishResponse(p PublishResponse) apiclient.PublishResponse {
	return apiclient.PublishResponse{
		Status: p.Status, ID: p.ID, Name: p.Name, Version: p.Version,
		Category: p.Category, Stage: p.Stage, TarballSHA: p.TarballSHA,
		Signature: p.Signature, IngestionWarnings: p.IngestionWarnings,
	}
}

func toPortPromoteResponse(r apiclient.PromoteResponse) PromoteResponse {
	return PromoteResponse{
		Status: r.Status, Name: r.Name, Version: r.Version,
		JobID: r.JobID, Message: r.Message, Warning: r.Warning,
	}
}

func fromPortPromoteResponse(p PromoteResponse) apiclient.PromoteResponse {
	return apiclient.PromoteResponse{
		Status: p.Status, Name: p.Name, Version: p.Version,
		JobID: p.JobID, Message: p.Message, Warning: p.Warning,
	}
}

func toPortCheckNameAvailableResponse(r apiclient.CheckNameAvailableResponse) CheckNameAvailableResponse {
	return CheckNameAvailableResponse{
		Available: r.Available, Message: r.Message,
	}
}

func fromPortCheckNameAvailableResponse(p CheckNameAvailableResponse) apiclient.CheckNameAvailableResponse {
	return apiclient.CheckNameAvailableResponse{
		Available: p.Available, Message: p.Message,
	}
}

func toPortUnpublishResponse(r apiclient.UnpublishResponse) UnpublishResponse {
	return UnpublishResponse{
		Status: r.Status, Name: r.Name, Version: r.Version,
	}
}

func fromPortUnpublishResponse(p UnpublishResponse) apiclient.UnpublishResponse {
	return apiclient.UnpublishResponse{
		Status: p.Status, Name: p.Name, Version: p.Version,
	}
}

func toPortSearchResult(r apiclient.SearchResult) SearchResult {
	return SearchResult{
		Name: r.Name, Version: r.Version, Category: r.Category,
		Description: r.Description, Author: r.Author,
		DownloadCount: r.DownloadCount, Downloads: r.Downloads,
	}
}

func fromPortSearchResult(p SearchResult) apiclient.SearchResult {
	return apiclient.SearchResult{
		Name: p.Name, Version: p.Version, Category: p.Category,
		Description: p.Description, Author: p.Author,
		DownloadCount: p.DownloadCount, Downloads: p.Downloads,
	}
}

func toPortSearchResponse(r apiclient.SearchResponse) SearchResponse {
	return SearchResponse{
		Results: mapSlice(r.Results, toPortSearchResult),
		HasMore: r.HasMore,
		Count:   r.Count,
	}
}

func fromPortSearchResponse(p SearchResponse) apiclient.SearchResponse {
	return apiclient.SearchResponse{
		Results: mapSlice(p.Results, fromPortSearchResult),
		HasMore: p.HasMore,
		Count:   p.Count,
	}
}

func toPortAuthConfig(r apiclient.AuthConfig) AuthConfig {
	return AuthConfig{
		Issuer: r.Issuer, Audience: r.Audience, ClientID: r.ClientID,
		Scopes: r.Scopes, AccountsURL: r.AccountsURL, SettingsURL: r.SettingsURL,
	}
}

func fromPortAuthConfig(p AuthConfig) apiclient.AuthConfig {
	return apiclient.AuthConfig{
		Issuer: p.Issuer, Audience: p.Audience, ClientID: p.ClientID,
		Scopes: p.Scopes, AccountsURL: p.AccountsURL, SettingsURL: p.SettingsURL,
	}
}

func toPortProfile(r apiclient.Profile) Profile {
	return Profile{
		ID:          r.ID,
		Username:    r.Username,
		DisplayName: r.DisplayName,
		Orgs: mapSlice(r.Orgs, func(o struct {
			ID   string `json:"id"`
			Name string `json:"name"`
			Role string `json:"role"`
		}) struct {
			ID   string `json:"id"   port:"required"`
			Name string `json:"name" port:"required"`
			Role string `json:"role" port:"required"`
		} {
			return struct {
				ID   string `json:"id"   port:"required"`
				Name string `json:"name" port:"required"`
				Role string `json:"role" port:"required"`
			}{ID: o.ID, Name: o.Name, Role: o.Role}
		}),
	}
}

func fromPortProfile(p Profile) apiclient.Profile {
	return apiclient.Profile{
		ID:          p.ID,
		Username:    p.Username,
		DisplayName: p.DisplayName,
		Orgs: mapSlice(p.Orgs, func(o struct {
			ID   string `json:"id"   port:"required"`
			Name string `json:"name" port:"required"`
			Role string `json:"role" port:"required"`
		}) struct {
			ID   string `json:"id"`
			Name string `json:"name"`
			Role string `json:"role"`
		} {
			return struct {
				ID   string `json:"id"`
				Name string `json:"name"`
				Role string `json:"role"`
			}{ID: o.ID, Name: o.Name, Role: o.Role}
		}),
	}
}

// --- Admin / Namespaces / Jobs / Orgs / Credentials <-> ports ---

func toPortAdminJobsStats(r apiclient.AdminJobsStats) AdminJobsStats {
	return AdminJobsStats{
		Queued: r.Queued, Running: r.Running, Passed: r.Passed,
		Failed: r.Failed, Total: r.Total, FailureRate: r.FailureRate,
	}
}

func fromPortAdminJobsStats(p AdminJobsStats) apiclient.AdminJobsStats {
	return apiclient.AdminJobsStats{
		Queued: p.Queued, Running: p.Running, Passed: p.Passed,
		Failed: p.Failed, Total: p.Total, FailureRate: p.FailureRate,
	}
}

func toPortAdminDashboardPackage(r apiclient.AdminDashboardPackage) AdminDashboardPackage {
	return AdminDashboardPackage{
		ID: r.ID, Name: r.Name, Version: r.Version,
		Category: r.Category, Publisher: r.Publisher, CreatedAt: r.CreatedAt,
	}
}

func fromPortAdminDashboardPackage(p AdminDashboardPackage) apiclient.AdminDashboardPackage {
	return apiclient.AdminDashboardPackage{
		ID: p.ID, Name: p.Name, Version: p.Version,
		Category: p.Category, Publisher: p.Publisher, CreatedAt: p.CreatedAt,
	}
}

func toPortAdminPendingPR(r apiclient.AdminPendingPR) AdminPendingPR {
	return AdminPendingPR{
		ID: r.ID, PRNumber: r.PRNumber, Repo: r.Repo,
		HeadSHA: r.HeadSHA, Status: r.Status, CreatedAt: r.CreatedAt,
	}
}

func fromPortAdminPendingPR(p AdminPendingPR) apiclient.AdminPendingPR {
	return apiclient.AdminPendingPR{
		ID: p.ID, PRNumber: p.PRNumber, Repo: p.Repo,
		HeadSHA: p.HeadSHA, Status: p.Status, CreatedAt: p.CreatedAt,
	}
}

func toPortAdminStatusResponse(r apiclient.AdminStatusResponse) AdminStatusResponse {
	return AdminStatusResponse{
		StagingPackages:     mapSlice(r.StagingPackages, toPortAdminDashboardPackage),
		PendingPRs:          mapSlice(r.PendingPRs, toPortAdminPendingPR),
		ValidationJobsStats: toPortAdminJobsStats(r.ValidationJobsStats),
		PublishJobsStats:    toPortAdminJobsStats(r.PublishJobsStats),
	}
}

func fromPortAdminStatusResponse(p AdminStatusResponse) apiclient.AdminStatusResponse {
	return apiclient.AdminStatusResponse{
		StagingPackages:     mapSlice(p.StagingPackages, fromPortAdminDashboardPackage),
		PendingPRs:          mapSlice(p.PendingPRs, fromPortAdminPendingPR),
		ValidationJobsStats: fromPortAdminJobsStats(p.ValidationJobsStats),
		PublishJobsStats:    fromPortAdminJobsStats(p.PublishJobsStats),
	}
}

func toPortAdminStagingPackage(r apiclient.AdminStagingPackage) AdminStagingPackage {
	return AdminStagingPackage{
		ID: r.ID, Name: r.Name, Version: r.Version, Category: r.Category,
		PublisherID: r.PublisherID, StagingStatus: r.StagingStatus,
		StagingFeedback: r.StagingFeedback, CreatedAt: r.CreatedAt,
	}
}

func fromPortAdminStagingPackage(p AdminStagingPackage) apiclient.AdminStagingPackage {
	return apiclient.AdminStagingPackage{
		ID: p.ID, Name: p.Name, Version: p.Version, Category: p.Category,
		PublisherID: p.PublisherID, StagingStatus: p.StagingStatus,
		StagingFeedback: p.StagingFeedback, CreatedAt: p.CreatedAt,
	}
}

func toPortAdminStagingResponse(r apiclient.AdminStagingResponse) AdminStagingResponse {
	return AdminStagingResponse{
		Packages: mapSlice(r.Packages, toPortAdminStagingPackage),
	}
}

func fromPortAdminStagingResponse(p AdminStagingResponse) apiclient.AdminStagingResponse {
	return apiclient.AdminStagingResponse{
		Packages: mapSlice(p.Packages, fromPortAdminStagingPackage),
	}
}

func toPortAdminReleaseResponse(r apiclient.AdminReleaseResponse) AdminReleaseResponse {
	return AdminReleaseResponse{
		Status: r.Status, RevisionID: r.RevisionID,
		Count: r.Count, MirrorStatus: r.MirrorStatus,
	}
}

func fromPortAdminReleaseResponse(p AdminReleaseResponse) apiclient.AdminReleaseResponse {
	return apiclient.AdminReleaseResponse{
		Status: p.Status, RevisionID: p.RevisionID,
		Count: p.Count, MirrorStatus: p.MirrorStatus,
	}
}

func toPortAdminRevokeRequest(r apiclient.AdminRevokeRequest) AdminRevokeRequest {
	return AdminRevokeRequest{
		Name: r.Name, Version: r.Version, Severity: r.Severity,
		Title: r.Title, Description: r.Description,
	}
}

func fromPortAdminRevokeRequest(p AdminRevokeRequest) apiclient.AdminRevokeRequest {
	return apiclient.AdminRevokeRequest{
		Name: p.Name, Version: p.Version, Severity: p.Severity,
		Title: p.Title, Description: p.Description,
	}
}

func toPortAdminRevokeResponse(r apiclient.AdminRevokeResponse) AdminRevokeResponse {
	return AdminRevokeResponse{
		Status: r.Status, AdvisoryID: r.AdvisoryID,
		AffectedRevisions: r.AffectedRevisions, AffectedPublishers: r.AffectedPublishers,
		MirrorStatus: r.MirrorStatus,
	}
}

func fromPortAdminRevokeResponse(p AdminRevokeResponse) apiclient.AdminRevokeResponse {
	return apiclient.AdminRevokeResponse{
		Status: p.Status, AdvisoryID: p.AdvisoryID,
		AffectedRevisions: p.AffectedRevisions, AffectedPublishers: p.AffectedPublishers,
		MirrorStatus: p.MirrorStatus,
	}
}

func toPortAdminMockWebhookRequest(r apiclient.AdminMockWebhookRequest) AdminMockWebhookRequest {
	return AdminMockWebhookRequest{
		Action: r.Action, PRNumber: r.PRNumber, Repo: r.Repo,
		HeadSHA: r.HeadSHA, GitHubUserID: r.GitHubUserID, Files: r.Files,
	}
}

func fromPortAdminMockWebhookRequest(p AdminMockWebhookRequest) apiclient.AdminMockWebhookRequest {
	return apiclient.AdminMockWebhookRequest{
		Action: p.Action, PRNumber: p.PRNumber, Repo: p.Repo,
		HeadSHA: p.HeadSHA, GitHubUserID: p.GitHubUserID, Files: p.Files,
	}
}

func toPortAdminMockWebhookResponse(r apiclient.AdminMockWebhookResponse) AdminMockWebhookResponse {
	return AdminMockWebhookResponse{
		Status: r.Status, JobID: r.JobID, Reason: r.Reason,
	}
}

func fromPortAdminMockWebhookResponse(p AdminMockWebhookResponse) apiclient.AdminMockWebhookResponse {
	return apiclient.AdminMockWebhookResponse{
		Status: p.Status, JobID: p.JobID, Reason: p.Reason,
	}
}

func toPortNamespace(r apiclient.Namespace) Namespace {
	return Namespace{
		ID: r.ID, TenantID: r.TenantID, Name: r.Name,
		CreatedAt: r.CreatedAt, SyncedAt: r.SyncedAt,
	}
}

func fromPortNamespace(p Namespace) apiclient.Namespace {
	return apiclient.Namespace{
		ID: p.ID, TenantID: p.TenantID, Name: p.Name,
		CreatedAt: p.CreatedAt, SyncedAt: p.SyncedAt,
	}
}

func toPortNamespaceMembership(r apiclient.NamespaceMembership) NamespaceMembership {
	return NamespaceMembership{
		ID: r.ID, Name: r.Name, Role: r.Role,
	}
}

func fromPortNamespaceMembership(p NamespaceMembership) apiclient.NamespaceMembership {
	return apiclient.NamespaceMembership{
		ID: p.ID, Name: p.Name, Role: p.Role,
	}
}

func toPortPublishJob(r apiclient.PublishJob) PublishJob {
	return PublishJob{
		ID: r.ID, PackageID: r.PackageID, PackageName: r.PackageName,
		PackageVersion: r.PackageVersion, PublisherID: r.PublisherID,
		ReferenceContext: r.ReferenceContext, Status: r.Status,
		CompilerLog: r.CompilerLog, ErrorMessage: r.ErrorMessage,
		ErrorSummary: r.ErrorSummary, RetryCount: r.RetryCount,
		CreatedAt: r.CreatedAt, StartedAt: r.StartedAt, FinishedAt: r.FinishedAt,
	}
}

func fromPortPublishJob(p PublishJob) apiclient.PublishJob {
	return apiclient.PublishJob{
		ID: p.ID, PackageID: p.PackageID, PackageName: p.PackageName,
		PackageVersion: p.PackageVersion, PublisherID: p.PublisherID,
		ReferenceContext: p.ReferenceContext, Status: p.Status,
		CompilerLog: p.CompilerLog, ErrorMessage: p.ErrorMessage,
		ErrorSummary: p.ErrorSummary, RetryCount: p.RetryCount,
		CreatedAt: p.CreatedAt, StartedAt: p.StartedAt, FinishedAt: p.FinishedAt,
	}
}

func toPortOrganization(r apiclient.Organization) Organization {
	return Organization{
		ID: r.ID, Name: r.Name, Role: r.Role, Plan: r.Plan,
	}
}

func fromPortOrganization(p Organization) apiclient.Organization {
	return apiclient.Organization{
		ID: p.ID, Name: p.Name, Role: p.Role, Plan: p.Plan,
	}
}

func toPortOrganizations(r apiclient.Organizations) Organizations {
	return Organizations{
		Tenants:     mapSlice(r.Tenants, toPortOrganization),
		Created:     r.Created,
		CreateLimit: r.CreateLimit,
	}
}

func fromPortOrganizations(p Organizations) apiclient.Organizations {
	return apiclient.Organizations{
		Tenants:     mapSlice(p.Tenants, fromPortOrganization),
		Created:     p.Created,
		CreateLimit: p.CreateLimit,
	}
}

func toPortInvitation(r apiclient.Invitation) Invitation {
	return Invitation{
		ID: r.ID, Email: r.Email, Role: r.Role, ExpiresAt: r.ExpiresAt,
	}
}

func fromPortInvitation(p Invitation) apiclient.Invitation {
	return apiclient.Invitation{
		ID: p.ID, Email: p.Email, Role: p.Role, ExpiresAt: p.ExpiresAt,
	}
}

func toPortInvitationAcceptance(r apiclient.InvitationAcceptance) InvitationAcceptance {
	return InvitationAcceptance{
		Organization: toPortOrganization(r.Organization),
		Joined:       r.Joined,
	}
}

func fromPortInvitationAcceptance(p InvitationAcceptance) apiclient.InvitationAcceptance {
	return apiclient.InvitationAcceptance{
		Organization: fromPortOrganization(p.Organization),
		Joined:       p.Joined,
	}
}

func toPortCredential(r apiclient.Credential) Credential {
	return Credential{
		ID: r.ID, TenantID: r.TenantID, Kind: r.Kind, Name: r.Name,
		Namespace: r.Namespace, Scopes: r.Scopes, Status: r.Status,
		CreatedAt: r.CreatedAt, ExpiresAt: r.ExpiresAt, LastUsedAt: r.LastUsedAt,
	}
}

func fromPortCredential(p Credential) apiclient.Credential {
	return apiclient.Credential{
		ID: p.ID, TenantID: p.TenantID, Kind: p.Kind, Name: p.Name,
		Namespace: p.Namespace, Scopes: p.Scopes, Status: p.Status,
		CreatedAt: p.CreatedAt, ExpiresAt: p.ExpiresAt, LastUsedAt: p.LastUsedAt,
	}
}

func toPortCredentialRequest(r apiclient.CredentialRequest) CredentialRequest {
	return CredentialRequest{
		Name: r.Name, TenantID: r.TenantID, Namespace: r.Namespace,
		Scopes: r.Scopes, ExpiresInDays: r.ExpiresInDays,
	}
}

func fromPortCredentialRequest(p CredentialRequest) apiclient.CredentialRequest {
	return apiclient.CredentialRequest{
		Name: p.Name, TenantID: p.TenantID, Namespace: p.Namespace,
		Scopes: p.Scopes, ExpiresInDays: p.ExpiresInDays,
	}
}

func toPortCreatedCredential(r apiclient.CreatedCredential) CreatedCredential {
	return CreatedCredential{
		Credential: toPortCredential(r.Credential),
		Token:      r.Token,
	}
}

func fromPortCreatedCredential(p CreatedCredential) apiclient.CreatedCredential {
	return apiclient.CreatedCredential{
		Credential: fromPortCredential(p.Credential),
		Token:      p.Token,
	}
}

// --- registry.json <-> ports ---

func toPortRegistryEcosystem(r registry.EcosystemVersions) RegistryEcosystem {
	return RegistryEcosystem{
		CLI: r.CLI, CoreSDK: r.CoreSDK, Compiler: r.Compiler, CoreSDKSha256: r.CoreSDKSha256,
	}
}

func fromPortRegistryEcosystem(p RegistryEcosystem) registry.EcosystemVersions {
	return registry.EcosystemVersions{
		CLI: p.CLI, CoreSDK: p.CoreSDK, Compiler: p.Compiler, CoreSDKSha256: p.CoreSDKSha256,
	}
}

func toPortRegistryChipSources(r registry.ChipSources) RegistryChipSources {
	return RegistryChipSources{
		Startup: r.Startup, Platform: r.Platform, Config: r.Config,
		Linker: r.Linker, Hardware: r.Hardware, Drivers: r.Drivers, Extra: r.Extra,
	}
}

func fromPortRegistryChipSources(p RegistryChipSources) registry.ChipSources {
	return registry.ChipSources{
		Startup: p.Startup, Platform: p.Platform, Config: p.Config,
		Linker: p.Linker, Hardware: p.Hardware, Drivers: p.Drivers, Extra: p.Extra,
	}
}

func toPortRegistryChipCrypto(r registry.ChipCrypto) RegistryChipCrypto {
	return RegistryChipCrypto{
		Backend: r.Backend, Hash: r.Hash, Pqc: r.Pqc,
	}
}

func fromPortRegistryChipCrypto(p RegistryChipCrypto) registry.ChipCrypto {
	return registry.ChipCrypto{
		Backend: p.Backend, Hash: p.Hash, Pqc: p.Pqc,
	}
}

func toPortRegistryRecoveryCrypto(r registry.RecoveryCrypto) RegistryRecoveryCrypto {
	return RegistryRecoveryCrypto{
		Backend: r.Backend, Hash: r.Hash,
	}
}

func fromPortRegistryRecoveryCrypto(p RegistryRecoveryCrypto) registry.RecoveryCrypto {
	return registry.RecoveryCrypto{
		Backend: p.Backend, Hash: p.Hash,
	}
}

func toPortRegistryChipRecovery(r registry.ChipRecovery) RegistryChipRecovery {
	return RegistryChipRecovery{
		Console: r.Console, Flash: r.Flash, WDT: r.WDT, Clock: r.Clock, RTC: r.RTC,
		Crypto:  mapPtr(r.Crypto, toPortRegistryRecoveryCrypto),
		Sources: r.Sources, Includes: r.Includes,
	}
}

func fromPortRegistryChipRecovery(p RegistryChipRecovery) registry.ChipRecovery {
	return registry.ChipRecovery{
		Console: p.Console, Flash: p.Flash, WDT: p.WDT, Clock: p.Clock, RTC: p.RTC,
		Crypto:  mapPtr(p.Crypto, fromPortRegistryRecoveryCrypto),
		Sources: p.Sources, Includes: p.Includes,
	}
}

func toPortRegistryChip(r registry.ChipInfo) RegistryChip {
	return RegistryChip{
		Name: r.Name, Author: r.Author, Tier: r.Tier, Arch: r.Arch,
		CompilerPrefix: r.CompilerPrefix, Path: r.Path, Version: r.Version,
		SHA256: r.SHA256, TarballSHA: r.TarballSHA,
		CliCompatibility: r.CliCompatibility, Description: r.Description,
		Verified: r.Verified, HalBindings: r.HalBindings,
		Sources:  mapPtr(r.Sources, toPortRegistryChipSources),
		Includes: r.Includes,
		Crypto:   mapPtr(r.Crypto, toPortRegistryChipCrypto),
		Recovery: mapPtr(r.Recovery, toPortRegistryChipRecovery),
	}
}

func fromPortRegistryChip(p RegistryChip) registry.ChipInfo {
	return registry.ChipInfo{
		Name: p.Name, Author: p.Author, Tier: p.Tier, Arch: p.Arch,
		CompilerPrefix: p.CompilerPrefix, Path: p.Path, Version: p.Version,
		SHA256: p.SHA256, TarballSHA: p.TarballSHA,
		CliCompatibility: p.CliCompatibility, Description: p.Description,
		Verified: p.Verified, HalBindings: p.HalBindings,
		Sources:  mapPtr(p.Sources, fromPortRegistryChipSources),
		Includes: p.Includes,
		Crypto:   mapPtr(p.Crypto, fromPortRegistryChipCrypto),
		Recovery: mapPtr(p.Recovery, fromPortRegistryChipRecovery),
	}
}

func toPortRegistryCryptoFootprint(r registry.CryptoFootprint) RegistryCryptoFootprint {
	return RegistryCryptoFootprint{
		FlashBytes: r.FlashBytes, RamBytes: r.RamBytes,
	}
}

func fromPortRegistryCryptoFootprint(p RegistryCryptoFootprint) registry.CryptoFootprint {
	return registry.CryptoFootprint{
		FlashBytes: p.FlashBytes, RamBytes: p.RamBytes,
	}
}

func toPortRegistryCrypto(r registry.CryptoInfo) RegistryCrypto {
	return RegistryCrypto{
		Name: r.Name, Author: r.Author, Tier: r.Tier, Path: r.Path,
		Version: r.Version, SHA256: r.SHA256, TarballSHA: r.TarballSHA,
		Description: r.Description, AbiVersion: r.AbiVersion, Category: r.Category,
		License: r.License, MinCoreSdk: r.MinCoreSdk, Wrapper: r.Wrapper,
		UpstreamSources: r.UpstreamSources, Headers: r.Headers, Symbols: r.Symbols,
		Cflags: r.Cflags, Includes: r.Includes, ChipBinding: r.ChipBinding,
		HasHwAcceleration: r.HasHwAcceleration,
		Footprint:         mapPtr(r.Footprint, toPortRegistryCryptoFootprint),
	}
}

func fromPortRegistryCrypto(p RegistryCrypto) registry.CryptoInfo {
	return registry.CryptoInfo{
		Name: p.Name, Author: p.Author, Tier: p.Tier, Path: p.Path,
		Version: p.Version, SHA256: p.SHA256, TarballSHA: p.TarballSHA,
		Description: p.Description, AbiVersion: p.AbiVersion, Category: p.Category,
		License: p.License, MinCoreSdk: p.MinCoreSdk, Wrapper: p.Wrapper,
		UpstreamSources: p.UpstreamSources, Headers: p.Headers, Symbols: p.Symbols,
		Cflags: p.Cflags, Includes: p.Includes, ChipBinding: p.ChipBinding,
		HasHwAcceleration: p.HasHwAcceleration,
		Footprint:         mapPtr(p.Footprint, fromPortRegistryCryptoFootprint),
	}
}

func toPortRegistryDriver(r registry.DriverInfo) RegistryDriver {
	return RegistryDriver{
		Name: r.Name, Author: r.Author, Tier: r.Tier, Trait: r.Trait,
		Path: r.Path, Version: r.Version, SHA256: r.SHA256, TarballSHA: r.TarballSHA,
		Description: r.Description, Category: r.Category,
	}
}

func fromPortRegistryDriver(p RegistryDriver) registry.DriverInfo {
	return registry.DriverInfo{
		Name: p.Name, Author: p.Author, Tier: p.Tier, Trait: p.Trait,
		Path: p.Path, Version: p.Version, SHA256: p.SHA256, TarballSHA: p.TarballSHA,
		Description: p.Description, Category: p.Category,
	}
}

func toPortRegistryArch(r registry.ArchInfo) RegistryArch {
	return RegistryArch{
		Name: r.Name, Author: r.Author, Tier: r.Tier, Path: r.Path,
		Version: r.Version, SHA256: r.SHA256, TarballSHA: r.TarballSHA,
		Description: r.Description,
	}
}

func fromPortRegistryArch(p RegistryArch) registry.ArchInfo {
	return registry.ArchInfo{
		Name: p.Name, Author: p.Author, Tier: p.Tier, Path: p.Path,
		Version: p.Version, SHA256: p.SHA256, TarballSHA: p.TarballSHA,
		Description: p.Description,
	}
}

func toPortRegistryIntegration(r registry.IntegrationInfo) RegistryIntegration {
	return RegistryIntegration{
		Name: r.Name, Author: r.Author, Tier: r.Tier, Path: r.Path,
		Version: r.Version, SHA256: r.SHA256, TarballSHA: r.TarballSHA,
		Description: r.Description,
	}
}

func fromPortRegistryIntegration(p RegistryIntegration) registry.IntegrationInfo {
	return registry.IntegrationInfo{
		Name: p.Name, Author: p.Author, Tier: p.Tier, Path: p.Path,
		Version: p.Version, SHA256: p.SHA256, TarballSHA: p.TarballSHA,
		Description: p.Description,
	}
}

func toPortRegistrySoC(r registry.SoCInfo) RegistrySoC {
	return RegistrySoC{
		Name: r.Name, Author: r.Author, Tier: r.Tier, Path: r.Path,
		Version: r.Version, SHA256: r.SHA256, TarballSHA: r.TarballSHA,
		Description: r.Description, Chips: r.Chips,
	}
}

func fromPortRegistrySoC(p RegistrySoC) registry.SoCInfo {
	return registry.SoCInfo{
		Name: p.Name, Author: p.Author, Tier: p.Tier, Path: p.Path,
		Version: p.Version, SHA256: p.SHA256, TarballSHA: p.TarballSHA,
		Description: p.Description, Chips: p.Chips,
	}
}

func toPortRegistryPort(r registry.PortInfo) RegistryPort {
	return RegistryPort{
		Name: r.Name, Author: r.Author, Tier: r.Tier, Path: r.Path,
		Version: r.Version, SHA256: r.SHA256, TarballSHA: r.TarballSHA,
		Description: r.Description,
	}
}

func fromPortRegistryPort(p RegistryPort) registry.PortInfo {
	return registry.PortInfo{
		Name: p.Name, Author: p.Author, Tier: p.Tier, Path: p.Path,
		Version: p.Version, SHA256: p.SHA256, TarballSHA: p.TarballSHA,
		Description: p.Description,
	}
}

func toPortRegistryToolchain(r registry.ToolchainInfo) RegistryToolchain {
	return RegistryToolchain{
		Path: r.Path, Version: r.Version, UpstreamVersion: r.UpstreamVersion,
		TarballSHA: r.TarballSHA, CompilerBinary: r.CompilerBinary,
		URLs: r.URLs, Sha256: r.Sha256,
	}
}

func fromPortRegistryToolchain(p RegistryToolchain) registry.ToolchainInfo {
	return registry.ToolchainInfo{
		Path: p.Path, Version: p.Version, UpstreamVersion: p.UpstreamVersion,
		TarballSHA: p.TarballSHA, CompilerBinary: p.CompilerBinary,
		URLs: p.URLs, Sha256: p.Sha256,
	}
}

func toPortToolchainFromMgr(r toolchain.RegistryToolchain) RegistryToolchain {
	return RegistryToolchain{
		Version: r.Version, UpstreamVersion: r.UpstreamVersion,
		CompilerBinary: r.CompilerBinary, URLs: r.URLs, Sha256: r.Sha256,
	}
}

func fromPortToolchainToMgr(p RegistryToolchain) toolchain.RegistryToolchain {
	return toolchain.RegistryToolchain{
		Version: p.Version, UpstreamVersion: p.UpstreamVersion,
		CompilerBinary: p.CompilerBinary, URLs: p.URLs, Sha256: p.Sha256,
	}
}

func toPortRegistryIndex(r registry.Index) RegistryIndex {
	return RegistryIndex{
		FormatVersion:   r.FormatVersion,
		RegistryVersion: r.RegistryVersion,
		Ecosystem:       mapPtr(r.Ecosystem, toPortRegistryEcosystem),
		Chips:           mapMap(r.Chips, toPortRegistryChip),
		Archs:           mapMap(r.Archs, toPortRegistryArch),
		Toolchains:      mapMap(r.Toolchains, toPortRegistryToolchain),
		Integrations:    mapMap(r.Integrations, toPortRegistryIntegration),
		Drivers:         mapMap(r.Drivers, toPortRegistryDriver),
		Crypto:          mapMap(r.Crypto, toPortRegistryCrypto),
		SoCs:            mapMap(r.SoCs, toPortRegistrySoC),
		Ports:           mapMap(r.Ports, toPortRegistryPort),
	}
}

func fromPortRegistryIndex(p RegistryIndex) registry.Index {
	return registry.Index{
		FormatVersion:   p.FormatVersion,
		RegistryVersion: p.RegistryVersion,
		Ecosystem:       mapPtr(p.Ecosystem, fromPortRegistryEcosystem),
		Chips:           mapMap(p.Chips, fromPortRegistryChip),
		Archs:           mapMap(p.Archs, fromPortRegistryArch),
		Toolchains:      mapMap(p.Toolchains, fromPortRegistryToolchain),
		Integrations:    mapMap(p.Integrations, fromPortRegistryIntegration),
		Drivers:         mapMap(p.Drivers, fromPortRegistryDriver),
		Crypto:          mapMap(p.Crypto, fromPortRegistryCrypto),
		SoCs:            mapMap(p.SoCs, fromPortRegistrySoC),
		Ports:           mapMap(p.Ports, fromPortRegistryPort),
	}
}

// --- Compatibility Matrix <-> ports ---

func toPortMatrixDependencies(r registry.MatrixDependencies) MatrixDependencies {
	return MatrixDependencies{
		Toolchain: r.Toolchain, Arch: r.Arch, Compiler: r.Compiler, CoreSDK: r.CoreSDK,
	}
}

func fromPortMatrixDependencies(p MatrixDependencies) registry.MatrixDependencies {
	return registry.MatrixDependencies{
		Toolchain: p.Toolchain, Arch: p.Arch, Compiler: p.Compiler, CoreSDK: p.CoreSDK,
	}
}

func toPortMatrixVerifiedCli(r registry.MatrixVerifiedCli) MatrixVerifiedCli {
	return MatrixVerifiedCli{
		Status: r.Status, LastTested: r.LastTested,
	}
}

func fromPortMatrixVerifiedCli(p MatrixVerifiedCli) registry.MatrixVerifiedCli {
	return registry.MatrixVerifiedCli{
		Status: p.Status, LastTested: p.LastTested,
	}
}

func toPortMatrixVersion(r registry.MatrixVersion) MatrixVersion {
	return MatrixVersion{
		EnvironmentHash:     r.EnvironmentHash,
		Dependencies:        toPortMatrixDependencies(r.Dependencies),
		VerifiedCliVersions: mapMap(r.VerifiedCliVersions, toPortMatrixVerifiedCli),
	}
}

func fromPortMatrixVersion(p MatrixVersion) registry.MatrixVersion {
	return registry.MatrixVersion{
		EnvironmentHash:     p.EnvironmentHash,
		Dependencies:        fromPortMatrixDependencies(p.Dependencies),
		VerifiedCliVersions: mapMap(p.VerifiedCliVersions, fromPortMatrixVerifiedCli),
	}
}

func toPortMatrixChip(r registry.MatrixChip) MatrixChip {
	return MatrixChip{
		Versions: mapMap(r.Versions, toPortMatrixVersion),
	}
}

func fromPortMatrixChip(p MatrixChip) registry.MatrixChip {
	return registry.MatrixChip{
		Versions: mapMap(p.Versions, fromPortMatrixVersion),
	}
}

// --- Lockfile v2 <-> ports ---

func toPortLockfileRegistry(r lockfile.RegistryLock) LockfileRegistry {
	return LockfileRegistry{
		URL: r.URL, Revision: r.Revision, IndexSHA256: r.IndexSHA256,
		Version: r.Version, Commit: r.Commit,
	}
}

func fromPortLockfileRegistry(p LockfileRegistry) lockfile.RegistryLock {
	return lockfile.RegistryLock{
		URL: p.URL, Revision: p.Revision, IndexSHA256: p.IndexSHA256,
		Version: p.Version, Commit: p.Commit,
	}
}

func toPortLockfileEnvironment(r lockfile.EnvironmentLock) LockfileEnvironment {
	return LockfileEnvironment{
		CoreSDK: r.CoreSDK, CoreSDKSHA256: r.CoreSDKSHA256,
		Compiler: r.Compiler, CompilerDigest: r.CompilerDigest,
	}
}

func fromPortLockfileEnvironment(p LockfileEnvironment) lockfile.EnvironmentLock {
	return lockfile.EnvironmentLock{
		CoreSDK: p.CoreSDK, CoreSDKSHA256: p.CoreSDKSHA256,
		Compiler: p.Compiler, CompilerDigest: p.CompilerDigest,
	}
}

func toPortLockfilePackage(r lockfile.LockedPackage) LockfilePackage {
	return LockfilePackage{
		Category: r.Category, Name: r.Name, Version: r.Version, Source: r.Source,
		SHA256: r.SHA256, BaseVersion: r.BaseVersion, BaseSHA256: r.BaseSHA256, Trait: r.Trait,
	}
}

func fromPortLockfilePackage(p LockfilePackage) lockfile.LockedPackage {
	return lockfile.LockedPackage{
		Category: p.Category, Name: p.Name, Version: p.Version, Source: p.Source,
		SHA256: p.SHA256, BaseVersion: p.BaseVersion, BaseSHA256: p.BaseSHA256, Trait: p.Trait,
	}
}

func toPortLockfileChipEntry(r lockfile.ChipEntry) LockfileChipEntry {
	return LockfileChipEntry{
		Name: r.Name, Version: r.Version, Arch: r.Arch, ArchVersion: r.ArchVersion,
		Toolchain: r.Toolchain, ToolchainVersion: r.ToolchainVersion,
		CryptoBackend: r.CryptoBackend, CryptoHash: r.CryptoHash, CryptoPqc: r.CryptoPqc,
		Spawned: r.Spawned,
	}
}

func fromPortLockfileChipEntry(p LockfileChipEntry) lockfile.ChipEntry {
	return lockfile.ChipEntry{
		Name: p.Name, Version: p.Version, Arch: p.Arch, ArchVersion: p.ArchVersion,
		Toolchain: p.Toolchain, ToolchainVersion: p.ToolchainVersion,
		CryptoBackend: p.CryptoBackend, CryptoHash: p.CryptoHash, CryptoPqc: p.CryptoPqc,
		Spawned: p.Spawned,
	}
}

func toPortLockfileToolchainEntry(r lockfile.ToolchainEntry) LockfileToolchainEntry {
	return LockfileToolchainEntry{
		Version: r.Version, SHA256: r.SHA256,
	}
}

func fromPortLockfileToolchainEntry(p LockfileToolchainEntry) lockfile.ToolchainEntry {
	return lockfile.ToolchainEntry{
		Version: p.Version, SHA256: p.SHA256,
	}
}

func toPortLockfileTarget(r lockfile.TargetLock) LockfileTarget {
	return LockfileTarget{
		Chip: r.Chip, Arch: r.Arch, Toolchain: r.Toolchain, SoC: r.SoC,
		Integration: r.Integration, Drivers: r.Drivers, Crypto: r.Crypto,
		RecoveryDrivers: r.RecoveryDrivers, RecoveryCrypto: r.RecoveryCrypto,
	}
}

func fromPortLockfileTarget(p LockfileTarget) lockfile.TargetLock {
	return lockfile.TargetLock{
		Chip: p.Chip, Arch: p.Arch, Toolchain: p.Toolchain, SoC: p.SoC,
		Integration: p.Integration, Drivers: p.Drivers, Crypto: p.Crypto,
		RecoveryDrivers: p.RecoveryDrivers, RecoveryCrypto: p.RecoveryCrypto,
	}
}

func toPortLockfileV2(r lockfile.Lockfile) LockfileV2 {
	return LockfileV2{
		FormatVersion: r.FormatVersion,
		Registry:      toPortLockfileRegistry(r.Registry),
		Environment:   toPortLockfileEnvironment(r.Environment),
		Packages:      mapSlice(r.Packages, toPortLockfilePackage),
		Chips:         mapSlice(r.Chips, toPortLockfileChipEntry),
		Toolchains:    mapMap(r.Toolchains, toPortLockfileToolchainEntry),
		Targets:       mapMap(r.Targets, toPortLockfileTarget),
	}
}

func fromPortLockfileV2(p LockfileV2) lockfile.Lockfile {
	return lockfile.Lockfile{
		FormatVersion: p.FormatVersion,
		Registry:      fromPortLockfileRegistry(p.Registry),
		Environment:   fromPortLockfileEnvironment(p.Environment),
		Packages:      mapSlice(p.Packages, fromPortLockfilePackage),
		Chips:         mapSlice(p.Chips, fromPortLockfileChipEntry),
		Toolchains:    mapMap(p.Toolchains, fromPortLockfileToolchainEntry),
		Targets:       mapMap(p.Targets, fromPortLockfileTarget),
	}
}

// Keep all bidirectional conversion helpers referenced at package scope so static
// analyzers do not mark compile-time contract checks unused.
var _ = []any{
	toPortRevisionResponse, fromPortRevisionResponse,
	toPortChipResolveResponse, fromPortChipResolveResponse,
	toPortIntegrationItem, fromPortIntegrationItem,
	toPortMatrixEntry, fromPortMatrixEntry,
	toPortCheckCombinationResponse, fromPortCheckCombinationResponse,
	toPortPackageResponse, fromPortPackageResponse,
	toPortMyPackageSummary, fromPortMyPackageSummary,
	toPortMyPackagesResponse, fromPortMyPackagesResponse,
	toPortPublishResponse, fromPortPublishResponse,
	toPortPromoteResponse, fromPortPromoteResponse,
	toPortCheckNameAvailableResponse, fromPortCheckNameAvailableResponse,
	toPortUnpublishResponse, fromPortUnpublishResponse,
	toPortSearchResult, fromPortSearchResult,
	toPortSearchResponse, fromPortSearchResponse,
	toPortAuthConfig, fromPortAuthConfig,
	toPortProfile, fromPortProfile,
	toPortAdminJobsStats, fromPortAdminJobsStats,
	toPortAdminDashboardPackage, fromPortAdminDashboardPackage,
	toPortAdminPendingPR, fromPortAdminPendingPR,
	toPortAdminStatusResponse, fromPortAdminStatusResponse,
	toPortAdminStagingPackage, fromPortAdminStagingPackage,
	toPortAdminStagingResponse, fromPortAdminStagingResponse,
	toPortAdminReleaseResponse, fromPortAdminReleaseResponse,
	toPortAdminRevokeRequest, fromPortAdminRevokeRequest,
	toPortAdminRevokeResponse, fromPortAdminRevokeResponse,
	toPortAdminMockWebhookRequest, fromPortAdminMockWebhookRequest,
	toPortAdminMockWebhookResponse, fromPortAdminMockWebhookResponse,
	toPortNamespace, fromPortNamespace,
	toPortNamespaceMembership, fromPortNamespaceMembership,
	toPortPublishJob, fromPortPublishJob,
	toPortOrganization, fromPortOrganization,
	toPortOrganizations, fromPortOrganizations,
	toPortInvitation, fromPortInvitation,
	toPortInvitationAcceptance, fromPortInvitationAcceptance,
	toPortCredential, fromPortCredential,
	toPortCredentialRequest, fromPortCredentialRequest,
	toPortCreatedCredential, fromPortCreatedCredential,
	toPortRegistryIndex, fromPortRegistryIndex,
	toPortToolchainFromMgr, fromPortToolchainToMgr,
	toPortMatrixChip, fromPortMatrixChip,
	toPortLockfileV2, fromPortLockfileV2,
}
