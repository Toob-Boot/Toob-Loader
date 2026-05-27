package ports

import (
	"reflect"
	"testing"

	"github.com/toob-boot/toob/internal/apiclient"
	"github.com/toob-boot/toob/internal/lockfile"
	"github.com/toob-boot/toob/internal/manifest"
	"github.com/toob-boot/toob/internal/registry"
	"github.com/toob-boot/toob/internal/toolchain"
	"github.com/toob-boot/toob/internal/updater"
)

// TestPortFieldCounts verifies that port contract types have the same
// number of fields as their implementation counterparts.
//
// This complements assertions.go which catches removals and type changes
// at compile time. This test catches field ADDITIONS at test time.
func TestPortFieldCounts(t *testing.T) {
	tests := []struct {
		name     string
		portType reflect.Type
		realType reflect.Type
	}{
		// API Client
		{"RegistryRevisionResponse ↔ apiclient.RevisionResponse",
			reflect.TypeFor[RegistryRevisionResponse](), reflect.TypeFor[apiclient.RevisionResponse]()},
		{"RegistryVersionResponse ↔ apiclient.RegistryVersionResponse",
			reflect.TypeFor[RegistryVersionResponse](), reflect.TypeFor[apiclient.RegistryVersionResponse]()},
		{"ChipResolveResponse ↔ apiclient.ChipResolveResponse",
			reflect.TypeFor[ChipResolveResponse](), reflect.TypeFor[apiclient.ChipResolveResponse]()},
		{"IntegrationItem ↔ apiclient.IntegrationItem",
			reflect.TypeFor[IntegrationItem](), reflect.TypeFor[apiclient.IntegrationItem]()},
		{"LoginResponse ↔ apiclient.LoginResponse",
			reflect.TypeFor[LoginResponse](), reflect.TypeFor[apiclient.LoginResponse]()},
		{"CheckCombinationResponse ↔ apiclient.CheckCombinationResponse",
			reflect.TypeFor[CheckCombinationResponse](), reflect.TypeFor[apiclient.CheckCombinationResponse]()},
		{"PackageResponse ↔ apiclient.PackageResponse",
			reflect.TypeFor[PackageResponse](), reflect.TypeFor[apiclient.PackageResponse]()},
		{"MyPackagesResponse ↔ apiclient.MyPackagesResponse",
			reflect.TypeFor[MyPackagesResponse](), reflect.TypeFor[apiclient.MyPackagesResponse]()},
		{"MyPackageSummary ↔ apiclient.MyPackageSummary",
			reflect.TypeFor[MyPackageSummary](), reflect.TypeFor[apiclient.MyPackageSummary]()},
		{"PublishResponse ↔ apiclient.PublishResponse",
			reflect.TypeFor[PublishResponse](), reflect.TypeFor[apiclient.PublishResponse]()},
		{"SyncDeltaResponse ↔ apiclient.SyncDeltaResponse",
			reflect.TypeFor[SyncDeltaResponse](), reflect.TypeFor[apiclient.SyncDeltaResponse]()},
		{"AckSyncResponse ↔ apiclient.AckSyncResponse",
			reflect.TypeFor[AckSyncResponse](), reflect.TypeFor[apiclient.AckSyncResponse]()},

		// Registry
		{"RegistryIndex ↔ registry.Index",
			reflect.TypeFor[RegistryIndex](), reflect.TypeFor[registry.Index]()},
		{"RegistryChip ↔ registry.ChipInfo",
			reflect.TypeFor[RegistryChip](), reflect.TypeFor[registry.ChipInfo]()},
		{"ChipSources ↔ registry.ChipSources",
			reflect.TypeFor[ChipSources](), reflect.TypeFor[registry.ChipSources]()},
		{"RegistryArch ↔ registry.ArchInfo",
			reflect.TypeFor[RegistryArch](), reflect.TypeFor[registry.ArchInfo]()},
		{"RegistryToolchain ↔ registry.ToolchainInfo",
			reflect.TypeFor[RegistryToolchain](), reflect.TypeFor[registry.ToolchainInfo]()},

		// Toolchain download (extended registry entry)
		{"ToolchainDownload ↔ toolchain.RegistryToolchain",
			reflect.TypeFor[ToolchainDownload](), reflect.TypeFor[toolchain.RegistryToolchain]()},

		// Manifest
		{"HardwareFlashRegion ↔ manifest.FlashRegion",
			reflect.TypeFor[HardwareFlashRegion](), reflect.TypeFor[manifest.FlashRegion]()},

		// GitHub / Updater
		{"UpdateCheckResponse ↔ updater.ReleaseInfo",
			reflect.TypeFor[UpdateCheckResponse](), reflect.TypeFor[updater.ReleaseInfo]()},
		{"UpdateCheckAsset ↔ updater.Asset",
			reflect.TypeFor[UpdateCheckAsset](), reflect.TypeFor[updater.Asset]()},

		// Compatibility Matrix
		{"MatrixDependencies ↔ registry.MatrixDependencies",
			reflect.TypeFor[MatrixDependencies](), reflect.TypeFor[registry.MatrixDependencies]()},
		{"MatrixVerifiedCli ↔ registry.MatrixVerifiedCli",
			reflect.TypeFor[MatrixVerifiedCli](), reflect.TypeFor[registry.MatrixVerifiedCli]()},
		{"MatrixVersion ↔ registry.MatrixVersion",
			reflect.TypeFor[MatrixVersion](), reflect.TypeFor[registry.MatrixVersion]()},
		{"MatrixChip ↔ registry.MatrixChip",
			reflect.TypeFor[MatrixChip](), reflect.TypeFor[registry.MatrixChip]()},

		// Lockfile
		{"LockfileChipEntry ↔ lockfile.ChipEntry",
			reflect.TypeFor[LockfileChipEntry](), reflect.TypeFor[lockfile.ChipEntry]()},
		{"LockfileToolchainEntry ↔ lockfile.ToolchainEntry",
			reflect.TypeFor[LockfileToolchainEntry](), reflect.TypeFor[lockfile.ToolchainEntry]()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			portFields := tt.portType.NumField()
			realFields := tt.realType.NumField()
			if portFields != realFields {
				t.Errorf("\n[CONTRACT DRIFT] %s: Struct sizes don't match.\n"+
					"  Port type has %d fields, implementation has %d fields.\n"+
					"  Fix: If you added/removed a field, you MUST also update the corresponding type in internal/ports/ports.go.",
					tt.name, portFields, realFields)
				reportFieldDiff(t, tt.name, tt.portType, tt.realType)
			}
		})
	}
}

// TestPortFieldTypes verifies matching field names have matching types.
func TestPortFieldTypes(t *testing.T) {
	tests := []struct {
		name     string
		portType reflect.Type
		realType reflect.Type
	}{
		// API Client
		{"RegistryRevisionResponse ↔ apiclient.RevisionResponse",
			reflect.TypeFor[RegistryRevisionResponse](), reflect.TypeFor[apiclient.RevisionResponse]()},
		{"RegistryVersionResponse ↔ apiclient.RegistryVersionResponse",
			reflect.TypeFor[RegistryVersionResponse](), reflect.TypeFor[apiclient.RegistryVersionResponse]()},
		{"ChipResolveResponse ↔ apiclient.ChipResolveResponse",
			reflect.TypeFor[ChipResolveResponse](), reflect.TypeFor[apiclient.ChipResolveResponse]()},
		{"IntegrationItem ↔ apiclient.IntegrationItem",
			reflect.TypeFor[IntegrationItem](), reflect.TypeFor[apiclient.IntegrationItem]()},
		{"LoginResponse ↔ apiclient.LoginResponse",
			reflect.TypeFor[LoginResponse](), reflect.TypeFor[apiclient.LoginResponse]()},
		{"CheckCombinationResponse ↔ apiclient.CheckCombinationResponse",
			reflect.TypeFor[CheckCombinationResponse](), reflect.TypeFor[apiclient.CheckCombinationResponse]()},
		{"PackageResponse ↔ apiclient.PackageResponse",
			reflect.TypeFor[PackageResponse](), reflect.TypeFor[apiclient.PackageResponse]()},
		{"MyPackageSummary ↔ apiclient.MyPackageSummary",
			reflect.TypeFor[MyPackageSummary](), reflect.TypeFor[apiclient.MyPackageSummary]()},
		{"PublishResponse ↔ apiclient.PublishResponse",
			reflect.TypeFor[PublishResponse](), reflect.TypeFor[apiclient.PublishResponse]()},
		{"SyncDeltaResponse ↔ apiclient.SyncDeltaResponse",
			reflect.TypeFor[SyncDeltaResponse](), reflect.TypeFor[apiclient.SyncDeltaResponse]()},
		{"AckSyncResponse ↔ apiclient.AckSyncResponse",
			reflect.TypeFor[AckSyncResponse](), reflect.TypeFor[apiclient.AckSyncResponse]()},

		// RegistryIndex is excluded: its map-value types (RegistryChip vs ChipInfo etc.)
		// are cross-package mirrors. Each inner type has its own entry below.
		{"RegistryChip ↔ registry.ChipInfo",
			reflect.TypeFor[RegistryChip](), reflect.TypeFor[registry.ChipInfo]()},
		{"ChipSources ↔ registry.ChipSources",
			reflect.TypeFor[ChipSources](), reflect.TypeFor[registry.ChipSources]()},
		{"RegistryArch ↔ registry.ArchInfo",
			reflect.TypeFor[RegistryArch](), reflect.TypeFor[registry.ArchInfo]()},
		{"RegistryToolchain ↔ registry.ToolchainInfo",
			reflect.TypeFor[RegistryToolchain](), reflect.TypeFor[registry.ToolchainInfo]()},
		{"ToolchainDownload ↔ toolchain.RegistryToolchain",
			reflect.TypeFor[ToolchainDownload](), reflect.TypeFor[toolchain.RegistryToolchain]()},
		{"HardwareFlashRegion ↔ manifest.FlashRegion",
			reflect.TypeFor[HardwareFlashRegion](), reflect.TypeFor[manifest.FlashRegion]()},
		{"UpdateCheckAsset ↔ updater.Asset",
			reflect.TypeFor[UpdateCheckAsset](), reflect.TypeFor[updater.Asset]()},
		{"MatrixDependencies ↔ registry.MatrixDependencies",
			reflect.TypeFor[MatrixDependencies](), reflect.TypeFor[registry.MatrixDependencies]()},
		{"MatrixVerifiedCli ↔ registry.MatrixVerifiedCli",
			reflect.TypeFor[MatrixVerifiedCli](), reflect.TypeFor[registry.MatrixVerifiedCli]()},
		{"LockfileChipEntry ↔ lockfile.ChipEntry",
			reflect.TypeFor[LockfileChipEntry](), reflect.TypeFor[lockfile.ChipEntry]()},
		{"LockfileToolchainEntry ↔ lockfile.ToolchainEntry",
			reflect.TypeFor[LockfileToolchainEntry](), reflect.TypeFor[lockfile.ToolchainEntry]()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for pf := range tt.portType.Fields() {
				rf, found := tt.realType.FieldByName(pf.Name)
				if !found {
					continue // Field count test catches missing fields
				}
				if pf.Type != rf.Type {
					// Handle cross-package pointer mapping for embedded structs
					if pf.Type.String() == "*ports.ChipSources" && rf.Type.String() == "*registry.ChipSources" {
						continue
					}
					if pf.Type.String() == "*ports.ChipCrypto" && rf.Type.String() == "*registry.ChipCrypto" {
						continue
					}
					t.Errorf("\n[BREAKING CHANGE] %s: Field %q type changed.\n"+
						"  Port expects %s, but implementation has %s.\n"+
						"  Fix: Update the field type in internal/ports/ports.go to match. This triggers a MAJOR bump.",
						tt.name, pf.Name, pf.Type, rf.Type)
				}
			}
		})
	}
}

func reportFieldDiff(t *testing.T, testName string, portType, realType reflect.Type) {
	t.Helper()
	portMap := make(map[string]bool)
	for field := range portType.Fields() {
		portMap[field.Name] = true
	}
	realMap := make(map[string]bool)
	for field := range realType.Fields() {
		realMap[field.Name] = true
	}
	for name := range realMap {
		if !portMap[name] {
			t.Errorf("\n[CONTRACT DRIFT] %s:\n  Field %q exists in the implementation but not in ports.go.\n  -> Add it to ports.go with `port:\"optional\"` (MINOR) or `port:\"required\"` (MAJOR).", testName, name)
		}
	}
	for name := range portMap {
		if !realMap[name] {
			field, _ := portType.FieldByName(name)
			tag := field.Tag.Get("port")
			if tag == "optional" {
				t.Errorf("\n[MINOR CHANGE] %s:\n  Optional field %q was removed from the implementation.\n  -> Remove it from ports.go to align contracts (this is a MINOR change).", testName, name)
			} else {
				t.Errorf("\n[BREAKING CHANGE] %s:\n  Required field %q was removed from the implementation.\n  -> Removing a required field triggers a MAJOR version bump. Remove it from ports.go if intentional.", testName, name)
			}
		}
	}
}
