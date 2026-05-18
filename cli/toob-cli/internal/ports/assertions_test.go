package ports

import (
	"reflect"
	"testing"

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
		// Registry
		{"RegistryIndex ↔ registry.Index",
			reflect.TypeOf(RegistryIndex{}), reflect.TypeOf(registry.Index{})},
		{"RegistryChip ↔ registry.ChipInfo",
			reflect.TypeOf(RegistryChip{}), reflect.TypeOf(registry.ChipInfo{})},
		{"ChipSources ↔ registry.ChipSources",
			reflect.TypeOf(ChipSources{}), reflect.TypeOf(registry.ChipSources{})},
		{"RegistryArch ↔ registry.ArchInfo",
			reflect.TypeOf(RegistryArch{}), reflect.TypeOf(registry.ArchInfo{})},
		{"RegistryToolchain ↔ registry.ToolchainInfo",
			reflect.TypeOf(RegistryToolchain{}), reflect.TypeOf(registry.ToolchainInfo{})},

		// Toolchain download (extended registry entry)
		{"ToolchainDownload ↔ toolchain.RegistryToolchain",
			reflect.TypeOf(ToolchainDownload{}), reflect.TypeOf(toolchain.RegistryToolchain{})},

		// Manifest
		{"HardwareFlashRegion ↔ manifest.FlashRegion",
			reflect.TypeOf(HardwareFlashRegion{}), reflect.TypeOf(manifest.FlashRegion{})},

		// GitHub / Updater
		{"UpdateCheckResponse ↔ updater.ReleaseInfo",
			reflect.TypeOf(UpdateCheckResponse{}), reflect.TypeOf(updater.ReleaseInfo{})},
		{"UpdateCheckAsset ↔ updater.Asset",
			reflect.TypeOf(UpdateCheckAsset{}), reflect.TypeOf(updater.Asset{})},

		// Compatibility Matrix
		{"MatrixDependencies ↔ registry.MatrixDependencies",
			reflect.TypeOf(MatrixDependencies{}), reflect.TypeOf(registry.MatrixDependencies{})},
		{"MatrixVerifiedCli ↔ registry.MatrixVerifiedCli",
			reflect.TypeOf(MatrixVerifiedCli{}), reflect.TypeOf(registry.MatrixVerifiedCli{})},
		{"MatrixVersion ↔ registry.MatrixVersion",
			reflect.TypeOf(MatrixVersion{}), reflect.TypeOf(registry.MatrixVersion{})},
		{"MatrixChip ↔ registry.MatrixChip",
			reflect.TypeOf(MatrixChip{}), reflect.TypeOf(registry.MatrixChip{})},

		// Lockfile
		{"LockfileChipEntry ↔ lockfile.ChipEntry",
			reflect.TypeOf(LockfileChipEntry{}), reflect.TypeOf(lockfile.ChipEntry{})},
		{"LockfileToolchainEntry ↔ lockfile.ToolchainEntry",
			reflect.TypeOf(LockfileToolchainEntry{}), reflect.TypeOf(lockfile.ToolchainEntry{})},
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
		// RegistryIndex is excluded: its map-value types (RegistryChip vs ChipInfo etc.)
		// are cross-package mirrors. Each inner type has its own entry below.
		{"RegistryChip ↔ registry.ChipInfo",
			reflect.TypeOf(RegistryChip{}), reflect.TypeOf(registry.ChipInfo{})},
		{"ChipSources ↔ registry.ChipSources",
			reflect.TypeOf(ChipSources{}), reflect.TypeOf(registry.ChipSources{})},
		{"RegistryArch ↔ registry.ArchInfo",
			reflect.TypeOf(RegistryArch{}), reflect.TypeOf(registry.ArchInfo{})},
		{"RegistryToolchain ↔ registry.ToolchainInfo",
			reflect.TypeOf(RegistryToolchain{}), reflect.TypeOf(registry.ToolchainInfo{})},
		{"ToolchainDownload ↔ toolchain.RegistryToolchain",
			reflect.TypeOf(ToolchainDownload{}), reflect.TypeOf(toolchain.RegistryToolchain{})},
		{"HardwareFlashRegion ↔ manifest.FlashRegion",
			reflect.TypeOf(HardwareFlashRegion{}), reflect.TypeOf(manifest.FlashRegion{})},
		{"UpdateCheckAsset ↔ updater.Asset",
			reflect.TypeOf(UpdateCheckAsset{}), reflect.TypeOf(updater.Asset{})},
		{"MatrixDependencies ↔ registry.MatrixDependencies",
			reflect.TypeOf(MatrixDependencies{}), reflect.TypeOf(registry.MatrixDependencies{})},
		{"MatrixVerifiedCli ↔ registry.MatrixVerifiedCli",
			reflect.TypeOf(MatrixVerifiedCli{}), reflect.TypeOf(registry.MatrixVerifiedCli{})},
		{"LockfileChipEntry ↔ lockfile.ChipEntry",
			reflect.TypeOf(LockfileChipEntry{}), reflect.TypeOf(lockfile.ChipEntry{})},
		{"LockfileToolchainEntry ↔ lockfile.ToolchainEntry",
			reflect.TypeOf(LockfileToolchainEntry{}), reflect.TypeOf(lockfile.ToolchainEntry{})},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for i := 0; i < tt.portType.NumField(); i++ {
				pf := tt.portType.Field(i)
				rf, found := tt.realType.FieldByName(pf.Name)
				if !found {
					continue // Field count test catches missing fields
				}
				if pf.Type != rf.Type {
					// Handle cross-package pointer mapping for embedded structs
					if pf.Type.String() == "*ports.ChipSources" && rf.Type.String() == "*registry.ChipSources" {
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
	for i := 0; i < portType.NumField(); i++ {
		portMap[portType.Field(i).Name] = true
	}
	realMap := make(map[string]bool)
	for i := 0; i < realType.NumField(); i++ {
		realMap[realType.Field(i).Name] = true
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
