package ports

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/toob-boot/toob/internal/apiclient"
	"github.com/toob-boot/toob/internal/lockfile"
	"github.com/toob-boot/toob/internal/manifest"
	"github.com/toob-boot/toob/internal/registry"
	"github.com/toob-boot/toob/internal/toolchain"
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
		{"ChipResolveResponse ↔ apiclient.ChipResolveResponse",
			reflect.TypeFor[ChipResolveResponse](), reflect.TypeFor[apiclient.ChipResolveResponse]()},
		{"IntegrationItem ↔ apiclient.IntegrationItem",
			reflect.TypeFor[IntegrationItem](), reflect.TypeFor[apiclient.IntegrationItem]()},
		{"MatrixEntry ↔ apiclient.MatrixEntry",
			reflect.TypeFor[MatrixEntry](), reflect.TypeFor[apiclient.MatrixEntry]()},
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

		// Registry
		{"RegistryIndex ↔ registry.Index",
			reflect.TypeFor[RegistryIndex](), reflect.TypeFor[registry.Index]()},
		{"RegistryEcosystem ↔ registry.EcosystemVersions",
			reflect.TypeFor[RegistryEcosystem](), reflect.TypeFor[registry.EcosystemVersions]()},
		{"RegistryChip ↔ registry.ChipInfo",
			reflect.TypeFor[RegistryChip](), reflect.TypeFor[registry.ChipInfo]()},
		{"ChipRecovery ↔ registry.ChipRecovery",
			reflect.TypeFor[ChipRecovery](), reflect.TypeFor[registry.ChipRecovery]()},
		{"ChipSources ↔ registry.ChipSources",
			reflect.TypeFor[ChipSources](), reflect.TypeFor[registry.ChipSources]()},
		{"RegistryArch ↔ registry.ArchInfo",
			reflect.TypeFor[RegistryArch](), reflect.TypeFor[registry.ArchInfo]()},
		{"RegistryToolchain ↔ registry.ToolchainInfo",
			reflect.TypeFor[RegistryToolchain](), reflect.TypeFor[registry.ToolchainInfo]()},
		{"RegistryIntegration ↔ registry.IntegrationInfo",
			reflect.TypeFor[RegistryIntegration](), reflect.TypeFor[registry.IntegrationInfo]()},
		{"RegistrySoC ↔ registry.SoCInfo",
			reflect.TypeFor[RegistrySoC](), reflect.TypeFor[registry.SoCInfo]()},

		// Toolchain download (extended registry entry)
		{"ToolchainDownload ↔ toolchain.RegistryToolchain",
			reflect.TypeFor[ToolchainDownload](), reflect.TypeFor[toolchain.RegistryToolchain]()},

		// Manifest
		{"HardwareFlashRegion ↔ manifest.FlashRegion",
			reflect.TypeFor[HardwareFlashRegion](), reflect.TypeFor[manifest.FlashRegion]()},


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
		{"ChipResolveResponse ↔ apiclient.ChipResolveResponse",
			reflect.TypeFor[ChipResolveResponse](), reflect.TypeFor[apiclient.ChipResolveResponse]()},
		{"IntegrationItem ↔ apiclient.IntegrationItem",
			reflect.TypeFor[IntegrationItem](), reflect.TypeFor[apiclient.IntegrationItem]()},
		{"MatrixEntry ↔ apiclient.MatrixEntry",
			reflect.TypeFor[MatrixEntry](), reflect.TypeFor[apiclient.MatrixEntry]()},
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

		// RegistryIndex is excluded: its map-value types (RegistryChip vs ChipInfo etc.)
		// are cross-package mirrors. Each inner type has its own entry below.
		{"RegistryEcosystem ↔ registry.EcosystemVersions",
			reflect.TypeFor[RegistryEcosystem](), reflect.TypeFor[registry.EcosystemVersions]()},
		{"RegistryChip ↔ registry.ChipInfo",
			reflect.TypeFor[RegistryChip](), reflect.TypeFor[registry.ChipInfo]()},
		{"ChipRecovery ↔ registry.ChipRecovery",
			reflect.TypeFor[ChipRecovery](), reflect.TypeFor[registry.ChipRecovery]()},
		{"RecoveryCrypto ↔ registry.RecoveryCrypto",
			reflect.TypeFor[RecoveryCrypto](), reflect.TypeFor[registry.RecoveryCrypto]()},
		{"ChipSources ↔ registry.ChipSources",
			reflect.TypeFor[ChipSources](), reflect.TypeFor[registry.ChipSources]()},
		{"RegistryArch ↔ registry.ArchInfo",
			reflect.TypeFor[RegistryArch](), reflect.TypeFor[registry.ArchInfo]()},
		{"RegistryToolchain ↔ registry.ToolchainInfo",
			reflect.TypeFor[RegistryToolchain](), reflect.TypeFor[registry.ToolchainInfo]()},
		{"RegistryIntegration ↔ registry.IntegrationInfo",
			reflect.TypeFor[RegistryIntegration](), reflect.TypeFor[registry.IntegrationInfo]()},
		{"RegistrySoC ↔ registry.SoCInfo",
			reflect.TypeFor[RegistrySoC](), reflect.TypeFor[registry.SoCInfo]()},
		{"ToolchainDownload ↔ toolchain.RegistryToolchain",
			reflect.TypeFor[ToolchainDownload](), reflect.TypeFor[toolchain.RegistryToolchain]()},
		{"HardwareFlashRegion ↔ manifest.FlashRegion",
			reflect.TypeFor[HardwareFlashRegion](), reflect.TypeFor[manifest.FlashRegion]()},
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
					if pf.Type.String() == "*ports.ChipRecovery" && rf.Type.String() == "*registry.ChipRecovery" {
						continue
					}
					if pf.Type.String() == "*ports.RecoveryCrypto" && rf.Type.String() == "*registry.RecoveryCrypto" {
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

// TestPortsGoASTValidation parses ports.go using the Go AST and verifies
// that every exported struct field carries both required annotations:
//
//  1. A `port` tag with value "required" or "optional".
//  2. A `json` tag for wire-format serialization.
//
// This catches developer mistakes (missing or malformed tags) locally
// during `go test`, before the CI semver-tool ever runs. Without this
// gate, a missing tag would cause the semver differ to silently default
// to PATCH — potentially shipping a breaking change unversioned.
func TestPortsGoASTValidation(t *testing.T) {
	portsFile := locatePortsGo(t)

	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, portsFile, nil, 0)
	if err != nil {
		t.Fatalf("Failed to parse ports.go: %v", err)
	}

	for _, decl := range node.Decls {
		genDecl, ok := decl.(*ast.GenDecl)
		if !ok || genDecl.Tok != token.TYPE {
			continue
		}

		for _, spec := range genDecl.Specs {
			typeSpec, ok := spec.(*ast.TypeSpec)
			if !ok || !typeSpec.Name.IsExported() {
				continue
			}

			structType, ok := typeSpec.Type.(*ast.StructType)
			if !ok {
				continue
			}

			validateStructFields(t, fset, typeSpec.Name.Name, structType)
		}
	}
}

// validateStructFields checks every exported field in a single struct definition.
func validateStructFields(t *testing.T, fset *token.FileSet, structName string, st *ast.StructType) {
	t.Helper()

	for _, field := range st.Fields.List {
		if len(field.Names) == 0 || !field.Names[0].IsExported() {
			continue
		}
		fieldName := field.Names[0].Name
		pos := fset.Position(field.Pos())

		// Every exported field must carry a struct tag
		if field.Tag == nil {
			t.Errorf("\n[MISSING TAG] %s.%s (at %s):\n"+
				"  Exported struct field has no struct tag.\n"+
				"  Fix: Add `json:\"...\" port:\"required\"` or `port:\"optional\"`.",
				structName, fieldName, pos)
			continue
		}

		// Strip surrounding backticks to get the raw tag string
		rawTag := field.Tag.Value[1 : len(field.Tag.Value)-1]
		tag := reflect.StructTag(rawTag)

		// Validate `port` tag presence and value
		portVal, portOK := tag.Lookup("port")
		if !portOK {
			t.Errorf("\n[MISSING PORT TAG] %s.%s (at %s):\n"+
				"  Field has a struct tag but no `port` annotation.\n"+
				"  Fix: Add `port:\"required\"` or `port:\"optional\"`.",
				structName, fieldName, pos)
		} else if portVal != "required" && portVal != "optional" {
			t.Errorf("\n[INVALID PORT TAG] %s.%s (at %s):\n"+
				"  port tag has value %q, expected \"required\" or \"optional\".\n"+
				"  Fix: Change to `port:\"required\"` or `port:\"optional\"`.",
				structName, fieldName, pos, portVal)
		}

		// Validate `json` tag presence
		jsonVal, jsonOK := tag.Lookup("json")
		if !jsonOK || jsonVal == "" {
			t.Errorf("\n[MISSING JSON TAG] %s.%s (at %s):\n"+
				"  Field has no `json` tag for wire-format serialization.\n"+
				"  Fix: Add `json:\"field_name\"` matching the wire format.",
				structName, fieldName, pos)
		} else if jsonVal == "-" {
			t.Errorf("\n[EXCLUDED JSON TAG] %s.%s (at %s):\n"+
				"  Field has `json:\"-\"` which excludes it from serialization.\n"+
				"  A port contract field must participate in the wire format.",
				structName, fieldName, pos)
		} else {
			// Verify the json key is a valid lowercase identifier (no spaces, no uppercase)
			wireKey := jsonVal
			if idx := strings.Index(wireKey, ","); idx != -1 {
				wireKey = wireKey[:idx]
			}
			if wireKey != strings.ToLower(wireKey) {
				t.Errorf("\n[NON-STANDARD JSON KEY] %s.%s (at %s):\n"+
					"  json tag key %q contains uppercase characters.\n"+
					"  Convention: Use snake_case for all wire-format keys.",
					structName, fieldName, pos, wireKey)
			}
		}
	}
}

// locatePortsGo resolves the absolute path to ports.go relative to this test file.
func locatePortsGo(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("Failed to determine test file location via runtime.Caller")
	}
	return filepath.Join(filepath.Dir(thisFile), "ports.go")
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
