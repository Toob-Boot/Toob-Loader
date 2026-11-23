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
	"github.com/toob-boot/toob/internal/registry"
	"github.com/toob-boot/toob/internal/toolchain"
)

type portParityPair struct {
	name     string
	portType reflect.Type
	realType reflect.Type
}

// portParityPairs maps every exported ports contract struct (outside container IPC)
// to its exact concrete implementation counterpart.
func portParityPairs() []portParityPair {
	return []portParityPair{
		// Registry & Identity HTTP API
		{
			"RegistryRevisionResponse <-> apiclient.RevisionResponse",
			reflect.TypeFor[RegistryRevisionResponse](), reflect.TypeFor[apiclient.RevisionResponse](),
		},
		{
			"ChipResolveResponse <-> apiclient.ChipResolveResponse",
			reflect.TypeFor[ChipResolveResponse](), reflect.TypeFor[apiclient.ChipResolveResponse](),
		},
		{
			"IntegrationItem <-> apiclient.IntegrationItem",
			reflect.TypeFor[IntegrationItem](), reflect.TypeFor[apiclient.IntegrationItem](),
		},
		{
			"MatrixEntry <-> apiclient.MatrixEntry",
			reflect.TypeFor[MatrixEntry](), reflect.TypeFor[apiclient.MatrixEntry](),
		},
		{
			"CheckCombinationResponse <-> apiclient.CheckCombinationResponse",
			reflect.TypeFor[CheckCombinationResponse](), reflect.TypeFor[apiclient.CheckCombinationResponse](),
		},
		{
			"PackageResponse <-> apiclient.PackageResponse",
			reflect.TypeFor[PackageResponse](), reflect.TypeFor[apiclient.PackageResponse](),
		},
		{
			"MyPackageSummary <-> apiclient.MyPackageSummary",
			reflect.TypeFor[MyPackageSummary](), reflect.TypeFor[apiclient.MyPackageSummary](),
		},
		{
			"MyPackagesResponse <-> apiclient.MyPackagesResponse",
			reflect.TypeFor[MyPackagesResponse](), reflect.TypeFor[apiclient.MyPackagesResponse](),
		},
		{
			"PublishResponse <-> apiclient.PublishResponse",
			reflect.TypeFor[PublishResponse](), reflect.TypeFor[apiclient.PublishResponse](),
		},
		{
			"PromoteResponse <-> apiclient.PromoteResponse",
			reflect.TypeFor[PromoteResponse](), reflect.TypeFor[apiclient.PromoteResponse](),
		},
		{
			"CheckNameAvailableResponse <-> apiclient.CheckNameAvailableResponse",
			reflect.TypeFor[CheckNameAvailableResponse](), reflect.TypeFor[apiclient.CheckNameAvailableResponse](),
		},
		{
			"UnpublishResponse <-> apiclient.UnpublishResponse",
			reflect.TypeFor[UnpublishResponse](), reflect.TypeFor[apiclient.UnpublishResponse](),
		},
		{
			"SearchResult <-> apiclient.SearchResult",
			reflect.TypeFor[SearchResult](), reflect.TypeFor[apiclient.SearchResult](),
		},
		{
			"SearchResponse <-> apiclient.SearchResponse",
			reflect.TypeFor[SearchResponse](), reflect.TypeFor[apiclient.SearchResponse](),
		},
		{
			"AuthConfig <-> apiclient.AuthConfig",
			reflect.TypeFor[AuthConfig](), reflect.TypeFor[apiclient.AuthConfig](),
		},
		{
			"Profile <-> apiclient.Profile",
			reflect.TypeFor[Profile](), reflect.TypeFor[apiclient.Profile](),
		},

		// Admin, Namespaces, Jobs, Organizations & Credentials HTTP APIs
		{
			"AdminJobsStats <-> apiclient.AdminJobsStats",
			reflect.TypeFor[AdminJobsStats](), reflect.TypeFor[apiclient.AdminJobsStats](),
		},
		{
			"AdminDashboardPackage <-> apiclient.AdminDashboardPackage",
			reflect.TypeFor[AdminDashboardPackage](), reflect.TypeFor[apiclient.AdminDashboardPackage](),
		},
		{
			"AdminPendingPR <-> apiclient.AdminPendingPR",
			reflect.TypeFor[AdminPendingPR](), reflect.TypeFor[apiclient.AdminPendingPR](),
		},
		{
			"AdminStatusResponse <-> apiclient.AdminStatusResponse",
			reflect.TypeFor[AdminStatusResponse](), reflect.TypeFor[apiclient.AdminStatusResponse](),
		},
		{
			"AdminStagingPackage <-> apiclient.AdminStagingPackage",
			reflect.TypeFor[AdminStagingPackage](), reflect.TypeFor[apiclient.AdminStagingPackage](),
		},
		{
			"AdminStagingResponse <-> apiclient.AdminStagingResponse",
			reflect.TypeFor[AdminStagingResponse](), reflect.TypeFor[apiclient.AdminStagingResponse](),
		},
		{
			"AdminReleaseResponse <-> apiclient.AdminReleaseResponse",
			reflect.TypeFor[AdminReleaseResponse](), reflect.TypeFor[apiclient.AdminReleaseResponse](),
		},
		{
			"AdminRevokeRequest <-> apiclient.AdminRevokeRequest",
			reflect.TypeFor[AdminRevokeRequest](), reflect.TypeFor[apiclient.AdminRevokeRequest](),
		},
		{
			"AdminRevokeResponse <-> apiclient.AdminRevokeResponse",
			reflect.TypeFor[AdminRevokeResponse](), reflect.TypeFor[apiclient.AdminRevokeResponse](),
		},
		{
			"AdminMockWebhookRequest <-> apiclient.AdminMockWebhookRequest",
			reflect.TypeFor[AdminMockWebhookRequest](), reflect.TypeFor[apiclient.AdminMockWebhookRequest](),
		},
		{
			"AdminMockWebhookResponse <-> apiclient.AdminMockWebhookResponse",
			reflect.TypeFor[AdminMockWebhookResponse](), reflect.TypeFor[apiclient.AdminMockWebhookResponse](),
		},
		{
			"Namespace <-> apiclient.Namespace",
			reflect.TypeFor[Namespace](), reflect.TypeFor[apiclient.Namespace](),
		},
		{
			"NamespaceMembership <-> apiclient.NamespaceMembership",
			reflect.TypeFor[NamespaceMembership](), reflect.TypeFor[apiclient.NamespaceMembership](),
		},
		{
			"PublishJob <-> apiclient.PublishJob",
			reflect.TypeFor[PublishJob](), reflect.TypeFor[apiclient.PublishJob](),
		},
		{
			"Organization <-> apiclient.Organization",
			reflect.TypeFor[Organization](), reflect.TypeFor[apiclient.Organization](),
		},
		{
			"Organizations <-> apiclient.Organizations",
			reflect.TypeFor[Organizations](), reflect.TypeFor[apiclient.Organizations](),
		},
		{
			"Invitation <-> apiclient.Invitation",
			reflect.TypeFor[Invitation](), reflect.TypeFor[apiclient.Invitation](),
		},
		{
			"InvitationAcceptance <-> apiclient.InvitationAcceptance",
			reflect.TypeFor[InvitationAcceptance](), reflect.TypeFor[apiclient.InvitationAcceptance](),
		},
		{
			"Credential <-> apiclient.Credential",
			reflect.TypeFor[Credential](), reflect.TypeFor[apiclient.Credential](),
		},
		{
			"CredentialRequest <-> apiclient.CredentialRequest",
			reflect.TypeFor[CredentialRequest](), reflect.TypeFor[apiclient.CredentialRequest](),
		},
		{
			"CreatedCredential <-> apiclient.CreatedCredential",
			reflect.TypeFor[CreatedCredential](), reflect.TypeFor[apiclient.CreatedCredential](),
		},

		// registry.json
		{
			"RegistryEcosystem <-> registry.EcosystemVersions",
			reflect.TypeFor[RegistryEcosystem](), reflect.TypeFor[registry.EcosystemVersions](),
		},
		{
			"RegistryIndex <-> registry.Index",
			reflect.TypeFor[RegistryIndex](), reflect.TypeFor[registry.Index](),
		},
		{
			"RegistryChipSources <-> registry.ChipSources",
			reflect.TypeFor[RegistryChipSources](), reflect.TypeFor[registry.ChipSources](),
		},
		{
			"RegistryChipCrypto <-> registry.ChipCrypto",
			reflect.TypeFor[RegistryChipCrypto](), reflect.TypeFor[registry.ChipCrypto](),
		},
		{
			"RegistryRecoveryCrypto <-> registry.RecoveryCrypto",
			reflect.TypeFor[RegistryRecoveryCrypto](), reflect.TypeFor[registry.RecoveryCrypto](),
		},
		{
			"RegistryChipRecovery <-> registry.ChipRecovery",
			reflect.TypeFor[RegistryChipRecovery](), reflect.TypeFor[registry.ChipRecovery](),
		},
		{
			"RegistryChip <-> registry.ChipInfo",
			reflect.TypeFor[RegistryChip](), reflect.TypeFor[registry.ChipInfo](),
		},
		{
			"RegistryCryptoFootprint <-> registry.CryptoFootprint",
			reflect.TypeFor[RegistryCryptoFootprint](), reflect.TypeFor[registry.CryptoFootprint](),
		},
		{
			"RegistryCrypto <-> registry.CryptoInfo",
			reflect.TypeFor[RegistryCrypto](), reflect.TypeFor[registry.CryptoInfo](),
		},
		{
			"RegistryDriver <-> registry.DriverInfo",
			reflect.TypeFor[RegistryDriver](), reflect.TypeFor[registry.DriverInfo](),
		},
		{
			"RegistryArch <-> registry.ArchInfo",
			reflect.TypeFor[RegistryArch](), reflect.TypeFor[registry.ArchInfo](),
		},
		{
			"RegistryIntegration <-> registry.IntegrationInfo",
			reflect.TypeFor[RegistryIntegration](), reflect.TypeFor[registry.IntegrationInfo](),
		},
		{
			"RegistrySoC <-> registry.SoCInfo",
			reflect.TypeFor[RegistrySoC](), reflect.TypeFor[registry.SoCInfo](),
		},
		{
			"RegistryPort <-> registry.PortInfo",
			reflect.TypeFor[RegistryPort](), reflect.TypeFor[registry.PortInfo](),
		},
		{
			"RegistryToolchain <-> registry.ToolchainInfo",
			reflect.TypeFor[RegistryToolchain](), reflect.TypeFor[registry.ToolchainInfo](),
		},

		// Compatibility Matrix
		{
			"MatrixDependencies <-> registry.MatrixDependencies",
			reflect.TypeFor[MatrixDependencies](), reflect.TypeFor[registry.MatrixDependencies](),
		},
		{
			"MatrixVerifiedCli <-> registry.MatrixVerifiedCli",
			reflect.TypeFor[MatrixVerifiedCli](), reflect.TypeFor[registry.MatrixVerifiedCli](),
		},
		{
			"MatrixVersion <-> registry.MatrixVersion",
			reflect.TypeFor[MatrixVersion](), reflect.TypeFor[registry.MatrixVersion](),
		},
		{
			"MatrixChip <-> registry.MatrixChip",
			reflect.TypeFor[MatrixChip](), reflect.TypeFor[registry.MatrixChip](),
		},

		// Lockfile v2 (toob.lock)
		{
			"LockfileRegistry <-> lockfile.RegistryLock",
			reflect.TypeFor[LockfileRegistry](), reflect.TypeFor[lockfile.RegistryLock](),
		},
		{
			"LockfileEnvironment <-> lockfile.EnvironmentLock",
			reflect.TypeFor[LockfileEnvironment](), reflect.TypeFor[lockfile.EnvironmentLock](),
		},
		{
			"LockfilePackage <-> lockfile.LockedPackage",
			reflect.TypeFor[LockfilePackage](), reflect.TypeFor[lockfile.LockedPackage](),
		},
		{
			"LockfileChipEntry <-> lockfile.ChipEntry",
			reflect.TypeFor[LockfileChipEntry](), reflect.TypeFor[lockfile.ChipEntry](),
		},
		{
			"LockfileToolchainEntry <-> lockfile.ToolchainEntry",
			reflect.TypeFor[LockfileToolchainEntry](), reflect.TypeFor[lockfile.ToolchainEntry](),
		},
		{
			"LockfileTarget <-> lockfile.TargetLock",
			reflect.TypeFor[LockfileTarget](), reflect.TypeFor[lockfile.TargetLock](),
		},
		{
			"LockfileV2 <-> lockfile.Lockfile",
			reflect.TypeFor[LockfileV2](), reflect.TypeFor[lockfile.Lockfile](),
		},
	}
}

// TestPortFieldCounts verifies that port contract types have the exact same
// number of fields as their implementation counterparts, plus subset alignment
// between RegistryToolchain and toolchain.RegistryToolchain.
func TestPortFieldCounts(t *testing.T) {
	for _, tt := range portParityPairs() {
		t.Run(tt.name, func(t *testing.T) {
			if tt.portType.NumField() != tt.realType.NumField() {
				t.Errorf("\n[CONTRACT DRIFT] %s:\n  ports.go has %d fields, implementation has %d fields.",
					tt.name, tt.portType.NumField(), tt.realType.NumField())
				reportFieldDiff(t, tt.name, tt.portType, tt.realType)
			}
		})
	}

	t.Run("RegistryToolchain subset <-> toolchain.RegistryToolchain", func(t *testing.T) {
		portTC := reflect.TypeFor[RegistryToolchain]()
		mgrTC := reflect.TypeFor[toolchain.RegistryToolchain]()
		for field := range mgrTC.Fields() {
			pf, ok := portTC.FieldByName(field.Name)
			if !ok {
				t.Errorf("toolchain.RegistryToolchain.%s is missing from ports.RegistryToolchain", field.Name)
				continue
			}
			if pf.Type != field.Type {
				t.Errorf("toolchain.RegistryToolchain.%s type %s != ports.RegistryToolchain.%s type %s",
					field.Name, field.Type, pf.Name, pf.Type)
			}
		}
	})
}

// TestPortFieldTypes recursively checks that every field, pointer, slice, map,
// and inline nested struct type matches between ports.go and implementation structs.
func TestPortFieldTypes(t *testing.T) {
	pairs := portParityPairs()
	pairLookup := make(map[reflect.Type]reflect.Type, len(pairs))
	for _, p := range pairs {
		pairLookup[p.portType] = p.realType
	}

	for _, tt := range pairs {
		t.Run(tt.name, func(t *testing.T) {
			visited := make(map[[2]reflect.Type]bool)
			assertRecursiveTypeParity(t, tt.name, tt.portType, tt.realType, pairLookup, visited)
		})
	}
}

func assertRecursiveTypeParity(
	t *testing.T,
	ctx string,
	portType reflect.Type,
	realType reflect.Type,
	pairLookup map[reflect.Type]reflect.Type,
	visited map[[2]reflect.Type]bool,
) {
	t.Helper()
	key := [2]reflect.Type{portType, realType}
	if visited[key] {
		return
	}
	visited[key] = true

	if portType.Kind() != realType.Kind() {
		t.Errorf("[BREAKING CHANGE] %s: kind mismatch: ports=%s (%s), impl=%s (%s)",
			ctx, portType, portType.Kind(), realType, realType.Kind())
		return
	}

	switch portType.Kind() {
	case reflect.Pointer, reflect.Slice, reflect.Array:
		if portType.Kind() == reflect.Array && portType.Len() != realType.Len() {
			t.Errorf("[BREAKING CHANGE] %s: array length %d != %d", ctx, portType.Len(), realType.Len())
			return
		}
		assertRecursiveTypeParity(t, ctx, portType.Elem(), realType.Elem(), pairLookup, visited)
	case reflect.Map:
		assertRecursiveTypeParity(t, ctx+"[key]", portType.Key(), realType.Key(), pairLookup, visited)
		assertRecursiveTypeParity(t, ctx+"[val]", portType.Elem(), realType.Elem(), pairLookup, visited)
	case reflect.Struct:
		// If named struct in ports, ensure it matches expected concrete partner when mapped.
		if expected, ok := pairLookup[portType]; ok && expected != realType {
			t.Errorf("[BREAKING CHANGE] %s: port struct %s mapped to %s, expected %s",
				ctx, portType, realType, expected)
			return
		}
		if portType.PkgPath() == "" && realType.PkgPath() == "" {
			// Anonymous inline struct (e.g. Profile.Orgs elements): compare all fields deeply.
			if portType.NumField() != realType.NumField() {
				t.Errorf("[CONTRACT DRIFT] %s: inline struct field count %d != %d",
					ctx, portType.NumField(), realType.NumField())
				reportFieldDiff(t, ctx, portType, realType)
				return
			}
		} else if _, ok := pairLookup[portType]; !ok && portType != realType {
			// External value struct like time.Time must be identical type.
			t.Errorf("[BREAKING CHANGE] %s: external struct type mismatch: ports=%s, impl=%s",
				ctx, portType, realType)
			return
		}

		for pf := range portType.Fields() {
			rf, found := realType.FieldByName(pf.Name)
			if !found {
				t.Errorf("[CONTRACT DRIFT] %s.%s: missing in implementation %s", ctx, pf.Name, realType)
				continue
			}
			assertRecursiveTypeParity(t, ctx+"."+pf.Name, pf.Type, rf.Type, pairLookup, visited)
		}
		for rf := range realType.Fields() {
			if _, found := portType.FieldByName(rf.Name); !found {
				t.Errorf("[CONTRACT DRIFT] %s.%s: missing in ports.go", ctx, rf.Name)
			}
		}
	default:
		if portType != realType {
			t.Errorf("[BREAKING CHANGE] %s: type mismatch: ports=%s, impl=%s", ctx, portType, realType)
		}
	}
}

// TestAllExportedStructsCovered ensures no exported boundary struct in ports.go
// can be added without a reflection parity test in portParityPairs (or explicit
// membership in the container IPC list).
func TestAllExportedStructsCovered(t *testing.T) {
	covered := map[string]bool{
		"DockerBuildInput":  true,
		"DockerBuildOutput": true,
	}
	for _, p := range portParityPairs() {
		covered[p.portType.Name()] = true
	}

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
			if _, isStruct := typeSpec.Type.(*ast.StructType); isStruct {
				if !covered[typeSpec.Name.Name] {
					t.Errorf("exported struct %q in ports.go is not registered in portParityPairs()", typeSpec.Name.Name)
				}
			}
		}
	}
}

// TestPortsGoASTValidation parses ports.go using Go AST and verifies every
// exported struct field (including multi-identifier fields and inline structs)
// has valid `port`, `json`, and (for Lockfile*) `toml` annotations.
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

			requireTOML := strings.HasPrefix(typeSpec.Name.Name, "Lockfile")
			validateStructFields(t, fset, typeSpec.Name.Name, structType, requireTOML)
		}
	}
}

func validateStructFields(t *testing.T, fset *token.FileSet, structName string, st *ast.StructType, requireTOML bool) {
	t.Helper()

	for _, field := range st.Fields.List {
		if len(field.Names) == 0 {
			continue
		}
		for _, ident := range field.Names {
			if !ident.IsExported() {
				continue
			}
			fieldName := ident.Name
			pos := fset.Position(field.Pos())

			if field.Tag == nil {
				t.Errorf("\n[MISSING TAG] %s.%s (at %s): exported field has no struct tag",
					structName, fieldName, pos)
				continue
			}

			rawTag := field.Tag.Value[1 : len(field.Tag.Value)-1]
			tag := reflect.StructTag(rawTag)

			portVal, portOK := tag.Lookup("port")
			if !portOK {
				t.Errorf("[MISSING PORT TAG] %s.%s (at %s): missing `port` tag", structName, fieldName, pos)
			} else if portVal != "required" && portVal != "optional" {
				t.Errorf("[INVALID PORT TAG] %s.%s (at %s): port tag %q must be \"required\" or \"optional\"",
					structName, fieldName, pos, portVal)
			}

			validateWireTag(t, structName, fieldName, pos.String(), tag, "json")
			if requireTOML {
				validateWireTag(t, structName, fieldName, pos.String(), tag, "toml")
			}

			validateInlineStructs(t, fset, structName+"."+fieldName, field.Type, requireTOML)
		}
	}
}

func validateWireTag(t *testing.T, structName, fieldName, pos string, tag reflect.StructTag, tagKey string) {
	t.Helper()
	val, ok := tag.Lookup(tagKey)
	if !ok || val == "" {
		t.Errorf("[MISSING %s TAG] %s.%s (at %s): missing serialization key", strings.ToUpper(tagKey), structName, fieldName, pos)
		return
	}
	if val == "-" {
		t.Errorf("[EXCLUDED %s TAG] %s.%s (at %s): contract field cannot be excluded", strings.ToUpper(tagKey), structName, fieldName, pos)
		return
	}
	wireKey, _, _ := strings.Cut(val, ",")
	if wireKey != strings.ToLower(wireKey) {
		t.Errorf("[NON-STANDARD %s KEY] %s.%s (at %s): key %q must be lowercase snake_case",
			strings.ToUpper(tagKey), structName, fieldName, pos, wireKey)
	}
}

func validateInlineStructs(t *testing.T, fset *token.FileSet, prefix string, expr ast.Expr, requireTOML bool) {
	t.Helper()
	switch node := expr.(type) {
	case *ast.StructType:
		validateStructFields(t, fset, prefix, node, requireTOML)
	case *ast.StarExpr:
		validateInlineStructs(t, fset, prefix, node.X, requireTOML)
	case *ast.ArrayType:
		validateInlineStructs(t, fset, prefix, node.Elt, requireTOML)
	case *ast.MapType:
		validateInlineStructs(t, fset, prefix+".key", node.Key, requireTOML)
		validateInlineStructs(t, fset, prefix+".val", node.Value, requireTOML)
	}
}

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
			t.Errorf("[CONTRACT DRIFT] %s: field %q exists in implementation but not in ports.go", testName, name)
		}
	}
	for name := range portMap {
		if !realMap[name] {
			field, _ := portType.FieldByName(name)
			tag := field.Tag.Get("port")
			if tag == "optional" {
				t.Errorf("[BREAKING CHANGE] %s: optional field %q was removed from implementation", testName, name)
			} else {
				t.Errorf("[BREAKING CHANGE] %s: required field %q was removed from implementation", testName, name)
			}
		}
	}
}
