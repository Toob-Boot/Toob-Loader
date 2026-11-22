package conformance

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/toob-boot/toob/internal/manifest"
)

// AuditOptions configures optional overrides for HAL conformance auditing.
type AuditOptions struct {
	// ContractPath optionally points directly to hal_contract.json.
	// When empty, AuditPackageWithOptions searches upward in the monorepo/SDK
	// and falls back to the embedded hal_contract.json SSoT copy.
	ContractPath string
}

// ConformanceReport represents the outcome of a HAL conformance audit.
type ConformanceReport struct {
	Timestamp       time.Time             `json:"timestamp"`
	PackageName     string                `json:"package_name"`
	PackagePath     string                `json:"package_path"`
	Trait           string                `json:"trait"`
	AbiVersion      string                `json:"abi_version"`
	Passed          bool                  `json:"passed"`
	Checks          []ConformanceCheck    `json:"checks"`
	MockEquivalence *MockEquivalenceCheck `json:"mock_equivalence,omitempty"`
}

// ConformanceCheck represents an individual trait contract check.
type ConformanceCheck struct {
	Name    string `json:"name"`
	Passed  bool   `json:"passed"`
	Details string `json:"details"`
}

// MockEquivalenceCheck captures Mock vs. Real implementation parity.
type MockEquivalenceCheck struct {
	Passed      bool     `json:"passed"`
	Divergences []string `json:"divergences,omitempty"`
}

type referenceBuildContext struct {
	Chip               string `json:"chip,omitempty"`
	CoreSDKVersion     string `json:"core_sdk_version,omitempty"`
	ToolchainVersion   string `json:"toolchain_version,omitempty"`
	TargetArchitecture string `json:"target_architecture,omitempty"`
}

// stringOrSlice decodes either a JSON string ("esp32c6") or []string (["esp32c6", "esp32h2"]).
type stringOrSlice []string

func (s *stringOrSlice) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		*s = nil
		return nil
	}
	if trimmed[0] == '"' {
		var single string
		if err := json.Unmarshal(trimmed, &single); err != nil {
			return err
		}
		if strings.TrimSpace(single) == "" {
			return errors.New("chip_binding string must not be empty")
		}
		*s = stringOrSlice{single}
		return nil
	}
	if trimmed[0] == '[' {
		var list []string
		dec := json.NewDecoder(bytes.NewReader(trimmed))
		if err := dec.Decode(&list); err != nil {
			return err
		}
		if _, err := dec.Token(); !errors.Is(err, io.EOF) {
			return errors.New("unexpected trailing data in chip_binding array")
		}
		for _, item := range list {
			if strings.TrimSpace(item) == "" {
				return errors.New("chip_binding array entry must not be empty")
			}
		}
		*s = stringOrSlice(list)
		return nil
	}
	return fmt.Errorf("chip_binding must be a JSON string or array of strings, got %s", string(trimmed))
}

// compilerFlagsSpec decodes either a flat []string (e.g. ["-Os"]) or a structured
// flag set ({"c_flags": [...], "asm_flags": [...], "ld_flags": [...]}).
type compilerFlagsSpec struct {
	CFlags   []string `json:"c_flags,omitempty"`
	AsmFlags []string `json:"asm_flags,omitempty"`
	LdFlags  []string `json:"ld_flags,omitempty"`
}

func (c *compilerFlagsSpec) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		*c = compilerFlagsSpec{}
		return nil
	}
	if trimmed[0] == '[' {
		var flat []string
		dec := json.NewDecoder(bytes.NewReader(trimmed))
		if err := dec.Decode(&flat); err != nil {
			return err
		}
		if _, err := dec.Token(); !errors.Is(err, io.EOF) {
			return errors.New("unexpected trailing data in compiler_flags array")
		}
		*c = compilerFlagsSpec{CFlags: flat}
		return nil
	}
	if trimmed[0] == '{' {
		type objWire struct {
			CFlags   []string `json:"c_flags,omitempty"`
			AsmFlags []string `json:"asm_flags,omitempty"`
			LdFlags  []string `json:"ld_flags,omitempty"`
		}
		dec := json.NewDecoder(bytes.NewReader(trimmed))
		dec.DisallowUnknownFields()
		var w objWire
		if err := dec.Decode(&w); err != nil {
			return err
		}
		if _, err := dec.Token(); !errors.Is(err, io.EOF) {
			return errors.New("unexpected trailing data in compiler_flags object")
		}
		*c = compilerFlagsSpec(w)
		return nil
	}
	return fmt.Errorf("compiler_flags must be a JSON array or object, got %s", string(trimmed))
}

type commonManifestMeta struct {
	Name                  string                 `json:"name,omitempty"`
	Author                string                 `json:"author,omitempty"`
	Tier                  string                 `json:"tier,omitempty"`
	Version               string                 `json:"version,omitempty"`
	Description           string                 `json:"description,omitempty"`
	License               string                 `json:"license,omitempty"`
	Repository            string                 `json:"repository,omitempty"`
	Keywords              []string               `json:"keywords,omitempty"`
	Dependencies          map[string]string      `json:"dependencies,omitempty"`
	MinCoreSDK            string                 `json:"min_core_sdk,omitempty"`
	ReferenceBuildContext *referenceBuildContext `json:"reference_build_context,omitempty"`
	CompilerFlags         *compilerFlagsSpec     `json:"compiler_flags,omitempty"`
	Cflags                []string               `json:"cflags,omitempty"`
	Includes              []string               `json:"includes,omitempty"`
	ChipBinding           stringOrSlice          `json:"chip_binding,omitempty"`
}

type driverManifestSchema struct {
	commonManifestMeta

	Trait          string            `json:"trait,omitempty"`
	Category       string            `json:"category,omitempty"`
	AbiVersion     string            `json:"abi_version,omitempty"`
	ExecModel      string            `json:"exec_model,omitempty"`
	IsHardwareTRNG bool              `json:"is_hardware_trng,omitempty"`
	Headers        []string          `json:"headers,omitempty"`
	Sources        []string          `json:"sources,omitempty"`
	MockSources    []string          `json:"mock_sources,omitempty"`
	Symbols        map[string]string `json:"symbols,omitempty"`
}

type chipManifestSchema struct {
	commonManifestMeta

	Arch             string                     `json:"arch,omitempty"`
	CompilerPrefix   string                     `json:"compiler_prefix,omitempty"`
	MinCompiler      string                     `json:"min_compiler,omitempty"`
	Stage0ExecMode   string                     `json:"stage0_exec_mode,omitempty"`
	EntrySymbol      string                     `json:"entry_symbol,omitempty"`
	SlotCapabilities *manifest.SlotCapabilities `json:"slot_capabilities,omitempty"`
	HalBindings      map[string]string          `json:"hal_bindings,omitempty"`
	Sources          *manifest.ChipSources      `json:"sources,omitempty"`
	Crypto           *manifest.ChipCrypto       `json:"crypto,omitempty"`
	Recovery         *manifest.ChipRecovery     `json:"recovery,omitempty"`
}

type archManifestSchema struct {
	commonManifestMeta

	Headers        []string          `json:"headers,omitempty"`
	Sources        []string          `json:"sources,omitempty"`
	Symbols        map[string]string `json:"symbols,omitempty"`
	RequiredMacros []string          `json:"required_macros,omitempty"`
}

type cryptoManifestSchema struct {
	commonManifestMeta

	AbiVersion        string                    `json:"abi_version,omitempty"`
	Category          []string                  `json:"category,omitempty"`
	Wrapper           string                    `json:"wrapper,omitempty"`
	UpstreamSources   []string                  `json:"upstream_sources,omitempty"`
	Headers           []string                  `json:"headers,omitempty"`
	Symbols           map[string]string         `json:"symbols,omitempty"`
	HasHwAcceleration bool                      `json:"has_hw_acceleration,omitempty"`
	Footprint         *manifest.CryptoFootprint `json:"footprint,omitempty"`
}

type socManifestSchema struct {
	commonManifestMeta

	Chips        []string `json:"chips,omitempty"`
	Headers      []string `json:"headers,omitempty"`
	Sources      []string `json:"sources,omitempty"`
	BootromImage string   `json:"bootrom_image,omitempty"`
}

type integrationManifestSchema struct {
	commonManifestMeta

	Files []string `json:"files,omitempty"`
}

type toolchainManifestSchema struct {
	commonManifestMeta

	UpstreamVersion string            `json:"upstream_version,omitempty"`
	CompilerPrefix  string            `json:"compiler_prefix,omitempty"`
	CompilerBinary  string            `json:"compiler_binary,omitempty"`
	ToolchainFile   string            `json:"toolchain_file,omitempty"`
	URLs            map[string]string `json:"urls,omitempty"`
	SHA256          map[string]string `json:"sha256,omitempty"`
}

type portManifestSchema struct {
	commonManifestMeta

	Chip        string            `json:"chip,omitempty"`
	Arch        string            `json:"arch,omitempty"`
	Board       string            `json:"board,omitempty"`
	Framework   string            `json:"framework,omitempty"`
	Headers     []string          `json:"headers,omitempty"`
	Sources     []string          `json:"sources,omitempty"`
	MockSources []string          `json:"mock_sources,omitempty"`
	Symbols     map[string]string `json:"symbols,omitempty"`
}
