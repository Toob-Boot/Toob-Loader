// Package registry manages the local cache and tarball operations for the Toob Registry.
//
// BOUNDARY TYPES: Struct types in this file are mirrored in internal/ports/ports.go.
package registry

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// ChipSources maps canonical source/header/linker roles inside a chip package.
type ChipSources struct {
	Startup  string   `json:"startup"`
	Platform string   `json:"platform"`
	Config   string   `json:"config"`
	Linker   string   `json:"linker"`
	Hardware string   `json:"hardware"`
	Drivers  []string `json:"drivers,omitempty"`
	Extra    []string `json:"extra,omitempty"`
}

// ChipInfo holds metadata for a single chip package in registry.json.
type ChipInfo struct {
	Name             string            `json:"name"`
	Author           string            `json:"author,omitempty"`
	Tier             string            `json:"tier,omitempty"`
	Arch             string            `json:"arch"`
	CompilerPrefix   string            `json:"compiler_prefix"`
	Path             string            `json:"path"`
	Version          string            `json:"version"`
	SHA256           string            `json:"sha256,omitempty"`
	TarballSHA       string            `json:"tarball_sha,omitempty"`
	CliCompatibility string            `json:"cli_compatibility"`
	Description      string            `json:"description,omitempty"`
	Verified         bool              `json:"verified"`
	HalBindings      map[string]string `json:"hal_bindings,omitempty"`
	Sources          *ChipSources      `json:"sources,omitempty"`
	Includes         []string          `json:"includes,omitempty"`
	Crypto           *ChipCrypto       `json:"crypto,omitempty"`
	Recovery         *ChipRecovery     `json:"recovery,omitempty"`
}

// ChipCrypto defines the default crypto package assignments for a chip.
type ChipCrypto struct {
	Backend string `json:"backend,omitempty"`
	Hash    string `json:"hash,omitempty"`
	Pqc     string `json:"pqc,omitempty"`
}

// ChipRecovery defines default recovery driver and crypto bindings for a chip.
type ChipRecovery struct {
	Console  string          `json:"console"`
	Flash    string          `json:"flash"`
	WDT      string          `json:"wdt,omitempty"`
	Clock    string          `json:"clock,omitempty"`
	RTC      string          `json:"rtc,omitempty"`
	Crypto   *RecoveryCrypto `json:"crypto,omitempty"`
	Sources  []string        `json:"sources,omitempty"`
	Includes []string        `json:"includes,omitempty"`
}

// RecoveryCrypto defines default recovery crypto bindings for a chip.
type RecoveryCrypto struct {
	Backend string `json:"backend,omitempty"`
	Hash    string `json:"hash,omitempty"`
}

// ArchInfo holds metadata for an architecture package in registry.json.
type ArchInfo struct {
	Name        string `json:"name"`
	Author      string `json:"author,omitempty"`
	Tier        string `json:"tier,omitempty"`
	Path        string `json:"path"`
	Version     string `json:"version"`
	SHA256      string `json:"sha256,omitempty"`
	TarballSHA  string `json:"tarball_sha,omitempty"`
	Description string `json:"description"`
}

// ToolchainInfo holds metadata and per-platform download assets for a toolchain in registry.json.
type ToolchainInfo struct {
	Path            string            `json:"path"`
	Version         string            `json:"version"`
	UpstreamVersion string            `json:"upstream_version"`
	TarballSHA      string            `json:"tarball_sha,omitempty"`
	CompilerBinary  string            `json:"compiler_binary,omitempty"`
	URLs            map[string]string `json:"urls,omitempty"`
	Sha256          map[string]string `json:"sha256,omitempty"`
}

// IntegrationInfo holds metadata for an RTOS/framework integration package in registry.json.
type IntegrationInfo struct {
	Name        string `json:"name"`
	Author      string `json:"author,omitempty"`
	Tier        string `json:"tier,omitempty"`
	Path        string `json:"path"`
	Version     string `json:"version"`
	SHA256      string `json:"sha256,omitempty"`
	TarballSHA  string `json:"tarball_sha,omitempty"`
	Description string `json:"description"`
}

// PortInfo holds metadata for a board/port package in registry.json.
type PortInfo struct {
	Name        string `json:"name"`
	Author      string `json:"author,omitempty"`
	Tier        string `json:"tier,omitempty"`
	Path        string `json:"path"`
	Version     string `json:"version"`
	SHA256      string `json:"sha256,omitempty"`
	TarballSHA  string `json:"tarball_sha,omitempty"`
	Description string `json:"description,omitempty"`
}

// CryptoFootprint estimates Flash and RAM usage for a crypto package.
type CryptoFootprint struct {
	FlashBytes uint32 `json:"flash_bytes,omitempty"`
	//nolint:staticcheck // ST1003: kept for ports/assertions.go compatibility until Stage-3B ports cleanup.
	RamBytes uint32 `json:"ram_bytes,omitempty"`
}

// UnmarshalJSON decodes both canonical (flash_bytes/ram_bytes) and legacy
// (flash_estimate_bytes/ram_estimate_bytes) crypto footprint fields strictly.
func (f *CryptoFootprint) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	type wire struct {
		FlashBytes         *uint32 `json:"flash_bytes"`
		RAMBytes           *uint32 `json:"ram_bytes"`
		FlashEstimateBytes *uint32 `json:"flash_estimate_bytes"`
		RAMEstimateBytes   *uint32 `json:"ram_estimate_bytes"`
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.DisallowUnknownFields()
	var w wire
	if err := dec.Decode(&w); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("unexpected trailing data in crypto footprint")
	}
	if w.FlashBytes != nil && w.FlashEstimateBytes != nil && *w.FlashBytes != *w.FlashEstimateBytes {
		return fmt.Errorf("conflicting flash_bytes (%d) and flash_estimate_bytes (%d)", *w.FlashBytes, *w.FlashEstimateBytes)
	}
	if w.RAMBytes != nil && w.RAMEstimateBytes != nil && *w.RAMBytes != *w.RAMEstimateBytes {
		return fmt.Errorf("conflicting ram_bytes (%d) and ram_estimate_bytes (%d)", *w.RAMBytes, *w.RAMEstimateBytes)
	}
	var out CryptoFootprint
	if w.FlashBytes != nil {
		out.FlashBytes = *w.FlashBytes
	} else if w.FlashEstimateBytes != nil {
		out.FlashBytes = *w.FlashEstimateBytes
	}
	if w.RAMBytes != nil {
		out.RamBytes = *w.RAMBytes
	} else if w.RAMEstimateBytes != nil {
		out.RamBytes = *w.RAMEstimateBytes
	}
	*f = out
	return nil
}

// CryptoInfo holds metadata for a crypto package in registry.json.
type CryptoInfo struct {
	Name              string            `json:"name"`
	Author            string            `json:"author,omitempty"`
	Tier              string            `json:"tier,omitempty"`
	Path              string            `json:"path"`
	Version           string            `json:"version"`
	SHA256            string            `json:"sha256,omitempty"`
	TarballSHA        string            `json:"tarball_sha,omitempty"`
	Description       string            `json:"description,omitempty"`
	AbiVersion        string            `json:"abi_version,omitempty"`
	Category          []string          `json:"category"`
	License           string            `json:"license,omitempty"`
	MinCoreSdk        string            `json:"min_core_sdk,omitempty"`
	Wrapper           *string           `json:"wrapper,omitempty"`
	UpstreamSources   []string          `json:"upstream_sources,omitempty"`
	Headers           []string          `json:"headers,omitempty"`
	Symbols           map[string]string `json:"symbols,omitempty"`
	Cflags            []string          `json:"cflags,omitempty"`
	Includes          []string          `json:"includes,omitempty"`
	ChipBinding       []string          `json:"chip_binding,omitempty"`
	HasHwAcceleration bool              `json:"has_hw_acceleration,omitempty"`
	Footprint         *CryptoFootprint  `json:"footprint,omitempty"`
}

// DriverInfo holds metadata for a HAL driver package in registry.json.
type DriverInfo struct {
	Name        string `json:"name"`
	Author      string `json:"author,omitempty"`
	Tier        string `json:"tier,omitempty"`
	Trait       string `json:"trait,omitempty"`
	Path        string `json:"path"`
	Version     string `json:"version"`
	SHA256      string `json:"sha256,omitempty"`
	TarballSHA  string `json:"tarball_sha,omitempty"`
	Description string `json:"description,omitempty"`
	Category    string `json:"category,omitempty"`
}

// EcosystemVersions lists available versions and digests of ecosystem releases.
type EcosystemVersions struct {
	CLI           []string          `json:"cli"`
	CoreSDK       []string          `json:"core_sdk"`
	Compiler      []string          `json:"compiler"`
	CoreSDKSha256 map[string]string `json:"core_sdk_sha256,omitempty"`
}

// SoCInfo holds metadata for a shared SoC package in registry.json.
type SoCInfo struct {
	Name        string   `json:"name"`
	Author      string   `json:"author,omitempty"`
	Tier        string   `json:"tier,omitempty"`
	Path        string   `json:"path"`
	Version     string   `json:"version"`
	SHA256      string   `json:"sha256,omitempty"`
	TarballSHA  string   `json:"tarball_sha,omitempty"`
	Description string   `json:"description,omitempty"`
	Chips       []string `json:"chips,omitempty"`
}

// Index is the parsed content of registry.json across all 8 package categories.
type Index struct {
	FormatVersion   int                        `json:"format_version"`
	RegistryVersion string                     `json:"registry_version"`
	Ecosystem       *EcosystemVersions         `json:"ecosystem,omitempty"`
	Chips           map[string]ChipInfo        `json:"chips"`
	Archs           map[string]ArchInfo        `json:"archs"`
	Toolchains      map[string]ToolchainInfo   `json:"toolchains"`
	Integrations    map[string]IntegrationInfo `json:"integrations"`
	Drivers         map[string]DriverInfo      `json:"drivers"`
	Crypto          map[string]CryptoInfo      `json:"crypto"`
	SoCs            map[string]SoCInfo         `json:"socs,omitempty"`
	Ports           map[string]PortInfo        `json:"ports,omitempty"`
}

// MatrixDependencies lists the environment components tested in a compatibility matrix entry.
type MatrixDependencies struct {
	Toolchain string `json:"toolchain"`
	Arch      string `json:"arch"`
	Compiler  string `json:"compiler_container,omitempty"`
	CoreSDK   string `json:"core_sdk,omitempty"`
}

// MatrixVerifiedCli records the verification status of one CLI version against a chip entry.
type MatrixVerifiedCli struct {
	Status     string `json:"status"`
	LastTested string `json:"last_tested"`
}

// MatrixVersion groups verified CLI statuses for one chip version.
type MatrixVersion struct {
	EnvironmentHash     string                       `json:"environment_hash"`
	Dependencies        MatrixDependencies           `json:"dependencies"`
	VerifiedCliVersions map[string]MatrixVerifiedCli `json:"verified_cli_versions"`
}

// MatrixChip maps chip versions to their verified compatibility records.
type MatrixChip struct {
	Versions map[string]MatrixVersion `json:"versions"`
}

// Matrix maps chip names to their compatibility records.
type Matrix map[string]MatrixChip
