// BOUNDARY TYPES: Struct types in this file are mirrored in internal/ports/ports.go.
// If you add, remove, or modify a struct field here, you MUST update ports.go
// and the assertions in internal/ports/assertions.go accordingly.
package manifest

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
)

type DeviceToml struct {
	Name    string `toml:"name"`
	Version string `toml:"version"`
	Device  struct {
		Chip string `toml:"chip"`
	} `toml:"device"`
	Build struct {
		Compiler string `toml:"compiler"`
		CoreSDK  string `toml:"core_sdk"`
		Registry string `toml:"registry"`
	} `toml:"build"`
	Crypto struct {
		Backend string `toml:"backend"`
		Hash    string `toml:"hash"`
		Pqc     string `toml:"pqc"`
	} `toml:"crypto"`
	Recovery struct {
		Console  string   `toml:"console"`
		Flash    string   `toml:"flash"`
		WDT      string   `toml:"wdt"`
		Clock    string   `toml:"clock"`
		RTC      string   `toml:"rtc"`
		Crypto   struct {
			Backend       string `toml:"backend"`
			Hash          string `toml:"hash"`
			Justification string `toml:"justification"`
		} `toml:"crypto"`
		Sources  []string `toml:"sources"`
		Includes []string `toml:"includes"`
	} `toml:"recovery"`
	DriverConfig map[string]any `toml:"driver_config"`
	Partitions   struct {
		Stage0Size    uint32 `toml:"stage0_size"`
		Stage1Size    uint32 `toml:"stage1_size"`
		AppSize       uint32 `toml:"app_size"`
		ScratchSize   uint32 `toml:"scratch_size"`
		RecoverySize  uint32 `toml:"recovery_size"`
		NetcoreSize   uint32 `toml:"netcore_size"`
		WalSectors    uint32 `toml:"wal_sectors"`
		StagingSlotID uint32 `toml:"staging_slot_id"`
		EnableDeltas  bool   `toml:"enable_deltas"`
	} `toml:"partitions"`
	BootConfig struct {
		MaxRetries         uint32 `toml:"max_retries"`
		MaxRecoveryRetries uint32 `toml:"max_recovery_retries"`
		EdgeUnattendedMode bool   `toml:"edge_unattended_mode"`
		BackoffBaseS       uint32 `toml:"backoff_base_s"`
		WdtTimeoutMs       uint32 `toml:"wdt_timeout_ms"`
		Stage1Svn          uint32 `toml:"stage1_svn"`
		TransportProvider  string `toml:"transport_provider"`
	} `toml:"boot_config"`
}

type Provenance struct {
	Source   string `json:"source"` // "trm", "datasheet", "rom_disasm", "scan", "vendor_sdk"
	Ref      string `json:"ref,omitempty"`
	Verified string `json:"verified,omitempty"`
}

type FlashRegion struct {
	Type       string      `json:"type"`
	Base       uint32      `json:"base"`
	Size       uint32      `json:"size,omitempty"`
	SectorSize uint32      `json:"sector_size,omitempty"`
	Count      uint32      `json:"count,omitempty"`
	Name       string      `json:"name,omitempty"`
	Provenance *Provenance `json:"provenance,omitempty"`
}

type ReservedRamRegion struct {
	Name        string      `json:"name"`
	Base        string      `json:"base"`
	Size        uint32      `json:"size"`
	Description string      `json:"description"`
	Provenance  *Provenance `json:"provenance,omitempty"`
}

type RegisterBlock struct {
	Base       string            `json:"base"`
	Regs       map[string]string `json:"regs"`
	Provenance *Provenance       `json:"provenance,omitempty"`
}

type ResetCauseCode struct {
	Name       string      `json:"name"`
	Value      int         `json:"value"`
	Class      string      `json:"class"` // "power", "intentional", "crash"
	Provenance *Provenance `json:"provenance,omitempty"`
}

type ResetCauses struct {
	RegisterOffset string           `json:"register_offset"`
	Mask           string           `json:"mask"`
	Codes          []ResetCauseCode `json:"codes"`
	Provenance     *Provenance      `json:"provenance,omitempty"`
}

type HardwareJson struct {
	ChipFamily string      `json:"chip_family"`
	Provenance *Provenance `json:"provenance,omitempty"`
	Flash      struct {
		Size           uint32        `json:"size"`
		WriteAlignment uint32        `json:"write_alignment"`
		AppAlignment   uint32        `json:"app_alignment"`
		BaseAddr       string        `json:"base_addr"`
		XipBase        string        `json:"xip_base"`
		Regions        []FlashRegion `json:"regions"`
		Provenance     *Provenance   `json:"provenance,omitempty"`
	} `json:"flash"`
	CryptoCapabilities struct {
		ArenaSize  uint32      `json:"arena_size"`
		Provenance *Provenance `json:"provenance,omitempty"`
	} `json:"crypto_capabilities"`
	Memory struct {
		IramBase   string      `json:"iram_base"`
		IramSize   string      `json:"iram_size"`
		LpRamBase  string      `json:"lp_ram_base,omitempty"`
		LpRamSize  string      `json:"lp_ram_size,omitempty"`
		Provenance *Provenance `json:"provenance,omitempty"`
	} `json:"memory"`
	ReservedRamRegions []ReservedRamRegion      `json:"reserved_ram_regions,omitempty"`
	RegisterBlocks     map[string]RegisterBlock `json:"register_blocks,omitempty"`
	RegistersFlat      map[string]string        `json:"registers_flat,omitempty"`
	ResetCauses        *ResetCauses             `json:"reset_causes,omitempty"`
	Registers          map[string]any           `json:"registers,omitempty"`
	Constants          map[string]any           `json:"constants"`
}


func ParseToml(path string) (*DeviceToml, error) {
	var dt DeviceToml
	meta, err := toml.DecodeFile(path, &dt)
	if err != nil {
		return nil, err
	}
	if len(meta.Undecoded()) > 0 {
		return nil, fmt.Errorf("FATAL [TOML_STRICT]: Unknown fields in %s: %v", path, meta.Undecoded())
	}
	return &dt, nil
}

type SlotCapabilities struct {
	ExecModel      string `json:"exec_model"`
	SlotCount      int    `json:"slot_count"`
	HasScratch     bool   `json:"has_scratch"`
	MaxEraseCycles uint32 `json:"max_erase_cycles"`
}

type DriverManifest struct {
	Name        string            `json:"name"`
	Author      string            `json:"author,omitempty"`
	Version     string            `json:"version,omitempty"`
	Description string            `json:"description,omitempty"`
	Trait       string            `json:"trait,omitempty"`
	AbiVersion  string            `json:"abi_version,omitempty"`
	Headers     []string          `json:"headers,omitempty"`
	Symbols     map[string]string `json:"symbols,omitempty"`
}

type ChipSources struct {
	Startup  string   `json:"startup,omitempty"`
	Linker   string   `json:"linker,omitempty"`
	Hardware string   `json:"hardware,omitempty"`
	Drivers  []string `json:"drivers,omitempty"`
	Extra    []string `json:"extra,omitempty"`
}

type ChipManifest struct {
	Name             string            `json:"name,omitempty"`
	Arch             string            `json:"arch"`
	CompilerPrefix   string            `json:"compiler_prefix"`
	Version          string            `json:"version"`
	MinCoreSDK       string            `json:"min_core_sdk"`
	MinCompiler      string            `json:"min_compiler"`
	SlotCapabilities *SlotCapabilities `json:"slot_capabilities"`
	HalBindings      map[string]string `json:"hal_bindings,omitempty"`
	Sources          *ChipSources      `json:"sources,omitempty"`
}

func LoadConfig(tomlPath, jsonPath string) (*DeviceToml, *HardwareJson, error) {
	dt, err := ParseToml(tomlPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse TOML %s: %w", tomlPath, err)
	}

	jd, err := os.ReadFile(jsonPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read JSON %s: %w", jsonPath, err)
	}

	var hj HardwareJson
	if err := json.Unmarshal(jd, &hj); err != nil {
		return nil, nil, fmt.Errorf("failed to parse JSON %s: %w", jsonPath, err)
	}

	return dt, &hj, nil
}
