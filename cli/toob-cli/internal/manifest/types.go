package manifest

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
)

type DeviceToml struct {
	Device struct {
		Chip string `toml:"chip"`
	} `toml:"device"`
	Partitions struct {
		Stage0Size    uint32 `toml:"stage0_size"`
		Stage1Size    uint32 `toml:"stage1_size"`
		AppSize       uint32 `toml:"app_size"`
		ScratchSize   uint32 `toml:"scratch_size"`
		RecoverySize  uint32 `toml:"recovery_size"`
		NetcoreSize   uint32 `toml:"netcore_size"`
		WalSectors    uint32 `toml:"wal_sectors"`
		StagingSlotID uint32 `toml:"staging_slot_id"`
	} `toml:"partitions"`
	BootConfig struct {
		MaxRetries         uint32 `toml:"max_retries"`
		MaxRecoveryRetries uint32 `toml:"max_recovery_retries"`
		EdgeUnattendedMode bool   `toml:"edge_unattended_mode"`
		BackoffBaseS       uint32 `toml:"backoff_base_s"`
		WdtTimeoutMs       uint32 `toml:"wdt_timeout_ms"`
	} `toml:"boot_config"`
}

type FlashRegion struct {
	Type       string `json:"type"`
	Base       uint32 `json:"base"`
	Size       uint32 `json:"size,omitempty"`
	SectorSize uint32 `json:"sector_size,omitempty"`
	Count      uint32 `json:"count,omitempty"`
	Name       string `json:"name,omitempty"`
}

type HardwareJson struct {
	ChipFamily string `json:"chip_family"`
	Flash      struct {
		Size           uint32        `json:"size"`
		WriteAlignment uint32        `json:"write_alignment"`
		AppAlignment   uint32        `json:"app_alignment"`
		BaseAddr       string        `json:"base_addr"`
		XipBase        string        `json:"xip_base"`
		Regions        []FlashRegion `json:"regions"`
	} `json:"flash"`
	CryptoCapabilities struct {
		ArenaSize uint32 `json:"arena_size"`
	} `json:"crypto_capabilities"`
	Memory struct {
		RamBase string `json:"ram_base"`
		RamSize string `json:"ram_size"`
	} `json:"memory"`
}

func LoadConfig(tomlPath, jsonPath string) (*DeviceToml, *HardwareJson, error) {
	var dt DeviceToml
	if _, err := toml.DecodeFile(tomlPath, &dt); err != nil {
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

	return &dt, &hj, nil
}
