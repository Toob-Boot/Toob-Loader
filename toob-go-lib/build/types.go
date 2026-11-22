// BOUNDARY TYPES: Struct types in this file are mirrored in internal/ports/ports.go.
// If you add, remove, or modify a struct field here, you MUST update ports.go
// and the assertions in internal/ports/assertions.go accordingly.
//
// Exception: ports mirrors only a subset of HardwareJson. Fields that exist
// solely so that strict parsing accepts the full hardware.json schema
// (CryptoPrimitive, MultiCore, Coprocessor) are library-internal, as are the
// unexported HAL contract schema types in hal_contract.go.
package build

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/BurntSushi/toml"
)

// StringOrSlice decodes either a single JSON string ("esp32c6") or a JSON
// array of strings (["esp32c3", "esp32c6"]).
type StringOrSlice []string

func (s *StringOrSlice) UnmarshalJSON(data []byte) error {
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
		if single == "" {
			*s = nil
			return nil
		}
		*s = StringOrSlice{single}
		return nil
	}
	if trimmed[0] == '[' {
		dec := json.NewDecoder(bytes.NewReader(trimmed))
		var list []string
		if err := dec.Decode(&list); err != nil {
			return err
		}
		if _, err := dec.Token(); !errors.Is(err, io.EOF) {
			return errors.New("unexpected trailing data after string array")
		}
		*s = StringOrSlice(list)
		return nil
	}
	return fmt.Errorf("expected JSON string or array of strings, got %s", string(trimmed))
}

func (s StringOrSlice) MarshalJSON() ([]byte, error) {
	if len(s) == 0 {
		return []byte("null"), nil
	}
	if len(s) == 1 {
		return json.Marshal(s[0])
	}
	return json.Marshal([]string(s))
}

// ReferenceBuildContext records the reference silicon/SDK/toolchain combination
// against which a promotable third-party package was validated (CRIT-57).
type ReferenceBuildContext struct {
	Chip             string `json:"chip,omitempty"`
	CoreSDKVersion   string `json:"core_sdk_version,omitempty"`
	ToolchainVersion string `json:"toolchain_version,omitempty"`
}

// CompilerFlags declares silicon ISA, ABI, and linker flags in chip/arch manifests
// so toolchain.cmake never hardcodes chip names (HIGH-87).
type CompilerFlags struct {
	CFlags   []string `json:"c_flags,omitempty"`
	AsmFlags []string `json:"asm_flags,omitempty"`
	LDFlags  []string `json:"ld_flags,omitempty"`
}

// HexUint32 decodes either a JSON unsigned integer (e.g. 1) or a C-style
// decimal / 0x-prefixed hexadecimal string literal (e.g. "0x08000000").
type HexUint32 uint32

func (h *HexUint32) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	if trimmed[0] == '"' {
		var raw string
		if err := json.Unmarshal(trimmed, &raw); err != nil {
			return err
		}
		v, err := parseU32Literal(raw)
		if err != nil {
			return err
		}
		*h = HexUint32(v)
		return nil
	}
	var num json.Number
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.UseNumber()
	if err := dec.Decode(&num); err != nil {
		return fmt.Errorf("invalid uint32 value %s: %w", string(trimmed), err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return fmt.Errorf("invalid uint32 value %s", string(trimmed))
	}
	v, err := parseU32Literal(num.String())
	if err != nil {
		return err
	}
	*h = HexUint32(v)
	return nil
}

type DeviceToml struct {
	Name     string `toml:"name"`
	Version  string `toml:"version"`
	Identity struct {
		VendorID  uint16 `toml:"vendor_id"`
		ProductID uint16 `toml:"product_id"`
		HwRev     uint16 `toml:"hw_rev"`
	} `toml:"identity"`
	Device struct {
		Chip string `toml:"chip"`
	} `toml:"device"`
	Build struct {
		Compiler string   `toml:"compiler"`
		CoreSDK  string   `toml:"core_sdk"`
		Registry string   `toml:"registry"`
		Profile  string   `toml:"profile"`
		Mock     []string `toml:"mock"`
	} `toml:"build"`
	Drivers map[string]string `toml:"drivers"`
	Crypto  struct {
		Backend string `toml:"backend"`
		Hash    string `toml:"hash"`
		Pqc     string `toml:"pqc"`
	} `toml:"crypto"`
	Recovery struct {
		Console string `toml:"console"`
		Flash   string `toml:"flash"`
		WDT     string `toml:"wdt"`
		Clock   string `toml:"clock"`
		RTC     string `toml:"rtc"`
		Crypto  struct {
			Backend       string `toml:"backend"`
			Hash          string `toml:"hash"`
			Justification string `toml:"justification"`
		} `toml:"crypto"`
		Sources  []string `toml:"sources"`
		Includes []string `toml:"includes"`
	} `toml:"recovery"`
	DriverConfig map[string]any `toml:"driver_config"`
	Partitions   struct {
		Stage0Size    uint32  `toml:"stage0_size"`
		Stage1Size    uint32  `toml:"stage1_size"`
		AppSize       uint32  `toml:"app_size"`
		ScratchSize   uint32  `toml:"scratch_size"`
		RecoverySize  uint32  `toml:"recovery_size"`
		NetcoreSize   uint32  `toml:"netcore_size"`
		WalSectors    uint32  `toml:"wal_sectors"`
		StagingSlotID *uint32 `toml:"staging_slot_id"`
		EnableDeltas  bool    `toml:"enable_deltas"`
	} `toml:"partitions"`
	BootConfig struct {
		MaxRetries         uint32 `toml:"max_retries"`
		MaxRecoveryRetries uint32 `toml:"max_recovery_retries"`
		EdgeUnattendedMode bool   `toml:"edge_unattended_mode"`
		BackoffBaseS       uint32 `toml:"backoff_base_s"`
		WdtTimeoutMs       uint32 `toml:"wdt_timeout_ms"`
		Stage1Svn          uint32 `toml:"stage1_svn"`
		CryptoArenaSize    uint32 `toml:"crypto_arena_size"`
		TransportProvider  string `toml:"transport_provider"`
		BackupMode         string `toml:"backup_mode"`
	} `toml:"boot_config"`
	Features struct {
		CloudCommands    *bool `toml:"cloud_commands"`
		UartProvisioning *bool `toml:"uart_provisioning"`
		MultiImage       *bool `toml:"multi_image"`
		Delta            *bool `toml:"delta"`
		Compression      *bool `toml:"compression"`
	} `toml:"features"`
}

type Provenance struct {
	Source   string `json:"source"` // "trm", "datasheet", "rom_disasm", "scan", "vendor_sdk"
	Ref      string `json:"ref,omitempty"`
	Verified string `json:"verified,omitempty"`
}

type FlashRegion struct {
	Type        string      `json:"type"`
	Base        uint32      `json:"base"`
	Size        uint32      `json:"size,omitempty"`
	SectorSize  uint32      `json:"sector_size,omitempty"`
	Count       uint32      `json:"count,omitempty"`
	Name        string      `json:"name,omitempty"`
	Description string      `json:"description,omitempty"`
	Provenance  *Provenance `json:"provenance,omitempty"`
}

// FlashSpec describes the physical flash geometry and XIP mapping of a chip.
type FlashSpec struct {
	Size              uint32        `json:"size"`
	WriteAlignment    uint32        `json:"write_alignment"`
	AppAlignment      uint32        `json:"app_alignment"`
	Base              HexUint32     `json:"base,omitempty"`
	BaseAddr          string        `json:"base_addr,omitempty"`
	XipBase           string        `json:"xip_base,omitempty"`
	VtorAlignment     uint32        `json:"vtor_alignment,omitempty"`
	ImageHeaderOffset uint32        `json:"image_header_offset,omitempty"`
	EraseTimeUsMax    uint32        `json:"erase_time_us_max,omitempty"`
	WriteTimeUsPage   uint32        `json:"write_time_us_page,omitempty"`
	Stage0ExecMode    string        `json:"stage0_exec_mode,omitempty"`
	EntrySymbol       string        `json:"entry_symbol,omitempty"`
	Regions           []FlashRegion `json:"regions"`
	Provenance        *Provenance   `json:"provenance,omitempty"`
}

// MemorySpec describes the RAM windows and optional Cortex-M vector alignment.
type MemorySpec struct {
	IramBase          string      `json:"iram_base"`
	IramSize          string      `json:"iram_size"`
	SramBase          string      `json:"sram_base,omitempty"`
	SramSize          string      `json:"sram_size,omitempty"`
	LpRamBase         string      `json:"lp_ram_base,omitempty"` //nolint:staticcheck // ST1003: boundary field mirrored in cli/toob-cli/internal/ports
	LpRamSize         string      `json:"lp_ram_size,omitempty"` //nolint:staticcheck // ST1003: boundary field mirrored in cli/toob-cli/internal/ports
	VtorAlignment     uint32      `json:"vtor_alignment,omitempty"`
	ImageHeaderOffset uint32      `json:"image_header_offset,omitempty"`
	Provenance        *Provenance `json:"provenance,omitempty"`
}

// CryptoPrimitive states whether a primitive exists in hardware and whether
// the boot stages may use it.
type CryptoPrimitive struct {
	HwPresent  bool   `json:"hw_present"`
	BootUsable bool   `json:"boot_usable"`
	Note       string `json:"note,omitempty"`
}

// Coprocessor is an auxiliary core of a multi-core chip.
type Coprocessor struct {
	Name              string     `json:"name"`
	FlashBase         *HexUint32 `json:"flash_base,omitempty"`
	AppAlignmentBytes *uint32    `json:"app_alignment_bytes,omitempty"`
}

// MultiCore describes the core topology of the chip.
type MultiCore struct {
	IsMultiCore  bool          `json:"is_multi_core"`
	IpcMechanism string        `json:"ipc_mechanism,omitempty"`
	Coprocessors []Coprocessor `json:"coprocessors,omitempty"`
}

//nolint:staticcheck // ST1003: boundary type mirrored in cli/toob-cli
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
	Value      HexUint32   `json:"value"`
	Mask       HexUint32   `json:"mask,omitempty"`
	ClearReg   string      `json:"clear_reg,omitempty"`
	ClearMask  HexUint32   `json:"clear_mask,omitempty"`
	Class      string      `json:"class"` // "power", "intentional", "crash"
	Provenance *Provenance `json:"provenance,omitempty"`
}

type ResetCauses struct {
	RegisterOffset string           `json:"register_offset,omitempty"`
	Mask           string           `json:"mask,omitempty"`
	ClearReg       string           `json:"clear_reg,omitempty"`
	ClearMask      HexUint32        `json:"clear_mask,omitempty"`
	Codes          []ResetCauseCode `json:"codes"`
	Provenance     *Provenance      `json:"provenance,omitempty"`
}

// BootromFieldSpec writes a static constant or dynamic ELF/hardware property
// into a fixed-size header or segment-descriptor buffer.
type BootromFieldSpec struct {
	Offset int       `json:"offset"`
	Size   int       `json:"size"`
	Endian string    `json:"endian,omitempty"` // "little" (default) or "big"
	Source string    `json:"source"`           // "const", "segment_count", "entry_point", "image_size", "segment_addr", "segment_size", "flash_size_log2_mib"
	Value  HexUint32 `json:"value,omitempty"`
	Shift  int       `json:"shift,omitempty"`
	OrMask HexUint32 `json:"or_mask,omitempty"`
}

// BootromHeaderSpec defines the container header prepended in "segmented" layout.
type BootromHeaderSpec struct {
	Size     int                `json:"size,omitempty"`
	FillByte *HexUint32         `json:"fill_byte,omitempty"`
	Fields   []BootromFieldSpec `json:"fields,omitempty"`
}

// BootromSegmentSpec defines how loadable ELF sections are merged and framed in "segmented" layout.
type BootromSegmentSpec struct {
	Align        int                `json:"align,omitempty"`
	MaxCount     int                `json:"max_count,omitempty"`
	HeaderSize   int                `json:"header_size,omitempty"`
	HeaderFields []BootromFieldSpec `json:"header_fields,omitempty"`
}

// BootromPatchSpec applies an in-place checksum, digest, or metadata write to a "flat" image.
type BootromPatchSpec struct {
	Op         string    `json:"op"` // "crc32", "sum32", "neg_sum32", "sha256", "entry_point", "image_size", "const"
	Offset     int       `json:"offset"`
	Size       int       `json:"size"`
	Endian     string    `json:"endian,omitempty"`
	RangeStart int       `json:"range_start,omitempty"`
	RangeEnd   int       `json:"range_end,omitempty"` // 0 means len(image)
	Poly       HexUint32 `json:"poly,omitempty"`
	Init       HexUint32 `json:"init,omitempty"`
	Reflect    bool      `json:"reflect,omitempty"`
	XorOut     HexUint32 `json:"xor_out,omitempty"`
	Value      HexUint32 `json:"value,omitempty"`
}

// BootromTrailerOp appends padding, checksums, or digests to a packed image.
type BootromTrailerOp struct {
	Op      string    `json:"op"`              // "pad", "xor8", "crc32", "sha256"
	Align   int       `json:"align,omitempty"` // for "pad"
	Reserve int       `json:"reserve,omitempty"`
	Byte    HexUint32 `json:"byte,omitempty"`
	Seed    HexUint32 `json:"seed,omitempty"`
	Scope   string    `json:"scope,omitempty"` // "segment_data" or "image"
	Poly    HexUint32 `json:"poly,omitempty"`
	Init    HexUint32 `json:"init,omitempty"`
	Reflect bool      `json:"reflect,omitempty"`
	XorOut  HexUint32 `json:"xor_out,omitempty"`
	Endian  string    `json:"endian,omitempty"`
}

// BootromImageSpec declaratively describes how a linked Stage 0 ELF is packed
// into a BootROM-loadable image for the target SoC, optionally inheriting a
// shared SoC profile (e.g. "soc/esp/bootrom_image.json") via Extends.
type BootromImageSpec struct {
	Extends    string              `json:"extends,omitempty"`
	Layout     string              `json:"layout,omitempty"` // "flat" (default) or "segmented"
	FillByte   *HexUint32          `json:"fill_byte,omitempty"`
	MinSize    int                 `json:"min_size,omitempty"`
	Header     *BootromHeaderSpec  `json:"header,omitempty"`
	Segments   *BootromSegmentSpec `json:"segments,omitempty"`
	Patches    []BootromPatchSpec  `json:"patches,omitempty"`
	Trailer    []BootromTrailerOp  `json:"trailer,omitempty"`
	Provenance *Provenance         `json:"provenance,omitempty"`
}

//nolint:staticcheck // ST1003: boundary type mirrored in cli/toob-cli/internal/ports
type HardwareJson struct {
	ChipFamily         string            `json:"chip_family"`
	Provenance         *Provenance       `json:"provenance,omitempty"`
	BootromImage       *BootromImageSpec `json:"bootrom_image,omitempty"`
	Flash              FlashSpec         `json:"flash"`
	CryptoCapabilities struct {
		Aes        CryptoPrimitive `json:"aes"`
		Ed25519    CryptoPrimitive `json:"ed25519"`
		Rng        CryptoPrimitive `json:"rng"`
		Sha256     CryptoPrimitive `json:"sha256"`
		Pka        CryptoPrimitive `json:"pka"`
		ArenaSize  uint32          `json:"arena_size"`
		Provenance *Provenance     `json:"provenance,omitempty"`
	} `json:"crypto_capabilities"`
	MultiCore          *MultiCore               `json:"multi_core,omitempty"`
	Memory             MemorySpec               `json:"memory"`
	ReservedRamRegions []ReservedRamRegion      `json:"reserved_ram_regions,omitempty"` //nolint:staticcheck // ST1003: boundary field mirrored in cli/toob-cli
	RegisterBlocks     map[string]RegisterBlock `json:"register_blocks,omitempty"`
	RegistersFlat      map[string]string        `json:"registers_flat,omitempty"`
	ResetCauses        *ResetCauses             `json:"reset_causes,omitempty"`
	Registers          map[string]any           `json:"registers,omitempty"`
	Constants          map[string]any           `json:"constants"`
}

// Maximum input sizes and nesting depth to prevent OOM / stack-exhaustion DoS
// when parsing untrusted or corrupted manifests.
const (
	maxManifestBytes = 4 << 20 // 4 MiB
	maxJSONDepth     = 32
)

func readBoundedFile(path string, maxBytes int64) ([]byte, error) {
	// #nosec G304 -- caller validates path containment; regular-file and size bounds enforced below
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if info.Size() > maxBytes {
		return nil, fmt.Errorf("%s size (%d bytes) exceeds maximum allowed limit (%d bytes)", path, info.Size(), maxBytes)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("%s exceeds maximum allowed limit (%d bytes)", path, maxBytes)
	}
	return data, nil
}

func ParseToml(path string) (*DeviceToml, error) {
	data, err := readBoundedFile(path, maxManifestBytes)
	if err != nil {
		return nil, err
	}
	var dt DeviceToml
	meta, err := toml.Decode(string(data), &dt)
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
	Name                  string                 `json:"name"`
	Author                string                 `json:"author,omitempty"`
	Tier                  string                 `json:"tier,omitempty"`
	Version               string                 `json:"version,omitempty"`
	Description           string                 `json:"description,omitempty"`
	License               string                 `json:"license,omitempty"`
	Repository            string                 `json:"repository,omitempty"`
	Keywords              []string               `json:"keywords,omitempty"`
	MinCoreSDK            string                 `json:"min_core_sdk,omitempty"`
	Trait                 string                 `json:"trait,omitempty"`
	AbiVersion            string                 `json:"abi_version,omitempty"`
	ExecModel             string                 `json:"exec_model,omitempty"`
	IsHardwareTRNG        bool                   `json:"is_hardware_trng,omitempty"`
	Headers               []string               `json:"headers,omitempty"`
	Sources               []string               `json:"sources,omitempty"`
	MockSources           []string               `json:"mock_sources,omitempty"`
	Symbols               map[string]string      `json:"symbols,omitempty"`
	ReferenceBuildContext *ReferenceBuildContext `json:"reference_build_context,omitempty"`
}

type CryptoFootprint struct {
	FlashBytes uint32 `json:"flash_bytes,omitempty"`
	RamBytes   uint32 `json:"ram_bytes,omitempty"` //nolint:staticcheck // ST1003: boundary field mirrored in cli/toob-cli/internal/ports
}

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

type CryptoManifest struct {
	Name                  string                 `json:"name"`
	Author                string                 `json:"author,omitempty"`
	Tier                  string                 `json:"tier,omitempty"`
	Version               string                 `json:"version,omitempty"`
	Description           string                 `json:"description,omitempty"`
	AbiVersion            string                 `json:"abi_version,omitempty"`
	Category              []string               `json:"category,omitempty"`
	License               string                 `json:"license,omitempty"`
	Repository            string                 `json:"repository,omitempty"`
	Keywords              []string               `json:"keywords,omitempty"`
	MinCoreSdk            string                 `json:"min_core_sdk,omitempty"`
	Wrapper               string                 `json:"wrapper,omitempty"`
	UpstreamSources       []string               `json:"upstream_sources,omitempty"`
	Headers               []string               `json:"headers,omitempty"`
	Symbols               map[string]string      `json:"symbols,omitempty"`
	Cflags                []string               `json:"cflags,omitempty"`
	Includes              []string               `json:"includes,omitempty"`
	ChipBinding           string                 `json:"chip_binding,omitempty"`
	HasHwAcceleration     bool                   `json:"has_hw_acceleration,omitempty"`
	Footprint             *CryptoFootprint       `json:"footprint,omitempty"`
	ReferenceBuildContext *ReferenceBuildContext `json:"reference_build_context,omitempty"`
	chipBindings          StringOrSlice
}

type cryptoManifestWire struct {
	Name                  string                 `json:"name"`
	Author                string                 `json:"author,omitempty"`
	Tier                  string                 `json:"tier,omitempty"`
	Version               string                 `json:"version,omitempty"`
	Description           string                 `json:"description,omitempty"`
	AbiVersion            string                 `json:"abi_version,omitempty"`
	Category              []string               `json:"category,omitempty"`
	License               string                 `json:"license,omitempty"`
	Repository            string                 `json:"repository,omitempty"`
	Keywords              []string               `json:"keywords,omitempty"`
	MinCoreSdk            string                 `json:"min_core_sdk,omitempty"`
	Wrapper               string                 `json:"wrapper,omitempty"`
	UpstreamSources       []string               `json:"upstream_sources,omitempty"`
	Headers               []string               `json:"headers,omitempty"`
	Symbols               map[string]string      `json:"symbols,omitempty"`
	Cflags                []string               `json:"cflags,omitempty"`
	Includes              []string               `json:"includes,omitempty"`
	ChipBinding           StringOrSlice          `json:"chip_binding,omitempty"`
	HasHwAcceleration     bool                   `json:"has_hw_acceleration,omitempty"`
	Footprint             *CryptoFootprint       `json:"footprint,omitempty"`
	ReferenceBuildContext *ReferenceBuildContext `json:"reference_build_context,omitempty"`
}

// ChipBindings returns all silicon chip bindings declared by the crypto package,
// supporting both single-string ("esp32c6") and multi-chip (["esp32c3", "esp32c6"]) manifests.
func (m *CryptoManifest) ChipBindings() []string {
	if m == nil {
		return nil
	}
	if len(m.chipBindings) > 0 {
		if m.ChipBinding != "" && len(m.chipBindings) == 1 && m.chipBindings[0] != m.ChipBinding {
			return []string{m.ChipBinding}
		}
		return slices.Clone([]string(m.chipBindings))
	}
	if m.ChipBinding != "" {
		return []string{m.ChipBinding}
	}
	return nil
}

// SetChipBindings sets one or more silicon chip bindings on m while keeping
// ChipBinding synchronized with the primary binding.
func (m *CryptoManifest) SetChipBindings(bindings ...string) {
	if m == nil {
		return
	}
	if len(bindings) == 0 {
		m.chipBindings = nil
		m.ChipBinding = ""
		return
	}
	m.chipBindings = StringOrSlice(slices.Clone(bindings))
	m.ChipBinding = bindings[0]
}

func (m *CryptoManifest) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.DisallowUnknownFields()
	var w cryptoManifestWire
	if err := dec.Decode(&w); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("unexpected trailing data in crypto manifest")
	}
	var primary string
	if len(w.ChipBinding) > 0 {
		primary = w.ChipBinding[0]
	}
	*m = CryptoManifest{
		Name:                  w.Name,
		Author:                w.Author,
		Tier:                  w.Tier,
		Version:               w.Version,
		Description:           w.Description,
		AbiVersion:            w.AbiVersion,
		Category:              w.Category,
		License:               w.License,
		Repository:            w.Repository,
		Keywords:              w.Keywords,
		MinCoreSdk:            w.MinCoreSdk,
		Wrapper:               w.Wrapper,
		UpstreamSources:       w.UpstreamSources,
		Headers:               w.Headers,
		Symbols:               w.Symbols,
		Cflags:                w.Cflags,
		Includes:              w.Includes,
		ChipBinding:           primary,
		HasHwAcceleration:     w.HasHwAcceleration,
		Footprint:             w.Footprint,
		ReferenceBuildContext: w.ReferenceBuildContext,
		chipBindings:          w.ChipBinding,
	}
	return nil
}

func (m *CryptoManifest) MarshalJSON() ([]byte, error) {
	if m == nil {
		return []byte("null"), nil
	}
	w := cryptoManifestWire{
		Name:                  m.Name,
		Author:                m.Author,
		Tier:                  m.Tier,
		Version:               m.Version,
		Description:           m.Description,
		AbiVersion:            m.AbiVersion,
		Category:              m.Category,
		License:               m.License,
		Repository:            m.Repository,
		Keywords:              m.Keywords,
		MinCoreSdk:            m.MinCoreSdk,
		Wrapper:               m.Wrapper,
		UpstreamSources:       m.UpstreamSources,
		Headers:               m.Headers,
		Symbols:               m.Symbols,
		Cflags:                m.Cflags,
		Includes:              m.Includes,
		ChipBinding:           StringOrSlice(m.ChipBindings()),
		HasHwAcceleration:     m.HasHwAcceleration,
		Footprint:             m.Footprint,
		ReferenceBuildContext: m.ReferenceBuildContext,
	}
	return json.Marshal(w)
}

type ArchManifest struct {
	Name                  string                 `json:"name"`
	Author                string                 `json:"author,omitempty"`
	Tier                  string                 `json:"tier,omitempty"`
	Version               string                 `json:"version,omitempty"`
	Description           string                 `json:"description,omitempty"`
	License               string                 `json:"license,omitempty"`
	Repository            string                 `json:"repository,omitempty"`
	Keywords              []string               `json:"keywords,omitempty"`
	MinCoreSDK            string                 `json:"min_core_sdk,omitempty"`
	CompilerFlags         *CompilerFlags         `json:"compiler_flags,omitempty"`
	Headers               []string               `json:"headers,omitempty"`
	Sources               []string               `json:"sources,omitempty"`
	Symbols               map[string]string      `json:"symbols,omitempty"`
	RequiredMacros        []string               `json:"required_macros,omitempty"`
	ReferenceBuildContext *ReferenceBuildContext `json:"reference_build_context,omitempty"`
}

type ChipSources struct {
	Startup  string   `json:"startup,omitempty"`
	Platform string   `json:"platform,omitempty"`
	Config   string   `json:"config,omitempty"`
	Linker   string   `json:"linker,omitempty"`
	Hardware string   `json:"hardware,omitempty"`
	Drivers  []string `json:"drivers,omitempty"`
	Extra    []string `json:"extra,omitempty"`
}

type ChipCrypto struct {
	Backend string `json:"backend,omitempty"`
	Hash    string `json:"hash,omitempty"`
	Pqc     string `json:"pqc,omitempty"`
}

type RecoveryCrypto struct {
	Backend string `json:"backend,omitempty"`
	Hash    string `json:"hash,omitempty"`
}

type ChipRecovery struct {
	Console  string          `json:"console,omitempty"`
	Flash    string          `json:"flash,omitempty"`
	WDT      string          `json:"wdt,omitempty"`
	Clock    string          `json:"clock,omitempty"`
	RTC      string          `json:"rtc,omitempty"`
	Crypto   *RecoveryCrypto `json:"crypto,omitempty"`
	Sources  []string        `json:"sources,omitempty"`
	Includes []string        `json:"includes,omitempty"`
}

type ChipManifest struct {
	Name                  string                 `json:"name,omitempty"`
	Author                string                 `json:"author,omitempty"`
	Tier                  string                 `json:"tier,omitempty"`
	Arch                  string                 `json:"arch"`
	CompilerPrefix        string                 `json:"compiler_prefix"`
	CompilerFlags         *CompilerFlags         `json:"compiler_flags,omitempty"`
	Description           string                 `json:"description,omitempty"`
	License               string                 `json:"license,omitempty"`
	Repository            string                 `json:"repository,omitempty"`
	Keywords              []string               `json:"keywords,omitempty"`
	Version               string                 `json:"version"`
	MinCoreSDK            string                 `json:"min_core_sdk"`
	MinCompiler           string                 `json:"min_compiler"`
	Stage0ExecMode        string                 `json:"stage0_exec_mode,omitempty"`
	EntrySymbol           string                 `json:"entry_symbol,omitempty"`
	SlotCapabilities      *SlotCapabilities      `json:"slot_capabilities"`
	HalBindings           map[string]string      `json:"hal_bindings,omitempty"`
	Sources               *ChipSources           `json:"sources,omitempty"`
	Includes              []string               `json:"includes,omitempty"`
	Crypto                *ChipCrypto            `json:"crypto,omitempty"`
	Recovery              *ChipRecovery          `json:"recovery,omitempty"`
	ReferenceBuildContext *ReferenceBuildContext `json:"reference_build_context,omitempty"`
}

// ParseHardwareJSON reads and decodes a chip hardware description. Unknown
// keys are rejected: a misspelled key would otherwise silently fall back to
// the zero value of the field it was meant to set.
func ParseHardwareJSON(path string) (*HardwareJson, error) {
	hw, _, err := parseHardwareJSONWithRaw(path)
	return hw, err
}

func parseHardwareJSONWithRaw(path string) (*HardwareJson, []byte, error) {
	data, err := readBoundedFile(path, maxManifestBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read %s: %w", path, err)
	}
	hw, err := decodeJSONBytes[HardwareJson](path, data, true)
	if err != nil {
		return nil, nil, err
	}
	return hw, data, nil
}

// validateJSONStructure enforces maximum nesting depth and rejects duplicate
// object keys across the entire JSON value so parsers cannot disagree on
// shadowed security properties (CWE-436 / CWE-674).
func validateJSONStructure(data []byte, maxDepth int) error {
	type frame struct {
		isObj   bool
		needKey bool
		keys    map[string]struct{}
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	var stack []frame
	var seenTop bool

	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		seenTop = true

		if d, ok := tok.(json.Delim); ok && (d == '}' || d == ']') {
			if len(stack) == 0 {
				return fmt.Errorf("unexpected closing delimiter %q", d)
			}
			stack = stack[:len(stack)-1]
			if len(stack) > 0 && stack[len(stack)-1].isObj && !stack[len(stack)-1].needKey {
				stack[len(stack)-1].needKey = true
			}
			if len(stack) == 0 {
				return nil
			}
			continue
		}

		if len(stack) > 0 {
			top := &stack[len(stack)-1]
			if top.isObj {
				if top.needKey {
					key, ok := tok.(string)
					if !ok {
						return errors.New("expected JSON object key")
					}
					folded := strings.ToLower(key)
					if _, dup := top.keys[folded]; dup {
						return fmt.Errorf("duplicate JSON key %q", key)
					}
					top.keys[folded] = struct{}{}
					top.needKey = false
					continue
				}
				if _, isDelim := tok.(json.Delim); !isDelim {
					top.needKey = true
				}
			}
		}

		if d, ok := tok.(json.Delim); ok {
			if len(stack)+1 > maxDepth {
				return fmt.Errorf("JSON nesting depth exceeds maximum of %d", maxDepth)
			}
			if d == '{' {
				stack = append(stack, frame{isObj: true, needKey: true, keys: make(map[string]struct{})})
			} else {
				stack = append(stack, frame{isObj: false})
			}
		} else if seenTop && len(stack) == 0 {
			return nil
		}
	}
}

// decodeJSONFile reads path and decodes its JSON content into a new T. With
// strict set, keys unknown to T are an error. Duplicate keys, excessive nesting,
// and trailing data after the top-level value are always rejected.
func decodeJSONFile[T any](path string, strict bool) (*T, error) {
	data, err := readBoundedFile(path, maxManifestBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", path, err)
	}
	return decodeJSONBytes[T](path, data, strict)
}

func decodeJSONBytes[T any](path string, data []byte, strict bool) (*T, error) {
	if err := validateJSONStructure(data, maxJSONDepth); err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", path, err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if strict {
		dec.DisallowUnknownFields()
	}
	var v T
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", path, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("failed to parse %s: unexpected data after the top-level value", path)
	}
	return &v, nil
}
