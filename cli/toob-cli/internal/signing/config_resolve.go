package signing

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"

	"github.com/Toob-Boot/Toob-Loader/toob-go-lib/build"
	"github.com/Toob-Boot/Toob-Loader/toob-go-lib/tbm1"
	"github.com/toob-boot/toob/internal/manifest"
	"github.com/toob-boot/toob/internal/paths"
	"github.com/toob-boot/toob/internal/registry"
)

const (
	maxJSONManifestBytes = 1 << 20
	maxFirmwareFileBytes = 64 << 20
	// Minimum reserved sector estimate for WAL (2) + KDM quorum (3) when partitioning remainder flash.
	minMetadataSectors = 5
)

type resolvedChipContext struct {
	Hardware     *manifest.HardwareJson
	HardwarePath string
	ChipManifest *manifest.ChipManifest
	ChipDir      string
	PackagesDir  string
}

func resolveChipContext(chip, hwPath, cacheDir, packagesDir string, cache *registry.Cache) (*resolvedChipContext, error) {
	chip = strings.TrimSpace(chip)
	hwPath = strings.TrimSpace(hwPath)
	cacheDir = strings.TrimSpace(cacheDir)
	packagesDir = strings.TrimSpace(packagesDir)

	if hwPath != "" {
		return resolveFromExplicitHardwarePath(chip, hwPath, packagesDir)
	}
	if chip == "" {
		return nil, nil
	}
	return resolveFromChipRegistry(chip, cacheDir, packagesDir, cache)
}

func resolveFromExplicitHardwarePath(chip, hwPath, packagesDir string) (*resolvedChipContext, error) {
	cleanHW := filepath.Clean(hwPath)
	hw, err := manifest.ParseHardwareJSON(cleanHW)
	if err != nil {
		return nil, fmt.Errorf("parse hardware.json %s: %w", cleanHW, err)
	}

	chipDir := filepath.Dir(cleanHW)
	cmPath := filepath.Join(chipDir, "chip_manifest.json")
	var cm *manifest.ChipManifest
	if _, statErr := os.Stat(cmPath); statErr == nil {
		cm, err = parseChipManifestStrict(cmPath)
		if err != nil {
			return nil, fmt.Errorf("invalid sibling chip_manifest.json %s: %w", cmPath, err)
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return nil, fmt.Errorf("stat chip_manifest.json %s: %w", cmPath, statErr)
	}

	if chip != "" {
		if err := validateChipIdentity(chip, chipDir, cm); err != nil {
			return nil, err
		}
	}

	resolvedPkgDir := packagesDir
	if resolvedPkgDir == "" && filepath.Base(filepath.Dir(chipDir)) == "chips" {
		resolvedPkgDir = filepath.Dir(filepath.Dir(chipDir))
	}

	return &resolvedChipContext{
		Hardware:     hw,
		HardwarePath: cleanHW,
		ChipManifest: cm,
		ChipDir:      chipDir,
		PackagesDir:  resolvedPkgDir,
	}, nil
}

func resolveFromChipRegistry(chip, cacheDir, packagesDir string, cache *registry.Cache) (*resolvedChipContext, error) {
	chipDir, resolvedPkgDir, err := locateChipDirectory(chip, cacheDir, packagesDir, cache)
	if err != nil {
		return nil, err
	}

	hwPath := filepath.Join(chipDir, "hardware.json")
	hw, err := manifest.ParseHardwareJSON(hwPath)
	if err != nil {
		return nil, fmt.Errorf("parse chip hardware.json %s: %w", hwPath, err)
	}

	cmPath := filepath.Join(chipDir, "chip_manifest.json")
	cm, err := parseChipManifestStrict(cmPath)
	if err != nil {
		return nil, fmt.Errorf("parse chip_manifest.json %s: %w", cmPath, err)
	}

	if err := validateChipIdentity(chip, chipDir, cm); err != nil {
		return nil, err
	}

	return &resolvedChipContext{
		Hardware:     hw,
		HardwarePath: hwPath,
		ChipManifest: cm,
		ChipDir:      chipDir,
		PackagesDir:  resolvedPkgDir,
	}, nil
}

func locateChipDirectory(chip, cacheDir, packagesDir string, cache *registry.Cache) (string, string, error) {
	if err := build.ValidateName("chip", chip); err != nil {
		return "", "", fmt.Errorf("invalid chip name %q: %w", chip, err)
	}

	if cache != nil {
		chipDir, err := cache.ChipSourcePath(chip)
		if err != nil {
			return "", "", fmt.Errorf("resolve chip %q from registry cache: %w", chip, err)
		}
		pkgDir := packagesDir
		if pkgDir == "" && filepath.Base(filepath.Dir(chipDir)) == "chips" {
			pkgDir = filepath.Dir(filepath.Dir(chipDir))
		}
		if pkgDir == "" && cache.Dir() != "" {
			pkgDir = filepath.Join(cache.Dir(), "packages")
		}
		return chipDir, pkgDir, nil
	}

	if cacheDir != "" {
		cleanCache := filepath.Clean(cacheDir)
		candidates := []struct {
			chipDir string
			pkgDir  string
		}{
			{
				chipDir: filepath.Join(cleanCache, "packages", "chips", chip),
				pkgDir:  filepath.Join(cleanCache, "packages"),
			},
			{
				chipDir: filepath.Join(cleanCache, "chips", chip),
				pkgDir:  cleanCache,
			},
		}
		for _, cand := range candidates {
			if info, err := os.Stat(filepath.Join(cand.chipDir, "hardware.json")); err == nil && !info.IsDir() {
				pkgDir := packagesDir
				if pkgDir == "" {
					pkgDir = cand.pkgDir
				}
				return cand.chipDir, pkgDir, nil
			}
		}
		return "", "", fmt.Errorf("chip %q not found under cache dir %s", chip, cleanCache)
	}

	regDir, err := paths.RegistryDir()
	if err == nil && regDir != "" {
		candidate := filepath.Join(regDir, "packages", "chips", chip)
		if info, statErr := os.Stat(filepath.Join(candidate, "hardware.json")); statErr == nil && !info.IsDir() {
			pkgDir := packagesDir
			if pkgDir == "" {
				pkgDir = filepath.Join(regDir, "packages")
			}
			return candidate, pkgDir, nil
		}
	}

	defaultCache := registry.NewCache("")
	chipDir, cacheErr := defaultCache.ChipSourcePath(chip)
	if cacheErr != nil {
		return "", "", fmt.Errorf("resolve chip %q from default registry: %w", chip, cacheErr)
	}
	pkgDir := packagesDir
	if pkgDir == "" && filepath.Base(filepath.Dir(chipDir)) == "chips" {
		pkgDir = filepath.Dir(filepath.Dir(chipDir))
	}
	return chipDir, pkgDir, nil
}

func validateChipIdentity(requested, chipDir string, cm *manifest.ChipManifest) error {
	baseName := filepath.Base(chipDir)
	if cm != nil && strings.TrimSpace(cm.Name) != "" {
		if !strings.EqualFold(cm.Name, requested) && !strings.EqualFold(baseName, requested) {
			return fmt.Errorf("requested chip %q mismatches chip_manifest name %q (%s)", requested, cm.Name, chipDir)
		}
	}
	return nil
}

func parseChipManifestStrict(path string) (*manifest.ChipManifest, error) {
	raw, err := readFileBounded(path, maxJSONManifestBytes)
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, errors.New("chip_manifest.json is empty")
	}

	if err := checkJSONNoDuplicateKeys(raw); err != nil {
		return nil, err
	}

	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()

	var cm manifest.ChipManifest
	if err := dec.Decode(&cm); err != nil {
		return nil, fmt.Errorf("decode chip_manifest.json: %w", err)
	}

	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("unexpected trailing JSON content in chip_manifest.json")
	}

	if strings.TrimSpace(cm.Arch) == "" && cm.SlotCapabilities == nil && cm.Crypto == nil && strings.TrimSpace(cm.Name) == "" {
		return nil, errors.New("chip_manifest.json contains no recognized chip definition")
	}
	return &cm, nil
}

func checkJSONNoDuplicateKeys(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := scanJSONValue(dec); err != nil {
		return err
	}
	return nil
}

func scanJSONValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("invalid JSON syntax: %w", err)
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}

	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for dec.More() {
			keyTok, keyErr := dec.Token()
			if keyErr != nil {
				return fmt.Errorf("invalid JSON object key: %w", keyErr)
			}
			key, isStr := keyTok.(string)
			if !isStr {
				return errors.New("expected string JSON object key")
			}
			if _, dup := seen[key]; dup {
				return fmt.Errorf("duplicate JSON key %q", key)
			}
			seen[key] = struct{}{}
			if valErr := scanJSONValue(dec); valErr != nil {
				return valErr
			}
		}
		endTok, endErr := dec.Token()
		if endErr != nil || endTok != json.Delim('}') {
			return errors.New("unterminated JSON object")
		}
	case '[':
		for dec.More() {
			if elemErr := scanJSONValue(dec); elemErr != nil {
				return elemErr
			}
		}
		endTok, endErr := dec.Token()
		if endErr != nil || endTok != json.Delim(']') {
			return errors.New("unterminated JSON array")
		}
	}
	return nil
}

func effectiveArch(cm *manifest.ChipManifest, hw *manifest.HardwareJson) string {
	if cm != nil && strings.TrimSpace(cm.Arch) != "" {
		return strings.TrimSpace(cm.Arch)
	}
	if hw != nil && strings.TrimSpace(hw.ChipFamily) != "" {
		return strings.TrimSpace(hw.ChipFamily)
	}
	return ""
}

func effectiveExecModel(explicit string, cm *manifest.ChipManifest) string {
	if trimmed := strings.TrimSpace(explicit); trimmed != "" {
		return trimmed
	}
	if cm != nil && cm.SlotCapabilities != nil {
		return strings.TrimSpace(cm.SlotCapabilities.ExecModel)
	}
	return ""
}

func effectiveStage0ExecMode(hw *manifest.HardwareJson, cm *manifest.ChipManifest) string {
	if hw != nil && strings.TrimSpace(hw.Flash.Stage0ExecMode) != "" {
		return strings.TrimSpace(hw.Flash.Stage0ExecMode)
	}
	if cm != nil && strings.TrimSpace(cm.Stage0ExecMode) != "" {
		return strings.TrimSpace(cm.Stage0ExecMode)
	}
	return "xip"
}

func effectiveVtorAlign(hw *manifest.HardwareJson) uint32 {
	if hw == nil {
		return 0
	}
	if hw.Flash.VtorAlignment > 0 {
		return hw.Flash.VtorAlignment
	}
	return hw.Memory.VtorAlignment
}

func resolveFlashSectorSize(hw *manifest.HardwareJson) (uint32, error) {
	if hw == nil {
		return 0, errors.New("hardware.json required to resolve flash sector size")
	}

	var maxSector uint32
	for _, r := range hw.Flash.Regions {
		kind := strings.ToLower(strings.TrimSpace(r.Type))
		if kind == "bootrom" || kind == "rom" || kind == "otp" || kind == "efuse" {
			continue
		}
		if r.SectorSize > maxSector {
			maxSector = r.SectorSize
		}
	}

	if maxSector == 0 {
		return 0, errors.New("hardware.json declares no flash region with non-zero sector_size")
	}
	if maxSector&(maxSector-1) != 0 {
		return 0, fmt.Errorf("flash sector_size %d is not a power of two", maxSector)
	}
	if maxSector > tbm1.MaxSectorSize {
		return 0, fmt.Errorf("flash sector_size %d exceeds TBM1 limit %d", maxSector, tbm1.MaxSectorSize)
	}
	return maxSector, nil
}

func resolveFlashTotalBytes(hw *manifest.HardwareJson) (uint64, error) {
	if hw == nil {
		return 0, errors.New("hardware.json required to resolve flash size")
	}
	if hw.Flash.Size > 0 {
		return uint64(hw.Flash.Size), nil
	}

	var total uint64
	for _, r := range hw.Flash.Regions {
		kind := strings.ToLower(strings.TrimSpace(r.Type))
		if kind == "bootrom" || kind == "rom" || kind == "otp" || kind == "efuse" {
			continue
		}
		regSize := uint64(r.Size)
		if regSize == 0 && r.SectorSize > 0 && r.Count > 0 {
			regSize = uint64(r.SectorSize) * uint64(r.Count)
		}
		total += regSize
	}
	if total == 0 {
		return 0, errors.New("hardware.json declares zero usable flash capacity")
	}
	return total, nil
}

func alignUpU64(val, align uint64) (uint64, error) {
	if align == 0 {
		return val, nil
	}
	if val > math.MaxUint64-(align-1) {
		return 0, fmt.Errorf("alignment overflow for %d", val)
	}
	return ((val + align - 1) / align) * align, nil
}

func parseRAMWindow(baseStr, sizeStr string) (uint64, uint64, bool, error) {
	baseTrim := strings.TrimSpace(baseStr)
	sizeTrim := strings.TrimSpace(sizeStr)
	if baseTrim == "" || sizeTrim == "" {
		return 0, 0, false, nil
	}
	baseVal, err := build.ParseU64Literal(baseTrim)
	if err != nil {
		return 0, 0, false, fmt.Errorf("parse RAM base %q: %w", baseStr, err)
	}
	sizeVal, err := build.ParseU64Literal(sizeTrim)
	if err != nil {
		return 0, 0, false, fmt.Errorf("parse RAM size %q: %w", sizeStr, err)
	}
	if sizeVal == 0 {
		return 0, 0, false, nil
	}
	return baseVal, sizeVal, true, nil
}

func validateRAMEntryPoint(hw *manifest.HardwareJson, entry uint32) error {
	if entry == 0 || entry%4 != 0 {
		return fmt.Errorf("RAM-exec entry_point 0x%x must be non-zero and 4-byte aligned", entry)
	}
	if hw == nil {
		return errors.New("hardware.json required to validate RAM-exec entry_point")
	}

	type ramWindow struct {
		base string
		size string
	}
	windows := []ramWindow{
		{base: hw.Memory.IramBase, size: hw.Memory.IramSize},
		{base: hw.Memory.SramBase, size: hw.Memory.SramSize},
	}

	var parsedAny bool
	e64 := uint64(entry)
	for _, w := range windows {
		base, size, ok, err := parseRAMWindow(w.base, w.size)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		parsedAny = true
		if e64 >= base && e64 < base+size {
			return nil
		}
	}

	if !parsedAny {
		return errors.New("hardware.json defines no memory.iram or memory.sram window for RAM-exec stage1")
	}
	return fmt.Errorf("RAM-exec entry_point 0x%x falls outside hardware memory.iram/sram windows", entry)
}
