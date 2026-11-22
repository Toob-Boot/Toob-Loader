package build

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

const (
	halContractFile    = "hal_contract.json"
	cryptoManifestFile = "crypto_manifest.json"
)

type halContract struct {
	SchemaVersion      int                `json:"schema_version"`
	PlatformStructType string             `json:"platform_struct_type"`
	PlatformInitSymbol string             `json:"platform_init_symbol"`
	BringupFunction    string             `json:"bringup_function"`
	BringupStepType    string             `json:"bringup_step_type"`
	CoreHeaders        []string           `json:"core_headers"`
	Arch               halArchContract    `json:"arch"`
	Traits             []halTraitContract `json:"traits"`
	BringupSteps       []halBringupStep   `json:"bringup_steps"`
}

type halArchContract struct {
	RequiredSymbols       []string `json:"required_symbols"`
	BaseRequiredMacros    []string `json:"base_required_macros"`
	EntryIRQDisableSymbol string   `json:"entry_irq_disable_symbol"`
}

type halTraitContract struct {
	Name             string                `json:"name"`
	PlatformField    string                `json:"platform_field"`
	BindingMode      string                `json:"binding_mode"`
	StructType       string                `json:"struct_type,omitempty"`
	AbiVersion       string                `json:"abi_version,omitempty"`
	AbiConstant      string                `json:"abi_constant,omitempty"`
	Optional         bool                  `json:"optional"`
	InstantiateWhen  string                `json:"instantiate_when"`
	DriverTraits     []string              `json:"driver_traits,omitempty"`
	RequireAnyMethod bool                  `json:"require_any_method,omitempty"`
	SymbolKey        string                `json:"symbol_key,omitempty"`
	Guard            string                `json:"guard,omitempty"`
	Methods          []halMethodContract   `json:"methods,omitempty"`
	Properties       []halPropertyContract `json:"properties,omitempty"`
}

type halMethodContract struct {
	Field             string   `json:"field"`
	Source            string   `json:"source"`
	Key               string   `json:"key,omitempty"`
	CryptoCategory    string   `json:"crypto_category,omitempty"`
	ArgMacro          string   `json:"arg_macro,omitempty"`
	DriverOverrideKey string   `json:"driver_override_key,omitempty"`
	DriverTraits      []string `json:"driver_traits,omitempty"`
	Required          bool     `json:"required"`
	Guard             string   `json:"guard,omitempty"`
}

type halPropertyContract struct {
	Field     string `json:"field"`
	Source    string `json:"source"`
	Expr      string `json:"expr,omitempty"`
	Key       string `json:"key,omitempty"`
	HwKey     string `json:"hw_key,omitempty"`
	ChipMacro string `json:"chip_macro,omitempty"`
	Default   string `json:"default,omitempty"`
}

type halBringupStep struct {
	Trait     string `json:"trait"`
	KindEnum  string `json:"kind_enum"`
	Mandatory bool   `json:"mandatory"`
	PanicSite string `json:"panic_site"`
	Condition string `json:"condition"`
}

func resolveHalContractPath(coreDir string, sourceDirs []string) (string, error) {
	if coreDir != "" {
		p := filepath.Join(coreDir, halContractFile)
		info, err := os.Stat(p)
		if err != nil {
			return "", fmt.Errorf("FATAL: HAL contract %s: %w", p, err)
		}
		if !info.Mode().IsRegular() {
			return "", fmt.Errorf("FATAL: HAL contract %s is not a regular file", p)
		}
		return p, nil
	}
	for _, dir := range sourceDirs {
		for _, candidate := range []string{
			filepath.Join(dir, halContractFile),
			filepath.Join(dir, "core", halContractFile),
		} {
			if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
				return candidate, nil
			}
		}
	}
	return "", errors.New("FATAL: hal_contract.json not found (set Inputs.CoreDir or include the core directory in Inputs.SourceDirs)")
}

func loadHalContract(coreDir string, sourceDirs []string) (*halContract, error) {
	path, err := resolveHalContractPath(coreDir, sourceDirs)
	if err != nil {
		return nil, err
	}
	return loadHalContractFromFile(path)
}

func loadHalContractFromFile(path string) (*halContract, error) {
	hc, err := decodeJSONFile[halContract](path, true)
	if err != nil {
		return nil, fmt.Errorf("FATAL: HAL contract: %w", err)
	}
	if err := validateHalContract(hc); err != nil {
		return nil, fmt.Errorf("FATAL: HAL contract %s: %w", path, err)
	}
	return hc, nil
}

func validateHalContract(hc *halContract) error {
	if hc == nil {
		return errors.New("contract must not be nil")
	}
	if hc.SchemaVersion <= 0 {
		return fmt.Errorf("unsupported schema_version %d", hc.SchemaVersion)
	}
	if !isCSymbol(hc.PlatformStructType) {
		return fmt.Errorf("invalid platform_struct_type %q", hc.PlatformStructType)
	}
	if !isCSymbol(hc.PlatformInitSymbol) {
		return fmt.Errorf("invalid platform_init_symbol %q", hc.PlatformInitSymbol)
	}
	if !isCSymbol(hc.BringupFunction) {
		return fmt.Errorf("invalid bringup_function %q", hc.BringupFunction)
	}
	if !isCSymbol(hc.BringupStepType) {
		return fmt.Errorf("invalid bringup_step_type %q", hc.BringupStepType)
	}
	if len(hc.CoreHeaders) == 0 {
		return errors.New("core_headers must not be empty")
	}
	for _, h := range hc.CoreHeaders {
		if err := validateHeaderPath(h); err != nil {
			return fmt.Errorf("core_headers: %w", err)
		}
	}
	for _, symKey := range hc.Arch.RequiredSymbols {
		if err := ValidateName("arch required symbol", symKey); err != nil {
			return err
		}
	}
	for _, m := range hc.Arch.BaseRequiredMacros {
		if !isCSymbol(m) {
			return fmt.Errorf("invalid arch base_required_macros entry %q", m)
		}
	}
	if hc.Arch.EntryIRQDisableSymbol != "" {
		if err := ValidateName("entry_irq_disable_symbol", hc.Arch.EntryIRQDisableSymbol); err != nil {
			return err
		}
	}

	seenTraits := make(map[string]bool, len(hc.Traits))
	seenPlatformFields := make(map[string]bool, len(hc.Traits))
	for i := range hc.Traits {
		t := &hc.Traits[i]
		if !isCSymbol(t.Name) {
			return fmt.Errorf("invalid trait name %q", t.Name)
		}
		if seenTraits[t.Name] {
			return fmt.Errorf("duplicate trait %q", t.Name)
		}
		seenTraits[t.Name] = true
		if !isCSymbol(t.PlatformField) {
			return fmt.Errorf("trait %q: invalid platform_field %q", t.Name, t.PlatformField)
		}
		if seenPlatformFields[t.PlatformField] {
			return fmt.Errorf("trait %q: duplicate platform_field %q", t.Name, t.PlatformField)
		}
		seenPlatformFields[t.PlatformField] = true

		switch t.InstantiateWhen {
		case "driver_bound", "always", "any_method_bound":
		default:
			return fmt.Errorf("trait %q: unsupported instantiate_when %q", t.Name, t.InstantiateWhen)
		}
		if t.AbiVersion != "" {
			if err := ValidateName("abi_version", t.AbiVersion); err != nil {
				return fmt.Errorf("trait %q: %w", t.Name, err)
			}
		}
		if t.AbiConstant != "" && !isCSymbol(t.AbiConstant) {
			return fmt.Errorf("trait %q: invalid abi_constant %q", t.Name, t.AbiConstant)
		}
		for _, dt := range t.DriverTraits {
			if err := ValidateName("driver_traits", dt); err != nil {
				return fmt.Errorf("trait %q: %w", t.Name, err)
			}
		}
		if t.Guard != "" {
			if err := validateGuardExpr(t.Guard); err != nil {
				return fmt.Errorf("trait %q: %w", t.Name, err)
			}
		}

		switch t.BindingMode {
		case "struct":
			if !isCSymbol(t.StructType) {
				return fmt.Errorf("trait %q: invalid struct_type %q", t.Name, t.StructType)
			}
		case "symbol_pointer":
			if err := ValidateName("symbol_key", t.SymbolKey); err != nil {
				return fmt.Errorf("trait %q: %w", t.Name, err)
			}
		default:
			return fmt.Errorf("trait %q: unsupported binding_mode %q", t.Name, t.BindingMode)
		}

		seenFields := make(map[string]bool, len(t.Methods)+len(t.Properties))
		for j := range t.Methods {
			m := &t.Methods[j]
			if !isCSymbol(m.Field) {
				return fmt.Errorf("trait %q: invalid method field %q", t.Name, m.Field)
			}
			if seenFields[m.Field] {
				return fmt.Errorf("trait %q: duplicate field %q", t.Name, m.Field)
			}
			seenFields[m.Field] = true
			if err := validateHalMethod(t.Name, *m); err != nil {
				return err
			}
		}
		for _, p := range t.Properties {
			if !isCSymbol(p.Field) {
				return fmt.Errorf("trait %q: invalid property field %q", t.Name, p.Field)
			}
			if seenFields[p.Field] {
				return fmt.Errorf("trait %q: duplicate field %q", t.Name, p.Field)
			}
			seenFields[p.Field] = true
			if err := validateHalProperty(t.Name, p); err != nil {
				return err
			}
		}
	}

	for _, step := range hc.BringupSteps {
		if !seenTraits[step.Trait] {
			return fmt.Errorf("bringup_steps references unknown trait %q", step.Trait)
		}
		if !isCSymbol(step.KindEnum) {
			return fmt.Errorf("bringup_steps[%s]: invalid kind_enum %q", step.Trait, step.KindEnum)
		}
		if step.PanicSite != "0" && !isCSymbol(step.PanicSite) {
			return fmt.Errorf("bringup_steps[%s]: invalid panic_site %q", step.Trait, step.PanicSite)
		}
		switch step.Condition {
		case "always", "trait_bound", "init_bound":
		default:
			return fmt.Errorf("bringup_steps[%s]: unsupported condition %q", step.Trait, step.Condition)
		}
	}
	return nil
}

func validateHalMethod(traitName string, m halMethodContract) error {
	switch m.Source {
	case "driver":
		if err := ValidateName("method key", m.Key); err != nil {
			return fmt.Errorf("trait %q method %q: %w", traitName, m.Field, err)
		}
	case "arch":
		if err := ValidateName("arch method key", m.Key); err != nil {
			return fmt.Errorf("trait %q method %q: %w", traitName, m.Field, err)
		}
	case "crypto":
		if err := ValidateName("crypto_category", m.CryptoCategory); err != nil {
			return fmt.Errorf("trait %q method %q: %w", traitName, m.Field, err)
		}
		if err := ValidateName("crypto method key", m.Key); err != nil {
			return fmt.Errorf("trait %q method %q: %w", traitName, m.Field, err)
		}
	case "arch_timer_init_adapter":
		if err := ValidateName("arch adapter key", m.Key); err != nil {
			return fmt.Errorf("trait %q method %q: %w", traitName, m.Field, err)
		}
		if !isCSymbol(m.ArgMacro) {
			return fmt.Errorf("trait %q method %q: invalid arg_macro %q", traitName, m.Field, m.ArgMacro)
		}
		if m.DriverOverrideKey != "" {
			if err := ValidateName("driver_override_key", m.DriverOverrideKey); err != nil {
				return fmt.Errorf("trait %q method %q: %w", traitName, m.Field, err)
			}
		}
	case "noop_void_adapter":
		if m.DriverOverrideKey != "" {
			if err := ValidateName("driver_override_key", m.DriverOverrideKey); err != nil {
				return fmt.Errorf("trait %q method %q: %w", traitName, m.Field, err)
			}
		}
	default:
		return fmt.Errorf("trait %q method %q: unsupported source %q", traitName, m.Field, m.Source)
	}
	for _, dt := range m.DriverTraits {
		if err := ValidateName("method driver_traits", dt); err != nil {
			return fmt.Errorf("trait %q method %q: %w", traitName, m.Field, err)
		}
	}
	if m.Guard != "" {
		if err := validateGuardExpr(m.Guard); err != nil {
			return fmt.Errorf("trait %q method %q: %w", traitName, m.Field, err)
		}
	}
	return nil
}

func validateHalProperty(traitName string, p halPropertyContract) error {
	switch p.Source {
	case "macro":
		if !isCSymbol(p.Expr) {
			return fmt.Errorf("trait %q property %q: invalid macro expr %q", traitName, p.Field, p.Expr)
		}
	case "flash_max_erase_cycles":
		if p.Default == "" || !isSafeCUnsignedExpr(p.Default) {
			return fmt.Errorf("trait %q property %q: invalid default %q", traitName, p.Field, p.Default)
		}
	case "flash_timing_us":
		if err := ValidateName("hw_key", p.HwKey); err != nil {
			return fmt.Errorf("trait %q property %q: %w", traitName, p.Field, err)
		}
		if p.ChipMacro != "" && !isCSymbol(p.ChipMacro) {
			return fmt.Errorf("trait %q property %q: invalid chip_macro %q", traitName, p.Field, p.ChipMacro)
		}
		if p.Default == "" || !isSafeCUnsignedExpr(p.Default) {
			return fmt.Errorf("trait %q property %q: invalid default %q", traitName, p.Field, p.Default)
		}
	case "hardware_uint":
		if err := ValidateName("hw_key", p.HwKey); err != nil {
			return fmt.Errorf("trait %q property %q: %w", traitName, p.Field, err)
		}
		if p.ChipMacro != "" && !isCSymbol(p.ChipMacro) {
			return fmt.Errorf("trait %q property %q: invalid chip_macro %q", traitName, p.Field, p.ChipMacro)
		}
		if p.Default == "" || !isSafeCUnsignedExpr(p.Default) {
			return fmt.Errorf("trait %q property %q: invalid default %q", traitName, p.Field, p.Default)
		}
	case "driver_bool", "crypto_bool":
		if err := ValidateName("property key", p.Key); err != nil {
			return fmt.Errorf("trait %q property %q: %w", traitName, p.Field, err)
		}
		if p.Default != "" && p.Default != "true" && p.Default != "false" {
			return fmt.Errorf("trait %q property %q: boolean default must be 'true' or 'false', got %q", traitName, p.Field, p.Default)
		}
	default:
		return fmt.Errorf("trait %q property %q: unsupported source %q", traitName, p.Field, p.Source)
	}
	return nil
}

func isSafeCUnsignedExpr(s string) bool {
	if isCSymbol(s) {
		return true
	}
	raw := strings.TrimSuffix(s, "U")
	_, err := parseU32Literal(raw)
	return err == nil
}

func validateGuardExpr(guard string) error {
	trimmed := strings.TrimSpace(guard)
	if trimmed == "" {
		return errors.New("guard must not be whitespace-only")
	}
	if strings.Contains(guard, "/*") || strings.Contains(guard, "*/") || strings.Contains(guard, "//") {
		return fmt.Errorf("guard %q must not contain comment delimiters", guard)
	}
	for i := range len(guard) {
		c := guard[i]
		allowed := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '_' || c == ' ' || c == '!' || c == '&' || c == '|' || c == '(' || c == ')' ||
			c == '<' || c == '>' || c == '=' || c == '+' || c == '-'
		if !allowed {
			return fmt.Errorf("guard %q contains forbidden character %q at offset %d", guard, c, i)
		}
	}
	return nil
}

func loadCryptoManifests(dirs []string) ([]*CryptoManifest, error) {
	if len(dirs) == 0 {
		return nil, nil
	}
	manifests := make([]*CryptoManifest, 0, len(dirs))
	for _, dir := range dirs {
		path := filepath.Join(dir, cryptoManifestFile)
		cm, err := decodeJSONFile[CryptoManifest](path, true)
		if err != nil {
			return nil, fmt.Errorf("FATAL: crypto manifest: %w", err)
		}
		if err := validateCryptoManifestFiles(dir, path, cm); err != nil {
			return nil, err
		}
		manifests = append(manifests, cm)
	}
	return manifests, nil
}

func validateCryptoManifestFiles(dir, path string, cm *CryptoManifest) error {
	if err := validateCryptoManifest(cm); err != nil {
		return fmt.Errorf("FATAL: crypto manifest %s: %w", path, err)
	}
	if cm.Wrapper != "" {
		if err := validateRelPath("crypto wrapper", cm.Wrapper); err != nil {
			return fmt.Errorf("FATAL: crypto manifest %s wrapper: %w", path, err)
		}
		if _, err := containPath(dir, cm.Wrapper); err != nil {
			return fmt.Errorf("FATAL: crypto manifest %s wrapper: %w", path, err)
		}
	}
	for _, src := range cm.UpstreamSources {
		if err := validateRelPath("crypto upstream_source", src); err != nil {
			return fmt.Errorf("FATAL: crypto manifest %s upstream_sources: %w", path, err)
		}
		if _, err := containPath(dir, src); err != nil {
			return fmt.Errorf("FATAL: crypto manifest %s upstream_sources: %w", path, err)
		}
	}
	for _, inc := range cm.Includes {
		if inc != "." {
			if err := validateRelPath("crypto include", inc); err != nil {
				return fmt.Errorf("FATAL: crypto manifest %s includes: %w", path, err)
			}
		}
		if _, err := containPath(dir, inc); err != nil {
			return fmt.Errorf("FATAL: crypto manifest %s includes: %w", path, err)
		}
	}
	return nil
}

func validateCryptoManifest(cm *CryptoManifest) error {
	if cm == nil {
		return errors.New("crypto manifest must not be nil")
	}
	if cm.Name == "" {
		return errors.New("does not declare a 'name'")
	}
	if err := ValidatePackageRef("crypto", cm.Name); err != nil {
		return err
	}
	if len(cm.Category) == 0 {
		return fmt.Errorf("crypto '%s' must declare at least one category", cm.Name)
	}
	for _, cat := range cm.Category {
		if err := ValidateName("crypto category", cat); err != nil {
			return err
		}
	}
	if cm.AbiVersion != "" {
		if err := ValidateName("crypto abi_version", cm.AbiVersion); err != nil {
			return err
		}
	}
	for _, binding := range cm.ChipBindings() {
		if err := ValidateName("crypto chip_binding", binding); err != nil {
			return err
		}
	}
	for _, flag := range cm.Cflags {
		if err := ValidateCompilerFlag("crypto cflags", flag); err != nil {
			return err
		}
	}
	for _, h := range cm.Headers {
		if err := validateHeaderPath(h); err != nil {
			return fmt.Errorf("invalid header path %q: %w", h, err)
		}
	}
	for _, k := range slices.Sorted(maps.Keys(cm.Symbols)) {
		if err := ValidateName("crypto symbol key", k); err != nil {
			return err
		}
		if !isCSymbol(cm.Symbols[k]) {
			return fmt.Errorf("invalid C symbol %s=%q", k, cm.Symbols[k])
		}
	}
	return nil
}
