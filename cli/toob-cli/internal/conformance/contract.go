package conformance

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

//go:embed hal_contract_embed.json
var embeddedHalContractJSON []byte

const (
	halContractFilename     = "hal_contract.json"
	maxPackageManifestBytes = 1 << 20
	maxSourceFileBytes      = 4 << 20
	maxJSONNestingDepth     = 32
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

func validateStrictJSONStructure(data []byte, maxDepth int) error {
	type frame struct {
		isObj   bool
		needKey bool
		keys    map[string]struct{}
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	var stack []frame

	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}

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
		} else if len(stack) == 0 {
			return nil
		}
	}
}

func decodeStrictJSON[T any](label string, data []byte) (*T, error) {
	if err := validateStrictJSONStructure(data, maxJSONNestingDepth); err != nil {
		return nil, fmt.Errorf("invalid %s: %w", label, err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var v T
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("invalid %s: %w", label, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("invalid %s: unexpected trailing JSON data", label)
	}
	return &v, nil
}

func loadHalContract(packagePath string, opts AuditOptions) (*halContract, error) {
	if strings.TrimSpace(opts.ContractPath) != "" {
		raw, err := readBoundedHostFile(opts.ContractPath, maxPackageManifestBytes)
		if err != nil {
			return nil, fmt.Errorf("read HAL contract %s: %w", opts.ContractPath, err)
		}
		return parseAndValidateHalContract(opts.ContractPath, raw)
	}

	if foundPath := discoverHalContractPath(packagePath); foundPath != "" {
		raw, err := readBoundedHostFile(foundPath, maxPackageManifestBytes)
		if err != nil {
			return nil, fmt.Errorf("read HAL contract %s: %w", foundPath, err)
		}
		return parseAndValidateHalContract(foundPath, raw)
	}

	return parseAndValidateHalContract("embedded:hal_contract.json", embeddedHalContractJSON)
}

func readBoundedHostFile(path string, maxBytes int64) ([]byte, error) {
	// #nosec G304 -- explicit contract file path configured or discovered from SDK root.
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if st.Size() > maxBytes {
		return nil, fmt.Errorf("%s (%d bytes) exceeds %d-byte limit", path, st.Size(), maxBytes)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("%s exceeds %d-byte limit", path, maxBytes)
	}
	return data, nil
}

func discoverHalContractPath(packagePath string) string {
	var roots []string
	if envDir := strings.TrimSpace(os.Getenv("TOOB_COMPILER_DIR")); envDir != "" {
		roots = append(roots, envDir)
	}
	if absPkg, err := filepath.Abs(packagePath); err == nil {
		roots = append(roots, absPkg)
	}
	if wd, err := os.Getwd(); err == nil {
		roots = append(roots, wd)
	}

	for _, start := range roots {
		cur := start
		for cur != "" {
			curRoot, rootErr := os.OpenRoot(cur)
			if rootErr == nil {
				for _, rel := range []string{
					filepath.Join("toobloader", "core", halContractFilename),
					filepath.Join("core", halContractFilename),
					halContractFilename,
				} {
					if st, statErr := curRoot.Stat(rel); statErr == nil && st.Mode().IsRegular() {
						_ = curRoot.Close()
						return filepath.Join(cur, rel)
					}
				}
				_ = curRoot.Close()
			}
			parent := filepath.Dir(cur)
			if parent == cur {
				break
			}
			cur = parent
		}
	}
	return ""
}

func parseAndValidateHalContract(label string, data []byte) (*halContract, error) {
	hc, err := decodeStrictJSON[halContract](label, data)
	if err != nil {
		return nil, err
	}
	if hc.SchemaVersion <= 0 {
		return nil, fmt.Errorf("invalid %s: unsupported schema_version %d", label, hc.SchemaVersion)
	}
	if len(hc.Traits) == 0 {
		return nil, fmt.Errorf("invalid %s: traits must not be empty", label)
	}
	if len(hc.Arch.RequiredSymbols) == 0 {
		return nil, fmt.Errorf("invalid %s: arch.required_symbols must not be empty", label)
	}
	return hc, nil
}

func (hc *halContract) findDriverTrait(traitName string) *halTraitContract {
	for i := range hc.Traits {
		if hc.Traits[i].Name == traitName {
			return &hc.Traits[i]
		}
	}
	for i := range hc.Traits {
		t := &hc.Traits[i]
		if t.InstantiateWhen == "driver_bound" && slices.Contains(t.DriverTraits, traitName) {
			return t
		}
	}
	return nil
}

func (t *halTraitContract) driverSymbolContract() (requiredKeys, allowedKeys []string, needAny bool) {
	if t.BindingMode == "symbol_pointer" {
		if t.SymbolKey != "" {
			return []string{t.SymbolKey}, []string{t.SymbolKey}, false
		}
		return nil, nil, false
	}
	for i := range t.Methods {
		m := &t.Methods[i]
		switch m.Source {
		case "driver":
			if m.Key != "" {
				if !slices.Contains(allowedKeys, m.Key) {
					allowedKeys = append(allowedKeys, m.Key)
				}
				if m.Required && !slices.Contains(requiredKeys, m.Key) {
					requiredKeys = append(requiredKeys, m.Key)
				}
			}
		case "arch_timer_init_adapter", "noop_void_adapter":
			if m.DriverOverrideKey != "" && !slices.Contains(allowedKeys, m.DriverOverrideKey) {
				allowedKeys = append(allowedKeys, m.DriverOverrideKey)
			}
		}
	}
	needAny = (t.RequireAnyMethod || t.InstantiateWhen == "any_method_bound") && len(requiredKeys) == 0
	return requiredKeys, allowedKeys, needAny
}

func (hc *halContract) cryptoCategoryRequirements() (abiVersion string, requiredByCat map[string][]string) {
	requiredByCat = make(map[string][]string)
	for i := range hc.Traits {
		t := &hc.Traits[i]
		if t.Name != "crypto" {
			continue
		}
		abiVersion = t.AbiVersion
		for j := range t.Methods {
			m := &t.Methods[j]
			if m.Source != "crypto" || m.CryptoCategory == "" {
				continue
			}
			if _, exists := requiredByCat[m.CryptoCategory]; !exists {
				requiredByCat[m.CryptoCategory] = nil
			}
			if m.Required && m.Key != "" && !slices.Contains(requiredByCat[m.CryptoCategory], m.Key) {
				requiredByCat[m.CryptoCategory] = append(requiredByCat[m.CryptoCategory], m.Key)
			}
		}
		break
	}
	return abiVersion, requiredByCat
}

func (hc *halContract) requiredArchSymbols() []string {
	out := slices.Clone(hc.Arch.RequiredSymbols)
	if hc.Arch.EntryIRQDisableSymbol != "" && !slices.Contains(out, hc.Arch.EntryIRQDisableSymbol) {
		out = append(out, hc.Arch.EntryIRQDisableSymbol)
	}
	return out
}
