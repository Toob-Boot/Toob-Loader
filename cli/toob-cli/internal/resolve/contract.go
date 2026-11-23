package resolve

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

//go:embed hal_contract_embed.json
var embeddedHALContract []byte

type halContractSpec struct {
	SchemaVersion int                `json:"schema_version"`
	Traits        []halContractTrait `json:"traits"`
}

type halContractTrait struct {
	Name         string              `json:"name"`
	DriverTraits []string            `json:"driver_traits,omitempty"`
	Optional     bool                `json:"optional"`
	Guard        string              `json:"guard,omitempty"`
	Methods      []halContractMethod `json:"methods,omitempty"`
}

type halContractMethod struct {
	Field    string `json:"field"`
	Key      string `json:"key,omitempty"`
	Guard    string `json:"guard,omitempty"`
	Required bool   `json:"required"`
}

// loadHALContract loads hal_contract.json from coreDir when available, falling back
// to the embedded Core SDK contract snapshot.
func loadHALContract(coreDir string) (*halContractSpec, error) {
	if coreDir != "" {
		candidates := []string{
			filepath.Join(coreDir, "toobloader", "core", "hal_contract.json"),
			filepath.Join(coreDir, "hal_contract.json"),
		}
		for _, path := range candidates {
			st, err := os.Lstat(path)
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					continue
				}
				return nil, fmt.Errorf("hal_contract.json at %s: %w", path, err)
			}
			if !st.Mode().IsRegular() {
				return nil, fmt.Errorf("%s must be a regular file", path)
			}
			raw, err := readBoundedManifest(path)
			if err != nil {
				return nil, fmt.Errorf("reading %s: %w", path, err)
			}
			return parseHALContractBytes(raw, path)
		}
	}
	return parseHALContractBytes(embeddedHALContract, "embedded hal_contract.json")
}

func parseHALContractBytes(raw []byte, label string) (*halContractSpec, error) {
	if err := validateJSONStructure(raw); err != nil {
		return nil, fmt.Errorf("invalid %s: %w", label, err)
	}
	var spec halContractSpec
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&spec); err != nil {
		return nil, fmt.Errorf("decoding %s: %w", label, err)
	}
	return &spec, nil
}

// securityCriticalMockTraits derives hardware traits that protect device identity,
// key material, or secure provisioning directly from hal_contract.json so dev defaults
// never rely on a hardcoded slice.
func (c *halContractSpec) securityCriticalMockTraits() map[string]bool {
	out := make(map[string]bool)
	if c == nil {
		return out
	}
	securityMethods := map[string]bool{
		"read_pubkey":             true,
		"burn_pubkey":             true,
		"read_dslc":               true,
		"write_dslc":              true,
		"read_monotonic":          true,
		"advance_monotonic":       true,
		"set_protection_bits":     true,
		"enable_secure_boot":      true,
		"enable_flash_encryption": true,
	}
	for _, tr := range c.Traits {
		name := strings.ToLower(strings.TrimSpace(tr.Name))
		critical := name == "keystore" || name == "provisioning" || name == "otp"
		if !critical && strings.Contains(strings.ToUpper(tr.Guard), "PROVISIONING") {
			critical = true
		}
		if !critical {
			for _, m := range tr.Methods {
				if securityMethods[strings.ToLower(m.Key)] {
					critical = true
					break
				}
			}
		}
		if !critical {
			continue
		}
		if name != "" {
			out[name] = true
		}
		for _, dt := range tr.DriverTraits {
			if norm := strings.ToLower(strings.TrimSpace(dt)); norm != "" {
				out[norm] = true
			}
		}
	}
	// OTP hardware surfaces back both keystore and provisioning in Core SDK hal_contract.
	if out["keystore"] || out["provisioning"] {
		out["otp"] = true
	}
	return out
}

// expandMockToken expands a contract trait into any security-equivalent sibling traits
// (for example, keystore/provisioning <-> otp) derived from hal_contract.json.
func (c *halContractSpec) expandMockToken(tok string) []string {
	norm := strings.ToLower(strings.TrimSpace(tok))
	if norm == "" {
		return nil
	}
	crit := c.securityCriticalMockTraits()
	if crit[norm] {
		out := make([]string, 0, len(crit))
		for k := range crit {
			out = append(out, k)
		}
		slices.Sort(out)
		return out
	}
	return []string{norm}
}

// traitMatches reports whether declaredTrait satisfies expectedTrait according to
// hal_contract.json driver_traits mappings (e.g. confirm <-> rtc, console <-> uart).
func (c *halContractSpec) traitMatches(expectedTrait, declaredTrait string) bool {
	exp := strings.ToLower(strings.TrimSpace(expectedTrait))
	dec := strings.ToLower(strings.TrimSpace(declaredTrait))
	if exp == "" || dec == "" {
		return dec == "" || exp == dec
	}
	if exp == dec {
		return true
	}
	if c == nil {
		return false
	}
	for _, tr := range c.Traits {
		names := make([]string, 0, 1+len(tr.DriverTraits))
		if n := strings.ToLower(strings.TrimSpace(tr.Name)); n != "" {
			names = append(names, n)
		}
		for _, dt := range tr.DriverTraits {
			if d := strings.ToLower(strings.TrimSpace(dt)); d != "" {
				names = append(names, d)
			}
		}
		if slices.Contains(names, exp) && slices.Contains(names, dec) {
			return true
		}
	}
	return false
}
