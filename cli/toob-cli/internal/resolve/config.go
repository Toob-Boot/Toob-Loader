package resolve

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// cmakeEscaper escapes a value for use inside a quoted CMake argument:
// quotes, variable references and line breaks lose their meaning, and ';' is
// kept as a literal character instead of a list separator.
var cmakeEscaper = strings.NewReplacer(
	`\`, `\\`,
	`"`, `\"`,
	`$`, `\$`,
	`;`, `\;`,
	"\n", `\n`,
	"\r", `\r`,
)

var cmakeCommentSanitizer = strings.NewReplacer("\r\n", " ", "\n", " ", "\r", " ")

var cmakeVarPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func sanitizeCMakeVar(name string) string {
	if cmakeVarPattern.MatchString(name) {
		return name
	}
	var b strings.Builder
	b.Grow(len(name) + 1)
	for i := 0; i < len(name); i++ {
		c := name[i]
		valid := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_' || (i > 0 && c >= '0' && c <= '9')
		if valid {
			b.WriteByte(c)
		} else {
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "_"
	}
	return b.String()
}

// cmakeFile accumulates the lines of toob_config.cmake.
type cmakeFile struct{ b strings.Builder }

func (f *cmakeFile) comment(text string) {
	fmt.Fprintf(&f.b, "# %s\n", cmakeCommentSanitizer.Replace(text))
}

func (f *cmakeFile) set(name, value string) {
	fmt.Fprintf(&f.b, "set(%s \"%s\")\n", sanitizeCMakeVar(name), cmakeEscaper.Replace(value))
}

func (f *cmakeFile) setPath(name, path string) { f.set(name, filepath.ToSlash(path)) }

func (f *cmakeFile) setBool(name string, on bool) {
	state := "OFF"
	if on {
		state = "ON"
	}
	fmt.Fprintf(&f.b, "set(%s %s)\n", sanitizeCMakeVar(name), state)
}

// setList emits a CMake list; each element is escaped individually.
func (f *cmakeFile) setList(name string, items []string, asPath bool) {
	escaped := make([]string, len(items))
	for i, item := range items {
		if asPath {
			item = filepath.ToSlash(item)
		}
		escaped[i] = cmakeEscaper.Replace(item)
	}
	fmt.Fprintf(&f.b, "set(%s \"%s\")\n", sanitizeCMakeVar(name), strings.Join(escaped, ";"))
}

func (f *cmakeFile) appendPath(list, path string) {
	fmt.Fprintf(&f.b, "list(APPEND %s \"%s\")\n", sanitizeCMakeVar(list), cmakeEscaper.Replace(filepath.ToSlash(path)))
}

// RenderConfig renders toob_config.cmake for the plan. cliPath is the toob
// executable the CMake build calls back into.
func (p *Plan) RenderConfig(sdk SDKPaths, cliPath string) string {
	var f cmakeFile
	f.set("TOOB_ARCH", p.Chip.Arch)
	f.set("TOOB_CHIP", p.Chip.Name)
	f.set("TOOLCHAIN_PREFIX", p.Chip.Prefix)
	f.setPath("TOOB_CORE_DIR", sdk.Core)
	f.setPath("TOOB_STAGE0_DIR", sdk.Stage0)
	f.setPath("TOOB_HAL_CHIP_DIR", p.Chip.Dir)
	f.setPath("TOOB_HAL_ARCH_DIR", p.Arch.Dir)
	f.setPath("TOOB_SDK_DIR", sdk.SDK)
	f.setPath("TOOB_CLI_PATH", cliPath)
	f.setPath("TOOB_CRYPTO_DIR", filepath.Join(sdk.Bootloader, "crypto"))
	f.setBool("TOOB_FEATURE_PQC_HYBRID", p.PQCEnabled())
	if p.Profile != "" {
		f.set("TOOB_PROFILE", p.Profile)
		f.setBool("TOOB_MOCK_HW", p.MockHW)
	}
	for _, dir := range p.Drivers {
		f.appendPath("TOOB_DRIVERS", dir)
	}
	for _, list := range []struct {
		name  string
		items []string
	}{
		{"TOOB_ARCH_SOURCES", p.Arch.Sources},
		{"TOOB_CHIP_SOURCES", p.ChipSources},
		{"TOOB_CHIP_INCLUDES", p.ChipIncludes},
		{"TOOB_DRIVER_SOURCES", p.DriverSources},
	} {
		if len(list.items) > 0 {
			f.setList(list.name, list.items, true)
		}
	}

	f.comment("--- Dynamic Crypto Configuration ---")
	for _, slot := range p.Crypto {
		slot.render(&f)
	}

	f.comment("--- Dynamic Recovery Configuration ---")
	f.set("TOOB_RECOVERY_CRYPTO_BACKEND", p.Recovery.Backend)
	f.set("TOOB_RECOVERY_CRYPTO_HASH", p.Recovery.Hash)
	renderRecoveryCryptoSlot(&f, "TOOB_RECOVERY_CRYPTO_BACKEND", p.Recovery.BackendSlot)
	renderRecoveryCryptoSlot(&f, "TOOB_RECOVERY_CRYPTO_HASH", p.Recovery.HashSlot)
	for _, list := range []struct {
		name  string
		items []string
	}{
		{"TOOB_RECOVERY_DRIVERS", p.Recovery.Drivers},
		{"TOOB_RECOVERY_DRIVER_SOURCES", p.Recovery.DriverSources},
		{"TOOB_RECOVERY_SOURCES", p.Recovery.Sources},
		{"TOOB_RECOVERY_INCLUDES", p.Recovery.Includes},
	} {
		if len(list.items) > 0 {
			f.setList(list.name, list.items, true)
		}
	}
	return f.b.String()
}

func (s CryptoSlot) render(f *cmakeFile) {
	prefix := "TOOB_CRYPTO_" + strings.ToUpper(s.Slot)
	f.setBool(prefix+"_ENABLED", s.Enabled())
	if !s.Enabled() {
		return
	}
	f.set(prefix+"_NAME", s.Name)
	f.setPath(prefix+"_DIR", s.Dir)
	if s.Reused {
		f.comment(fmt.Sprintf("%s slot reuses package '%s' (already compiled by another slot)", strings.ToUpper(s.Slot), s.Name))
	} else if len(s.Sources) > 0 {
		f.setList(prefix+"_SOURCES", s.Sources, true)
	}
	if s.Wrapper != "" {
		f.setPath(prefix+"_WRAPPER", s.Wrapper)
	}
	if !s.Reused && len(s.Cflags) > 0 {
		f.setList(prefix+"_CFLAGS", s.Cflags, false)
	}
	if len(s.Includes) > 0 {
		f.setList(prefix+"_INCLUDES", s.Includes, true)
	}
}

func renderRecoveryCryptoSlot(f *cmakeFile, prefix string, s *CryptoSlot) {
	if s == nil || !s.Enabled() {
		return
	}
	f.setPath(prefix+"_DIR", s.Dir)
	if len(s.Sources) > 0 {
		f.setList(prefix+"_SOURCES", s.Sources, true)
	}
	if s.Wrapper != "" {
		f.setPath(prefix+"_WRAPPER", s.Wrapper)
	}
	if len(s.Cflags) > 0 {
		f.setList(prefix+"_CFLAGS", s.Cflags, false)
	}
	if len(s.Includes) > 0 {
		f.setList(prefix+"_INCLUDES", s.Includes, true)
	}
}
