package resolve

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Masterminds/semver/v3"

	manifestpkg "github.com/toob-boot/toob/internal/manifest"
	"github.com/toob-boot/toob/internal/registry"
)

// Origins of the resolved Core SDK version.
const (
	originLockfile = "lockfile-pinned"
	originDevice   = "device.toml"
	originAuto     = "auto-resolved"
	originFallback = "fallback"
)

var (
	compilerSemverPattern = regexp.MustCompile(`(?:^|[^0-9.])(\d+\.\d+(?:\.\d+)?)`)
	toolchainVerPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]*$`)
)

func isBranchRef(version string) bool { return version == "main" || version == "dev" }

func isDevModeEnv() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("TOOB_DEV")))
	return v == "1" || v == "true"
}

func validateToolchainVersion(kind, ver string) error {
	if ver == "" {
		return fmt.Errorf("%s must not be empty", kind)
	}
	if strings.Contains(ver, "..") || !toolchainVerPattern.MatchString(ver) {
		return fmt.Errorf("invalid %s %q", kind, ver)
	}
	return nil
}

// ExtractCompilerSemver extracts the major.minor[.patch] compiler version from
// toolchain version strings such as "esp-14.2.0_20251107", "15.2.1-1.1", "14.2.rel1",
// or `gcc -dumpfullversion -dumpversion` output.
func ExtractCompilerSemver(raw string) (*semver.Version, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, errors.New("empty compiler version")
	}
	m := compilerSemverPattern.FindStringSubmatch(trimmed)
	if len(m) < 2 {
		return nil, fmt.Errorf("cannot extract semantic compiler version from %q", raw)
	}
	verStr := m[1]
	if strings.Count(verStr, ".") == 1 {
		verStr += ".0"
	}
	return semver.NewVersion(verStr)
}

// CheckMinCompiler enforces chip_manifest.json min_compiler (REG-009) against a
// resolved or probed compiler version string.
func CheckMinCompiler(subject, currentRaw, minRaw string) error {
	if strings.TrimSpace(minRaw) == "" {
		return nil
	}
	if strings.EqualFold(strings.TrimSpace(minRaw), "latest") {
		return fmt.Errorf("%s declares invalid min_compiler = \"latest\" (REG-009)", subject)
	}
	vMin, err := ExtractCompilerSemver(minRaw)
	if err != nil {
		return fmt.Errorf("%s declares an invalid min_compiler %q: %w", subject, minRaw, err)
	}
	if strings.TrimSpace(currentRaw) == "" {
		return fmt.Errorf("%s requires compiler >= %s, but toolchain version is unknown", subject, minRaw)
	}
	vCur, err := ExtractCompilerSemver(currentRaw)
	if err != nil {
		return fmt.Errorf("cannot compare %s min_compiler %q against toolchain version %q: %w", subject, minRaw, currentRaw, err)
	}
	if vCur.LessThan(vMin) {
		return fmt.Errorf("%s requires compiler >= %s, but resolved toolchain version is %s (%s)",
			subject, minRaw, vCur.String(), currentRaw)
	}
	return nil
}

// resolveCoreSDK picks the Core SDK version: the lockfile pin wins over
// device.toml, and an unset or symbolic version resolves to the newest
// registry release. The result must satisfy the chip's minimum.
func resolveCoreSDK(in Input, chip *Chip) (CoreSDK, error) {
	if in.Device == nil {
		return CoreSDK{}, errors.New("device.toml input is nil")
	}
	version, origin := in.Device.Build.CoreSDK, originDevice
	if in.Lock != nil {
		if pinned := in.Lock.Environment.CoreSDK; pinned != "" {
			version, origin = pinned, originLockfile
		}
	}

	if version == "" || version == "latest" || version == "toob-boot" {
		version, origin = resolveLatestCoreSDK(in.Index, chip)
	}
	if err := validateRelName("Core SDK version", version); err != nil {
		return CoreSDK{}, err
	}
	if err := checkMinCoreSDK(fmt.Sprintf("chip '%s'", chip.Name), version, chip.Spec.MinCoreSDK); err != nil {
		return CoreSDK{}, err
	}
	return CoreSDK{Version: version, Origin: origin}, nil
}

func resolveLatestCoreSDK(idx *registry.Index, chip *Chip) (string, string) {
	if tag, err := latestCoreSDK(idx); err == nil {
		return tag, originAuto
	}
	if chip.Spec.MinCoreSDK != "" {
		return chip.Spec.MinCoreSDK, originFallback
	}
	return "main", originFallback
}

func checkMinCoreSDK(subject, current, min string) error {
	if min == "" || isBranchRef(current) {
		return nil
	}
	vCurrent, err := parseCoreSDKVersion(current)
	if err != nil {
		return fmt.Errorf("cannot check %s against Core SDK '%s': %w", subject, current, err)
	}
	vMin, err := parseCoreSDKVersion(min)
	if err != nil {
		return fmt.Errorf("%s declares an invalid min_core_sdk '%s': %w", subject, min, err)
	}
	if vCurrent.LessThan(vMin) {
		return fmt.Errorf("%s requires Core SDK >= %s, but the resolved version is %s", subject, min, current)
	}
	return nil
}

func parseCoreSDKVersion(tag string) (*semver.Version, error) {
	clean, _ := strings.CutPrefix(tag, "core/")
	if !strings.HasPrefix(clean, "v") {
		clean = "v" + clean
	}
	return semver.NewVersion(clean)
}

func latestCoreSDK(idx *registry.Index) (string, error) {
	if idx == nil || idx.Ecosystem == nil || len(idx.Ecosystem.CoreSDK) == 0 {
		return "", errors.New("no core SDK versions listed in registry")
	}
	var highest *semver.Version
	var highestTag string
	for _, tag := range idx.Ecosystem.CoreSDK {
		if v, err := parseCoreSDKVersion(tag); err == nil && (highest == nil || v.GreaterThan(highest)) {
			highest, highestTag = v, tag
		}
	}
	if highestTag == "" {
		return "", errors.New("no valid semantic versions for core SDK in registry")
	}
	return highestTag, nil
}

// SDKPaths locates the Core SDK components. Local project overrides of Core/Stage0/SDK
// are strictly gated behind development mode (TOOB_DEV=1 / --dev) so untrusted projects
// cannot shadow signature-verification C sources or break macro audits on spawned chips.
type SDKPaths struct {
	Bootloader string
	Core       string
	Stage0     string
	SDK        string
	Recovery   string
	LibToob    string
}

// LocateSDK resolves the SDK components from compilerRoot, allowing local overrides
// under root ONLY when TOOB_DEV=1 (--dev) is enabled and root contains Core SDK sources.
func LocateSDK(root, compilerRoot string) SDKPaths {
	dev := isDevModeEnv()
	hasLocalCore := false
	if dev && root != "" {
		if st, err := os.Stat(filepath.Join(root, "toobloader", "core")); err == nil && st.IsDir() {
			hasLocalCore = true
		}
	}

	pick := func(rel string) string {
		if hasLocalCore {
			local := filepath.Join(root, rel)
			if st, err := os.Stat(local); err == nil && st.IsDir() {
				return local
			}
		}
		return filepath.Join(compilerRoot, rel)
	}

	return SDKPaths{
		Bootloader: pick("toobloader"),
		Core:       pick(filepath.Join("toobloader", "core")),
		Stage0:     pick(filepath.Join("toobloader", "stage0")),
		SDK:        pick("sdk"),
		Recovery:   pick("recovery"),
		LibToob:    pick(filepath.Join("sdk", "libtoob")),
	}
}

func resolveToolchain(in Input, chip *Chip) (Toolchain, error) {
	name := strings.TrimSuffix(chip.Prefix, "-")
	if err := manifestpkg.ValidateName("toolchain", name); err != nil {
		return Toolchain{}, err
	}
	if in.Registry == nil {
		return Toolchain{}, errors.New("registry source is nil")
	}
	dir, err := in.Registry.ToolchainConfigPath(name)
	if err != nil {
		return Toolchain{}, fmt.Errorf("failed to resolve toolchain config for '%s': %w", name, err)
	}
	file, err := Contain(dir, "toolchain.cmake")
	if err != nil {
		return Toolchain{}, fmt.Errorf("registry toolchain '%s': %w", name, err)
	}
	if st, err := os.Lstat(file); err != nil {
		return Toolchain{}, fmt.Errorf("registry toolchain missing: %w", err)
	} else if !st.Mode().IsRegular() {
		return Toolchain{}, fmt.Errorf("registry toolchain %s must be a regular file", file)
	}

	var expectedVer, upstreamVer string
	if in.Index != nil {
		tcInfo := in.Index.Toolchains[name]
		expectedVer = tcInfo.Version
		upstreamVer = tcInfo.UpstreamVersion
	}
	if expectedVer != "" {
		if err := validateToolchainVersion("toolchain version", expectedVer); err != nil {
			return Toolchain{}, err
		}
	}
	if upstreamVer != "" {
		if err := validateToolchainVersion("toolchain upstream_version", upstreamVer); err != nil {
			return Toolchain{}, err
		}
	}

	var minCompiler string
	if chip.Spec != nil {
		minCompiler = chip.Spec.MinCompiler
	}

	tc := Toolchain{
		Name:            name,
		Prefix:          chip.Prefix,
		File:            file,
		ExpectedVersion: expectedVer,
		UpstreamVersion: upstreamVer,
		MinCompiler:     minCompiler,
	}

	pinnedFromLock := false
	if in.Lock != nil {
		if pinned, ok := in.Lock.Toolchains[name]; ok && pinned.Version != "" {
			if err := validateToolchainVersion("locked toolchain version", pinned.Version); err != nil {
				return Toolchain{}, err
			}
			tc.ExpectedVersion = pinned.Version
			pinnedFromLock = true
		} else if lc := in.Lock.GetChip(chip.Name); lc != nil && lc.ToolchainVersion != "" && (lc.Toolchain == "" || lc.Toolchain == name) {
			if err := validateToolchainVersion("locked chip toolchain_version", lc.ToolchainVersion); err != nil {
				return Toolchain{}, err
			}
			tc.ExpectedVersion = lc.ToolchainVersion
			pinnedFromLock = true
		}
	}

	if minCompiler != "" {
		subject := fmt.Sprintf("chip '%s'", chip.Name)
		if err := CheckMinCompiler(subject, tc.ExpectedVersion, minCompiler); err != nil {
			return Toolchain{}, err
		}
		if !pinnedFromLock && tc.UpstreamVersion != "" {
			if err := CheckMinCompiler(subject+" (upstream archive)", tc.UpstreamVersion, minCompiler); err != nil {
				return Toolchain{}, err
			}
		}
	}

	return tc, nil
}
