package resolve

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/Masterminds/semver/v3"

	"github.com/toob-boot/toob/internal/registry"
)

// Origins of the resolved Core SDK version.
const (
	originLockfile = "lockfile-pinned"
	originDevice   = "device.toml"
	originAuto     = "auto-resolved"
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

// resolveCoreSDK selects the Core SDK version fail-fast (no silent "main" fallback).
// Under Locked == true, the lockfile pin is mandatory and device.toml conflicts fail.
// Under Locked == false, explicit device.toml [build].core_sdk overrides a stale pin (CRIT-64).
func resolveCoreSDK(in Input, chip *Chip) (CoreSDK, error) {
	if in.Device == nil {
		return CoreSDK{}, errors.New("device.toml input is nil")
	}

	devSDK := strings.TrimSpace(in.Device.Build.CoreSDK)
	lockedSDK := ""
	lockedSHA := ""
	if in.Lock != nil {
		lockedSDK = strings.TrimSpace(in.Lock.Environment.CoreSDK)
		lockedSHA = strings.TrimSpace(in.Lock.Environment.CoreSDKSHA256)
	}

	var version, origin string
	if in.Locked {
		if in.Lock == nil || lockedSDK == "" {
			return CoreSDK{}, errors.New("--locked build requires [environment].core_sdk in toob.lock")
		}
		if devSDK != "" && devSDK != "latest" && devSDK != "toob-boot" && devSDK != lockedSDK {
			return CoreSDK{}, fmt.Errorf("device.toml [build] core_sdk %q conflicts with locked version %q in toob.lock",
				devSDK, lockedSDK)
		}
		version, origin = lockedSDK, originLockfile
	} else {
		switch {
		case devSDK == "latest" || devSDK == "toob-boot":
			tag, err := latestCoreSDK(in.Index)
			if err != nil {
				return CoreSDK{}, fmt.Errorf("cannot resolve Core SDK %q: %w", devSDK, err)
			}
			version, origin = tag, originAuto
		case devSDK != "":
			version, origin = devSDK, originDevice
		case lockedSDK != "" && lockedSDK != "latest" && lockedSDK != "toob-boot":
			version, origin = lockedSDK, originLockfile
		default:
			tag, err := latestCoreSDK(in.Index)
			if err != nil {
				return CoreSDK{}, fmt.Errorf("cannot auto-resolve Core SDK version: %w; set [build].core_sdk in device.toml", err)
			}
			version, origin = tag, originAuto
		}
	}

	if err := validateRelName("Core SDK version", version); err != nil {
		return CoreSDK{}, err
	}
	if err := checkMinCoreSDK(fmt.Sprintf("chip '%s'", chip.Name), version, chip.Spec.MinCoreSDK); err != nil {
		return CoreSDK{}, err
	}

	idxSHA := ""
	if in.Index != nil && in.Index.Ecosystem != nil && len(in.Index.Ecosystem.CoreSDKSha256) > 0 {
		idxSHA = strings.TrimSpace(in.Index.Ecosystem.CoreSDKSha256[version])
	}
	if in.Locked && lockedSHA != "" && idxSHA != "" && lockedSHA != idxSHA {
		return CoreSDK{}, fmt.Errorf("locked Core SDK %q sha256 %s does not match registry ecosystem sha256 %s",
			version, lockedSHA, idxSHA)
	}

	return CoreSDK{
		Version: version,
		Origin:  origin,
		SHA256:  firstNonEmpty(lockedSHA, idxSHA),
	}, nil
}

func checkMinCoreSDK(subject, current, minSDK string) error {
	if minSDK == "" || isBranchRef(current) {
		return nil
	}
	vCurrent, err := parseCoreSDKVersion(current)
	if err != nil {
		return fmt.Errorf("cannot check %s against Core SDK '%s': %w", subject, current, err)
	}
	vMin, err := parseCoreSDKVersion(minSDK)
	if err != nil {
		return fmt.Errorf("%s declares an invalid min_core_sdk '%s': %w", subject, minSDK, err)
	}
	if vCurrent.LessThan(vMin) {
		return fmt.Errorf("%s requires Core SDK >= %s, but the resolved version is %s", subject, minSDK, current)
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

func selectToolchainName(in Input, chip *Chip) (string, error) {
	if chip.Prefix != "" {
		name := strings.TrimSuffix(chip.Prefix, "-")
		if name == "" {
			return "", fmt.Errorf("invalid toolchain name %q", chip.Prefix)
		}
		if err := validatePackageOrRelName("toolchain", name); err != nil {
			return "", err
		}
		return name, nil
	}

	// Empty compiler_prefix selects Clang/LLVM toolchains.
	if in.Lock != nil {
		if tLock, ok := in.Lock.Targets[chip.Name]; ok && tLock.Toolchain != "" {
			tName, _ := splitLockedRef(tLock.Toolchain)
			if isClangToolchainName(tName) {
				return tName, nil
			}
		}
		for _, k := range slices.Sorted(maps.Keys(in.Lock.Toolchains)) {
			if isClangToolchainName(k) {
				if in.Index == nil {
					return k, nil
				}
				if _, exists := in.Index.Toolchains[k]; exists {
					return k, nil
				}
			}
		}
	}

	if in.Index != nil {
		for _, k := range slices.Sorted(maps.Keys(in.Index.Toolchains)) {
			tcInfo := in.Index.Toolchains[k]
			bin := strings.ToLower(strings.TrimSpace(tcInfo.CompilerBinary))
			if bin == "clang" || strings.HasSuffix(bin, "/clang") || isClangToolchainName(k) {
				if err := validatePackageOrRelName("toolchain", k); err != nil {
					return "", err
				}
				return k, nil
			}
		}
	}

	return "", fmt.Errorf("chip '%s' has empty compiler_prefix (Clang/LLVM), but no Clang/LLVM toolchain was found in registry index", chip.Name)
}

func isClangToolchainName(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	return strings.Contains(lower, "clang") || strings.Contains(lower, "llvm")
}

func resolveToolchain(in Input, chip *Chip) (Toolchain, error) {
	name, err := selectToolchainName(in, chip)
	if err != nil {
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
	if st, statErr := os.Lstat(file); statErr != nil {
		return Toolchain{}, fmt.Errorf("registry toolchain missing: %w", statErr)
	} else if !st.Mode().IsRegular() {
		return Toolchain{}, fmt.Errorf("registry toolchain %s must be a regular file", file)
	}

	var expectedVer, upstreamVer, compilerBin string
	var idxSHA map[string]string
	if in.Index != nil {
		if tcInfo, ok := in.Index.Toolchains[name]; ok {
			expectedVer = tcInfo.Version
			upstreamVer = tcInfo.UpstreamVersion
			compilerBin = tcInfo.CompilerBinary
			if len(tcInfo.Sha256) > 0 {
				idxSHA = maps.Clone(tcInfo.Sha256)
			}
		}
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
		CompilerBinary:  compilerBin,
		SHA256:          idxSHA,
	}

	pinnedFromLock := false
	if in.Lock != nil {
		if pinned, ok := in.Lock.Toolchains[name]; ok && pinned.Version != "" {
			if err := validateToolchainVersion("locked toolchain version", pinned.Version); err != nil {
				return Toolchain{}, err
			}
			if in.Locked && len(pinned.SHA256) > 0 && len(tc.SHA256) > 0 {
				for _, plat := range slices.Sorted(maps.Keys(pinned.SHA256)) {
					wantSum := pinned.SHA256[plat]
					gotSum, exists := tc.SHA256[plat]
					if !exists || gotSum != wantSum {
						return Toolchain{}, fmt.Errorf("locked toolchain %q platform %s sha256 %q does not match registry sha256 %q",
							name, plat, wantSum, gotSum)
					}
				}
			}
			if len(pinned.SHA256) > 0 && len(tc.SHA256) == 0 {
				tc.SHA256 = maps.Clone(pinned.SHA256)
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

	if in.Locked && !pinnedFromLock {
		return Toolchain{}, fmt.Errorf("--locked build requires toolchain %q in toob.lock [toolchains]", name)
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
