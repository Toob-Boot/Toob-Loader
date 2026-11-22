package cmd

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"github.com/toob-boot/toob/internal/apiclient"
	"github.com/toob-boot/toob/internal/archiveutil"
	"github.com/toob-boot/toob/internal/elfaudit"
	"github.com/toob-boot/toob/internal/lockfile"
	manifestpkg "github.com/toob-boot/toob/internal/manifest"
	"github.com/toob-boot/toob/internal/paths"
	"github.com/toob-boot/toob/internal/registry"
	"github.com/toob-boot/toob/internal/resolve"
	"github.com/toob-boot/toob/internal/toolchain"
	"github.com/toob-boot/toob/internal/ui"
)

var (
	flagManifest      string
	flagBuildDir      string
	flagToolchainPath string
	flagNative        bool
	flagCloud         bool
	flagSkipChecks    bool
	flagLocked        bool
)

type TimingTracker struct {
	mu     sync.Mutex
	phases []struct {
		Name     string
		Duration time.Duration
	}
}

func (t *TimingTracker) Add(name string, duration time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for i := range t.phases {
		if t.phases[i].Name == name {
			t.phases[i].Duration += duration
			return
		}
	}
	t.phases = append(t.phases, struct {
		Name     string
		Duration time.Duration
	}{name, duration})
}

func (t *TimingTracker) Print(total time.Duration) {
	t.mu.Lock()
	entries := make([]ui.TimingEntry, 0, len(t.phases))
	for _, p := range t.phases {
		entries = append(entries, ui.TimingEntry{Name: p.Name, Duration: p.Duration})
	}
	t.mu.Unlock()
	ui.TimingSummary(entries, total)
}

var buildCmd = &cobra.Command{
	Use:   "build",
	Short: "Run the full build pipeline (manifest -> cmake -> ninja)",
	Args:  cobra.NoArgs,
	RunE:  runBuild,
}

var (
	flagDev        bool
	flagProfile    string
	flagMock       string
	flagMockEfuses bool
)

func init() {
	buildCmd.Flags().StringVar(&flagManifest, "manifest", "", "Path to device.toml (auto-detected if omitted)")
	buildCmd.Flags().StringVar(&flagBuildDir, "build-dir", "", "Build output directory (default: builds/build_<chip>)")
	buildCmd.Flags().StringVar(&flagToolchainPath, "toolchain-path", "", "Path to the cross-compiler bin/ directory")
	buildCmd.Flags().BoolVar(&flagNative, "native", false, "Force native build (use local toolchains instead of Docker)")
	buildCmd.Flags().BoolVar(&flagCloud, "cloud", false, "Compile firmware in the cloud (not yet supported)")
	buildCmd.Flags().BoolVar(&flagSkipChecks, "skip-checks", false, "Skip compatibility checks")
	buildCmd.Flags().BoolVar(&flagLocked, "locked", false, "Require an existing up-to-date toob.lock without modifying it")
	buildCmd.Flags().BoolVar(&flagDev, "dev", false, "Development mode: enable local registry and SDK auto-discovery")
	buildCmd.Flags().StringVar(&flagProfile, "profile", "", "Build profile: 'dev' (default, anti-brick mocks enabled) or 'production' (100% real hardware)")
	buildCmd.Flags().StringVar(&flagMock, "mock", "", "Comma-separated HAL traits to mock in dev profile (e.g. 'keystore,wdt', 'all', or 'none')")
	buildCmd.Flags().BoolVar(&flagMockEfuses, "mock-efuses", true, "Deprecated alias for --mock=keystore / --mock=none")
}

func isDevEnvEnabled() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("TOOB_DEV")))
	return v == "1" || v == "true"
}

func validateCMakeArgPath(label, p string) error {
	if strings.ContainsAny(p, ";\x00\r\n") {
		return fmt.Errorf("refusing unsafe %s path %q: contains CMake list separator ';' or control character", label, p)
	}
	return nil
}

// resolveRegistryOverride classifies device.toml [build] registry into either a
// validated local/remote override or a registry version pin. Local filesystem and
// plaintext http:// overrides strictly require --dev (TOOB_DEV=1).
func resolveRegistryOverride(rawReg, root string, devMode bool) (override string, versionPin string, err error) {
	trimmed := strings.TrimSpace(rawReg)
	if trimmed == "" || trimmed == "latest" {
		return "", "", nil
	}

	if strings.HasPrefix(trimmed, "https://") {
		return trimmed, "", nil
	}
	if strings.HasPrefix(trimmed, "http://") {
		if !devMode {
			return "", "", fmt.Errorf("insecure http:// [build] registry override %q in device.toml requires --dev", trimmed)
		}
		return trimmed, "", nil
	}
	if strings.HasPrefix(trimmed, "file://") {
		if !devMode {
			return "", "", fmt.Errorf("local filesystem [build] registry override %q in device.toml requires --dev", trimmed)
		}
		localPath, parseErr := registry.ParseFileURL(trimmed)
		if parseErr != nil {
			return "", "", parseErr
		}
		if !filepath.IsAbs(localPath) {
			localPath = filepath.Join(root, localPath)
		}
		if _, statErr := os.Stat(filepath.Join(localPath, "registry.json")); statErr != nil {
			return "", "", fmt.Errorf("local [build] registry %q does not contain registry.json: %w", localPath, statErr)
		}
		return localPath, "", nil
	}

	looksLikePath := trimmed == "." || trimmed == ".." ||
		strings.ContainsAny(trimmed, `/\`) || filepath.IsAbs(trimmed)
	candPath := trimmed
	if !filepath.IsAbs(candPath) {
		candPath = filepath.Join(root, candPath)
	}
	_, localRegErr := os.Stat(filepath.Join(candPath, "registry.json"))
	if looksLikePath || localRegErr == nil {
		if !devMode {
			return "", "", fmt.Errorf("local filesystem [build] registry override %q in device.toml requires --dev", trimmed)
		}
		if localRegErr != nil {
			return "", "", fmt.Errorf("local [build] registry %q does not contain registry.json: %w", candPath, localRegErr)
		}
		absCand, absErr := filepath.Abs(candPath)
		if absErr != nil {
			return "", "", absErr
		}
		return absCand, "", nil
	}

	if err := manifestpkg.ValidateName("registry version", trimmed); err != nil {
		return "", "", fmt.Errorf("device.toml [build] registry: %w", err)
	}
	return "", trimmed, nil
}

func runBuild(cmd *cobra.Command, _ []string) error {
	devMode := flagDev || isDevEnvEnabled()
	if flagDev {
		_ = os.Setenv("TOOB_DEV", "1")
		ui.Info("Mode: Development (--dev) - local registry and SDK auto-discovery enabled")
	}

	var root string
	if flagManifest != "" {
		absManifest, err := filepath.Abs(flagManifest)
		if err != nil {
			return err
		}
		if _, err := os.Stat(absManifest); err != nil {
			return fmt.Errorf("manifest not found: %s", absManifest)
		}
		root = filepath.Dir(absManifest)
	} else {
		var err error
		root, err = paths.FindProjectRoot("")
		if err != nil {
			return err
		}
	}

	manifestPath := flagManifest
	if manifestPath == "" {
		manifestPath = filepath.Join(root, "device.toml")
	}
	dt, err := manifestpkg.ParseToml(manifestPath)
	if err != nil {
		return fmt.Errorf("failed to parse %s: %w", manifestPath, err)
	}

	regOverride, regVerPin, err := resolveRegistryOverride(dt.Build.Registry, root, devMode)
	if err != nil {
		return err
	}

	lfPath := paths.LockfilePath(root)
	if flagLocked {
		if _, statErr := os.Stat(lfPath); errors.Is(statErr, fs.ErrNotExist) {
			return fmt.Errorf("--locked was specified, but %s does not exist", lfPath)
		}
	}
	lf, err := lockfile.Load(lfPath)
	if err != nil {
		return fmt.Errorf("the lockfile is unreadable; repair or delete it to continue: %w", err)
	}

	cache := registry.NewCache(regOverride)
	if targetVer := firstNonEmpty(lf.Registry.Commit, lf.Registry.Version, regVerPin); targetVer != "" {
		if err := cache.SelectVersion(targetVer, !flagLocked); err != nil {
			return fmt.Errorf("failed to select locked registry version %s: %w", targetVer, err)
		}
	}

	if !cache.IsInitialized() {
		if flagLocked {
			return errors.New("registry cache is not initialized and --locked forbids auto-syncing")
		}
		ui.Step("Registry not initialized. Auto-syncing...")
		if err := cache.Sync(false, false); err != nil {
			return fmt.Errorf("failed to sync registry: %w", err)
		}
	}

	if flagCloud {
		return fmt.Errorf("cloud build is not supported yet; remote compilation will be available in a future release")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	if flagNative {
		return runNativeBuild(ctx, cmd, root, cache, lf)
	}
	return runDockerBuild(ctx, cmd, root, dt, regOverride, cache, lf)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func resolveCLIMockArgs(cmd *cobra.Command) ([]string, bool) {
	if cmd != nil && cmd.Flags().Changed("mock") {
		return []string{flagMock}, true
	}
	if cmd != nil && cmd.Flags().Changed("mock-efuses") {
		if flagMockEfuses {
			return []string{"keystore"}, true
		}
		return []string{"none"}, true
	}
	return nil, false
}

func logResolvedPackages(plan *resolve.Plan) {
	ui.Info("Target: %s [%s] | Arch: %s [%s] | Profile: %s",
		plan.Chip.Name, plan.Chip.Tier, plan.Arch.Name, plan.Arch.Tier, plan.Profile)
	if plan.Profile == resolve.ProfileProduction {
		if plan.Chip.Tier == "community" || plan.Chip.Tier == "local" {
			ui.Warn("Security notice: production build uses %s-tier chip package '%s'.", plan.Chip.Tier, plan.Chip.Name)
		}
		if plan.Arch.Tier == "community" || plan.Arch.Tier == "local" {
			ui.Warn("Security notice: production build uses %s-tier architecture package '%s'.", plan.Arch.Tier, plan.Arch.Name)
		}
	}
	if len(plan.DriverPackages) > 0 {
		var parts []string
		for _, dp := range plan.DriverPackages {
			label := fmt.Sprintf("%s=%s[%s]", dp.Trait, dp.Name, dp.Tier)
			if dp.Mocked {
				label += "(MOCK)"
			}
			parts = append(parts, label)
			if plan.Profile == resolve.ProfileProduction && (dp.Tier == "community" || dp.Tier == "local") &&
				(dp.Trait == "keystore" || dp.Trait == "otp" || dp.Trait == "entropy") {
				ui.Warn("Security notice: production build binds %s trait '%s' to %s-tier package '%s'.",
					dp.Trait, dp.Trait, dp.Tier, dp.Name)
			}
		}
		ui.Info("Drivers: %s", strings.Join(parts, ", "))
	}
	for _, cs := range plan.Crypto {
		if cs.Enabled() && plan.Profile == resolve.ProfileProduction && (cs.Tier == "community" || cs.Tier == "local") {
			ui.Warn("Security notice: production build uses %s-tier crypto package '%s' for slot '%s'.",
				cs.Tier, cs.Name, cs.Slot)
		}
	}
}

func computeCMakeFingerprint(fields ...string) string {
	h := sha256.New()
	for _, f := range fields {
		_, _ = h.Write([]byte(f))
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func runNativeBuild(ctx context.Context, cmd *cobra.Command, root string, cache *registry.Cache, lf *lockfile.Lockfile) error {
	ensureBuildToolsOnPath()
	buildStartTime := time.Now()
	timings := &TimingTracker{}

	manifest := flagManifest
	if manifest == "" {
		manifest = filepath.Join(root, "device.toml")
	}
	manifest, err := filepath.Abs(manifest)
	if err != nil {
		return err
	}
	if err := validateCMakeArgPath("manifest", manifest); err != nil {
		return err
	}
	if _, err := os.Stat(manifest); err != nil {
		return fmt.Errorf("device manifest not found: %s", manifest)
	}
	dt, err := manifestpkg.ParseToml(manifest)
	if err != nil {
		return fmt.Errorf("failed to parse %s: %w", manifest, err)
	}

	if flagSkipChecks && !cache.IsInitialized() {
		ui.Warn("Cannot skip checks because local registry is missing. Auto-syncing...")
		flagSkipChecks = false
	}

	idx, err := cache.LoadIndex()
	if err != nil {
		return fmt.Errorf("failed to load the registry index: %w", err)
	}
	mockOverrides, mockSet := resolveCLIMockArgs(cmd)
	plan, err := resolve.Resolve(resolve.Input{
		Root:          root,
		Device:        dt,
		Lock:          lf,
		Index:         idx,
		Registry:      cache,
		Profile:       flagProfile,
		MockOverrides: mockOverrides,
		MockSet:       mockSet,
	})
	if err != nil {
		return err
	}
	if err := validateCMakeArgPath("toolchain.cmake", plan.Toolchain.File); err != nil {
		return err
	}
	logResolvedPackages(plan)

	var combination <-chan combinationResult
	if !flagSkipChecks {
		combination = startCombinationCheck(plan.Chip)
	}

	compilerLabel := plan.Compiler
	if dt.Build.Compiler == "" {
		compilerLabel += " (auto)"
	}
	if envReg := os.Getenv("TOOB_REGISTRY_DIR"); envReg != "" {
		ui.Info("Environment: Compiler=%s, CoreSDK=%s, Registry=Local Override (%s)", compilerLabel, plan.CoreSDK.Label(), envReg)
	} else {
		ui.Info("Environment: Compiler=%s, CoreSDK=%s, Registry=Local Cache (%s)", compilerLabel, plan.CoreSDK.Label(), cache.Dir())
	}

	compilerRoot, err := ensureCoreSDK(ctx, root, plan.CoreSDK, idx)
	if err != nil {
		return err
	}
	if err := validateCMakeArgPath("compiler SDK root", compilerRoot); err != nil {
		return err
	}

	buildDir := flagBuildDir
	if buildDir == "" {
		buildDir = filepath.Join(root, "builds", "build_"+plan.Chip.Name)
	} else if !filepath.IsAbs(buildDir) {
		buildDir, err = filepath.Abs(buildDir)
		if err != nil {
			return err
		}
	}
	if err := validateCMakeArgPath("build-dir", buildDir); err != nil {
		return err
	}

	generatedDir := filepath.Join(buildDir, "generated")
	if err := os.MkdirAll(generatedDir, 0o750); err != nil {
		return err
	}
	timings.Add("Project Setup", time.Since(buildStartTime))

	ui.Step("Running manifest compiler (Go Native)")
	startManifest := time.Now()
	sdk := resolve.LocateSDK(root, compilerRoot)
	cryptoDirs := plan.CryptoDirs()
	var sourceDirs []string
	sourceDirs = appendExistingDir(sourceDirs, sdk.Bootloader)
	sourceDirs = appendExistingDir(sourceDirs, sdk.Core)
	sourceDirs = appendExistingDir(sourceDirs, sdk.Stage0)
	sourceDirs = appendExistingDir(sourceDirs, paths.HALDir(root))
	sourceDirs = appendExistingDir(sourceDirs, plan.Chip.Dir)
	sourceDirs = appendExistingDir(sourceDirs, sdk.Recovery)
	sourceDirs = appendExistingDir(sourceDirs, sdk.LibToob)
	sourceDirs = appendExistingDir(sourceDirs, plan.Arch.Dir)
	sourceDirs = appendExistingDir(sourceDirs, plan.SoCDir)
	for _, drv := range plan.Drivers {
		sourceDirs = appendExistingDir(sourceDirs, drv)
	}
	for _, rdrv := range plan.Recovery.Drivers {
		sourceDirs = appendExistingDir(sourceDirs, rdrv)
	}
	for _, rsrc := range plan.Recovery.Sources {
		sourceDirs = appendExistingDir(sourceDirs, filepath.Dir(rsrc))
	}
	for _, cdir := range cryptoDirs {
		sourceDirs = appendExistingDir(sourceDirs, cdir)
	}

	mctx, err := manifestpkg.Load(manifestpkg.Inputs{
		Device:           dt,
		HardwarePath:     plan.Chip.HardwarePath,
		ChipManifestPath: plan.Chip.ManifestPath,
		CoreDir:          sdk.Core,
		ArchDir:          plan.Arch.Dir,
		DriverDirs:       plan.Drivers,
		CryptoDirs:       cryptoDirs,
		SourceDirs:       sourceDirs,
		OutDir:           generatedDir,
	})
	if err != nil {
		return err
	}
	if _, err := manifestpkg.Generate(mctx); err != nil {
		return err
	}
	timings.Add("Manifest Compiler", time.Since(startManifest))

	startEnvValidation := time.Now()
	if combination != nil {
		if err := reportCombination(<-combination, plan.Chip); err != nil {
			return err
		}
	} else {
		ui.Muted("Skipping compatibility matrix checks (--skip-checks)")
	}

	toobCLIPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot determine the toob executable path: %w", err)
	}
	if err := validateCMakeArgPath("toob executable", toobCLIPath); err != nil {
		return err
	}

	configPath := filepath.Join(generatedDir, "toob_config.cmake")
	if err := writeFileIfChanged(configPath, []byte(plan.RenderConfig(sdk, toobCLIPath))); err != nil {
		return fmt.Errorf("failed to write %s: %w", configPath, err)
	}

	tcPath, err := provisionToolchain(ctx, plan.Toolchain, plan.Chip.Name, cache.Dir())
	if err != nil {
		return err
	}
	if tcPath != "" {
		if err := validateCMakeArgPath("toolchain-path", tcPath); err != nil {
			return err
		}
	}
	var customEnv []string
	if tcPath != "" {
		customEnv = append(os.Environ(), "PATH="+tcPath+string(os.PathListSeparator)+os.Getenv("PATH"))
		ui.Info("Toolchain: %s", tcPath)
	}
	timings.Add("Environment Validation", time.Since(startEnvValidation))

	startCMake := time.Now()
	mockOpt := "OFF"
	if plan.MockHW {
		mockOpt = "ON"
	}
	expectedFP := computeCMakeFingerprint(
		compilerRoot,
		plan.Toolchain.File,
		plan.Toolchain.Prefix,
		manifest,
		tcPath,
		plan.Chip.Name,
		plan.Chip.Arch,
		plan.Profile,
		mockOpt,
		strings.Join(mockOverrides, ","),
	)
	ninjaFile := filepath.Join(buildDir, "build.ninja")
	cacheFile := filepath.Join(buildDir, "CMakeCache.txt")
	fpFile := filepath.Join(buildDir, ".toob_cmake_fingerprint")
	needConfigure := false
	if _, err := os.Stat(ninjaFile); errors.Is(err, fs.ErrNotExist) {
		needConfigure = true
	} else if err != nil {
		return err
	} else if _, cacheErr := os.Stat(cacheFile); cacheErr != nil {
		needConfigure = true
	} else if fpBytes, fpErr := os.ReadFile(fpFile); fpErr != nil || strings.TrimSpace(string(fpBytes)) != expectedFP { // #nosec G304 -- fpFile is inside validated buildDir.
		needConfigure = true
	}

	if needConfigure {
		spinner := ui.NewSpinner("Configuring CMake")
		spinner.Start()

		cmakeArgs := []string{
			"-G", "Ninja",
			"-B", filepath.ToSlash(buildDir),
			"-S", filepath.ToSlash(compilerRoot),
			"-DCMAKE_TOOLCHAIN_FILE=" + filepath.ToSlash(plan.Toolchain.File),
			"-DTOOLCHAIN_PREFIX=" + plan.Toolchain.Prefix,
			"-DCMAKE_SYSTEM_NAME=Generic",
			"-DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY",
			"-DTOOB_DEVICE_MANIFEST=" + filepath.ToSlash(manifest),
			"-DTOOB_CHIP=" + plan.Chip.Name,
			"-DTOOB_ARCH=" + plan.Chip.Arch,
			"-DTOOB_PROFILE=" + plan.Profile,
			"-DTOOB_MOCK_HW=" + mockOpt,
			"-DTOOB_MOCK_EFUSES=" + mockOpt,
		}
		if tcPath != "" {
			cmakeArgs = append(cmakeArgs, "-DTOOLCHAIN_BIN_DIR="+filepath.ToSlash(tcPath))
		}
		if _, ccacheErr := exec.LookPath("ccache"); ccacheErr == nil {
			cmakeArgs = append(cmakeArgs, "-DCMAKE_C_COMPILER_LAUNCHER=ccache", "-DCMAKE_CXX_COMPILER_LAUNCHER=ccache")
		}

		if err := runWithLiveSpinner(ctx, root, "cmake", customEnv, spinner, cmakeArgs...); err != nil {
			spinner.Stop()
			return err
		}
		spinner.Stop()
		if err := writeFileIfChanged(fpFile, []byte(expectedFP+"\n")); err != nil {
			return fmt.Errorf("failed writing CMake fingerprint: %w", err)
		}
		timings.Add("CMake Configure", time.Since(startCMake))
	} else {
		ui.Info("CMake build files found in %s (fingerprint matched), skipping configure.", buildDir)
	}

	spinner := ui.NewSpinner("Building")
	spinner.Start()
	startNinja := time.Now()
	if err := runWithLiveSpinner(ctx, root, "cmake", customEnv, spinner, "--build", buildDir); err != nil {
		return err
	}
	spinner.Stop()
	timings.Add("Ninja Build", time.Since(startNinja))

	startGates := time.Now()
	if err := runPostLinkGates(manifest, buildDir, root, cache, dt, mctx, plan); err != nil {
		return err
	}
	timings.Add("Post-Link Gates", time.Since(startGates))

	ui.Success("Build complete.")
	timings.Print(time.Since(buildStartTime))

	if !flagLocked {
		recordNativeBuild(root, lf, cache, plan)
	}
	return nil
}

func runPostLinkGates(manifestPath, buildDir, projectRoot string, cache *registry.Cache, dt *manifestpkg.DeviceToml, mctx *manifestpkg.Context, plan *resolve.Plan) error {
	var reservedRegions []elfaudit.MemoryRegion
	if mctx != nil && mctx.Hardware != nil {
		for _, r := range mctx.Hardware.ReservedRamRegions {
			base, err := parseCLiteralU64(r.Base)
			if err != nil {
				return fmt.Errorf("invalid base address %q for reserved RAM region %q: %w", r.Base, r.Name, err)
			}
			reservedRegions = append(reservedRegions, elfaudit.MemoryRegion{
				Name: r.Name,
				Base: base,
				Size: uint64(r.Size),
			})
		}
	}

	isBareMetal := !strings.EqualFold(plan.Chip.Arch, "host")

	// 1. Stage-0 BootROM image packing + packed Stage-0 flash budget check.
	if isBareMetal && mctx != nil && mctx.Hardware != nil && mctx.Hardware.BootromImage != nil {
		stage0ELF := filepath.Join(buildDir, "toob_stage0")
		packedStage0, err := packStage0BootromImage(stage0ELF, projectRoot, cache, mctx.Hardware, plan)
		if err != nil {
			return fmt.Errorf("stage-0 BootROM image packing failed: %w", err)
		}
		stage0Bin := filepath.Join(buildDir, "toob_stage0.bin")
		if err := writeFileAtomic(stage0Bin, packedStage0, 0o644); err != nil {
			return fmt.Errorf("failed writing packed Stage-0 image %s: %w", stage0Bin, err)
		}
		if _, err := manifestpkg.CheckBudget(manifestPath, stage0Bin, "stage0"); err != nil {
			return err
		}
	}

	// 2. Post-link ELF security audit (mock poison-pill in production, reserved RAM overlap, Flash Filesz budget).
	type elfTarget struct {
		name     string
		required bool
		maxBytes uint64
	}
	elfTargets := []elfTarget{
		{name: "toob_stage0", required: isBareMetal, maxBytes: uint64(dt.Partitions.Stage0Size)},
		{name: "toob_stage1", required: isBareMetal, maxBytes: uint64(dt.Partitions.Stage1Size)},
		{name: "toob_stage1b", required: false, maxBytes: uint64(dt.Partitions.Stage1Size)},
		{name: "toob_recovery", required: false, maxBytes: uint64(dt.Partitions.RecoverySize)},
	}
	for _, tgt := range elfTargets {
		elfPath := filepath.Join(buildDir, tgt.name)
		if _, err := os.Stat(elfPath); err != nil {
			if errors.Is(err, fs.ErrNotExist) && !tgt.required {
				continue
			}
			return fmt.Errorf("expected linked ELF %s not found: %w", elfPath, err)
		}
		report, err := elfaudit.AuditELF(elfPath, elfaudit.ELFAuditConfig{
			Profile:         plan.Profile,
			ReservedRegions: reservedRegions,
			Stage1MaxBytes:  tgt.maxBytes,
		})
		if err != nil {
			return fmt.Errorf("post-link ELF audit failed on %s: %w", tgt.name, err)
		}
		if !report.Passed {
			for _, v := range report.Violations {
				ui.Error("ELF Audit [%s] %s: %s", tgt.name, v.Name, v.Details)
			}
			return fmt.Errorf("FATAL [ELF_AUDIT_FAIL]: %s failed post-link security audit", tgt.name)
		}
	}

	// 3. Recovery flash partition budget gate when recovery is configured/built.
	if isBareMetal && dt.Partitions.RecoverySize > 0 {
		recoveryBin := filepath.Join(buildDir, "toob_recovery.bin")
		if _, err := os.Stat(recoveryBin); err == nil {
			if _, bErr := manifestpkg.CheckBudget(manifestPath, recoveryBin, "recovery"); bErr != nil {
				return bErr
			}
		} else if plan.Recovery.Declared {
			return fmt.Errorf("recovery partition is configured (recovery_size=%d) but %s was not produced",
				dt.Partitions.RecoverySize, recoveryBin)
		}
	}

	return nil
}

func packStage0BootromImage(stage0ELF, projectRoot string, cache *registry.Cache, hw *manifestpkg.HardwareJson, plan *resolve.Plan) ([]byte, error) {
	if plan.Chip.Local && hw.BootromImage != nil && strings.TrimSpace(hw.BootromImage.Extends) != "" {
		localExt := filepath.Join(paths.HALDir(projectRoot), filepath.FromSlash(strings.TrimSpace(hw.BootromImage.Extends)))
		if _, err := os.Stat(localExt); errors.Is(err, fs.ErrNotExist) && cache != nil {
			return manifestpkg.PackStage0ELFWithPackagesDir(stage0ELF, hw, cache.Dir())
		}
	}
	return manifestpkg.PackStage0FromHardwareJSON(stage0ELF, plan.Chip.HardwarePath)
}

func recordNativeBuild(root string, lf *lockfile.Lockfile, cache *registry.Cache, plan *resolve.Plan) {
	lf.Toolchains[plan.Toolchain.Name] = lockfile.ToolchainEntry{Version: plan.Toolchain.ExpectedVersion}
	if cache != nil && !cache.IsLocalOverride() {
		if regVer, err := cache.HeadCommit(); err == nil && regVer != "" && regVer != "uninitialized" {
			lf.Registry.Commit = regVer
			lf.Registry.Version = regVer
		}
	}
	if os.Getenv("TOOB_COMPILER_DIR") == "" {
		lf.Environment.CoreSDK = plan.CoreSDK.Version
	}

	var archVer string
	if idx, err := cache.LoadIndex(); err == nil && idx != nil {
		if aInfo, ok := idx.Archs[plan.Chip.Arch]; ok {
			archVer = aInfo.Version
		}
	}
	var cBackend, cHash, cPqc string
	if len(plan.Crypto) == 3 {
		cBackend, cHash, cPqc = plan.Crypto[0].Name, plan.Crypto[1].Name, plan.Crypto[2].Name
	}
	entry := lockfile.ChipEntry{
		Name:             plan.Chip.Name,
		Version:          plan.Chip.Version,
		Arch:             plan.Chip.Arch,
		ArchVersion:      archVer,
		Toolchain:        plan.Toolchain.Name,
		ToolchainVersion: plan.Toolchain.ExpectedVersion,
		CryptoBackend:    cBackend,
		CryptoHash:       cHash,
		CryptoPqc:        cPqc,
		Spawned:          plan.Chip.Local,
	}
	updated := false
	for i := range lf.Chips {
		if lf.Chips[i].Name == entry.Name {
			lf.Chips[i] = entry
			updated = true
			break
		}
	}
	if !updated {
		lf.Chips = append(lf.Chips, entry)
	}

	if err := lf.Save(paths.LockfilePath(root)); err != nil {
		ui.Warn("Build succeeded, but the lockfile could not be saved: %v", err)
	}
}

// ensureCoreSDK returns the Core SDK directory, downloading and verifying it atomically on first use.
func ensureCoreSDK(ctx context.Context, projectRoot string, coreSDK resolve.CoreSDK, idx *registry.Index) (string, error) {
	version := coreSDK.Version
	devMode := isDevEnvEnabled()

	if dir := os.Getenv("TOOB_COMPILER_DIR"); dir != "" {
		absDir, err := filepath.Abs(dir)
		if err != nil {
			return "", err
		}
		if !devMode && version != "" && version != "main" && version != "dev" && version != "latest" {
			if compRoot, rErr := os.OpenRoot(absDir); rErr == nil {
				vf, fErr := compRoot.Open(".toob_core_version")
				if fErr == nil {
					verBytes, readErr := io.ReadAll(io.LimitReader(vf, 1024))
					_ = vf.Close()
					_ = compRoot.Close()
					if readErr == nil {
						embedded := strings.TrimSpace(string(verBytes))
						if embedded != "" && strings.TrimPrefix(embedded, "core/") != strings.TrimPrefix(version, "core/") {
							return "", fmt.Errorf("TOOB_COMPILER_DIR (%s) contains Core SDK %q, but build requires %q", absDir, embedded, version)
						}
					}
				} else {
					_ = compRoot.Close()
				}
			}
		}
		return absDir, nil
	}

	if devMode {
		startDir := projectRoot
		if startDir == "" {
			if r, err := paths.FindProjectRoot(""); err == nil {
				startDir = r
			} else if wd, wdErr := os.Getwd(); wdErr == nil {
				startDir = wd
			}
		}
		curr := startDir
		for curr != "" {
			if st, err := os.Stat(filepath.Join(curr, "toobloader", "core")); err == nil && st.IsDir() {
				return curr, nil
			}
			parent := filepath.Dir(curr)
			if parent == curr {
				break
			}
			curr = parent
		}
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}
	coreBase := filepath.Join(home, ".toob", "core")
	dir, err := archiveutil.SafeJoin(coreBase, version)
	if err != nil {
		return "", fmt.Errorf("unsafe Core SDK version %q: %w", version, err)
	}
	if st, err := os.Stat(dir); err == nil && st.IsDir() {
		return dir, nil
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}

	var expectedSHA string
	if idx != nil && idx.Ecosystem != nil && idx.Ecosystem.CoreSDKSha256 != nil {
		expectedSHA = cmp.Or(
			idx.Ecosystem.CoreSDKSha256[version],
			idx.Ecosystem.CoreSDKSha256[strings.TrimPrefix(version, "core/")],
			idx.Ecosystem.CoreSDKSha256["core/"+strings.TrimPrefix(version, "core/")],
		)
	}
	if envSHA := strings.TrimSpace(os.Getenv("TOOB_CORE_SDK_SHA256")); envSHA != "" {
		expectedSHA = envSHA
	}
	expectedSHA = strings.ToLower(strings.TrimSpace(expectedSHA))
	if expectedSHA != "" {
		if decoded, hexErr := hex.DecodeString(expectedSHA); hexErr != nil || len(decoded) != sha256.Size {
			return "", fmt.Errorf("invalid Core SDK SHA-256 digest %q", expectedSHA)
		}
	} else if !devMode {
		return "", fmt.Errorf("refusing unverified download for Core SDK %q: no sha256 digest in registry index (set TOOB_CORE_SDK_SHA256 or pass --dev)", version)
	}

	ui.Step("Core SDK '%s' not found locally. Downloading from Registry...", version)
	nonce := fmt.Sprintf("%d-%d", os.Getpid(), time.Now().UnixNano())
	tempDir := fmt.Sprintf("%s.tmp-%s", dir, nonce)
	tempTar := fmt.Sprintf("%s.tar-%s.tgz", dir, nonce)
	if err := os.MkdirAll(filepath.Dir(tempDir), 0o750); err != nil {
		return "", err
	}
	defer func() { _ = os.Remove(tempTar) }()

	// Ensure version has single URL-escaped segment via apiclient.DownloadPackage ("core/vX.Y.Z" -> "core%2FvX.Y.Z").
	dlVer := version
	if !strings.HasPrefix(dlVer, "core/") && dlVer != "main" && dlVer != "dev" {
		dlVer = "core/" + dlVer
	}
	body, err := apiclient.NewWithTimeout(120*time.Second).DownloadPackage(ctx, "toob-boot", dlVer)
	if err != nil {
		return "", fmt.Errorf("failed to fetch Core SDK '%s' from registry: %w", version, err)
	}

	// #nosec G304 -- tempTar is derived from SafeJoin(coreBase, version) above.
	tarOut, err := os.OpenFile(tempTar, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		_ = body.Close()
		return "", err
	}
	hasher := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(tarOut, hasher), io.LimitReader(body, archiveutil.PackageSizeLimit+1))
	bodyCloseErr := body.Close()
	tarCloseErr := tarOut.Close()
	if copyErr != nil {
		return "", fmt.Errorf("failed downloading Core SDK '%s': %w", version, copyErr)
	}
	if bodyCloseErr != nil {
		return "", fmt.Errorf("failed closing Core SDK response stream: %w", bodyCloseErr)
	}
	if tarCloseErr != nil {
		return "", fmt.Errorf("failed flushing Core SDK archive: %w", tarCloseErr)
	}
	if written > archiveutil.PackageSizeLimit {
		return "", fmt.Errorf("core SDK '%s' archive exceeds %d byte limit", version, archiveutil.PackageSizeLimit)
	}

	actualSHA := hex.EncodeToString(hasher.Sum(nil))
	if expectedSHA != "" && actualSHA != expectedSHA {
		return "", fmt.Errorf("core SDK '%s' SHA256 mismatch: expected %s, got %s", version, expectedSHA, actualSHA)
	}

	// #nosec G304 -- tempTar is the verified temporary archive created above.
	tarIn, err := os.Open(tempTar)
	if err != nil {
		return "", err
	}
	extractErr := registry.ExtractTarball(tarIn, tempDir)
	_ = tarIn.Close()
	if extractErr != nil {
		_ = os.RemoveAll(tempDir)
		return "", fmt.Errorf("failed to extract Core SDK: %w", extractErr)
	}

	if _, err := os.Stat(filepath.Join(tempDir, "CMakeLists.txt")); err != nil {
		_ = os.RemoveAll(tempDir)
		return "", fmt.Errorf("extracted Core SDK '%s' is incomplete (missing CMakeLists.txt)", version)
	}

	if err := os.Rename(tempDir, dir); err != nil {
		_ = os.RemoveAll(tempDir)
		if st, statErr := os.Stat(dir); statErr == nil && st.IsDir() {
			return dir, nil
		}
		return "", fmt.Errorf("failed to finalize atomic Core SDK download: %w", err)
	}
	return dir, nil
}

// provisionToolchain returns the directory of the cross-compiler to use, enforcing
// exact/upstream version alignment and chip min_compiler (REG-009).
func provisionToolchain(ctx context.Context, tc resolve.Toolchain, chipName, cacheDir string) (string, error) {
	if flagToolchainPath == "" {
		if bin := findToolchainBin(tc.Prefix, tc.ExpectedVersion, tc.UpstreamVersion); bin != "" {
			if err := verifyProbedCompilerVersion(ctx, bin, tc, chipName, false); err != nil {
				return "", err
			}
			return bin, nil
		}
		if flagLocked {
			return "", fmt.Errorf("toolchain %s (%s) is not cached locally and --locked forbids auto-provisioning", tc.Name, tc.ExpectedVersion)
		}
		bin, err := toolchain.EnsureAvailable(tc.Prefix, tc.ExpectedVersion, cacheDir)
		if err != nil {
			return "", fmt.Errorf("failed to auto-provision toolchain: %w (run 'toob install' or pass --toolchain-path)", err)
		}
		if err := verifyProbedCompilerVersion(ctx, bin, tc, chipName, false); err != nil {
			return "", err
		}
		return bin, nil
	}

	absTCPath, err := filepath.Abs(flagToolchainPath)
	if err != nil {
		return "", fmt.Errorf("invalid --toolchain-path %q: %w", flagToolchainPath, err)
	}
	if err := verifyProbedCompilerVersion(ctx, absTCPath, tc, chipName, true); err != nil {
		return "", err
	}
	return absTCPath, nil
}

func verifyProbedCompilerVersion(ctx context.Context, binDir string, tc resolve.Toolchain, chipName string, strictMatch bool) error {
	compilerExe := filepath.Join(binDir, tc.Prefix+"gcc")
	if runtime.GOOS == "windows" {
		compilerExe += ".exe"
	}
	if _, err := os.Stat(compilerExe); err != nil {
		if strictMatch {
			return fmt.Errorf("custom toolchain compiler not found at %s", compilerExe)
		}
		return nil
	}

	// #nosec G204 -- compilerExe is strictly <binDir>/<validated_prefix>gcc[.exe] with fixed flags.
	out, err := exec.CommandContext(ctx, compilerExe, "-dumpfullversion", "-dumpversion").Output()
	if err != nil {
		return fmt.Errorf("failed probing compiler version from %s: %w", compilerExe, err)
	}
	probedRaw := strings.TrimSpace(string(out))

	if tc.MinCompiler != "" {
		if err := resolve.CheckMinCompiler(fmt.Sprintf("chip '%s'", chipName), probedRaw, tc.MinCompiler); err != nil {
			return err
		}
	}

	if strictMatch && tc.ExpectedVersion != "" {
		actualSemver, parseErr := resolve.ExtractCompilerSemver(probedRaw)
		if parseErr != nil {
			return fmt.Errorf("cannot parse custom compiler version %q from %s: %w", probedRaw, compilerExe, parseErr)
		}
		matched := false
		for _, allowed := range []string{tc.ExpectedVersion, tc.UpstreamVersion} {
			if allowed == "" {
				continue
			}
			if wantSemver, wErr := resolve.ExtractCompilerSemver(allowed); wErr == nil && actualSemver.Equal(wantSemver) {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("FATAL: custom toolchain version mismatch (got GCC %s, expected %s); use a matching toolchain or omit --toolchain-path",
				actualSemver.String(), tc.ExpectedVersion)
		}
	}
	return nil
}

type combinationResult struct {
	resp *apiclient.CheckCombinationResponse
	err  error
}

func startCombinationCheck(chip resolve.Chip) <-chan combinationResult {
	result := make(chan combinationResult, 1)
	go func() {
		client := apiclient.New()
		client.HTTPClient.Timeout = 3 * time.Second
		cliVer := Version
		if !strings.HasPrefix(cliVer, "v") && cliVer != "main" && cliVer != "dev" {
			cliVer = "v" + cliVer
		}
		resp, err := client.CheckCombination(cmd_defaultCtx(), chip.Name, chip.Version, cliVer)
		result <- combinationResult{resp: resp, err: err}
	}()
	return result
}

func reportCombination(result combinationResult, chip resolve.Chip) error {
	if result.err != nil {
		errMsg := result.err.Error()
		switch {
		case strings.Contains(errMsg, "no such host") || strings.Contains(errMsg, "connect: connection refused") || strings.Contains(errMsg, "context deadline exceeded"):
			ui.Warn("Could not verify build combination: Registry API is unreachable (offline).")
		case strings.Contains(errMsg, "HTTP "):
			parts := strings.SplitN(errMsg, ": ", 2)
			if len(parts) == 2 && (strings.Contains(parts[1], "<") || len(parts[1]) > 100) {
				ui.Warn("Could not verify build combination: Registry API returned %s.", parts[0])
			} else {
				ui.Warn("Could not verify build combination: %v", result.err)
			}
		default:
			ui.Warn("Could not verify build combination: %v", result.err)
		}
		return nil
	}

	switch strings.ToUpper(result.resp.Status) {
	case "FAILED":
		return fmt.Errorf("FATAL: Chip %s (v%s) is explicitly incompatible with CLI %s according to the Compatibility Matrix. Build aborted", chip.Name, chip.Version, Version)
	case "UNKNOWN":
		ui.Warn("The combination of Chip %s (v%s) and CLI %s has not been verified by the CI yet.", chip.Name, chip.Version, Version)
	}
	return nil
}

func run(ctx context.Context, dir string, name string, env []string, args ...string) error {
	// #nosec G204 -- name is a fixed binary ("docker" or "cmake") invoked directly without shell interpolation.
	c := exec.CommandContext(ctx, name, args...)
	c.Dir = dir
	c.Stdin = os.Stdin
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	if len(env) > 0 {
		c.Env = env
	}
	return c.Run()
}

type ringBuffer struct {
	buf  []byte
	pos  int
	full bool
}

func newRingBuffer(size int) *ringBuffer {
	return &ringBuffer{buf: make([]byte, size)}
}

func (r *ringBuffer) Write(p []byte) (n int, err error) {
	for _, b := range p {
		r.buf[r.pos] = b
		r.pos++
		if r.pos == len(r.buf) {
			r.pos = 0
			r.full = true
		}
	}
	return len(p), nil
}

func (r *ringBuffer) String() string {
	if !r.full {
		return string(r.buf[:r.pos])
	}
	res := make([]byte, len(r.buf))
	copy(res, r.buf[r.pos:])
	copy(res[len(r.buf)-r.pos:], r.buf[:r.pos])
	return string(res)
}

type spinnerWriter struct {
	spinner *ui.LiveSpinner
}

func (w *spinnerWriter) Write(p []byte) (n int, err error) {
	str := string(p)
	lines := strings.Split(str, "\n")
	if len(lines) > 0 {
		last := strings.TrimSpace(lines[len(lines)-1])
		if last == "" && len(lines) > 1 {
			last = strings.TrimSpace(lines[len(lines)-2])
		}
		if last != "" {
			w.spinner.UpdateDetail(last)
		}
	}
	return len(p), nil
}

func sanitizeTerminalOutput(raw string) string {
	var b strings.Builder
	b.Grow(len(raw))
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if c == '\n' || c == '\r' || c == '\t' || (c >= 0x20 && c != 0x7f) {
			b.WriteByte(c)
		}
	}
	return b.String()
}

func runWithLiveSpinner(ctx context.Context, dir string, name string, env []string, spinner *ui.LiveSpinner, args ...string) error {
	// #nosec G204 -- name is strictly "cmake" with validated non-shell argv elements.
	c := exec.CommandContext(ctx, name, args...)
	c.Dir = dir
	c.Stdin = os.Stdin
	if len(env) > 0 {
		c.Env = env
	}

	ringBuf := newRingBuffer(1 * 1024 * 1024)
	sw := &spinnerWriter{spinner: spinner}
	c.Stdout = io.MultiWriter(sw, ringBuf)
	c.Stderr = io.MultiWriter(sw, ringBuf)

	err := c.Run()
	if err != nil {
		spinner.Stop()
		captured := sanitizeTerminalOutput(ringBuf.String())
		_, _ = fmt.Fprintf(os.Stderr, "\n%s\n", captured)
		classifyBuildError(captured, dir)
	}
	return err
}

func classifyBuildError(output string, projectDir string) {
	outLower := strings.ToLower(output)
	projectBase := strings.ToLower(filepath.Base(projectDir))

	switch {
	case strings.Contains(outLower, "toobloader/hal"):
		ui.ErrorBanner("HAL Layer Error",
			"The compiler found an error in the Hardware Abstraction Layer.",
			"If you spawned this chip locally, check your modifications. Otherwise, report a bug.")
	case strings.Contains(outLower, "toobloader/core"):
		ui.ErrorBanner("Core SDK Error",
			"The error originated in the Toob Core SDK.",
			"This is usually a bug in the Toob-Loader repository. Please report it.")
	case strings.Contains(outLower, "crypto/") || strings.Contains(outLower, "crypto\\") || strings.Contains(outLower, "crypto_"):
		ui.ErrorBanner("Cryptography Layer Error",
			"The compiler found an error in a crypto package.",
			"Check your [crypto] configuration in device.toml and ensure the package is compatible with your Core SDK version.")
	case strings.Contains(outLower, "src/") || strings.Contains(outLower, "app/") || strings.Contains(outLower, "main/") || strings.Contains(outLower, "components/") || strings.Contains(outLower, projectBase+"/"):
		ui.ErrorBanner("Application Code Error",
			"The compiler found an error in your application code.",
			"Check the files in your project directory.")
	case strings.Contains(outLower, "exec: \"cmake\": executable file not found") || strings.Contains(outLower, "gcc: fatal error: cannot execute") || strings.Contains(outLower, "unrecognized command line option"):
		ui.ErrorBanner("Toolchain / Environment Error",
			"The compiler executable failed or is missing components.",
			"Try running 'toob clean --toolchains' and rebuilding.")
	default:
		ui.ErrorBanner("Unknown Error Category",
			"Could not automatically classify the error.",
			"Please read the raw compiler output above.")
	}
}

func findToolchainBin(prefix, expectedVersion, upstreamVersion string) string {
	return toolchain.FindCachedBinDir(prefix, expectedVersion, upstreamVersion)
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".toob-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil && runtime.GOOS != "windows" {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func writeFileIfChanged(path string, data []byte) error {
	// #nosec G304 -- path is an internal build artifact path inside validated buildDir.
	if old, err := os.ReadFile(path); err == nil && bytes.Equal(old, data) {
		return nil
	}
	return writeFileAtomic(path, data, 0o644)
}
