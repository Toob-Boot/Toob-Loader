package buildrunner

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/Toob-Boot/Toob-Loader/toob-go-lib/build"
	"github.com/toob-boot/toob/internal/apiclient"
	"github.com/toob-boot/toob/internal/lockfile"
	"github.com/toob-boot/toob/internal/manifest"
	"github.com/toob-boot/toob/internal/paths"
	"github.com/toob-boot/toob/internal/registry"
	"github.com/toob-boot/toob/internal/resolve"
	"github.com/toob-boot/toob/internal/ui"
)

const (
	combinationCheckTimeout = 3 * time.Second
	combinationJoinWait     = 200 * time.Millisecond
)

// NativeOptions configures a single-pass native firmware build.
type NativeOptions struct {
	ManifestPath   string
	BuildDir       string
	OutDir         string
	Profile        string
	ToolchainPath  string
	RegistryURL    string
	Integration    string
	MockOverrides  []string
	MockSet        bool
	Stage0Only     bool
	Clean          bool
	Locked         bool
	DevMode        bool
	Verbose        bool
	NoCCache       bool
	NoUpdateCheck  bool
	SkipChecks     bool
	CLIVersion     string
	ExecutablePath string
	Stdout         io.Writer
	Stderr         io.Writer
}

// NativeResult captures the resolved plan, generated manifests, verified
// outputs, and timings from a completed RunNative execution.
type NativeResult struct {
	ProjectRoot    string
	ManifestPath   string
	BuildDir       string
	OutDir         string
	CoreSDKDir     string
	CoreSDKSHA256  string
	Plan           *resolve.Plan
	Device         *manifest.DeviceToml
	ManifestCtx    *manifest.Context
	ManifestResult *manifest.Result
	Toolchain      *ResolvedToolchain
	PostLink       *PostLinkResult
	RegistryRemote string
	Reconfigured   bool
	Timings        *TimingTracker
}

// TimingEntry records elapsed duration for one named build phase.
type TimingEntry struct {
	Phase    string
	Duration time.Duration
}

// TimingTracker collects non-global per-phase build timings.
type TimingTracker struct {
	entries []TimingEntry
}

// NewTimingTracker creates an empty build phase timing tracker.
func NewTimingTracker() *TimingTracker {
	return &TimingTracker{}
}

// Track executes fn and records its elapsed wall-clock duration under phase.
func (t *TimingTracker) Track(phase string, fn func() error) error {
	start := time.Now()
	err := fn()
	if t != nil {
		t.entries = append(t.entries, TimingEntry{
			Phase:    phase,
			Duration: time.Since(start),
		})
	}
	return err
}

// Entries returns a copy of the recorded phase durations.
func (t *TimingTracker) Entries() []TimingEntry {
	if t == nil {
		return nil
	}
	return slices.Clone(t.entries)
}

// WriteSummary prints formatted build phase timings to w.
func (t *TimingTracker) WriteSummary(w io.Writer) {
	if t == nil || w == nil || len(t.entries) == 0 {
		return
	}
	var total time.Duration
	for _, e := range t.entries {
		total += e.Duration
		_, _ = fmt.Fprintf(w, "  %-24s %s\n", e.Phase+":", e.Duration.Round(time.Millisecond))
	}
	_, _ = fmt.Fprintf(w, "  %-24s %s\n", "Total:", total.Round(time.Millisecond))
}

// ResolveWorkspaceAndManifest resolves the project root and verified
// device.toml path from an optional --manifest flag.
func ResolveWorkspaceAndManifest(manifestOpt string) (root, manifestPath string, err error) {
	trimmed := strings.TrimSpace(manifestOpt)
	if trimmed != "" {
		absManifest, absErr := filepath.Abs(trimmed)
		if absErr != nil {
			return "", "", fmt.Errorf("resolve manifest path %q: %w", manifestOpt, absErr)
		}
		if !isRegularFile(absManifest) {
			return "", "", fmt.Errorf("manifest file not found: %s", absManifest)
		}
		projRoot, rootErr := paths.FindProjectRootFromManifest(absManifest)
		if rootErr != nil {
			return "", "", rootErr
		}
		return projRoot, absManifest, nil
	}

	projRoot, rootErr := paths.FindProjectRoot("")
	if rootErr != nil {
		return "", "", rootErr
	}
	defaultManifest := filepath.Join(projRoot, "device.toml")
	if !isRegularFile(defaultManifest) {
		return "", "", fmt.Errorf("device.toml not found in project root %s", projRoot)
	}
	return projRoot, defaultManifest, nil
}

// ResolveRegistryOverride validates [build] registry from device.toml, gating
// insecure http://, file://, and filesystem paths strictly behind devMode.
func ResolveRegistryOverride(rawSpec, projectRoot string, devMode bool) (remoteURL, localDir string, err error) {
	spec := strings.TrimSpace(rawSpec)
	if spec == "" {
		return "", "", nil
	}

	lower := strings.ToLower(spec)
	switch {
	case strings.HasPrefix(lower, "https://"):
		return spec, "", nil
	case strings.HasPrefix(lower, "http://"):
		if !devMode {
			return "", "", fmt.Errorf("insecure http:// registry %q in device.toml requires --dev", spec)
		}
		return spec, "", nil
	case strings.HasPrefix(lower, "file://"):
		if !devMode {
			return "", "", fmt.Errorf("local file:// registry %q in device.toml requires --dev", spec)
		}
		parsed, parseErr := registry.ParseFileURL(spec)
		if parseErr != nil {
			return "", "", fmt.Errorf("parse [build] registry %q: %w", spec, parseErr)
		}
		dir := resolveDirAgainstRoot(parsed, projectRoot)
		if !isDir(dir) {
			return "", "", fmt.Errorf("local registry directory %s does not exist", dir)
		}
		return "", dir, nil
	default:
		if !devMode {
			return "", "", fmt.Errorf("local filesystem registry %q in device.toml requires --dev", spec)
		}
		dir := resolveDirAgainstRoot(spec, projectRoot)
		if !isDir(dir) {
			return "", "", fmt.Errorf("local registry directory %s does not exist", dir)
		}
		return "", dir, nil
	}
}

// PrepareManifestInputs executes resolve.Resolve in a single pass and converts
// the resulting plan into manifest.Inputs without reparsing device.toml.
func PrepareManifestInputs(
	root string,
	dt *manifest.DeviceToml,
	lf *lockfile.Lockfile,
	cache *registry.Cache,
	idx *registry.Index,
	coreDir string,
	halRootOverride string,
	profile string,
	integration string,
	mockOverrides []string,
	mockSet bool,
	locked bool,
	outDir string,
) (*resolve.Plan, manifest.Inputs, error) {
	if dt == nil {
		return nil, manifest.Inputs{}, errors.New("prepare manifest inputs: DeviceToml is required")
	}

	plan, err := resolve.Resolve(resolve.Input{
		Root:          root,
		Device:        dt,
		Lock:          lf,
		Index:         idx,
		Registry:      cache,
		Profile:       profile,
		HalRoot:       halRootOverride,
		CoreDir:       coreDir,
		Integration:   integration,
		MockOverrides: mockOverrides,
		MockSet:       mockSet,
		Locked:        locked,
	})
	if err != nil {
		return nil, manifest.Inputs{}, err
	}

	inputs := manifest.Inputs{
		Device:             dt,
		ProjectDir:         root,
		HardwarePath:       plan.Chip.HardwarePath,
		ChipManifestPath:   plan.Chip.ManifestPath,
		HalRoot:            plan.HalRoot,
		CoreDir:            coreDir,
		ArchDir:            plan.Arch.Dir,
		DriverDirs:         extractDriverDirs(plan.DriverPackages),
		CryptoDirs:         plan.CryptoDirs(),
		RecoveryDriverDirs: plan.RecoveryDriverDirs(),
		RecoveryCryptoDirs: plan.RecoveryCryptoDirs(),
		SourceDirs:         collectAuditSourceDirs(root, coreDir, plan),
		OutDir:             outDir,
	}

	return plan, inputs, nil
}

// RunNative executes a single-pass, end-to-end native Toob-Loader build.
func RunNative(ctx context.Context, opts NativeOptions) (*NativeResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	stdout := cmp.Or[io.Writer](opts.Stdout, os.Stdout)
	stderr := cmp.Or[io.Writer](opts.Stderr, os.Stderr)
	effectiveDev := opts.DevMode || paths.IsDevMode()
	timings := NewTimingTracker()

	root, manifestPath, err := ResolveWorkspaceAndManifest(opts.ManifestPath)
	if err != nil {
		return nil, err
	}

	buildDir, outDir, err := resolveOutputDirs(root, opts.BuildDir, opts.OutDir)
	if err != nil {
		return nil, err
	}

	if opts.Clean {
		if cleanErr := cleanBuildDirectory(root, buildDir); cleanErr != nil {
			return nil, cleanErr
		}
	}
	if mkErr := os.MkdirAll(outDir, 0o750); mkErr != nil {
		return nil, fmt.Errorf("create output directory %s: %w", outDir, mkErr)
	}

	var dt *manifest.DeviceToml
	var lf *lockfile.Lockfile
	var cache *registry.Cache
	var idx *registry.Index
	var regRemote string

	err = timings.Track("Resolve & Registry", func() error {
		var parseErr error
		dt, parseErr = manifest.ParseToml(manifestPath)
		if parseErr != nil {
			return fmt.Errorf("parse %s: %w", manifestPath, parseErr)
		}

		var lockErr error
		lf, lockErr = loadProjectLockfile(root, opts.Locked)
		if lockErr != nil {
			return lockErr
		}

		remoteOverride, localOverride, regErr := ResolveRegistryOverride(dt.Build.Registry, root, effectiveDev)
		if regErr != nil {
			return regErr
		}

		regRemote = resolveRemoteRegistryURL(opts.RegistryURL, remoteOverride, "")
		cache, idx, regErr = openBuildRegistry(ctx, root, manifestPath, dt, lf, regRemote, localOverride, effectiveDev, opts.Locked)
		if regErr != nil {
			return regErr
		}
		regRemote = resolveRemoteRegistryURL(opts.RegistryURL, remoteOverride, cache.Remote())
		return nil
	})
	if err != nil {
		return nil, err
	}

	var coreDir, coreSHA string
	err = timings.Track("Core SDK", func() error {
		coreVer, verErr := SelectCoreSDKVersion(dt, lf, idx, opts.Locked)
		if verErr != nil && !effectiveDev {
			return verErr
		}
		var sdkErr error
		coreDir, coreSHA, sdkErr = EnsureCoreSDK(ctx, CoreSDKOptions{
			ProjectRoot: root,
			Version:     coreVer,
			RegistryURL: regRemote,
			Index:       idx,
			Lock:        lf,
			DevMode:     effectiveDev,
			Locked:      opts.Locked,
		})
		return sdkErr
	})
	if err != nil {
		return nil, err
	}

	profile := normalizeBuildProfile(opts.Profile, dt)
	sdk := resolve.LocateSDK(root, coreDir)
	if sdk.Core == "" {
		sdk.Core = coreDir
	}
	effectiveCoreDir := sdk.Core

	var plan *resolve.Plan
	var manifestInputs manifest.Inputs
	var mctx *manifest.Context
	var mres *manifest.Result

	err = timings.Track("Manifest & Codegen", func() error {
		var resolveErr error
		plan, manifestInputs, resolveErr = PrepareManifestInputs(
			root, dt, lf, cache, idx, effectiveCoreDir, "",
			profile, opts.Integration, opts.MockOverrides, opts.MockSet, opts.Locked, outDir,
		)
		if resolveErr != nil {
			return resolveErr
		}

		var loadErr error
		if opts.Verbose {
			mctx, loadErr = manifest.Load(manifestInputs)
		} else {
			mctx, loadErr = manifest.LoadSilent(manifestInputs)
		}
		if loadErr != nil {
			return loadErr
		}

		var genErr error
		mres, genErr = manifest.Generate(mctx)
		if genErr != nil {
			return genErr
		}

		cliPath := strings.TrimSpace(opts.ExecutablePath)
		if cliPath == "" {
			if exePath, exeErr := os.Executable(); exeErr == nil {
				cliPath = filepath.Clean(exePath)
			}
		}

		cmakeCfg := plan.RenderConfig(sdk, cliPath)
		cfgPath := filepath.Join(outDir, "toob_config.cmake")
		if writeErr := build.WriteFileIfChanged(cfgPath, []byte(cmakeCfg)); writeErr != nil {
			return fmt.Errorf("write %s: %w", cfgPath, writeErr)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	var tc *ResolvedToolchain
	err = timings.Track("Toolchain", func() error {
		var tcErr error
		tc, tcErr = ProvisionToolchain(ctx, plan, cache.Dir(), opts.ToolchainPath, opts.Locked)
		return tcErr
	})
	if err != nil {
		return nil, err
	}

	comboCh := startCombinationCheck(ctx, regRemote, plan.Chip.Name, plan.Chip.Version, opts.CLIVersion, opts.NoUpdateCheck)

	mockOpt := "OFF"
	if plan.MockHW {
		mockOpt = "ON"
	}

	cmdEnv := buildSubprocessEnv(ctx, tc.BinDir)
	useCCache := !opts.NoCCache && hasExecutableInEnv(cmdEnv, "ccache")

	fpInputs := NewFingerprintInputs(opts, root, coreDir, plan.HalRoot, outDir, plan, mres, tc.CMakePathArg, mockOpt, useCCache)
	fingerprint, err := ComputeCMakeFingerprint(fpInputs)
	if err != nil {
		return nil, err
	}

	reconfigured := FingerprintNeedsConfigure(buildDir, fingerprint)
	if reconfigured {
		err = timings.Track("CMake Configure", func() error {
			return runCMakeConfigure(ctx, buildDir, coreDir, outDir, manifestPath, plan, tc.CMakePathArg, mockOpt, useCCache, fingerprint, cmdEnv, opts.Verbose, stdout, stderr)
		})
		if err != nil {
			return nil, err
		}
	}

	err = timings.Track("Ninja Build", func() error {
		return runCMakeBuild(ctx, buildDir, opts.Stage0Only, cmdEnv, opts.Verbose, stdout, stderr)
	})
	if err != nil {
		return nil, err
	}

	var postLink *PostLinkResult
	err = timings.Track("Post-Link Gates", func() error {
		var gateErr error
		postLink, gateErr = RunPostLinkGates(PostLinkGateOptions{
			BuildDir:       buildDir,
			PackagesDir:    plan.HalRoot,
			Profile:        profile,
			Plan:           plan,
			Device:         dt,
			ManifestCtx:    mctx,
			ManifestResult: mres,
			Stage0Only:     opts.Stage0Only,
		})
		return gateErr
	})
	if err != nil {
		return nil, err
	}

	if !opts.Locked {
		indexSHA, _ := fileSHA256Hex(filepath.Join(cache.Dir(), "registry.json"))
		regRev, _ := cache.HeadCommit()
		effectiveCoreSHA := cmp.Or(coreSHA, plan.CoreSDK.SHA256)
		updatedLF, lfErr := plan.ToLockfile(cache, lf, regRemote, regRev, indexSHA, effectiveCoreSHA, tc.DigestSHA256)
		if lfErr != nil {
			return nil, fmt.Errorf("generate toob.lock: %w", lfErr)
		}
		if saveErr := updatedLF.Save(paths.LockfilePath(root)); saveErr != nil {
			return nil, fmt.Errorf("save toob.lock: %w", saveErr)
		}
	}

	consumeCombinationWarning(comboCh, stderr)

	return &NativeResult{
		ProjectRoot:    root,
		ManifestPath:   manifestPath,
		BuildDir:       buildDir,
		OutDir:         outDir,
		CoreSDKDir:     effectiveCoreDir,
		CoreSDKSHA256:  cmp.Or(coreSHA, plan.CoreSDK.SHA256),
		Plan:           plan,
		Device:         dt,
		ManifestCtx:    mctx,
		ManifestResult: mres,
		Toolchain:      tc,
		PostLink:       postLink,
		RegistryRemote: regRemote,
		Reconfigured:   reconfigured,
		Timings:        timings,
	}, nil
}

func resolveOutputDirs(root, buildDirOpt, outDirOpt string) (buildDir, outDir string, err error) {
	if strings.TrimSpace(buildDirOpt) != "" {
		buildDir, err = filepath.Abs(buildDirOpt)
		if err != nil {
			return "", "", fmt.Errorf("resolve build dir %q: %w", buildDirOpt, err)
		}
	} else {
		buildDir = filepath.Join(root, "build")
	}

	if strings.TrimSpace(outDirOpt) != "" {
		outDir, err = filepath.Abs(outDirOpt)
		if err != nil {
			return "", "", fmt.Errorf("resolve output dir %q: %w", outDirOpt, err)
		}
	} else {
		outDir = filepath.Join(buildDir, "generated")
	}
	return buildDir, outDir, nil
}

func cleanBuildDirectory(root, buildDir string) error {
	cleanBuild := filepath.Clean(buildDir)
	cleanRoot := filepath.Clean(root)
	if cleanBuild == cleanRoot || cleanBuild == filepath.Dir(cleanBuild) {
		return fmt.Errorf("refusing to clean unsafe build directory %s", cleanBuild)
	}
	if err := os.RemoveAll(cleanBuild); err != nil {
		return fmt.Errorf("clean build directory %s: %w", cleanBuild, err)
	}
	return nil
}

func loadProjectLockfile(root string, locked bool) (*lockfile.Lockfile, error) {
	lockPath := paths.LockfilePath(root)
	lf, err := lockfile.Load(lockPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if locked {
				return nil, fmt.Errorf("--locked requires an existing lockfile at %s", lockPath)
			}
			return nil, nil
		}
		return nil, fmt.Errorf("load %s: %w", lockPath, err)
	}
	return lf, nil
}

func openBuildRegistry(
	ctx context.Context,
	root, manifestPath string,
	dt *manifest.DeviceToml,
	lf *lockfile.Lockfile,
	regRemote, localOverride string,
	devMode, locked bool,
) (*registry.Cache, *registry.Index, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	var cache *registry.Cache
	var err error

	canUseOpenForProject := !locked &&
		localOverride == "" &&
		filepath.Clean(manifestPath) == filepath.Clean(filepath.Join(root, "device.toml")) &&
		regRemote == cmp.Or(strings.TrimSpace(dt.Build.Registry), strings.TrimSpace(os.Getenv("TOOB_REGISTRY_URL")), apiclient.DefaultBaseURL)

	if canUseOpenForProject {
		cache, err = registry.OpenForProject(root, devMode) //nolint:contextcheck // internal/registry.OpenForProject does not accept context.Context.
		if err != nil {
			return nil, nil, fmt.Errorf("open project registry: %w", err)
		}
	} else {
		switch {
		case localOverride != "":
			cache = registry.NewCache("file://" + filepath.ToSlash(localOverride))
		case regRemote != "":
			cache = registry.NewCache(regRemote)
		default:
			cache = registry.NewCache("")
		}

		if !cache.IsInitialized() {
			if locked {
				return nil, nil, errors.New("--locked requires an initialized local registry cache (run without --locked first)")
			}
			if syncErr := cache.Sync(false, false); syncErr != nil { //nolint:contextcheck // internal/registry.Cache.Sync does not accept context.Context.
				return nil, nil, fmt.Errorf("sync registry cache: %w", syncErr)
			}
		}

		if locked && !cache.IsLocalOverride() && lf != nil {
			ref := cmp.Or(strings.TrimSpace(lf.Registry.Revision), strings.TrimSpace(lf.Registry.Commit), strings.TrimSpace(lf.Registry.Version))
			if ref != "" {
				if selErr := cache.SelectVersion(ref, false); selErr != nil { //nolint:contextcheck // internal/registry.Cache.SelectVersion does not accept context.Context.
					return nil, nil, fmt.Errorf("select locked registry revision %q: %w", ref, selErr)
				}
			}
			if expectedIdxSHA := strings.TrimSpace(lf.Registry.IndexSHA256); expectedIdxSHA != "" {
				idxPath := filepath.Join(cache.Dir(), "registry.json")
				actualIdxSHA, hashErr := fileSHA256Hex(idxPath)
				if hashErr != nil {
					return nil, nil, fmt.Errorf("verify locked registry.json digest: %w", hashErr)
				}
				if !strings.EqualFold(actualIdxSHA, expectedIdxSHA) {
					return nil, nil, fmt.Errorf("registry.json SHA-256 (%s) mismatches toob.lock registry.index_sha256 (%s)", actualIdxSHA, expectedIdxSHA)
				}
			}
		}
	}

	idx, err := cache.LoadIndex()
	if err != nil {
		return nil, nil, fmt.Errorf("load registry index from %s: %w", cache.Dir(), err)
	}
	return cache, idx, nil
}

func resolveRemoteRegistryURL(optURL, deviceRemote, cacheRemote string) string {
	for _, cand := range []string{optURL, deviceRemote, cacheRemote, os.Getenv("TOOB_REGISTRY_URL")} {
		trimmed := strings.TrimSpace(cand)
		lower := strings.ToLower(trimmed)
		if strings.HasPrefix(lower, "https://") || strings.HasPrefix(lower, "http://") {
			return trimmed
		}
	}
	return apiclient.DefaultBaseURL
}

func normalizeBuildProfile(cliProfile string, dt *manifest.DeviceToml) string {
	if p := strings.TrimSpace(cliProfile); p != "" {
		return strings.ToLower(p)
	}
	if dt != nil && strings.TrimSpace(dt.Build.Profile) != "" {
		return strings.ToLower(strings.TrimSpace(dt.Build.Profile))
	}
	return resolve.ProfileProduction
}

func buildSubprocessEnv(ctx context.Context, tcBinDir string) []string {
	env := FindBuildToolsEnv(ctx, os.Environ())
	if strings.TrimSpace(tcBinDir) == "" {
		return env
	}
	sep := string(os.PathListSeparator)
	curPath := getEnvFold(env, "PATH")
	if curPath == "" {
		return setEnvFold(env, "PATH", tcBinDir)
	}
	return setEnvFold(env, "PATH", tcBinDir+sep+curPath)
}

func lookupExecutableInEnv(env []string, name string) (string, bool) {
	pathList := getEnvFold(env, "PATH")
	names := []string{name}
	if runtime.GOOS == "windows" && !strings.HasSuffix(strings.ToLower(name), ".exe") {
		names = []string{name + ".exe", name}
	}
	for _, dir := range filepath.SplitList(pathList) {
		if dir == "" {
			continue
		}
		for _, cand := range names {
			if isRegularFileInDir(dir, cand) {
				return filepath.Join(dir, cand), true
			}
		}
	}
	return name, false
}

func hasExecutableInEnv(env []string, name string) bool {
	_, ok := lookupExecutableInEnv(env, name)
	return ok
}

func runCMakeConfigure(
	ctx context.Context,
	buildDir, coreDir, outDir, manifestPath string,
	plan *resolve.Plan,
	tcPathArg, mockOpt string,
	useCCache bool,
	fingerprint string,
	cmdEnv []string,
	verbose bool,
	stdout, stderr io.Writer,
) error {
	for _, check := range []struct {
		path  string
		label string
	}{
		{coreDir, "core SDK path"},
		{buildDir, "build directory"},
		{outDir, "generated output directory"},
		{manifestPath, "device manifest path"},
		{plan.HalRoot, "HAL root directory"},
		{tcPathArg, "toolchain path"},
	} {
		if check.path == "" {
			continue
		}
		if err := ValidateCMakeArgPath(filepath.ToSlash(check.path), check.label); err != nil {
			return err
		}
	}

	_ = os.Remove(filepath.Join(buildDir, "CMakeCache.txt"))

	args := []string{
		"-S", filepath.ToSlash(coreDir),
		"-B", filepath.ToSlash(buildDir),
		"-G", "Ninja",
		"-DTOOB_BUILD_CONFIG=" + filepath.ToSlash(filepath.Join(outDir, "toob_config.cmake")),
		"-DTOOB_GENERATED_DIR=" + filepath.ToSlash(outDir),
		"-DTOOB_TARGET_CHIP=" + plan.Chip.Name,
		"-DTOOB_TARGET_ARCH=" + plan.Chip.Arch,
		"-DTOOB_TOOLCHAIN_PATH=" + tcPathArg,
		"-DTOOB_MOCK_HW=" + mockOpt,
		"-DCMAKE_BUILD_TYPE=Release",
	}
	if manifestPath != "" {
		args = append(args, "-DTOOB_DEVICE_MANIFEST="+filepath.ToSlash(manifestPath))
	}
	if plan.HalRoot != "" {
		args = append(args, "-DTOOB_HAL_ROOT="+filepath.ToSlash(plan.HalRoot))
	}
	if plan.Toolchain.File != "" {
		args = append(args, "-DCMAKE_TOOLCHAIN_FILE="+filepath.ToSlash(plan.Toolchain.File))
	}
	if useCCache {
		args = append(args, "-DCMAKE_C_COMPILER_LAUNCHER=ccache")
	}

	if err := execCMakeSubprocess(ctx, "Configuring build with CMake...", "cmake", args, cmdEnv, verbose, stdout, stderr); err != nil {
		return err
	}
	return WriteCMakeFingerprint(buildDir, fingerprint)
}

func runCMakeBuild(
	ctx context.Context,
	buildDir string,
	stage0Only bool,
	cmdEnv []string,
	verbose bool,
	stdout, stderr io.Writer,
) error {
	args := []string{"--build", filepath.ToSlash(buildDir)}
	if stage0Only {
		args = append(args, "--target", "toob_stage0")
	}
	return execCMakeSubprocess(ctx, "Compiling firmware targets...", "cmake", args, cmdEnv, verbose, stdout, stderr)
}

func execCMakeSubprocess(
	ctx context.Context,
	label, exe string,
	args, cmdEnv []string,
	verbose bool,
	stdout, stderr io.Writer,
) error {
	resolvedExe, _ := lookupExecutableInEnv(cmdEnv, exe)
	// #nosec G204,G702 -- exe is "cmake" resolved from validated cmdEnv PATH and args are validated via ValidateCMakeArgPath / fixed flags.
	cmd := exec.CommandContext(ctx, resolvedExe, args...)
	cmd.Env = cmdEnv

	ring := NewRingBuffer(defaultRingBufferBytes)
	var outWriter io.Writer
	var sw *SpinnerWriter
	var spinner *ui.LiveSpinner

	if verbose {
		outWriter = io.MultiWriter(stdout, ring)
	} else {
		spinner = ui.NewSpinner(label)
		spinner.Start()
		sw = NewSpinnerWriter(spinner)
		outWriter = io.MultiWriter(sw, ring)
	}

	cmd.Stdout = outWriter
	cmd.Stderr = outWriter

	err := cmd.Run()
	if sw != nil {
		sw.Flush()
	}
	if spinner != nil {
		spinner.Stop()
	}

	if err != nil {
		diag := ClassifyBuildError(ring.String())
		if diag != "" {
			_, _ = fmt.Fprintln(stderr, diag)
		}
		return fmt.Errorf("%s %s failed: %w", exe, strings.Join(args, " "), err)
	}
	return nil
}

func startCombinationCheck(
	ctx context.Context,
	regRemote, chip, chipVer, cliVer string,
	noUpdateCheck bool,
) <-chan string {
	ch := make(chan string, 1)
	if noUpdateCheck || strings.TrimSpace(regRemote) == "" || strings.TrimSpace(chip) == "" || strings.TrimSpace(chipVer) == "" {
		close(ch)
		return ch
	}

	go func() {
		defer close(ch)
		checkCtx, cancel := context.WithTimeout(ctx, combinationCheckTimeout)
		defer cancel()

		client := apiclient.NewForBaseURL(regRemote, combinationCheckTimeout)
		resp, err := client.CheckCombination(checkCtx, chip, chipVer, cliVer)
		if err != nil || resp == nil {
			return
		}
		if !resp.Compatible && strings.TrimSpace(resp.Status) != "" {
			ch <- fmt.Sprintf("%s@%s (CLI %s): status=%s", chip, chipVer, cliVer, SanitizeTerminalOutput(resp.Status))
		}
	}()
	return ch
}

func consumeCombinationWarning(ch <-chan string, stderr io.Writer) {
	select {
	case msg, ok := <-ch:
		if ok && msg != "" {
			_, _ = fmt.Fprintf(stderr, "Compatibility notice: %s\n", msg)
		}
	case <-time.After(combinationJoinWait):
	}
}

func resolveDirAgainstRoot(raw, root string) string {
	if filepath.IsAbs(raw) {
		return filepath.Clean(raw)
	}
	return filepath.Clean(filepath.Join(root, raw))
}

func isDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func extractDriverDirs(drivers []resolve.ResolvedDriver) []string {
	out := make([]string, 0, len(drivers))
	for i := range drivers {
		if drivers[i].Dir != "" {
			out = append(out, drivers[i].Dir)
		}
	}
	return out
}

func collectAuditSourceDirs(root, coreDir string, plan *resolve.Plan) []string {
	seen := make(map[string]struct{})
	var dirs []string
	add := func(d string) {
		if strings.TrimSpace(d) == "" {
			return
		}
		clean := filepath.Clean(d)
		if _, ok := seen[clean]; ok {
			return
		}
		seen[clean] = struct{}{}
		dirs = append(dirs, clean)
	}

	add(coreDir)
	add(root)
	if plan != nil {
		add(plan.Chip.Dir)
		add(plan.Arch.Dir)
		add(plan.SoCDir)
		for i := range plan.DriverPackages {
			add(plan.DriverPackages[i].Dir)
		}
		for _, c := range plan.CryptoDirs() {
			add(c)
		}
		for _, d := range plan.RecoveryDriverDirs() {
			add(d)
		}
		for _, c := range plan.RecoveryCryptoDirs() {
			add(c)
		}
	}
	return dirs
}
