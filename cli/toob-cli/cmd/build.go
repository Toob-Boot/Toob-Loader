package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Masterminds/semver/v3"

	"github.com/spf13/cobra"
	"github.com/toob-boot/toob/internal/apiclient"
	"github.com/toob-boot/toob/internal/lockfile"
	manifestpkg "github.com/toob-boot/toob/internal/manifest"
	"github.com/toob-boot/toob/internal/paths"
	"github.com/toob-boot/toob/internal/ports"
	"github.com/toob-boot/toob/internal/registry"
	"github.com/toob-boot/toob/internal/cbor"
	"github.com/toob-boot/toob/internal/toolchain"
	"github.com/toob-boot/toob/internal/ui"
)

func resolvePath(localRoot string, fallbackRoot string, relPath string) string {
	localPath := filepath.Join(localRoot, relPath)
	if _, err := os.Stat(localPath); err == nil {
		return localPath
	}
	return filepath.Join(fallbackRoot, relPath)
}

var (
	flagManifest      string
	flagBuildDir      string
	flagToolchainPath string
	flagNative        bool
	flagCloud         bool
	flagSkipChecks    bool
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
	var entries []ui.TimingEntry
	for _, p := range t.phases {
		entries = append(entries, ui.TimingEntry{Name: p.Name, Duration: p.Duration})
	}
	ui.TimingSummary(entries, total)
}

var buildCmd = &cobra.Command{
	Use:   "build",
	Short: "Run the full build pipeline (manifest -> cmake -> ninja)",
	RunE:  runBuild,
}

func init() {
	buildCmd.Flags().StringVar(&flagManifest, "manifest", "", "Path to device.toml (auto-detected if omitted)")
	buildCmd.Flags().StringVar(&flagBuildDir, "build-dir", "", "Build output directory (default: builds/build_<chip>)")
	buildCmd.Flags().StringVar(&flagToolchainPath, "toolchain-path", "", "Path to the cross-compiler bin/ directory")
	buildCmd.Flags().BoolVar(&flagNative, "native", false, "Force native build (use local toolchains instead of Docker)")
	buildCmd.Flags().BoolVar(&flagCloud, "cloud", false, "Compile firmware in the cloud (not yet supported)")
	buildCmd.Flags().BoolVar(&flagSkipChecks, "skip-checks", false, "Skip compatibility checks")
}

func runBuild(cmd *cobra.Command, args []string) error {

	// Resolve project root: if --manifest is given, use its parent directory.
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

	// 1. Enforce lockfile registry version and compatibility
	lfPath := paths.LockfilePath(root)
	lf, _ := lockfile.Load(lfPath)

	cache := registry.NewCache("")
	if lf != nil {
		targetVer := lf.Registry.Commit
		if targetVer == "" {
			targetVer = lf.Registry.Version
		}
		if targetVer != "" {
			if err := cache.SelectVersion(targetVer, true); err != nil {
				return fmt.Errorf("failed to select locked registry version %s: %w", targetVer, err)
			}
		}
	}

	if !cache.IsInitialized() {
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
		return runNativeBuild(ctx, root, cache)
	}
	return runDockerBuild(ctx, root, cache)
}

func runDockerBuild(ctx context.Context, root string, cache *registry.Cache) error {
	if _, err := exec.LookPath("docker"); err != nil {
		return fmt.Errorf("Docker is not installed or not in PATH.\nPlease install Docker to use the containerized compiler, or run `toob build --native`.")
	}

	regDir, _ := paths.RegistryDir()
	lfPath := paths.LockfilePath(root)
	lf, _ := lockfile.Load(lfPath)

	compilerTag := "latest"
	if lf != nil && lf.Environment.Compiler != "" {
		compilerTag = lf.Environment.Compiler
	}

	// Build the port contract struct — this is the single source of truth
	// for what we pass to the compiler container.
	input := ports.DockerBuildInput{
		Image:       fmt.Sprintf("mannomannx/toob-compiler:%s", compilerTag),
		Workspace:   root,
		RegistryDir: regDir,
		WorkDir:     "/workspace",
		Command:     "toob build --native",
		Manifest:    flagManifest,
		BuildDir:    flagBuildDir,
		ProxyVars:   make(map[string]string),
	}
	for _, envVar := range []string{"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy"} {
		if val := os.Getenv(envVar); val != "" {
			input.ProxyVars[envVar] = val
		}
	}

	// 1. Ensure image is fresh/pulled
	if compilerTag == "latest" {
		ui.Step("Pulling latest compiler image...")
		if err := exec.CommandContext(ctx, "docker", "pull", input.Image).Run(); err != nil {
			return fmt.Errorf("failed to pull compiler image %s: %w", input.Image, err)
		}
	} else {
		if err := exec.CommandContext(ctx, "docker", "image", "inspect", input.Image).Run(); err != nil {
			ui.Step("Compiler image %s not found locally. Pulling...", compilerTag)
			if err := exec.CommandContext(ctx, "docker", "pull", input.Image).Run(); err != nil {
				return fmt.Errorf("failed to pull compiler image %s: %w", input.Image, err)
			}
		}
	}

	// Protocol Handshake: verify the container image speaks our protocol
	if err := checkProtocolVersion(input.Image); err != nil {
		return err
	}

	// Derive Docker arguments from the port struct
	args := []string{"run", "--rm", "-i"}

	if stat, _ := os.Stdout.Stat(); (stat.Mode() & os.ModeCharDevice) != 0 {
		args = append(args, "-t")
	}

	if runtime.GOOS != "windows" {
		if u, err := user.Current(); err == nil {
			args = append(args, "-u", fmt.Sprintf("%s:%s", u.Uid, u.Gid))
		}
	}

	args = append(args,
		"-v", fmt.Sprintf("%s:/workspace", input.Workspace),
		"-v", fmt.Sprintf("%s:/root/.toob/registry", input.RegistryDir),
	)

	// Version-segmented ccache
	if home, err := os.UserHomeDir(); err == nil {
		ccacheDir := filepath.Join(home, ".toob", "ccache", compilerTag)
		os.MkdirAll(ccacheDir, 0755)
		args = append(args, "-v", fmt.Sprintf("%s:/ccache", ccacheDir), "-e", "CCACHE_DIR=/ccache")
	}

	hasProxy := false
	for k, v := range input.ProxyVars {
		args = append(args, "-e", fmt.Sprintf("%s=%s", k, v))
		hasProxy = true
	}

	if hasProxy && runtime.GOOS == "linux" {
		if _, err := os.Stat("/etc/ssl/certs"); err == nil {
			args = append(args, "-v", "/etc/ssl/certs:/etc/ssl/certs:ro")
		}
	}

	args = append(args, "-w", input.WorkDir, input.Image)
	args = append(args, strings.Fields(input.Command)...)

	if input.Manifest != "" {
		relManifest, err := filepath.Rel(root, input.Manifest)
		if err == nil {
			args = append(args, "--manifest", filepath.ToSlash(filepath.Join("/workspace", relManifest)))
		}
	}
	if input.BuildDir != "" {
		relBuildDir, err := filepath.Rel(root, input.BuildDir)
		if err == nil {
			args = append(args, "--build-dir", filepath.ToSlash(filepath.Join("/workspace", relBuildDir)))
		}
	}

	ui.Step("Starting Docker container (toob-compiler:%s)", compilerTag)
	err := run(ctx, root, "docker", nil, args...)
	if err == nil {
		ui.Tip("Run 'toob build --native' for much faster builds (requires local toolchains).")
		if lf, err := lockfile.Load(lfPath); err == nil {
			if os.Getenv("TOOB_REGISTRY_DIR") == "" {
				regVer := filepath.Base(cache.Dir())
				lf.Registry.Commit = regVer
				lf.Registry.Version = regVer
			}
			lf.Environment.Compiler = compilerTag
			_ = lf.Save(lfPath)
		}
	}
	return err
}

// checkProtocolVersion inspects the compiler container image for the
// toob.protocol_version label and compares it against our embedded version.
func checkProtocolVersion(image string) error {
	out, err := exec.Command("docker", "inspect",
		"--format", "{{index .Config.Labels \"toob.protocol_version\"}}",
		image,
	).Output()
	if err != nil {
		// Image might not exist yet (first pull). Skip handshake gracefully.
		ui.Muted("Protocol handshake skipped (image not cached locally).")
		return nil
	}

	label := strings.TrimSpace(string(out))
	if label == "" || label == "<no value>" {
		// Old image without label — allow but warn
		ui.Warn("Compiler image has no protocol version label. Consider pulling a newer image.")
		return nil
	}

	containerVersion, err := strconv.Atoi(label)
	if err != nil {
		return fmt.Errorf("invalid protocol version label on image: %q", label)
	}

	if containerVersion != ports.ProtocolVersion {
		if containerVersion > ports.ProtocolVersion {
			return fmt.Errorf(
				"Protocol mismatch: Compiler image speaks protocol v%d, but this CLI only supports v%d.\n"+
					"Your CLI is too old. Run `toob update` to get a compatible version.",
				containerVersion, ports.ProtocolVersion,
			)
		}
		return fmt.Errorf(
			"Protocol mismatch: Compiler image speaks protocol v%d, but this CLI requires v%d.\n"+
				"Your compiler image is outdated. Run `docker pull %s` to update.",
			containerVersion, ports.ProtocolVersion, image,
		)
	}

	return nil
}

func runNativeBuild(ctx context.Context, root string, cache *registry.Cache) error {
	buildStartTime := time.Now()
	timings := &TimingTracker{}

	// Accumulate all setup overhead mathematically perfectly
	var setupDuration time.Duration
	lastSetupResume := buildStartTime

	// 1. Resolve device manifest
	manifest := flagManifest
	if manifest == "" {
		manifest = filepath.Join(root, "device.toml")
	}
	manifest, _ = filepath.Abs(manifest)
	if _, err := os.Stat(manifest); err != nil {
		return fmt.Errorf("device manifest not found: %s", manifest)
	}
	dt, err := manifestpkg.ParseToml(manifest)
	if err != nil {
		return fmt.Errorf("failed to parse %s: %w", manifest, err)
	}

	lfPath := paths.LockfilePath(root)
	lf, _ := lockfile.Load(lfPath)

	chip := dt.Device.Chip
	if chip == "" {
		return fmt.Errorf("device.toml must define [device] with 'chip'")
	}
	ui.Info("Target: %s", chip)

	if flagSkipChecks && !cache.IsInitialized() {
		ui.Warn("Cannot skip checks because local registry is missing. Auto-syncing...")
		flagSkipChecks = false
	}

	// Pre-build compatibility check (async, resolved before compile step)
	type combinationResult struct {
		resp *apiclient.CheckCombinationResponse
		err  error
	}
	var combChan chan combinationResult

	if !flagSkipChecks {
		combChan = make(chan combinationResult, 1)
	}


	// Load Registry Index ONCE
	idx, err := cache.LoadIndex()
	if err != nil {
		ui.Warn("Could not load registry index: %v", err)
	}

	// 3. Resolve hardware.json & chip_manifest.json (HAL Registry Inheritance)
	var chipDir string
	var chipDirErr error
	getChipDir := func() (string, error) {
		if chipDir == "" && chipDirErr == nil {
			chipDir, chipDirErr = cache.ChipSourcePath(chip)
		}
		return chipDir, chipDirErr
	}

	hwJSON := filepath.Join(root, "toobloader", "hal", "chips", chip, "hardware.json")
	if _, err := os.Stat(hwJSON); err != nil {
		cd, err := getChipDir()
		if err != nil {
			return fmt.Errorf("failed to resolve chip '%s' from registry: %w", chip, err)
		}
		hwJSON = filepath.Join(cd, "hardware.json")
	}

	cmPath := filepath.Join(root, "toobloader", "hal", "chips", chip, "chip_manifest.json")
	if _, err := os.Stat(cmPath); err != nil {
		cd, err := getChipDir()
		if err != nil {
			return fmt.Errorf("failed to resolve chip '%s' from registry: %w", chip, err)
		}
		cmPath = filepath.Join(cd, "chip_manifest.json")
	}

	// Read Chip Manifest FIRST
	var cm ports.ChipManifest
	chipVersion := "1.0.0"
	arch := ""
	toolchainPrefix := ""

	if data, err := os.ReadFile(cmPath); err == nil {
		if err := json.Unmarshal(data, &cm); err == nil {
			if cm.Arch != "" {
				arch = cm.Arch
			}
			if cm.CompilerPrefix != "" {
				toolchainPrefix = cm.CompilerPrefix
			}
			if cm.Version != "" {
				chipVersion = cm.Version
			}
		} else {
			return fmt.Errorf("failed to parse chip_manifest.json: %w", err)
		}
	} else {
		ui.Step("Chip '%s' not found locally. Resolving from registry...", chip)
		chipDir, chipErr := cache.ChipSourcePath(chip)
		if chipErr != nil {
			return fmt.Errorf("chip '%s' not found locally or in registry: %w", chip, chipErr)
		}
		cmPath = filepath.Join(chipDir, "chip_manifest.json")
		if data, err := os.ReadFile(cmPath); err == nil {
			if err := json.Unmarshal(data, &cm); err != nil {
				return fmt.Errorf("failed to parse registry chip_manifest.json: %w", err)
			}
			if cm.Arch != "" {
				arch = cm.Arch
			}
			if cm.CompilerPrefix != "" {
				toolchainPrefix = cm.CompilerPrefix
			}
			if cm.Version != "" {
				chipVersion = cm.Version
			}
		} else {
			return fmt.Errorf("chip_manifest.json not found for chip '%s'", chip)
		}
	}

	if arch == "" || toolchainPrefix == "" {
		ui.ErrorBanner(
			"Missing Metadata",
			fmt.Sprintf("chip_manifest.json for '%s' is missing 'arch' or 'compiler_prefix'", chip),
			"Ensure the registry or local manifest defines these fields.",
		)
		return fmt.Errorf("invalid chip manifest")
	}

	// Fire async combination check now that chip + chipVersion are known
	if combChan != nil {
		go func() {
			client := apiclient.New()
			client.HTTPClient.Timeout = 3 * time.Second
			cliVer := Version
			if !strings.HasPrefix(cliVer, "v") && cliVer != "main" && cliVer != "dev" {
				cliVer = "v" + cliVer
			}
			resp, err := client.CheckCombination(cmd_defaultCtx(), chip, chipVersion, cliVer)
			combChan <- combinationResult{resp: resp, err: err}
		}()
	}

	// 4. Core SDK Version Resolution
	coreSDKVer := dt.Build.CoreSDK
	if lf != nil && lf.Environment.CoreSDK != "" {
		coreSDKVer = lf.Environment.CoreSDK
	}

	if coreSDKVer == "" || coreSDKVer == "latest" || coreSDKVer == "toob-boot" {
		ui.Step("Resolving latest Core SDK version...")
		latestTag, err := getLatestCoreSDKFromRegistry(idx)
		if err == nil {
			coreSDKVer = latestTag
		} else {
			if cm.MinCoreSDK != "" {
				coreSDKVer = cm.MinCoreSDK
			} else {
				coreSDKVer = "main"
			}
		}
	}

	coreSDKLabel := coreSDKVer
	if lf != nil && lf.Environment.CoreSDK != "" && lf.Environment.CoreSDK == coreSDKVer {
		coreSDKLabel = coreSDKVer + " (lockfile-pinned)"
	} else if coreSDKVer == "main" || coreSDKVer == "dev" {
		coreSDKLabel = coreSDKVer + " (fallback)"
	} else {
		coreSDKLabel = coreSDKVer + " (auto-resolved)"
	}

	// Validate against MinCoreSDK if present
	if cm.MinCoreSDK != "" && coreSDKVer != "main" && coreSDKVer != "dev" {
		vCurrent, errCurrent := parseCoreSDKVersion(coreSDKVer)
		vMin, errMin := parseCoreSDKVersion(cm.MinCoreSDK)
		if errCurrent == nil && errMin == nil {
			if vCurrent.LessThan(vMin) {
				return fmt.Errorf("FATAL: device.toml specifies Core SDK '%s', but the registry dictates a minimum of '%s' for chip '%s'!", coreSDKVer, cm.MinCoreSDK, chip)
			}
		}
	}

	compilerVer := dt.Build.Compiler
	compilerLabel := compilerVer
	if compilerVer == "" {
		compilerVer = "latest"
		compilerLabel = "latest (auto)"
	}

	if envReg := os.Getenv("TOOB_REGISTRY_DIR"); envReg != "" {
		ui.Info("Environment: Compiler=%s, CoreSDK=%s, Registry=Local Override (%s)", compilerLabel, coreSDKLabel, envReg)
	} else {
		ui.Info("Environment: Compiler=%s, CoreSDK=%s, Registry=Local Cache (%s)", compilerLabel, coreSDKLabel, cache.Dir())
	}

	// 5. Resolve Core SDK
	var compilerRoot string
	var coreDirToDownload string
	if envDir := os.Getenv("TOOB_COMPILER_DIR"); envDir != "" {
		compilerRoot = envDir
	} else {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("cannot determine home directory: %w", err)
		}
		coreDir := filepath.Join(homeDir, ".toob", "core", coreSDKVer)
		if _, err := os.Stat(coreDir); os.IsNotExist(err) {
			ui.Step("Core SDK '%s' not found locally. Downloading...", coreSDKVer)
			coreDirToDownload = coreDir
		}
		compilerRoot = coreDir
	}

	if coreDirToDownload != "" {
		ui.Step("Downloading Core SDK '%s' from Registry...", coreSDKVer)

		tempDir := coreDirToDownload + ".tmp-" + fmt.Sprintf("%d", time.Now().UnixNano())
		if err := os.MkdirAll(filepath.Dir(tempDir), 0o755); err != nil {
			return err
		}

		client := apiclient.NewWithTimeout(120 * time.Second)
		body, err := client.DownloadPackage(context.Background(), "toob-boot", coreSDKVer)
		if err != nil {
			return fmt.Errorf("failed to fetch Core SDK '%s' from registry: %w", coreSDKVer, err)
		}
		defer body.Close()

		if err := registry.ExtractTarball(body, tempDir); err != nil {
			os.RemoveAll(tempDir)
			return fmt.Errorf("failed to extract Core SDK: %w", err)
		}

		if err := os.Rename(tempDir, coreDirToDownload); err != nil {
			os.RemoveAll(tempDir)
			if _, statErr := os.Stat(coreDirToDownload); statErr == nil {
				return nil
			}
			return fmt.Errorf("failed to finalize atomic Core SDK download: %w", err)
		}
	}

	// 6. Determine build directory
	buildDir := flagBuildDir
	if buildDir == "" {
		buildDir = filepath.Join(root, "builds", "build_"+chip)
	}
	generatedDir := filepath.Join(buildDir, "generated")
	if err := os.MkdirAll(generatedDir, 0o755); err != nil {
		return err
	}

	setupDuration += time.Since(lastSetupResume)
	timings.Add("Project Setup", setupDuration)

	// 7. Run manifest compiler (Go Native)
	ui.Step("Running manifest compiler (Go Native)")
	startManifest := time.Now()
	bootloaderDir := resolvePath(root, compilerRoot, "toobloader")

	// Phase 3 Fix: Inject HAL paths to Manifest Compiler so it finds Registry sources
	halChipDir := filepath.Join(root, "toobloader", "hal", "chips", chip)
	if _, err := os.Stat(halChipDir); err != nil {
		if chipDir, chipErr := cache.ChipSourcePath(chip); chipErr == nil {
			halChipDir = chipDir
		}
	}

	var driverDirs []string
	var driversCMake strings.Builder
	var recoveryCMake strings.Builder

	var manifestRecovery *ports.ChipRecovery
	if idx != nil {
		if cInfo, ok := idx.Chips[chip]; ok && cInfo.Recovery != nil {
			manifestRecovery = &ports.ChipRecovery{
				Console:  cInfo.Recovery.Console,
				Flash:    cInfo.Recovery.Flash,
				WDT:      cInfo.Recovery.WDT,
				Clock:    cInfo.Recovery.Clock,
				RTC:      cInfo.Recovery.RTC,
				Sources:  cInfo.Recovery.Sources,
				Includes: cInfo.Recovery.Includes,
			}
			if cInfo.Recovery.Crypto != nil {
				manifestRecovery.Crypto = &ports.RecoveryCrypto{
					Backend: cInfo.Recovery.Crypto.Backend,
					Hash:    cInfo.Recovery.Crypto.Hash,
				}
			}
		}
	}
	if manifestRecovery == nil && cm.Recovery != nil {
		manifestRecovery = cm.Recovery
	}

	recCryptoBackend := ""
	recCryptoHash := ""

	if manifestRecovery != nil && manifestRecovery.Crypto != nil {
		recCryptoBackend = manifestRecovery.Crypto.Backend
		recCryptoHash = manifestRecovery.Crypto.Hash
	}

	if dt.Recovery.Crypto.Backend != "" {
		recCryptoBackend = dt.Recovery.Crypto.Backend
	}
	if dt.Recovery.Crypto.Hash != "" {
		recCryptoHash = dt.Recovery.Crypto.Hash
	}

	if recCryptoBackend == "" {
		if dt.Crypto.Backend != "" {
			recCryptoBackend = dt.Crypto.Backend
		} else if cm.Crypto != nil && cm.Crypto.Backend != "" {
			recCryptoBackend = cm.Crypto.Backend
		}
	}
	if recCryptoHash == "" {
		if dt.Crypto.Hash != "" {
			recCryptoHash = dt.Crypto.Hash
		} else if cm.Crypto != nil && cm.Crypto.Hash != "" {
			recCryptoHash = cm.Crypto.Hash
		}
	}

	recoveryCMake.WriteString(fmt.Sprintf("set(TOOB_RECOVERY_CRYPTO_BACKEND \"%s\")\n", recCryptoBackend))
	recoveryCMake.WriteString(fmt.Sprintf("set(TOOB_RECOVERY_CRYPTO_HASH \"%s\")\n", recCryptoHash))

	if idx != nil {
		if cInfo, ok := idx.Chips[chip]; ok {
			if cInfo.Sources != nil {
				for _, drvPath := range cInfo.Sources.Drivers {
					drvRelDir := filepath.Dir(drvPath)
					drvDir, err := cache.DriverSourcePath(filepath.ToSlash(drvRelDir))
					if err != nil {
						ui.Warn("Could not resolve driver '%s': %v", drvRelDir, err)
						continue
					}
					driverDirs = append(driverDirs, drvDir)
					driversCMake.WriteString(fmt.Sprintf("list(APPEND TOOB_DRIVERS \"%s\")\n", filepath.ToSlash(drvDir)))
				}
			}
		}
	}

	if manifestRecovery != nil {
		// Use manifest defaults, override with DeviceToml choices if set
		recConsole := manifestRecovery.Console
		if dt.Recovery.Console != "" {
			recConsole = dt.Recovery.Console
		}
		recFlash := manifestRecovery.Flash
		if dt.Recovery.Flash != "" {
			recFlash = dt.Recovery.Flash
		}
		recWDT := manifestRecovery.WDT
		if dt.Recovery.WDT != "" {
			recWDT = dt.Recovery.WDT
		}
		recClock := manifestRecovery.Clock
		if dt.Recovery.Clock != "" {
			recClock = dt.Recovery.Clock
		}
		recRTC := manifestRecovery.RTC
		if dt.Recovery.RTC != "" {
			recRTC = dt.Recovery.RTC
		}

		if recConsole == "" {
			return fmt.Errorf("chip '%s' manifest is missing required recovery 'console' driver mapping", chip)
		}
		if recFlash == "" {
			return fmt.Errorf("chip '%s' manifest is missing required recovery 'flash' driver mapping", chip)
		}
		var recDrivers []string
		for _, drvName := range []string{
			recConsole,
			recFlash,
			recWDT,
			recClock,
			recRTC,
		} {
			if drvName == "" {
				continue
			}
			drvDir, err := cache.DriverSourcePath(drvName)
			if err != nil {
				ui.Warn("Could not resolve recovery driver '%s': %v", drvName, err)
				continue
			}
			recDrivers = append(recDrivers, filepath.ToSlash(drvDir))
		}
		if len(recDrivers) > 0 {
			recoveryCMake.WriteString(fmt.Sprintf("set(TOOB_RECOVERY_DRIVERS \"%s\")\n", strings.Join(recDrivers, ";")))
		}
		var recSources []string
		for _, src := range manifestRecovery.Sources {
			recSources = append(recSources, filepath.ToSlash(filepath.Join(halChipDir, src)))
		}
		for _, src := range dt.Recovery.Sources {
			recSources = append(recSources, filepath.ToSlash(filepath.Join(root, src)))
		}
		if len(recSources) > 0 {
			recoveryCMake.WriteString(fmt.Sprintf("set(TOOB_RECOVERY_SOURCES \"%s\")\n", strings.Join(recSources, ";")))
		}
		var recIncludes []string
		for _, inc := range manifestRecovery.Includes {
			recIncludes = append(recIncludes, filepath.ToSlash(filepath.Join(halChipDir, inc)))
		}
		for _, inc := range dt.Recovery.Includes {
			recIncludes = append(recIncludes, filepath.ToSlash(filepath.Join(root, inc)))
		}
		if len(recIncludes) > 0 {
			fmt.Fprintf(&recoveryCMake, "set(TOOB_RECOVERY_INCLUDES \"%s\")\n", strings.Join(recIncludes, ";"))
		}
	}

	if socDir, err := cache.SoCSourcePath("soc"); err == nil {
		driverDirs = append(driverDirs, socDir)
	}

	if err := manifestpkg.Compile(manifest, hwJSON, generatedDir, bootloaderDir, halChipDir, driverDirs); err != nil {
		return err
	}
	timings.Add("Manifest Compiler", time.Since(startManifest))

	// 8. Run CBOR code generator
	startCbor := time.Now()
	if pyScripts := findPythonScriptsBin(); pyScripts != "" {
		os.Setenv("PATH", pyScripts+string(os.PathListSeparator)+os.Getenv("PATH"))
	}
	if err := cbor.Generate(generatedDir, compilerRoot, root, compilerVer); err != nil {
		return err
	}
	timings.Add("CBOR CodeGen", time.Since(startCbor))

	startEnvValidation := time.Now()

	// 7. CLI Blocker Logic: Check Compatibility Matrix (single-combination check)
	if !flagSkipChecks {
		result := <-combChan

		if result.err != nil {
			errMsg := result.err.Error()
			if strings.Contains(errMsg, "no such host") || strings.Contains(errMsg, "connect: connection refused") || strings.Contains(errMsg, "context deadline exceeded") {
				ui.Warn("Could not verify build combination: Registry API is unreachable (offline).")
			} else if strings.Contains(errMsg, "HTTP ") {
				parts := strings.SplitN(errMsg, ": ", 2)
				if len(parts) == 2 && (strings.Contains(parts[1], "<") || len(parts[1]) > 100) {
					ui.Warn("Could not verify build combination: Registry API returned %s.", parts[0])
				} else {
					ui.Warn("Could not verify build combination: %v", result.err)
				}
			} else {
				ui.Warn("Could not verify build combination: %v", result.err)
			}
		} else {
			switch strings.ToUpper(result.resp.Status) {
			case "FAILED":
				return fmt.Errorf("FATAL: Chip %s (v%s) is explicitly incompatible with CLI %s according to the Compatibility Matrix. Build aborted", chip, chipVersion, Version)
			case "UNKNOWN":
				ui.Warn("The combination of Chip %s (v%s) and CLI %s has not been verified by the CI yet.", chip, chipVersion, Version)
			case "VERIFIED":
				// Combination verified — proceed silently
			}
		}
	} else {
		ui.Muted("Skipping compatibility matrix checks (--skip-checks)")
	}

	// Calculate toolchain.cmake name based on architecture
	toolchainDirName := strings.TrimSuffix(toolchainPrefix, "-")
	tcConfigDir, tcErr := cache.ToolchainConfigPath(toolchainDirName)
	if tcErr != nil {
		return fmt.Errorf("failed to resolve toolchain config for '%s': %w", toolchainDirName, tcErr)
	}
	toolchainFile := filepath.Join(tcConfigDir, "toolchain.cmake")
	if _, err := os.Stat(toolchainFile); err != nil {
		return fmt.Errorf("registry toolchain missing: %s", toolchainFile)
	}

	coreDir := filepath.ToSlash(resolvePath(root, compilerRoot, filepath.Join("toobloader", "core")))
	stage0Dir := filepath.ToSlash(resolvePath(root, compilerRoot, filepath.Join("toobloader", "stage0")))

	// HALs: halChipDir already resolved above (step 7). Resolve arch.
	halArchDir := filepath.Join(root, "toobloader", "hal", "arch", arch)
	if _, err := os.Stat(halArchDir); err != nil {
		if archDir, archErr := cache.ArchSourcePath(arch); archErr == nil {
			halArchDir = archDir
		}
	}

	halChipDir = filepath.ToSlash(halChipDir)
	halArchDir = filepath.ToSlash(halArchDir)

	sdkDir := filepath.ToSlash(resolvePath(root, compilerRoot, filepath.Join("sdk")))

	toobCLIPath, err := os.Executable()
	if err != nil {
		toobCLIPath = "toob"
	}
	toobCLIPath = filepath.ToSlash(toobCLIPath)

	// --- Dynamic Crypto Resolution ---
	// Priority: device.toml override → chip_manifest.json default → empty (slot unused).
	cryptoSlots := map[string]string{"backend": "", "hash": "", "pqc": ""}
	if cm.Crypto != nil {
		if cm.Crypto.Backend != "" {
			cryptoSlots["backend"] = cm.Crypto.Backend
		}
		if cm.Crypto.Hash != "" {
			cryptoSlots["hash"] = cm.Crypto.Hash
		}
		if cm.Crypto.Pqc != "" {
			cryptoSlots["pqc"] = cm.Crypto.Pqc
		}
	}
	if dt.Crypto.Backend != "" {
		cryptoSlots["backend"] = dt.Crypto.Backend
	}
	if dt.Crypto.Hash != "" {
		cryptoSlots["hash"] = dt.Crypto.Hash
	}
	if dt.Crypto.Pqc != "" {
		cryptoSlots["pqc"] = dt.Crypto.Pqc
	}

	var cryptoCMake strings.Builder
	resolvedCryptoNames := make(map[string]bool) // deduplication tracker
	for _, slotName := range []string{"backend", "hash", "pqc"} {
		pkgName := cryptoSlots[slotName]
		slotUpper := strings.ToUpper(slotName)

		if pkgName == "" {
			cryptoCMake.WriteString(fmt.Sprintf("set(TOOB_CRYPTO_%s_ENABLED OFF)\n", slotUpper))
			continue
		}

		if idx == nil || idx.Crypto == nil {
			ui.Warn("Crypto package '%s' (slot: %s) declared but registry has no crypto index. Disabling slot.", pkgName, slotName)
			cryptoCMake.WriteString(fmt.Sprintf("set(TOOB_CRYPTO_%s_ENABLED OFF)\n", slotUpper))
			continue
		}
		cryptoPkg, ok := idx.Crypto[pkgName]
		if !ok {
			ui.Warn("Crypto package '%s' (slot: %s) not found in registry. Disabling slot.", pkgName, slotName)
			cryptoCMake.WriteString(fmt.Sprintf("set(TOOB_CRYPTO_%s_ENABLED OFF)\n", slotUpper))
			continue
		}

		// Validate min_core_sdk
		if cryptoPkg.MinCoreSdk != "" && coreSDKVer != "main" && coreSDKVer != "dev" {
			vCurrent, errCur := parseCoreSDKVersion(coreSDKVer)
			vMin, errMin := parseCoreSDKVersion(cryptoPkg.MinCoreSdk)
			if errCur == nil && errMin == nil && vCurrent.LessThan(vMin) {
				return fmt.Errorf("crypto package '%s' requires Core SDK >= %s, but resolved version is %s",
					pkgName, cryptoPkg.MinCoreSdk, coreSDKVer)
			}
		}

		// Validate chip_binding
		if len(cryptoPkg.ChipBinding) > 0 {
			bound := slices.Contains(cryptoPkg.ChipBinding, chip)
			if !bound {
				return fmt.Errorf("crypto package '%s' is chip-bound to %v, but target chip is '%s'",
					pkgName, cryptoPkg.ChipBinding, chip)
			}
		}

		// Resolve absolute paths and verify existence via API fetch
		cryptoDir, cryptoErr := cache.CryptoSourcePath(pkgName)
		if cryptoErr != nil {
			ui.Warn("Crypto package '%s' (slot: %s) not available: %v. Disabling slot.", pkgName, slotName, cryptoErr)
			cryptoCMake.WriteString(fmt.Sprintf("set(TOOB_CRYPTO_%s_ENABLED OFF)\n", slotUpper))
			continue
		}
		pkgDir := filepath.ToSlash(cryptoDir)

		// Deduplicate: if this package was already emitted for a previous slot, skip sources
		isDuplicate := resolvedCryptoNames[pkgName]
		resolvedCryptoNames[pkgName] = true

		cryptoCMake.WriteString(fmt.Sprintf("set(TOOB_CRYPTO_%s_ENABLED ON)\n", slotUpper))
		cryptoCMake.WriteString(fmt.Sprintf("set(TOOB_CRYPTO_%s_NAME \"%s\")\n", slotUpper, pkgName))
		cryptoCMake.WriteString(fmt.Sprintf("set(TOOB_CRYPTO_%s_DIR \"%s\")\n", slotUpper, pkgDir))

		if !isDuplicate {
			// Upstream sources
			var srcPaths []string
			for _, src := range cryptoPkg.UpstreamSources {
				srcPaths = append(srcPaths, filepath.ToSlash(filepath.Join(cryptoDir, src)))
			}
			cryptoCMake.WriteString(fmt.Sprintf("set(TOOB_CRYPTO_%s_SOURCES \"%s\")\n", slotUpper, strings.Join(srcPaths, ";")))

			// Wrapper
			if cryptoPkg.Wrapper != nil && *cryptoPkg.Wrapper != "" {
				wrapperPath := filepath.ToSlash(filepath.Join(cryptoDir, *cryptoPkg.Wrapper))
				cryptoCMake.WriteString(fmt.Sprintf("set(TOOB_CRYPTO_%s_WRAPPER \"%s\")\n", slotUpper, wrapperPath))
			}

			// Cflags
			if len(cryptoPkg.Cflags) > 0 {
				cryptoCMake.WriteString(fmt.Sprintf("set(TOOB_CRYPTO_%s_CFLAGS \"%s\")\n", slotUpper, strings.Join(cryptoPkg.Cflags, ";")))
			}

			// Include directories
			if len(cryptoPkg.Includes) > 0 {
				var incPaths []string
				for _, inc := range cryptoPkg.Includes {
					incPaths = append(incPaths, filepath.ToSlash(filepath.Join(cryptoDir, inc)))
				}
				cryptoCMake.WriteString(fmt.Sprintf("set(TOOB_CRYPTO_%s_INCLUDES \"%s\")\n", slotUpper, strings.Join(incPaths, ";")))
			}
		} else {
			// Duplicate: reference the previously emitted slot
			cryptoCMake.WriteString(fmt.Sprintf("# %s slot reuses package '%s' (already compiled by another slot)\n", slotUpper, pkgName))
		}
	}

	pqcEnabled := cryptoSlots["pqc"] != ""

	configContent := fmt.Sprintf(
		"set(TOOB_ARCH \"%s\")\nset(TOOB_CHIP \"%s\")\n"+
			"set(TOOLCHAIN_PREFIX \"%s\")\n"+
			"set(TOOB_CORE_DIR \"%s\")\n"+
			"set(TOOB_STAGE0_DIR \"%s\")\n"+
			"set(TOOB_HAL_CHIP_DIR \"%s\")\n"+
			"set(TOOB_HAL_ARCH_DIR \"%s\")\n"+
			"set(TOOB_SDK_DIR \"%s\")\n"+
			"set(TOOB_CLI_PATH \"%s\")\n"+
			"set(TOOB_CRYPTO_DIR \"%s\")\n"+
			"set(TOOB_FEATURE_PQC_HYBRID %s)\n"+
			"%s\n# --- Dynamic Crypto Configuration ---\n%s\n# --- Dynamic Recovery Configuration ---\n%s",
		arch, chip, toolchainPrefix,
		coreDir, stage0Dir, halChipDir, halArchDir, sdkDir, toobCLIPath,
		filepath.ToSlash(filepath.Join(bootloaderDir, "crypto")),
		map[bool]string{true: "ON", false: "OFF"}[pqcEnabled],
		driversCMake.String(), cryptoCMake.String(), recoveryCMake.String(),
	)

	if err := writeFileIfChanged(filepath.Join(generatedDir, "toob_config.cmake"), []byte(configContent)); err != nil {
		return err
	}

	// 8. Ensure cross-compiler is in PATH
	tcPath := flagToolchainPath
	var expectedVersion string
	if idx != nil && idx.Toolchains != nil {
		tcName := strings.TrimSuffix(toolchainPrefix, "-")
		if tcInfo, ok := idx.Toolchains[tcName]; ok {
			expectedVersion = tcInfo.Version
		}
	} else {
		expectedVersion = toolchain.GetExpectedVersion(toolchainPrefix, cache.Dir())
	}

	if lf, err := lockfile.Load(lfPath); err == nil {
		tcName := strings.TrimSuffix(toolchainPrefix, "-")
		if entry, ok := lf.Toolchains[tcName]; ok && entry.Version != "" {
			expectedVersion = entry.Version
		}
	}

	if tcPath == "" {
		tcPath = findToolchainBin(toolchainPrefix, expectedVersion)
		if tcPath == "" {
			// Auto-provision via Registry
			var err error

			tcPath, err = toolchain.EnsureAvailable(toolchainPrefix, expectedVersion, cache.Dir())
			if err != nil {
				return fmt.Errorf("failed to auto-provision toolchain: %w\nPlease run 'toob install' to verify your project dependencies or use --toolchain-path.", err)
			}
		}
	} else {
		compilerExe := filepath.Join(tcPath, toolchainPrefix+"gcc")
		if runtime.GOOS == "windows" {
			compilerExe += ".exe"
		}
		if _, err := os.Stat(compilerExe); err != nil {
			return fmt.Errorf("custom toolchain compiler not found at %s", compilerExe)
		}
		if expectedVersion != "" {
			out, err := exec.CommandContext(ctx, compilerExe, "--version").CombinedOutput()
			if err != nil || !strings.Contains(string(out), expectedVersion) {
				return fmt.Errorf("FATAL: Custom toolchain version mismatch!\nExpected: %s\nTo prevent tainted lockfiles and non-reproducible builds, please use a matching toolchain or use auto-provisioning.", expectedVersion)
			}
		}
	}

	var customEnv []string
	if tcPath != "" {
		customEnv = append(os.Environ(), "PATH="+tcPath+string(os.PathListSeparator)+os.Getenv("PATH"))
		ui.Info("Toolchain: %s", tcPath)
	}

	timings.Add("Environment Validation", time.Since(startEnvValidation))

	// 9. CMake configure
	startCMake := time.Now()
	ninjaFile := filepath.Join(buildDir, "build.ninja")
	if _, err := os.Stat(ninjaFile); os.IsNotExist(err) {
		spinner := ui.NewSpinner("Configuring CMake")
		spinner.Start()

		cmakeArgs := []string{
			"-G", "Ninja",
			"-B", buildDir,
			"-S", compilerRoot,
			"-DCMAKE_TOOLCHAIN_FILE=" + toolchainFile,
			"-DTOOLCHAIN_PREFIX=" + toolchainPrefix,
			"-DCMAKE_SYSTEM_NAME=Generic",
			"-DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY",
			"-DTOOB_DEVICE_MANIFEST=" + manifest,
			"-DTOOB_CHIP=" + chip,
			"-DTOOB_ARCH=" + arch,
		}

		if tcPath != "" {
			cmakeArgs = append(cmakeArgs, "-DTOOLCHAIN_BIN_DIR="+filepath.ToSlash(tcPath))
		}

		// Support ccache if present on the host
		if _, ccacheErr := exec.LookPath("ccache"); ccacheErr == nil {
			cmakeArgs = append(cmakeArgs, "-DCMAKE_C_COMPILER_LAUNCHER=ccache")
			cmakeArgs = append(cmakeArgs, "-DCMAKE_CXX_COMPILER_LAUNCHER=ccache")
		}

		if err := runWithLiveSpinner(ctx, root, "cmake", customEnv, spinner, cmakeArgs...); err != nil {
			spinner.Stop()
			return err
		}
		spinner.Stop()
		timings.Add("CMake Configure", time.Since(startCMake))
	} else {
		ui.Info("CMake build files found in %s, skipping configure.", buildDir)
	}

	// 10. Build
	spinner := ui.NewSpinner("Building")
	spinner.Start()
	startNinja := time.Now()
	if err := runWithLiveSpinner(ctx, root, "cmake", customEnv, spinner, "--build", buildDir); err != nil {
		return err
	}
	spinner.Stop()
	timings.Add("Ninja Build", time.Since(startNinja))

	ui.Success("Build complete.")

	// Output Timings (Gap 4.3)
	timings.Print(time.Since(buildStartTime))

	// 11. Update Lockfile with Toolchain info
	if lf, err := lockfile.Load(lfPath); err == nil {
		tcName := strings.TrimSuffix(toolchainPrefix, "-")
		lf.Toolchains[tcName] = lockfile.ToolchainEntry{
			Version: expectedVersion,
		}
		if os.Getenv("TOOB_REGISTRY_DIR") == "" {
			regVer := filepath.Base(cache.Dir())
			lf.Registry.Commit = regVer
			lf.Registry.Version = regVer
		}
		if os.Getenv("TOOB_COMPILER_DIR") == "" {
			lf.Environment.CoreSDK = coreSDKVer
		}
		_ = lf.Save(lfPath)
	}

	return nil
}

// run executes a command with stdout/stderr forwarded to the terminal.
func run(ctx context.Context, dir string, name string, env []string, args ...string) error {
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

// ringBuffer is a bounded, allocation-free buffer for capturing command output.
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

// spinnerWriter intercepts compiler stdout and pipes the latest line to the LiveSpinner
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

// runWithLiveSpinner executes a command, parsing its output to a lag-free UI spinner instead of stdout.
func runWithLiveSpinner(ctx context.Context, dir string, name string, env []string, spinner *ui.LiveSpinner, args ...string) error {
	c := exec.CommandContext(ctx, name, args...)
	c.Dir = dir
	c.Stdin = os.Stdin
	if len(env) > 0 {
		c.Env = env
	}

	// Bounded 1MB buffer to prevent OOM on massive outputs
	ringBuf := newRingBuffer(1 * 1024 * 1024)
	sw := &spinnerWriter{spinner: spinner}
	c.Stdout = io.MultiWriter(sw, ringBuf)
	c.Stderr = io.MultiWriter(sw, ringBuf)

	err := c.Run()
	if err != nil {
		// Stop the spinner so we can print the raw error clearly
		spinner.Stop()
		fmt.Fprintf(os.Stderr, "\n%s\n", ringBuf.String())
		classifyBuildError(ringBuf.String(), dir)
	}
	return err
}

func classifyBuildError(output string, projectDir string) {
	outLower := strings.ToLower(output)
	projectBase := strings.ToLower(filepath.Base(projectDir))

	if strings.Contains(outLower, "toobloader/hal") {
		ui.ErrorBanner("HAL Layer Error",
			"The compiler found an error in the Hardware Abstraction Layer.",
			"If you spawned this chip locally, check your modifications. Otherwise, report a bug.")
	} else if strings.Contains(outLower, "toobloader/core") {
		ui.ErrorBanner("Core SDK Error",
			"The error originated in the Toob Core SDK.",
			"This is usually a bug in the Toob-Loader repository. Please report it.")
	} else if strings.Contains(outLower, "crypto/") || strings.Contains(outLower, "crypto\\") || strings.Contains(outLower, "crypto_") {
		ui.ErrorBanner("Cryptography Layer Error",
			"The compiler found an error in a crypto package.",
			"Check your [crypto] configuration in device.toml and ensure the package is compatible with your Core SDK version.")
	} else if strings.Contains(outLower, "src/") || strings.Contains(outLower, "app/") || strings.Contains(outLower, "main/") || strings.Contains(outLower, "components/") || strings.Contains(outLower, projectBase+"/") {
		ui.ErrorBanner("Application Code Error",
			"The compiler found an error in your application code.",
			"Check the files in your project directory.")
	} else if strings.Contains(outLower, "exec: \"cmake\": executable file not found") || strings.Contains(outLower, "gcc: fatal error: cannot execute") || strings.Contains(outLower, "unrecognized command line option") {
		ui.ErrorBanner("Toolchain / Environment Error",
			"The compiler executable failed or is missing components.",
			"Try running 'toob clean --toolchains' and rebuilding.")
	} else {
		ui.ErrorBanner("Unknown Error Category",
			"Could not automatically classify the error.",
			"Please read the raw compiler output above.")
	}
}

// findToolchainBin strictly returns the toolchain path from the hermetic Toob cache.
// It explicitly avoids checking the system PATH to guarantee reproducible, hermetic builds.
func findToolchainBin(prefix string, expectedVersion string) string {
	// 1. Check hermetic Toob cache (~/.toob/toolchains)
	if home, err := os.UserHomeDir(); err == nil && expectedVersion != "" {
		toobPath := filepath.Join(home, ".toob", "toolchains", strings.TrimSuffix(prefix, "-"), expectedVersion)
		if bin := toolchain.FindBinDir(toobPath, prefix); bin != "" {
			return bin
		}
	}

	return ""
}

// findPythonScriptsBin finds the Scripts directory of the active python interpreter
func findPythonScriptsBin() string {
	cmd := exec.Command("python", "-c", "import sys, os; print(os.path.join(sys.prefix, 'Scripts'))")
	out, err := cmd.Output()
	if err == nil {
		path := strings.TrimSpace(string(out))
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return ""
}

// parseCoreSDKVersion extracts the raw semver from a tag (e.g., core/v1.2.3 -> v1.2.3)
func parseCoreSDKVersion(tag string) (*semver.Version, error) {
	cleanTag := tag
	if after, ok := strings.CutPrefix(tag, "core/"); ok {
		cleanTag = after
	}
	if !strings.HasPrefix(cleanTag, "v") {
		cleanTag = "v" + cleanTag
	}
	return semver.NewVersion(cleanTag)
}

func getLatestCoreSDKFromRegistry(idx *registry.Index) (string, error) {
	if idx == nil || idx.Ecosystem == nil || len(idx.Ecosystem.CoreSDK) == 0 {
		return "", fmt.Errorf("no core SDK versions listed in registry")
	}
	var highest *semver.Version
	var highestStr string
	for _, tag := range idx.Ecosystem.CoreSDK {
		v, err := parseCoreSDKVersion(tag)
		if err == nil {
			if highest == nil || v.GreaterThan(highest) {
				highest = v
				highestStr = tag
			}
		}
	}
	if highestStr == "" {
		return "", fmt.Errorf("no valid semantic versions for core SDK in registry")
	}
	return highestStr, nil
}

func writeFileIfChanged(path string, data []byte) error {
	if old, err := os.ReadFile(path); err == nil && string(old) == string(data) {
		return nil
	}
	return os.WriteFile(path, data, 0o644)
}
