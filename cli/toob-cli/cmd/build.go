package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Masterminds/semver/v3"

	"github.com/spf13/cobra"
	"github.com/toob-boot/toob/internal/lockfile"
	manifestpkg "github.com/toob-boot/toob/internal/manifest"
	"github.com/toob-boot/toob/internal/paths"
	"github.com/toob-boot/toob/internal/ports"
	"github.com/toob-boot/toob/internal/registry"
	"github.com/toob-boot/toob/internal/suit"
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
}


func runBuild(cmd *cobra.Command, args []string) error {
	// Premium UX: Show initialization progress bar
	pb := ui.NewProgressBar("Initializing Build Engine", 100)
	for i := 0; i <= 100; i += 10 {
		pb.Update(i)
		time.Sleep(15 * time.Millisecond)
	}
	pb.Finish()

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
	cache := registry.NewCache("")
	if !cache.IsInitialized() {
		lfPath := paths.LockfilePath(root)
		if lf, err := lockfile.Load(lfPath); err == nil {
			if lf.Registry.Commit != "" {
				if err := cache.Checkout(lf.Registry.Commit); err != nil {
					return fmt.Errorf("failed to checkout locked registry commit %s: %w", lf.Registry.Commit, err)
				}
			} else if lf.Registry.Version != "" {
				if err := cache.Checkout(lf.Registry.Version); err != nil {
					return fmt.Errorf("failed to checkout locked registry version %s: %w", lf.Registry.Version, err)
				}
			}
		}
	}

	if idx, err := cache.LoadIndex(); err == nil && idx.CliCompatibility != "" {
		constraint, err := semver.NewConstraint(idx.CliCompatibility)
		if err != nil {
			return fmt.Errorf("invalid cli_compatibility in registry: %w", err)
		}
		cliVer, err := semver.NewVersion(Version)
		if err == nil && !constraint.Check(cliVer) {
			return fmt.Errorf("HAL Registry requires CLI Version %s. You are using CLI v%s. Please upgrade your CLI or use an older registry version.", idx.CliCompatibility, Version)
		}
	}

	if flagNative {
		return runNativeBuild(root)
	}
	return runDockerBuild(root)
}

func runDockerBuild(root string) error {
	if _, err := exec.LookPath("docker"); err != nil {
		return fmt.Errorf("Docker is not installed or not in PATH.\nPlease install Docker to use the containerized compiler, or run `toob build --native`.")
	}

	regDir, _ := paths.RegistryDir()
	cache := registry.NewCache("")
	if !cache.IsInitialized() {
		ui.Step("Registry not initialized. Attempting auto-clone...")
		if err := cache.Sync(); err != nil {
			return fmt.Errorf("failed to sync registry (offline?): %w\nRun `toob chip add` when connected to the internet.", err)
		}
	}

	compilerTag := "latest"
	lfPath := paths.LockfilePath(root)
	if lf, err := lockfile.Load(lfPath); err == nil && lf.Environment.Compiler != "" {
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
		exec.Command("docker", "pull", input.Image).Run()
	} else {
		if err := exec.Command("docker", "image", "inspect", input.Image).Run(); err != nil {
			ui.Step("Compiler image %s not found locally. Pulling...", compilerTag)
			exec.Command("docker", "pull", input.Image).Run()
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
	err := run(root, "docker", args...)
	if err == nil {
		ui.Tip("Run 'toob build --native' for much faster builds (requires local toolchains).")
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

func runNativeBuild(root string) error {
	buildStartTime := time.Now()
	timings := &TimingTracker{}

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

	chip := dt.Device.Chip
	vendor := dt.Device.Vendor
	if chip == "" || vendor == "" {
		return fmt.Errorf("device.toml must define [device] with 'chip' and 'vendor'")
	}
	ui.Info("Target: %s/%s", vendor, chip)

	registryURL := ""
	if dt.Build.Registry != "" {
		registryURL = dt.Build.Registry
	}
	cache := registry.NewCache(registryURL)

	if flagSkipChecks && !cache.IsInitialized() {
		ui.Warn("Cannot skip checks because local registry is missing. Auto-syncing...")
		flagSkipChecks = false
	}

	// Fetch Live Matrix in the background (Gap 2.4)
	var matrixChan chan *registry.Matrix
	var matrixErrChan chan error

	if !flagSkipChecks {
		matrixChan = make(chan *registry.Matrix, 1)
		matrixErrChan = make(chan error, 1)
		go func() {
			m, err := cache.FetchLiveMatrix()
			if err != nil {
				matrixErrChan <- err
				return
			}
			matrixChan <- m
		}()
	}

	// 2. Registry Sync (Blocking)
	if !cache.IsInitialized() {
		ui.Step("Registry not initialized. Auto-syncing in background...")
		start := time.Now()
		if err := cache.Sync(); err != nil {
			return fmt.Errorf("failed to sync registry: %w", err)
		}
		timings.Add("Registry Sync", time.Since(start))
	}
	regDir := cache.Dir()

	// Load Registry Index ONCE
	idx, err := cache.LoadIndex()
	if err != nil {
		ui.Warn("Could not load registry index: %v", err)
	}

	// 3. Resolve hardware.json & chip_manifest.json (HAL Registry Inheritance)
	hwJSON := filepath.Join(root, "toobloader", "hal", "chips", chip, "hardware.json")
	if _, err := os.Stat(hwJSON); err != nil {
		hwJSON = filepath.Join(regDir, "chips", chip, "hardware.json")
	}
	
	cmPath := filepath.Join(root, "toobloader", "hal", "chips", chip, "chip_manifest.json")
	if _, err := os.Stat(cmPath); err != nil {
		cmPath = filepath.Join(regDir, "chips", chip, "chip_manifest.json")
	}

	// Read Chip Manifest FIRST
	var cm ports.ChipManifest
	chipVersion := "1.0.0"
	arch := ""
	toolchainPrefix := ""
	halVendor := vendor

	if data, err := os.ReadFile(cmPath); err == nil {
		if err := json.Unmarshal(data, &cm); err == nil {
			if cm.Arch != "" { arch = cm.Arch }
			if cm.CompilerPrefix != "" { toolchainPrefix = cm.CompilerPrefix }
			if cm.Vendor != "" { halVendor = cm.Vendor }
			if cm.Version != "" { chipVersion = cm.Version }
		}
	} else {
		ui.Step("Chip '%s' not found locally. Auto-syncing registry...", chip)
		if err := cache.Sync(); err != nil {
			return fmt.Errorf("chip_manifest.json not found and registry sync failed: %w", err)
		}
		if data, err := os.ReadFile(cmPath); err == nil {
			json.Unmarshal(data, &cm)
			if cm.Arch != "" { arch = cm.Arch }
			if cm.CompilerPrefix != "" { toolchainPrefix = cm.CompilerPrefix }
			if cm.Vendor != "" { halVendor = cm.Vendor }
			if cm.Version != "" { chipVersion = cm.Version }
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

	// 4. Core SDK Version Resolution
	coreSDKVer := dt.Build.CoreSDK
	coreSDKLabel := coreSDKVer
	
	if coreSDKVer == "" || coreSDKVer == "latest" {
		ui.Step("Resolving latest Core SDK version...")
		latestTag, err := getLatestCoreSDKTag()
		if err == nil {
			coreSDKVer = latestTag
			coreSDKLabel = latestTag + " (auto-latest)"
		} else {
			if cm.MinCoreSDK != "" {
				coreSDKVer = cm.MinCoreSDK
				coreSDKLabel = cm.MinCoreSDK + " (fallback-min)"
			} else {
				coreSDKVer = "main"
				coreSDKLabel = "main (fallback)"
			}
		}
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

	ui.Info("Environment: Compiler=%s, CoreSDK=%s", compilerLabel, coreSDKLabel)

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
		if err := os.MkdirAll(filepath.Join(filepath.Dir(coreDirToDownload)), 0o755); err != nil {
			return err
		}
		gitTarget := coreSDKVer
		if coreSDKVer != "main" && coreSDKVer != "latest" && !strings.HasPrefix(coreSDKVer, "core/v") {
			gitTarget = "core/v" + coreSDKVer
		}
		cloneCmd := exec.Command("git", "clone", "--depth", "1", "-b", gitTarget, "https://github.com/Toob-Boot/Toob-Loader.git", coreDirToDownload)
		cloneCmd.Stdout = os.Stdout
		cloneCmd.Stderr = os.Stderr
		if err := cloneCmd.Run(); err != nil {
			return fmt.Errorf("failed to download Core SDK tag '%s': %w", gitTarget, err)
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

	// 7. Run manifest compiler (Go Native)
	ui.Step("Running manifest compiler (Go Native)")
	startManifest := time.Now()
	bootloaderDir := resolvePath(root, compilerRoot, "toobloader")
	
	// Phase 3 Fix: Inject HAL paths to Manifest Compiler so it finds Registry sources
	halChipDir := filepath.Join(root, "toobloader", "hal", "chips", chip)
	if _, err := os.Stat(halChipDir); err != nil {
		halChipDir = filepath.Join(regDir, "chips", chip)
	}

	if err := manifestpkg.Compile(manifest, hwJSON, generatedDir, bootloaderDir, halChipDir); err != nil {
		return err
	}
	timings.Add("Manifest Compiler", time.Since(startManifest))

	// 8. Run SUIT code generator
	if pyScripts := findPythonScriptsBin(); pyScripts != "" {
		os.Setenv("PATH", pyScripts+string(os.PathListSeparator)+os.Getenv("PATH"))
	}
	if err := suit.Generate(generatedDir, compilerRoot, root, Version); err != nil {
		return err
	}

	// 7. CLI Blocker Logic: Check Compatibility Matrix (Wait for background fetch)
	if !flagSkipChecks {
		var matrix *registry.Matrix
		var matrixErr error
		select {
		case matrix = <-matrixChan:
		case matrixErr = <-matrixErrChan:
		}

		if matrixErr != nil {
			ui.Warn("Could not fetch Compatibility Matrix: %v", matrixErr)
		} else if matrix != nil {
			if chipEntry, hasChip := (*matrix)[chip]; hasChip {
				if versionEntry, hasVer := chipEntry.Versions[chipVersion]; hasVer {
					cliVer := Version
					if !strings.HasPrefix(cliVer, "v") && cliVer != "main" && cliVer != "dev" {
						cliVer = "v" + cliVer
					}
					
					if cliEntry, hasCli := versionEntry.VerifiedCliVersions[cliVer]; hasCli {
						if cliEntry.Status == "FAILED" {
							return fmt.Errorf("FATAL: Der Chip %s (v%s) ist laut aktueller Ledger Matrix explizit inkompatibel mit deiner CLI Version (%s). Build abgebrochen!", chip, chipVersion, cliVer)
						}
					} else {
						ui.Warn("The combination of Chip %s (v%s) and CLI %s has not been verified by the CI yet.", chip, chipVersion, cliVer)
					}
				}
			}
		}
	} else {
		ui.Muted("Skipping compatibility matrix checks (--skip-checks)")
	}

	// Calculate toolchain.cmake name based on architecture
	toolchainDirName := strings.TrimSuffix(toolchainPrefix, "-")
	toolchainFile := filepath.Join(regDir, "toolchains", toolchainDirName, "toolchain.cmake")
	if _, err := os.Stat(toolchainFile); err != nil {
		return fmt.Errorf("registry toolchain missing: %s", toolchainFile)
	}

	coreDir := filepath.ToSlash(resolvePath(root, compilerRoot, filepath.Join("toobloader", "core")))
	cryptoDir := filepath.ToSlash(resolvePath(root, compilerRoot, filepath.Join("toobloader", "crypto")))
	stage0Dir := filepath.ToSlash(resolvePath(root, compilerRoot, filepath.Join("toobloader", "stage0")))

	// HALs: halChipDir already resolved above (step 7). Resolve arch + vendor.
	halArchDir := filepath.Join(root, "toobloader", "hal", "arch", arch)
	if _, err := os.Stat(halArchDir); err != nil {
		halArchDir = filepath.Join(regDir, "arch", arch)
	}

	halVendorDir := filepath.Join(root, "toobloader", "hal", "vendor", halVendor)
	if _, err := os.Stat(halVendorDir); err != nil {
		halVendorDir = filepath.Join(regDir, "vendor", halVendor)
	}

	halChipDir = filepath.ToSlash(halChipDir)
	halArchDir = filepath.ToSlash(halArchDir)
	halVendorDir = filepath.ToSlash(halVendorDir)

	sdkDir := filepath.ToSlash(resolvePath(root, compilerRoot, filepath.Join("sdk")))

	toobCLIPath, err := os.Executable()
	if err != nil {
		toobCLIPath = "toob"
	}
	toobCLIPath = filepath.ToSlash(toobCLIPath)

	configContent := fmt.Sprintf(
		"set(TOOB_ARCH \"%s\")\nset(TOOB_VENDOR \"%s\")\nset(TOOB_CHIP \"%s\")\n"+
			"set(TOOLCHAIN_PREFIX \"%s\")\n"+
			"set(TOOB_CORE_DIR \"%s\")\n"+
			"set(TOOB_CRYPTO_DIR \"%s\")\n"+
			"set(TOOB_STAGE0_DIR \"%s\")\n"+
			"set(TOOB_HAL_CHIP_DIR \"%s\")\n"+
			"set(TOOB_HAL_ARCH_DIR \"%s\")\n"+
			"set(TOOB_HAL_VENDOR_DIR \"%s\")\n"+
			"set(TOOB_SDK_DIR \"%s\")\n"+
			"set(TOOB_CLI_PATH \"%s\")\n",
		arch, halVendor, chip, toolchainPrefix,
		coreDir, cryptoDir, stage0Dir, halChipDir, halArchDir, halVendorDir, sdkDir, toobCLIPath,
	)
	if err := os.WriteFile(filepath.Join(generatedDir, "toob_config.cmake"), []byte(configContent), 0o644); err != nil {
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
	
	lfPath := filepath.Join(root, "toob.lock")
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
			if expectedVersion == "" {
				if idx != nil && idx.Toolchains != nil {
					tcName := strings.TrimSuffix(toolchainPrefix, "-")
					if tcInfo, ok := idx.Toolchains[tcName]; ok {
						expectedVersion = tcInfo.Version
					}
				} else {
					expectedVersion = toolchain.GetExpectedVersion(toolchainPrefix, cache.Dir())
				}
			}
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
			out, err := exec.Command(compilerExe, "--version").CombinedOutput()
			if err != nil || !strings.Contains(string(out), expectedVersion) {
				return fmt.Errorf("FATAL: Custom toolchain version mismatch!\nExpected: %s\nTo prevent tainted lockfiles and non-reproducible builds, please use a matching toolchain or use auto-provisioning.", expectedVersion)
			}
		}
	}

	if tcPath != "" {
		os.Setenv("PATH", tcPath+string(os.PathListSeparator)+os.Getenv("PATH"))
		ui.Info("Toolchain: %s", tcPath)
	}

	// 9. CMake configure
	spinner := ui.NewSpinner("Configuring CMake")
	spinner.Start()
	startCMake := time.Now()
	
	cmakeArgs := []string{
		"-G", "Ninja",
		"-B", buildDir,
		"-S", compilerRoot,
		"-DCMAKE_TOOLCHAIN_FILE=" + toolchainFile,
		"-DTOOLCHAIN_PREFIX=" + toolchainPrefix,
		"-DCMAKE_SYSTEM_NAME=Generic",
		"-DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY",
		"-DTOOB_DEVICE_MANIFEST=" + manifest,
	}
	
	if tcPath != "" {
		cmakeArgs = append(cmakeArgs, "-DTOOLCHAIN_BIN_DIR=" + filepath.ToSlash(tcPath))
	}

	if err := runWithLiveSpinner(root, "cmake", spinner, cmakeArgs...); err != nil {
		return err
	}
	spinner.Stop()
	timings.Add("CMake Configure", time.Since(startCMake))

	// 10. Build
	spinner = ui.NewSpinner("Building")
	spinner.Start()
	startNinja := time.Now()
	if err := runWithLiveSpinner(root, "cmake", spinner, "--build", buildDir); err != nil {
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
		_ = lf.Save(lfPath)
	}

	return nil
}

// run executes a command with stdout/stderr forwarded to the terminal.
func run(dir string, name string, args ...string) error {
	c := exec.Command(name, args...)
	c.Dir = dir
	c.Stdin = os.Stdin
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
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
func runWithLiveSpinner(dir string, name string, spinner *ui.LiveSpinner, args ...string) error {
	c := exec.Command(name, args...)
	c.Dir = dir
	c.Stdin = os.Stdin

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
	if strings.HasPrefix(tag, "core/") {
		cleanTag = strings.TrimPrefix(tag, "core/")
	}
	if !strings.HasPrefix(cleanTag, "v") {
		cleanTag = "v" + cleanTag
	}
	return semver.NewVersion(cleanTag)
}

func getLatestCoreSDKTag() (string, error) {
	out, err := exec.Command("git", "ls-remote", "--tags", "https://github.com/Toob-Boot/Toob-Loader.git").Output()
	if err != nil {
		return "", err
	}
	
	lines := strings.Split(string(out), "\n")
	var highest *semver.Version
	var highestStr string
	
	for _, line := range lines {
		if !strings.Contains(line, "refs/tags/") {
			continue
		}
		parts := strings.Split(line, "refs/tags/")
		if len(parts) != 2 {
			continue
		}
		tag := strings.TrimSpace(parts[1])
		if strings.HasSuffix(tag, "^{}") {
			continue
		}
		
		v, err := parseCoreSDKVersion(tag)
		if err == nil {
			if highest == nil || v.GreaterThan(highest) {
				highest = v
				highestStr = tag
			}
		}
	}
	
	if highestStr == "" {
		return "", fmt.Errorf("no valid semantic versions found")
	}
	return highestStr, nil
}
