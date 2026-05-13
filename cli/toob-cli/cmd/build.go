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
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Masterminds/semver/v3"
	"golang.org/x/sync/errgroup"

	"github.com/spf13/cobra"
	"github.com/toob-boot/toob/internal/lockfile"
	manifestpkg "github.com/toob-boot/toob/internal/manifest"
	"github.com/toob-boot/toob/internal/paths"
	"github.com/toob-boot/toob/internal/ports"
	"github.com/toob-boot/toob/internal/registry"
	"github.com/toob-boot/toob/internal/suit"
	"github.com/toob-boot/toob/internal/toolchain"
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
	fmt.Printf("\n\033[36m[toob] Build Timings:\033[0m\n")
	for _, p := range t.phases {
		pad := strings.Repeat(".", 26-len(p.Name))
		fmt.Printf("       %s %s %v\n", p.Name, pad, p.Duration.Round(time.Millisecond))
	}
	fmt.Printf("       Total %s %v\n\n", strings.Repeat(".", 21), total.Round(time.Millisecond))
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


func isMonorepo(root string) bool {
	cmPath := filepath.Join(root, "CMakeLists.txt")
	data, err := os.ReadFile(cmPath)
	if err != nil {
		return false
	}
	return strings.Contains(string(data), "toob-boot")
}

func runBuild(cmd *cobra.Command, args []string) error {
	root, err := paths.FindProjectRoot("")
	if err != nil {
		return err
	}

	// 1. Enforce lockfile registry version and compatibility
	cache := registry.NewCache("")
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

	useNative := flagNative
	if !useNative && isMonorepo(root) {
		fmt.Println("[toob] Detected Toob-Loader Monorepo. Auto-enabling --native build.")
		useNative = true
	}

	if useNative {
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
		fmt.Println("[toob] Registry not initialized. Attempting auto-clone...")
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
		fmt.Printf("[toob] Pulling latest compiler image...\n")
		exec.Command("docker", "pull", input.Image).Run()
	} else {
		if err := exec.Command("docker", "image", "inspect", input.Image).Run(); err != nil {
			fmt.Printf("[toob] Compiler image %s not found locally. Pulling...\n", compilerTag)
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

	fmt.Printf("[toob] Starting Docker container (mannomannx/toob-compiler:%s)...\n", compilerTag)
	err := run(root, "docker", args...)
	if err == nil {
		fmt.Println("\n\033[36m[toob] TIP: Run 'toob build --native' for much faster builds (requires local toolchains).\033[0m")
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
		fmt.Println("[toob] Protocol handshake skipped (image not cached locally).")
		return nil
	}

	label := strings.TrimSpace(string(out))
	if label == "" || label == "<no value>" {
		// Old image without label — allow but warn
		fmt.Println("[toob] WARNING: Compiler image has no protocol version label. Consider pulling a newer image.")
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
	fmt.Printf("[toob] Target: %s/%s\n", vendor, chip)

	registryURL := ""
	if dt.Build.Registry != "" {
		registryURL = dt.Build.Registry
	}
	cache := registry.NewCache(registryURL)

	if flagSkipChecks && !cache.IsInitialized() {
		fmt.Println("\033[33m[toob] Warning: Cannot skip checks because local registry is missing. Auto-syncing...\033[0m")
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

	// Read Build settings from DeviceToml
	coreSDKVer := dt.Build.CoreSDK
	if coreSDKVer == "" {
		coreSDKVer = "main"
	}
	compilerVer := dt.Build.Compiler
	if compilerVer == "" {
		compilerVer = "latest" // Docker image tag
	}

	fmt.Printf("[toob] Environment: Compiler=%s, CoreSDK=%s\n", compilerVer, coreSDKVer)

	// Parallel Fetching: Registry Sync & Core SDK (Gap 2.3)
	g, _ := errgroup.WithContext(context.Background())

	if !cache.IsInitialized() {
		fmt.Println("[toob] Registry not initialized. Auto-syncing in background...")
		g.Go(func() error {
			start := time.Now()
			err := cache.Sync()
			timings.Add("Registry Sync", time.Since(start))
			return err
		})
	}

	compilerRoot := root
	var coreDirToDownload string
	if envDir := os.Getenv("TOOB_COMPILER_DIR"); envDir != "" {
		compilerRoot = envDir
	} else if !isMonorepo(root) {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("cannot determine home directory: %w", err)
		}
		coreDir := filepath.Join(homeDir, ".toob", "core", coreSDKVer)
		if _, err := os.Stat(coreDir); os.IsNotExist(err) {
			fmt.Printf("[toob] Core SDK '%s' not found locally. Downloading...\n", coreSDKVer)
			coreDirToDownload = coreDir
		}
		compilerRoot = coreDir
	} else {
		if _, err := os.Stat(filepath.Join(root, "CMakeLists.txt")); err != nil {
			return fmt.Errorf("native build failed: compiler core not found at %s", root)
		}
	}

	if coreDirToDownload != "" {
		g.Go(func() error {
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
			return nil
		})
	}

	// Wait for parallel downloads
	if err := g.Wait(); err != nil {
		return err
	}

	regDir := cache.Dir()

	// Load Registry Index ONCE (Gap 3.2)
	idx, err := cache.LoadIndex()
	if err != nil {
		fmt.Printf("\033[33m[toob] WARNING: Could not load registry index: %v\033[0m\n", err)
	}

	// 2. Resolve hardware.json (HAL Registry Inheritance)
	hwJSON := filepath.Join(root, "toobloader", "hal", "chips", chip, "hardware.json")
	if _, err := os.Stat(hwJSON); err != nil {
		hwJSON = filepath.Join(regDir, "chips", chip, "hardware.json")
	}
	if _, err := os.Stat(hwJSON); err != nil {
		fmt.Printf("[toob] Chip '%s' not found locally. Auto-syncing registry...\n", chip)
		start := time.Now()
		if err := cache.Sync(); err == nil {
			timings.Add("Registry Sync", time.Since(start))
			if _, statErr := os.Stat(hwJSON); statErr != nil {
				return fmt.Errorf("hardware.json not found for chip '%s' even after registry sync. Is the chip name correct?", chip)
			}
		} else {
			return fmt.Errorf("hardware.json not found for chip '%s' and registry sync failed: %w", chip, err)
		}
	}

	// 3. Determine build directory
	buildDir := flagBuildDir
	if buildDir == "" {
		buildDir = filepath.Join(root, "builds", "build_"+chip)
	}
	generatedDir := filepath.Join(buildDir, "generated")
	if err := os.MkdirAll(generatedDir, 0o755); err != nil {
		return err
	}

	// 4. Run manifest compiler (Go Native)
	fmt.Println("[toob] Running manifest compiler (Go Native)...")
	startManifest := time.Now()
	bootloaderDir := resolvePath(root, compilerRoot, "toobloader")
	if err := manifestpkg.Compile(manifest, hwJSON, generatedDir, bootloaderDir); err != nil {
		return err
	}
	timings.Add("Manifest Compiler", time.Since(startManifest))

	// 5. Run SUIT code generator
	if pyScripts := findPythonScriptsBin(); pyScripts != "" {
		os.Setenv("PATH", pyScripts+string(os.PathListSeparator)+os.Getenv("PATH"))
	}
	if err := suit.Generate(generatedDir, compilerRoot, root, Version); err != nil {
		return err
	}

	// 6. Resolve toolchain from chip metadata
	arch := "riscv32"
	toolchainPrefix := "riscv32-unknown-elf-"
	halVendor := vendor

	cmPath := filepath.Join(root, "toobloader", "hal", "chips", chip, "chip_manifest.json")
	if _, err := os.Stat(cmPath); err != nil {
		cmPath = filepath.Join(regDir, "chips", chip, "chip_manifest.json")
	}

	chipVersion := "1.0.0"
	if data, err := os.ReadFile(cmPath); err == nil {
		var cm ports.ChipManifest
		if err := json.Unmarshal(data, &cm); err == nil {
			if cm.Arch != "" {
				arch = cm.Arch
			}
			if cm.CompilerPrefix != "" {
				toolchainPrefix = cm.CompilerPrefix
			}
			if cm.Vendor != "" {
				halVendor = cm.Vendor
			}
			if cm.Version != "" {
				chipVersion = cm.Version
			}
		}
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
			fmt.Printf("\033[33m[toob] WARNING: Could not fetch Compatibility Matrix: %v\033[0m\n", matrixErr)
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
						fmt.Printf("\033[33m[toob] WARNING: The combination of Chip %s (v%s) and CLI %s has not been verified by the CI yet.\033[0m\n", chip, chipVersion, cliVer)
					}
				}
			}
		}
	} else {
		fmt.Println("\033[36m[toob] Skipping compatibility matrix checks (--skip-checks)\033[0m")
	}

	// Calculate toolchain.cmake name based on architecture
	toolchainName := fmt.Sprintf("toolchain-%s.cmake", arch)
	toolchainFile := resolvePath(root, compilerRoot, filepath.Join("cmake", toolchainName))

	coreDir := filepath.ToSlash(resolvePath(root, compilerRoot, filepath.Join("toobloader", "core")))
	cryptoDir := filepath.ToSlash(resolvePath(root, compilerRoot, filepath.Join("toobloader", "crypto")))
	stage0Dir := filepath.ToSlash(resolvePath(root, compilerRoot, filepath.Join("toobloader", "stage0")))

	// HALs: local first, fallback to registry
	halChipDir := filepath.Join(root, "toobloader", "hal", "chips", chip)
	if _, err := os.Stat(halChipDir); err != nil {
		halChipDir = filepath.Join(regDir, "chips", chip)
	}

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
				return fmt.Errorf("failed to auto-provision toolchain: %w\nIf you prefer to install it manually, use --toolchain-path.", err)
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
		fmt.Printf("[toob] Toolchain: %s\n", tcPath)
	}

	// 9. CMake configure
	fmt.Println("[toob] Configuring CMake ...")
	startCMake := time.Now()
	if err := runWithClassifier(root, "cmake",
		"-G", "Ninja",
		"-B", buildDir,
		"-S", compilerRoot,
		"-DCMAKE_TOOLCHAIN_FILE="+toolchainFile,
		"-DTOOLCHAIN_PREFIX="+toolchainPrefix,
		"-DCMAKE_SYSTEM_NAME=Generic",
		"-DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY",
		"-DTOOB_DEVICE_MANIFEST="+manifest,
	); err != nil {
		return err
	}
	timings.Add("CMake Configure", time.Since(startCMake))

	// 10. Build
	fmt.Println("[toob] Building ...")
	startNinja := time.Now()
	if err := runWithClassifier(root, "cmake", "--build", buildDir); err != nil {
		return err
	}
	timings.Add("Ninja Build", time.Since(startNinja))

	fmt.Println("[toob] Build complete.")

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

// runWithClassifier executes a command and parses its output for error classification if it fails.
func runWithClassifier(dir string, name string, args ...string) error {
	c := exec.Command(name, args...)
	c.Dir = dir
	c.Stdin = os.Stdin

	// Bounded 1MB buffer to prevent OOM on massive outputs
	ringBuf := newRingBuffer(1 * 1024 * 1024)
	c.Stdout = io.MultiWriter(os.Stdout, ringBuf)
	c.Stderr = io.MultiWriter(os.Stderr, ringBuf)

	err := c.Run()
	if err != nil {
		classifyBuildError(ringBuf.String(), dir)
	}
	return err
}

func classifyBuildError(output string, projectDir string) {
	fmt.Print("\n\033[31m================================================================================\n")
	fmt.Print("                          TOOB BUILD ERROR CLASSIFIER                           \n")
	fmt.Print("================================================================================\033[0m\n")

	outLower := strings.ToLower(output)
	projectBase := strings.ToLower(filepath.Base(projectDir))

	if strings.Contains(outLower, "toobloader/hal") {
		fmt.Print("\033[31m[!] HAL Layer Error:\033[0m The compiler found an error in the Hardware Abstraction Layer.\n")
		fmt.Print("    If you spawned this chip locally, check your modifications.\n")
		fmt.Print("    If not, this might be a bug in the Toob Registry.\n")
	} else if strings.Contains(outLower, "toobloader/core") {
		fmt.Print("\033[31m[!] Core SDK Error:\033[0m The error originated in the Toob Core SDK.\n")
		fmt.Print("    This is usually a bug in the Toob-Loader repository. Please report it.\n")
	} else if strings.Contains(outLower, "src/") || strings.Contains(outLower, "app/") || strings.Contains(outLower, "main/") || strings.Contains(outLower, "components/") || strings.Contains(outLower, projectBase+"/") {
		fmt.Print("\033[31m[!] Application Code Error:\033[0m The compiler found an error in your application code.\n")
		fmt.Print("    Check the files in your project directory.\n")
	} else if strings.Contains(outLower, "exec: \"cmake\": executable file not found") || strings.Contains(outLower, "gcc: fatal error: cannot execute") || strings.Contains(outLower, "unrecognized command line option") {
		fmt.Print("\033[31m[!] Toolchain / Environment Error:\033[0m The compiler executable failed or is missing components.\n")
		fmt.Print("    Try running 'toob clean --toolchains' and rebuilding to re-provision the toolchain.\n")
	} else {
		fmt.Print("\033[33m[!] Unknown Error Category:\033[0m Could not automatically classify the error.\n")
		fmt.Print("    Please read the raw compiler output above.\n")
	}
	fmt.Print("\033[31m================================================================================\033[0m\n\n")
}

// findToolchainBin auto-detects the cross-compiler bin directory.
func findToolchainBin(prefix string, expectedVersion string) string {
	compiler := prefix + "gcc"
	if runtime.GOOS == "windows" {
		compiler += ".exe"
	}

	// 0. Fast path: Check default Toob provisioning directory first (~/.toob/toolchains)
	if home, err := os.UserHomeDir(); err == nil && expectedVersion != "" {
		toobPath := filepath.Join(home, ".toob", "toolchains", strings.TrimSuffix(prefix, "-"), expectedVersion, "bin")
		if _, err := os.Stat(filepath.Join(toobPath, compiler)); err == nil {
			return toobPath // Zero-overhead, no os.ReadDir needed!
		}
	}

	compilerBin := prefix + "gcc"
	if path, err := exec.LookPath(compilerBin); err == nil {
		if expectedVersion == "" {
			return ""
		}
		out, err := exec.Command(path, "--version").CombinedOutput()
		if err == nil && strings.Contains(string(out), expectedVersion) {
			return "" // already in PATH and version matches
		}
	}

	// Espressif IDF standard layout
	if runtime.GOOS == "windows" {
		triplet := strings.TrimSuffix(prefix, "-")
		var bases []string
		if p := os.Getenv("IDF_TOOLS_PATH"); p != "" {
			bases = append(bases, filepath.Join(p, "tools", triplet))
		}
		if p, err := os.UserHomeDir(); err == nil {
			bases = append(bases, filepath.Join(p, ".espressif", "tools", triplet))
		}
		bases = append(bases, filepath.Join("C:\\", "Espressif", "tools", triplet))

		for _, base := range bases {
			entries, err := os.ReadDir(base)
			if err != nil {
				continue
			}
			// Sort reverse to pick the newest version
			sort.Slice(entries, func(i, j int) bool {
				return entries[i].Name() > entries[j].Name()
			})
			for _, e := range entries {
				if expectedVersion != "" && !strings.Contains(e.Name(), expectedVersion) {
					continue
				}
				candidate := filepath.Join(base, e.Name(), triplet, "bin")
				exe := filepath.Join(candidate, compiler+".exe")
				if _, err := os.Stat(exe); err == nil {
					fmt.Println("[toob] Warning: Using unhashed local toolchain. For guaranteed reproducible CI builds, consider using the auto-provisioned toolchain.")
					return candidate
				}
			}
		}
	}

	// Linux/macOS: check common ESP-IDF paths
	home, _ := os.UserHomeDir()
	if home != "" {
		triplet := strings.TrimSuffix(prefix, "-")
		base := filepath.Join(home, ".espressif", "tools", triplet)
		entries, err := os.ReadDir(base)
		if err == nil {
			sort.Slice(entries, func(i, j int) bool {
				return entries[i].Name() > entries[j].Name()
			})
			for _, e := range entries {
				if expectedVersion != "" && !strings.Contains(e.Name(), expectedVersion) {
					continue
				}
				candidate := filepath.Join(base, e.Name(), triplet, "bin")
				exe := filepath.Join(candidate, compiler)
				if _, err := os.Stat(exe); err == nil {
					fmt.Println("[toob] Warning: Using unhashed local toolchain. For guaranteed reproducible CI builds, consider using the auto-provisioned toolchain.")
					return candidate
				}
			}
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
