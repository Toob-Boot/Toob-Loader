package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/Masterminds/semver/v3"

	"github.com/spf13/cobra"
	"github.com/toob-boot/toob/internal/lockfile"
	manifestpkg "github.com/toob-boot/toob/internal/manifest"
	"github.com/toob-boot/toob/internal/paths"
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
)

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

// chipManifest mirrors chip_manifest.json.
type chipManifest struct {
	Vendor             string `json:"vendor"`
	Arch               string `json:"arch"`
	CompilerPrefix     string `json:"compiler_prefix"`
	Version            string `json:"version"`
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

	args := []string{
		"run", "--rm",
		"-v", fmt.Sprintf("%s:/workspace", root),
		"-v", fmt.Sprintf("%s:/root/.toob/registry", regDir),
	}

	// Pass through proxy variables
	for _, envVar := range []string{"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy"} {
		if val := os.Getenv(envVar); val != "" {
			args = append(args, "-e", fmt.Sprintf("%s=%s", envVar, val))
		}
	}

	args = append(args, "-w", "/workspace", "repowatt/toob-compiler:v"+Version, "toob", "build", "--native")

	if flagManifest != "" {
		relManifest, err := filepath.Rel(root, flagManifest)
		if err == nil {
			args = append(args, "--manifest", filepath.ToSlash(filepath.Join("/workspace", relManifest)))
		}
	}
	if flagBuildDir != "" {
		relBuildDir, err := filepath.Rel(root, flagBuildDir)
		if err == nil {
			args = append(args, "--build-dir", filepath.ToSlash(filepath.Join("/workspace", relBuildDir)))
		}
	}

	fmt.Println("[toob] Starting Docker container (repowatt/toob-compiler)...")
	return run(root, "docker", args...)
}

func runNativeBuild(root string) error {

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

	regDir, _ := paths.RegistryDir()

	cache := registry.NewCache("")
	if !cache.IsInitialized() {
		fmt.Println("[toob] Registry not initialized. Attempting auto-clone...")
		if err := cache.Sync(); err != nil {
			return fmt.Errorf("failed to sync registry (offline?): %w\nRun `toob chip add` when connected to the internet.", err)
		}
	}

	// Determine compiler source directory
	compilerRoot := root
	if envDir := os.Getenv("TOOB_COMPILER_DIR"); envDir != "" {
		compilerRoot = envDir
	} else {
		if _, err := os.Stat(filepath.Join(root, "CMakeLists.txt")); err != nil {
			return fmt.Errorf("native build failed: compiler core not found at %s.\n"+
				"End-users: Use 'toob build --docker' (recommended).\n"+
				"Core-Devs: Set TOOB_COMPILER_DIR environment variable to your Toob-Loader git repository path.", root)
		}
	}

	// 2. Resolve hardware.json (HAL Registry Inheritance)
	hwJSON := filepath.Join(root, "toobloader", "hal", "chips", chip, "hardware.json")
	if _, err := os.Stat(hwJSON); err != nil {
		hwJSON = filepath.Join(regDir, "chips", chip, "hardware.json")
	}
	if _, err := os.Stat(hwJSON); err != nil {
		fmt.Printf("[toob] Chip '%s' not found locally. Auto-syncing registry...\n", chip)
		if err := cache.Sync(); err == nil {
			// Reload index to check if chip exists now
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
	bootloaderDir := resolvePath(root, compilerRoot, "toobloader")
	if err := manifestpkg.Compile(manifest, hwJSON, generatedDir, bootloaderDir); err != nil {
		return err
	}

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
		var cm chipManifest
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

	// 7. CLI Blocker Logic: Check Compatibility Matrix
	matrix, err := cache.FetchLiveMatrix()
	if err != nil {
		fmt.Printf("\033[33m[toob] WARNING: Could not fetch Compatibility Matrix: %v\033[0m\n", err)
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
	expectedVersion := toolchain.GetExpectedVersion(toolchainPrefix)
	
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
			tcPath, err = toolchain.EnsureAvailable(toolchainPrefix, expectedVersion)
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
	if err := run(root, "cmake",
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

	// 10. Build
	fmt.Println("[toob] Building ...")
	if err := run(root, "cmake", "--build", buildDir); err != nil {
		return err
	}

	fmt.Println("[toob] Build complete.")

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
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	return c.Run()
}

// findToolchainBin auto-detects the cross-compiler bin directory.
func findToolchainBin(prefix string, expectedVersion string) string {
	compiler := prefix + "gcc"
	if path, err := exec.LookPath(compiler); err == nil {
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
