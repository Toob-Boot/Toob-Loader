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

	"github.com/BurntSushi/toml"
	"github.com/spf13/cobra"
	"github.com/toob-boot/toob/internal/paths"
	"github.com/toob-boot/toob/internal/registry"
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

// deviceToml mirrors the [device] section of device.toml.
type deviceToml struct {
	Device struct {
		Vendor string `toml:"vendor"`
		Chip   string `toml:"chip"`
	} `toml:"device"`
}

// chipManifest mirrors chip_manifest.json.
type chipManifest struct {
	Vendor          string `json:"vendor"`
	Arch            string `json:"arch"`
	Toolchain       string `json:"toolchain"`
	ToolchainPrefix string `json:"toolchain_prefix"`
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
		"-w", "/workspace",
		"repowatt/toob-compiler:latest",
		"toob", "build", "--native",
	}

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

	var dt deviceToml
	if _, err := toml.DecodeFile(manifest, &dt); err != nil {
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
	hwJSON := resolvePath(root, regDir, filepath.Join("toobloader", "hal", "chips", chip, "hardware.json"))
	if _, err := os.Stat(hwJSON); err != nil {
		return fmt.Errorf("hardware.json not found for chip '%s' (not in local or registry). Run `toob chip add` first", chip)
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

	// 4. Run manifest compiler (Compiler Inheritance Mode)
	manifestPy := resolvePath(root, compilerRoot, filepath.Join("cli", "manifest_compiler", "toob_manifest.py"))
	if _, err := os.Stat(manifestPy); err != nil {
		return fmt.Errorf("manifest compiler not found at %s", manifestPy)
	}
	fmt.Println("[toob] Running manifest compiler ...")
	if err := run(root, pythonBin(), manifestPy,
		"--toml", manifest, "--hardware", hwJSON, "--outdir", generatedDir); err != nil {
		return err
	}

	// 5. Run SUIT code generator if bash is available
	generateSh := resolvePath(root, compilerRoot, filepath.Join("cli", "suit", "generate.sh"))
	if _, err := os.Stat(generateSh); err == nil {
		if bash := findBash(); bash != "" {
			if pyScripts := findPythonScriptsBin(); pyScripts != "" {
				os.Setenv("PATH", pyScripts+string(os.PathListSeparator)+os.Getenv("PATH"))
			}
			fmt.Println("[toob] Running SUIT code generator ...")
			if err := run(root, bash, generateSh, generatedDir, manifest, chip); err != nil {
				return err
			}
		} else {
			fmt.Println("[toob] Skipping SUIT code generator (bash not found).")
		}
	}

	// 6. Resolve toolchain from chip metadata
	toolchainName := "toolchain-riscv32.cmake"
	arch := "riscv32"
	toolchainPrefix := "riscv32-unknown-elf-"
	halVendor := vendor

	cmPath := resolvePath(root, regDir, filepath.Join("toobloader", "hal", "chips", chip, "chip_manifest.json"))
	if data, err := os.ReadFile(cmPath); err == nil {
		var cm chipManifest
		if err := json.Unmarshal(data, &cm); err == nil {
			if cm.Toolchain != "" {
				toolchainName = cm.Toolchain
			}
			if cm.Arch != "" {
				arch = cm.Arch
			}
			if cm.ToolchainPrefix != "" {
				toolchainPrefix = cm.ToolchainPrefix
			}
			if cm.Vendor != "" {
				halVendor = cm.Vendor
			}
		}
	}

	toolchainFile := resolvePath(root, compilerRoot, filepath.Join("cmake", toolchainName))

	coreDir := filepath.ToSlash(resolvePath(root, compilerRoot, filepath.Join("toobloader", "core")))
	cryptoDir := filepath.ToSlash(resolvePath(root, compilerRoot, filepath.Join("toobloader", "crypto")))
	stage0Dir := filepath.ToSlash(resolvePath(root, compilerRoot, filepath.Join("toobloader", "stage0")))
	
	// HALs come from regDir
	halChipDir := filepath.ToSlash(resolvePath(root, regDir, filepath.Join("toobloader", "hal", "chips", chip)))
	halArchDir := filepath.ToSlash(resolvePath(root, regDir, filepath.Join("toobloader", "hal", "arch", arch)))
	halVendorDir := filepath.ToSlash(resolvePath(root, regDir, filepath.Join("toobloader", "hal", "vendor", halVendor)))
	
	sdkDir := filepath.ToSlash(resolvePath(root, compilerRoot, filepath.Join("sdk")))
	budgetCheckPy := filepath.ToSlash(resolvePath(root, compilerRoot, filepath.Join("cli", "manifest_compiler", "budget_check.py")))

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
			"set(TOOB_BUDGET_CHECK_SCRIPT \"%s\")\n",
		arch, halVendor, chip, toolchainPrefix,
		coreDir, cryptoDir, stage0Dir, halChipDir, halArchDir, halVendorDir, sdkDir, budgetCheckPy,
	)
	if err := os.WriteFile(filepath.Join(generatedDir, "toob_config.cmake"), []byte(configContent), 0o644); err != nil {
		return err
	}

	// 8. Ensure cross-compiler is in PATH
	tcPath := flagToolchainPath
	if tcPath == "" {
		tcPath = findToolchainBin(toolchainPrefix)
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

// pythonBin returns the Python interpreter name for the current OS.
func pythonBin() string {
	if runtime.GOOS == "windows" {
		return "python"
	}
	return "python3"
}

// findBash locates a working bash binary.
func findBash() string {
	if runtime.GOOS == "windows" {
		gitBash := `C:\Program Files\Git\bin\bash.exe`
		if _, err := os.Stat(gitBash); err == nil {
			return gitBash
		}
	}
	if p, err := exec.LookPath("bash"); err == nil {
		return p
	}
	return ""
}

// findToolchainBin auto-detects the cross-compiler bin directory.
func findToolchainBin(prefix string) string {
	compiler := prefix + "gcc"
	if _, err := exec.LookPath(compiler); err == nil {
		return "" // already in PATH
	}

	// Espressif IDF standard layout
	if runtime.GOOS == "windows" {
		triplet := strings.TrimSuffix(prefix, "-")
		base := filepath.Join("C:\\", "Espressif", "tools", triplet)
		entries, err := os.ReadDir(base)
		if err != nil {
			return ""
		}
		// Sort reverse to pick the newest version
		sort.Slice(entries, func(i, j int) bool {
			return entries[i].Name() > entries[j].Name()
		})
		for _, e := range entries {
			candidate := filepath.Join(base, e.Name(), triplet, "bin")
			exe := filepath.Join(candidate, compiler+".exe")
			if _, err := os.Stat(exe); err == nil {
				return candidate
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
				candidate := filepath.Join(base, e.Name(), triplet, "bin")
				exe := filepath.Join(candidate, compiler)
				if _, err := os.Stat(exe); err == nil {
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
