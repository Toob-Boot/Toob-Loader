package buildrunner

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/Toob-Boot/Toob-Loader/toob-go-lib/build"
	"github.com/toob-boot/toob/internal/manifest"
	"github.com/toob-boot/toob/internal/resolve"
)

const cmakeFingerprintFileName = ".toob_cmake_fingerprint"

// CMakeFingerprintInputs captures all configuration values and generated/linker
// files whose mutations must invalidate the cached CMake build tree.
type CMakeFingerprintInputs struct {
	ProjectRoot    string
	CoreDir        string
	HalRoot        string
	OutDir         string
	ManifestPath   string
	Profile        string
	MockOption     string
	MockOverrides  []string
	ToolchainPath  string
	ToolchainFile  string
	ToolchainPref  string
	CompilerBinary string
	ChipName       string
	ChipArch       string
	ChipLinker     string
	ChipDir        string
	CCacheEnabled  bool
	Artifacts      []string
}

var standardGeneratedCMakeTrackedFiles = []string{
	"toob_config.cmake",
	"generated_build_config.cmake",
	"generated_boot_config.h",
	"boot_generated_config.h",
	"chip_config.h",
	"generated_reset_causes.h",
	"boot_layout.h",
	"boot_layout_assert.h",
	"generated_memory.ld",
	"stage0_layout.ld",
	"flash_layout.ld",
	"flash_layout_stage1b.ld",
	"recovery_layout.ld",
	"generated_platform_wiring.c",
}

// ComputeCMakeFingerprint returns a deterministic SHA-256 hex digest over all
// build options, generated CMake/C/linker artifacts, and chip linker scripts.
func ComputeCMakeFingerprint(in CMakeFingerprintInputs) (string, error) {
	h := sha256.New()

	writeTaggedField(h, "project_root", filepath.Clean(in.ProjectRoot))
	writeTaggedField(h, "core_dir", filepath.Clean(in.CoreDir))
	writeTaggedField(h, "hal_root", filepath.Clean(in.HalRoot))
	writeTaggedField(h, "out_dir", filepath.Clean(in.OutDir))
	writeTaggedField(h, "manifest_path", filepath.Clean(in.ManifestPath))
	writeTaggedField(h, "profile", in.Profile)
	writeTaggedField(h, "mock_option", in.MockOption)
	writeTaggedField(h, "toolchain_path", filepath.Clean(in.ToolchainPath))
	writeTaggedField(h, "toolchain_file", in.ToolchainFile)
	writeTaggedField(h, "toolchain_prefix", in.ToolchainPref)
	writeTaggedField(h, "compiler_binary", in.CompilerBinary)
	writeTaggedField(h, "chip_name", in.ChipName)
	writeTaggedField(h, "chip_arch", in.ChipArch)
	writeTaggedField(h, "ccache", strconv.FormatBool(in.CCacheEnabled))

	sortedMocks := slices.Clone(in.MockOverrides)
	slices.Sort(sortedMocks)
	for _, m := range sortedMocks {
		writeTaggedField(h, "mock_override", m)
	}

	trackedFiles := collectTrackedFingerprintFiles(in)
	for _, path := range trackedFiles {
		state, err := hashTrackedFileState(path)
		if err != nil {
			return "", fmt.Errorf("hash fingerprint input %s: %w", path, err)
		}
		writeTaggedField(h, "file:"+filepath.ToSlash(path), state)
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// FingerprintNeedsConfigure reports whether buildDir must rerun CMake configure.
func FingerprintNeedsConfigure(buildDir, desiredFingerprint string) bool {
	if !isRegularFile(filepath.Join(buildDir, "CMakeCache.txt")) {
		return true
	}
	fpPath := filepath.Join(buildDir, cmakeFingerprintFileName)
	data, err := os.ReadFile(fpPath) // #nosec G304 -- fixed fingerprint filename inside build directory.
	if err != nil {
		return true
	}
	return strings.TrimSpace(string(data)) != strings.TrimSpace(desiredFingerprint)
}

// WriteCMakeFingerprint atomically persists the computed configure fingerprint.
func WriteCMakeFingerprint(buildDir, fingerprint string) error {
	return build.WriteFileAtomic(filepath.Join(buildDir, cmakeFingerprintFileName), []byte(fingerprint+"\n"))
}

// NewFingerprintInputs builds CMakeFingerprintInputs from resolved build inputs.
func NewFingerprintInputs(
	opts NativeOptions,
	projectRoot, coreDir, halRoot, outDir string,
	plan *resolve.Plan,
	mres *manifest.Result,
	tcPathArg string,
	mockOpt string,
	useCCache bool,
) CMakeFingerprintInputs {
	var artifacts []string
	if mres != nil {
		artifacts = mres.Artifacts
	}
	return CMakeFingerprintInputs{
		ProjectRoot:    projectRoot,
		CoreDir:        coreDir,
		HalRoot:        halRoot,
		OutDir:         outDir,
		ManifestPath:   opts.ManifestPath,
		Profile:        opts.Profile,
		MockOption:     mockOpt,
		MockOverrides:  opts.MockOverrides,
		ToolchainPath:  tcPathArg,
		ToolchainFile:  plan.Toolchain.File,
		ToolchainPref:  plan.Toolchain.Prefix,
		CompilerBinary: plan.Toolchain.CompilerBinary,
		ChipName:       plan.Chip.Name,
		ChipArch:       plan.Chip.Arch,
		ChipLinker:     plan.ChipLinker,
		ChipDir:        plan.Chip.Dir,
		CCacheEnabled:  useCCache,
		Artifacts:      artifacts,
	}
}

func collectTrackedFingerprintFiles(in CMakeFingerprintInputs) []string {
	seen := make(map[string]struct{})
	var list []string
	add := func(p string) {
		if strings.TrimSpace(p) == "" {
			return
		}
		clean := filepath.Clean(p)
		if _, exists := seen[clean]; exists {
			return
		}
		seen[clean] = struct{}{}
		list = append(list, clean)
	}

	if in.OutDir != "" {
		for _, name := range standardGeneratedCMakeTrackedFiles {
			add(filepath.Join(in.OutDir, name))
		}
		for _, name := range in.Artifacts {
			if filepath.IsAbs(name) {
				add(name)
			} else {
				add(filepath.Join(in.OutDir, name))
			}
		}
	}

	if in.CoreDir != "" {
		add(filepath.Join(in.CoreDir, "CMakeLists.txt"))
	}
	if in.ProjectRoot != "" {
		add(filepath.Join(in.ProjectRoot, "CMakeLists.txt"))
	}
	if in.ManifestPath != "" {
		add(in.ManifestPath)
	}

	add(in.ChipLinker)
	if in.ChipDir != "" && in.ChipName != "" {
		add(filepath.Join(in.ChipDir, in.ChipName+"_stage1.ld"))
		add(filepath.Join(in.ChipDir, in.ChipName+"_stage1b.ld"))
		add(filepath.Join(in.ChipDir, in.ChipName+"_recovery.ld"))
	}

	slices.Sort(list)
	return list
}

func hashTrackedFileState(path string) (string, error) {
	f, err := os.Open(path) // #nosec G304 -- validated build/generated/linker paths for fingerprint hashing.
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "missing", nil
		}
		return "", err
	}
	defer func() {
		_ = f.Close()
	}()

	h := sha256.New()
	size, err := io.Copy(h, f)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("present:%d:%s", size, hex.EncodeToString(h.Sum(nil))), nil
}

func writeTaggedField(w io.Writer, key, val string) {
	_, _ = fmt.Fprintf(w, "%s=%d:%s\n", key, len(val), val)
}
