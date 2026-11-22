package scaffold

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/BurntSushi/toml"
	"github.com/Masterminds/semver/v3"

	"github.com/toob-boot/toob/internal/manifest"
	"github.com/toob-boot/toob/internal/registry"
)

const (
	maxScaffoldFileBytes = 4 << 20
	defaultProjectName   = "toob-device"
	defaultJustification = "Recovery image integrity covered by Stage 1 SHA-256 + boot_proof seal; rescue TBM1 bundle signature verified by Stage 1 on reboot."
)

// TemplateData is the pure read-only value model passed to .tmpl files.
// Never pass Context or *registry.Cache to text/template (HIGH-84).
type TemplateData struct {
	ProjectName string
	ChipName    string
	Arch        string
}

// Context contains all the necessary parameters for generating a project.
type Context struct {
	ProjectName     string
	ProjectDir      string
	ChipName        string
	ChipInfo        *registry.ChipInfo
	Cache           *registry.Cache
	NoVSCode        bool
	UseDevContainer bool
	SdkUrl          string //nolint:staticcheck // ST1003: backward-compatible field used by cmd/init.go until Stage 3B
	SdkRevision     string
}

// Generator defines the interface for framework-specific scaffolders.
type Generator interface {
	Generate(ctx Context) error
}

// IntegrationGenerator generates minimal libtoob bridging code instead of full scaffolding.
type IntegrationGenerator struct {
	Framework string
}

func validateRelScaffoldPath(rel string) (string, string, error) {
	if rel == "" || strings.Contains(rel, `\`) || strings.ContainsRune(rel, 0) || strings.Contains(rel, ":") {
		return "", "", fmt.Errorf("invalid scaffold path %q", rel)
	}
	slash := filepath.ToSlash(rel)
	if strings.HasPrefix(slash, "/") {
		return "", "", fmt.Errorf("absolute scaffold path %q is forbidden", rel)
	}
	for part := range strings.SplitSeq(slash, "/") {
		if part == "" || part == "." || part == ".." {
			return "", "", fmt.Errorf("unsafe path component %q in %q", part, rel)
		}
	}
	return slash, filepath.FromSlash(slash), nil
}

func readRootBounded(root *os.Root, relOS string) ([]byte, error) {
	info, err := root.Lstat(relOS)
	if err != nil {
		return nil, err
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		return nil, fmt.Errorf("refusing symlink %q", relOS)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%q is not a regular file", relOS)
	}
	if info.Size() > maxScaffoldFileBytes {
		return nil, fmt.Errorf("%q (%d bytes) exceeds %d-byte limit", relOS, info.Size(), maxScaffoldFileBytes)
	}
	f, err := root.Open(relOS)
	if err != nil {
		return nil, err
	}
	data, readErr := io.ReadAll(io.LimitReader(f, maxScaffoldFileBytes+1))
	closeErr := f.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if int64(len(data)) > maxScaffoldFileBytes {
		return nil, fmt.Errorf("%q exceeds %d-byte limit", relOS, maxScaffoldFileBytes)
	}
	return data, nil
}

func writeRootFile(root *os.Root, relOS string, data []byte, perm os.FileMode) error {
	parent := filepath.Dir(relOS)
	if parent != "." && parent != "" {
		if err := root.MkdirAll(parent, 0o755); err != nil {
			return err
		}
	}
	f, err := root.OpenFile(relOS, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(data)
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}

func resolveChipArch(ctx Context, chipDir string) string {
	if ctx.ChipInfo != nil && strings.TrimSpace(ctx.ChipInfo.Arch) != "" {
		return strings.TrimSpace(ctx.ChipInfo.Arch)
	}
	if chipDir == "" {
		return ""
	}
	chipRoot, err := os.OpenRoot(chipDir)
	if err != nil {
		return ""
	}
	defer func() { _ = chipRoot.Close() }()
	data, err := readRootBounded(chipRoot, "chip_manifest.json")
	if err != nil {
		return ""
	}
	var cm manifest.ChipManifest
	if json.Unmarshal(data, &cm) == nil {
		return strings.TrimSpace(cm.Arch)
	}
	return ""
}

// Generate writes device.toml and copies/renders integration files into ctx.ProjectDir/toob_integration.
func (g *IntegrationGenerator) Generate(ctx Context) error {
	if ctx.Cache == nil {
		return errors.New("FATAL: Cache is required for scaffolding")
	}
	if err := GenerateDeviceToml(ctx); err != nil {
		return err
	}

	chipDir, err := ctx.Cache.ChipSourcePath(ctx.ChipName)
	if err != nil {
		return fmt.Errorf("FATAL: Failed to resolve chip '%s': %w", ctx.ChipName, err)
	}
	intDir, err := ctx.Cache.IntegrationSourcePath(strings.ToLower(g.Framework))
	if err != nil {
		return fmt.Errorf("FATAL: Failed to resolve integration '%s': %w", g.Framework, err)
	}

	tmplDir := filepath.Join(intDir, "files")
	st, err := os.Lstat(tmplDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("FATAL: Integration files not found for framework '%s' in registry", g.Framework)
		}
		return err
	}
	if st.Mode()&fs.ModeSymlink != 0 || !st.IsDir() {
		return fmt.Errorf("FATAL: Integration files path for '%s' is not a regular directory", g.Framework)
	}

	td := TemplateData{
		ProjectName: cmp.Or(strings.TrimSpace(ctx.ProjectName), defaultProjectName),
		ChipName:    strings.TrimSpace(ctx.ChipName),
		Arch:        resolveChipArch(ctx, chipDir),
	}

	integrationDir := filepath.Join(ctx.ProjectDir, "toob_integration")
	return CopyOrRenderScaffoldTree(tmplDir, integrationDir, td)
}

// CopyOrRenderScaffoldTree copies srcDir into dstDir through *os.Root handles.
// Files ending in ".tmpl" are rendered with pure-value TemplateData (stripping ".tmpl");
// all other regular files (.c, .h, .py, CMakeLists.txt, etc.) are byte-copied verbatim
// preserving executable permission bits (0o755 vs 0o644) while rejecting symlinks/traversal.
func CopyOrRenderScaffoldTree(srcDir, dstDir string, data TemplateData) error {
	if err := os.MkdirAll(dstDir, 0o750); err != nil {
		return err
	}
	srcRoot, err := os.OpenRoot(srcDir)
	if err != nil {
		return err
	}
	defer func() { _ = srcRoot.Close() }()

	dstRoot, err := os.OpenRoot(dstDir)
	if err != nil {
		return err
	}
	defer func() { _ = dstRoot.Close() }()

	return fs.WalkDir(srcRoot.FS(), ".", func(relPath string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if relPath == "." {
			return nil
		}

		relSlash, relOS, err := validateRelScaffoldPath(relPath)
		if err != nil {
			return err
		}

		info, err := srcRoot.Lstat(relOS)
		if err != nil {
			return err
		}
		if info.Mode()&fs.ModeSymlink != 0 {
			return fmt.Errorf("refusing symlink %q in scaffold template tree", relSlash)
		}
		if info.IsDir() {
			return dstRoot.MkdirAll(relOS, 0o755)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("unsupported non-regular file %q in scaffold template tree", relSlash)
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return fmt.Errorf("refusing symlink %q in scaffold template tree", relSlash)
		}

		raw, err := readRootBounded(srcRoot, relOS)
		if err != nil {
			return err
		}

		perm := os.FileMode(0o644)
		if info.Mode()&0o111 != 0 {
			perm = 0o755
		}

		if strings.HasSuffix(relSlash, ".tmpl") {
			destOS := strings.TrimSuffix(relOS, ".tmpl")
			if strings.TrimSpace(filepath.Base(destOS)) == "" {
				return fmt.Errorf("invalid template filename %q", relSlash)
			}
			tmpl, err := template.New(relSlash).Option("missingkey=error").Parse(string(raw))
			if err != nil {
				return fmt.Errorf("failed to parse template %s: %w", relSlash, err)
			}
			var rendered bytes.Buffer
			if err := tmpl.Execute(&rendered, data); err != nil {
				return fmt.Errorf("failed to execute template %s: %w", relSlash, err)
			}
			return writeRootFile(dstRoot, destOS, rendered.Bytes(), perm)
		}

		return writeRootFile(dstRoot, relOS, raw, perm)
	})
}

// GenerateDeviceToml writes device.toml into ctx.ProjectDir using template_device.toml
// (sanitized of legacy pins) when present, or declaratively from chip_manifest.json +
// hardware.json when template_device.toml is absent.
func GenerateDeviceToml(ctx Context) error {
	if ctx.Cache == nil {
		return errors.New("FATAL: Cache is required for generating device.toml")
	}

	chipDir, err := ctx.Cache.ChipSourcePath(ctx.ChipName)
	if err != nil {
		return fmt.Errorf("FATAL: Failed to resolve chip '%s': %w", ctx.ChipName, err)
	}
	return GenerateDeviceTomlFromChipDir(chipDir, ctx.ProjectDir, ctx.ProjectName, ctx.ChipName)
}

// GenerateDeviceTomlFromChipDir generates a validated device.toml inside projectDir
// directly from chipDir using *os.Root containment.
func GenerateDeviceTomlFromChipDir(chipDir, projectDir, projectName, chipName string) error {
	resolvedProjectName := cmp.Or(strings.TrimSpace(projectName), defaultProjectName)
	if err := os.MkdirAll(projectDir, 0o750); err != nil {
		return err
	}

	chipRoot, err := os.OpenRoot(chipDir)
	if err != nil {
		return fmt.Errorf("open chip directory %s: %w", chipDir, err)
	}
	defer func() { _ = chipRoot.Close() }()

	projRoot, err := os.OpenRoot(projectDir)
	if err != nil {
		return fmt.Errorf("open project directory %s: %w", projectDir, err)
	}
	defer func() { _ = projRoot.Close() }()

	var cm *manifest.ChipManifest
	if cmBytes, cmErr := readRootBounded(chipRoot, "chip_manifest.json"); cmErr == nil {
		var parsed manifest.ChipManifest
		if uErr := json.Unmarshal(cmBytes, &parsed); uErr != nil {
			return fmt.Errorf("invalid chip_manifest.json in %s: %w", chipDir, uErr)
		}
		cm = &parsed
	} else if !errors.Is(cmErr, os.ErrNotExist) {
		return cmErr
	}

	resolvedChipName := strings.TrimSpace(chipName)
	if resolvedChipName == "" && cm != nil {
		resolvedChipName = strings.TrimSpace(cm.Name)
	}
	if resolvedChipName == "" {
		resolvedChipName = filepath.Base(chipDir)
	}

	arch := ""
	if cm != nil {
		arch = strings.TrimSpace(cm.Arch)
	}

	var tomlContent string
	if rawTmpl, tErr := readRootBounded(chipRoot, "template_device.toml.tmpl"); tErr == nil {
		tmpl, pErr := template.New("template_device.toml.tmpl").Option("missingkey=error").Parse(string(rawTmpl))
		if pErr != nil {
			return fmt.Errorf("failed to parse template_device.toml.tmpl: %w", pErr)
		}
		var buf bytes.Buffer
		if exErr := tmpl.Execute(&buf, TemplateData{
			ProjectName: resolvedProjectName,
			ChipName:    resolvedChipName,
			Arch:        arch,
		}); exErr != nil {
			return fmt.Errorf("failed to execute template_device.toml.tmpl: %w", exErr)
		}
		tomlContent = sanitizeDeviceToml(buf.String(), resolvedProjectName, resolvedChipName, cm)
	} else if !errors.Is(tErr, os.ErrNotExist) {
		return tErr
	} else if rawStatic, sErr := readRootBounded(chipRoot, "template_device.toml"); sErr == nil {
		tomlContent = sanitizeDeviceToml(string(rawStatic), resolvedProjectName, resolvedChipName, cm)
	} else if !errors.Is(sErr, os.ErrNotExist) {
		return sErr
	} else {
		if cm == nil {
			return fmt.Errorf("FATAL: chip '%s' has neither template_device.toml nor chip_manifest.json", resolvedChipName)
		}
		hwRel := "hardware.json"
		if cm.Sources != nil && strings.TrimSpace(cm.Sources.Hardware) != "" {
			_, cleanHW, pathErr := validateRelScaffoldPath(strings.TrimSpace(cm.Sources.Hardware))
			if pathErr != nil {
				return fmt.Errorf("invalid hardware.json path in chip_manifest.json: %w", pathErr)
			}
			hwRel = cleanHW
		}
		hwBytes, hwErr := readRootBounded(chipRoot, hwRel)
		if hwErr != nil {
			return fmt.Errorf("FATAL: cannot read %s for declarative device.toml generation on chip '%s': %w",
				hwRel, resolvedChipName, hwErr)
		}
		var hw manifest.HardwareJson
		dec := json.NewDecoder(bytes.NewReader(hwBytes))
		dec.DisallowUnknownFields()
		if decErr := dec.Decode(&hw); decErr != nil {
			return fmt.Errorf("invalid %s for chip '%s': %w", hwRel, resolvedChipName, decErr)
		}
		tomlContent, err = synthesizeDeclarativeDeviceToml(resolvedProjectName, resolvedChipName, cm, &hw)
		if err != nil {
			return err
		}
	}

	if err := validateGeneratedDeviceToml(tomlContent); err != nil {
		return err
	}
	return writeRootFile(projRoot, "device.toml", []byte(tomlContent), 0o644)
}

func isValidCompilerSemver(val string) bool {
	trimmed := strings.TrimSpace(val)
	if trimmed == "" || trimmed[0] < '0' || trimmed[0] > '9' {
		return false
	}
	_, err := semver.NewVersion(trimmed)
	return err == nil
}

func isLegacyRegistryURL(val string) bool {
	lower := strings.ToLower(strings.TrimSpace(val))
	return strings.HasPrefix(lower, "https://github.com/") ||
		strings.HasPrefix(lower, "http://github.com/") ||
		strings.HasPrefix(lower, "git@github.com:")
}

func parseTomlKeyStringValue(line string) (string, string, bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "[") {
		return "", "", false
	}
	eqIdx := strings.IndexByte(trimmed, '=')
	if eqIdx <= 0 {
		return "", "", false
	}
	key := strings.TrimSpace(trimmed[:eqIdx])
	rhs := strings.TrimSpace(trimmed[eqIdx+1:])
	if len(rhs) >= 2 && rhs[0] == '"' {
		if endQuote := strings.IndexByte(rhs[1:], '"'); endQuote >= 0 {
			return key, rhs[1 : 1+endQuote], true
		}
	}
	if hashIdx := strings.IndexByte(rhs, '#'); hashIdx >= 0 {
		rhs = strings.TrimSpace(rhs[:hashIdx])
	}
	return key, strings.Trim(rhs, `"'`), true
}

func sanitizeDeviceToml(raw, projectName, chipName string, cm *manifest.ChipManifest) string {
	normalized := strings.ReplaceAll(raw, "\r\n", "\n")
	lines := strings.Split(normalized, "\n")

	var out []string
	var buildSectionLines []string
	inBuild := false
	section := ""
	sawTopName := false
	sawTopVersion := false

	flushBuildSection := func() {
		if !inBuild {
			return
		}
		inBuild = false
		hasActiveKey := false
		for _, bl := range buildSectionLines {
			t := strings.TrimSpace(bl)
			if t != "" && !strings.HasPrefix(t, "#") && !strings.HasPrefix(t, "[") {
				hasActiveKey = true
				break
			}
		}
		if hasActiveKey {
			out = append(out, buildSectionLines...)
		}
		buildSectionLines = nil
	}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") && strings.Contains(trimmed, "]") {
			flushBuildSection()
			if section == "" {
				var pre []string
				if !sawTopName {
					pre = append(pre, fmt.Sprintf("name = %q", projectName))
					sawTopName = true
				}
				if !sawTopVersion {
					pre = append(pre, `version = "v1.0.0"`)
					sawTopVersion = true
				}
				if len(pre) > 0 {
					out = append(pre, out...)
				}
			}
			endIdx := strings.IndexByte(trimmed, ']')
			section = strings.ToLower(strings.TrimSpace(trimmed[1:endIdx]))
			if section == "build" {
				inBuild = true
				buildSectionLines = []string{line}
				continue
			}
			out = append(out, line)
			continue
		}

		key, val, isKV := parseTomlKeyStringValue(line)
		if section == "" && isKV {
			switch key {
			case "name":
				sawTopName = true
				out = append(out, fmt.Sprintf("name = %q", projectName))
				continue
			case "version":
				sawTopVersion = true
			}
		}
		if section == "device" && isKV && key == "chip" && chipName != "" {
			out = append(out, fmt.Sprintf("chip = %q", chipName))
			continue
		}
		if inBuild {
			if isKV {
				switch key {
				case "core_sdk":
					if strings.EqualFold(val, "core/v0.1.0") {
						continue
					}
				case "registry":
					if isLegacyRegistryURL(val) {
						continue
					}
				case "compiler":
					if !isValidCompilerSemver(val) {
						continue
					}
				}
			}
			buildSectionLines = append(buildSectionLines, line)
			continue
		}
		out = append(out, line)
	}
	flushBuildSection()

	if !sawTopName {
		out = append([]string{fmt.Sprintf("name = %q", projectName)}, out...)
	}
	if !sawTopVersion {
		out = append([]string{out[0], `version = "v1.0.0"`}, out[1:]...)
	}

	rendered := strings.TrimRight(strings.Join(out, "\n"), "\n") + "\n"

	// Ensure [recovery.crypto] justification is present if chip defaults to unsigned recovery.
	var checkDT manifest.DeviceToml
	if _, err := toml.Decode(rendered, &checkDT); err == nil && needsUnsignedRecoveryJustification(&checkDT, cm) {
		if !strings.Contains(rendered, "[recovery.crypto]") {
			rendered += fmt.Sprintf("\n[recovery.crypto]\njustification = %q\n", defaultJustification)
		}
	}
	return rendered
}

func needsUnsignedRecoveryJustification(dt *manifest.DeviceToml, cm *manifest.ChipManifest) bool {
	if strings.TrimSpace(dt.Recovery.Crypto.Justification) != "" {
		return false
	}
	var chipRecBackend, chipRecHash, chipBackend, chipHash string
	if cm != nil {
		if cm.Recovery != nil && cm.Recovery.Crypto != nil {
			chipRecBackend = cm.Recovery.Crypto.Backend
			chipRecHash = cm.Recovery.Crypto.Hash
		}
		if cm.Crypto != nil {
			chipBackend = cm.Crypto.Backend
			chipHash = cm.Crypto.Hash
		}
	}
	effBackend := strings.TrimSpace(cmp.Or(dt.Recovery.Crypto.Backend, chipRecBackend, dt.Crypto.Backend, chipBackend))
	effHash := strings.TrimSpace(cmp.Or(dt.Recovery.Crypto.Hash, chipRecHash, dt.Crypto.Hash, chipHash))
	return strings.EqualFold(effBackend, "none") || strings.EqualFold(effHash, "none")
}

func nextPow2U32(v uint32) uint32 {
	if v <= 1 {
		return 1
	}
	p := uint64(1)
	for p < uint64(v) {
		p <<= 1
	}
	if p > math.MaxUint32 {
		return 1 << 31
	}
	return uint32(p)
}

func alignUpU32(val, align uint32) uint32 {
	if align <= 1 {
		return val
	}
	rem := val % align
	if rem == 0 {
		return val
	}
	if uint64(val)+uint64(align-rem) > math.MaxUint32 {
		return val
	}
	return val + (align - rem)
}

func alignDownU32(val, align uint32) uint32 {
	if align <= 1 {
		return val
	}
	return (val / align) * align
}

func synthesizeDeclarativeDeviceToml(projectName, chipName string, cm *manifest.ChipManifest, hw *manifest.HardwareJson) (string, error) {
	var writableBytes uint64
	var firstSec, maxSec uint32
	for _, r := range hw.Flash.Regions {
		if r.Type != "" && r.Type != "writable" {
			continue
		}
		sec := r.SectorSize
		if sec == 0 {
			continue
		}
		if firstSec == 0 {
			firstSec = sec
		}
		if sec > maxSec {
			maxSec = sec
		}
		if r.Count > 0 {
			writableBytes += uint64(sec) * uint64(r.Count)
		} else if r.Size > 0 {
			writableBytes += uint64(r.Size)
		}
	}
	if maxSec == 0 {
		maxSec = 4096
		firstSec = 4096
	}
	if writableBytes == 0 {
		writableBytes = uint64(hw.Flash.Size)
	}
	if writableBytes == 0 {
		return "", fmt.Errorf("FATAL: chip '%s' hardware.json defines zero writable flash capacity", chipName)
	}

	unitAlign := max(hw.Flash.AppAlignment, maxSec)
	if unitAlign == 0 {
		unitAlign = 4096
	}

	execModel := ""
	slotCount := 2
	hasScratch := false
	if cm.SlotCapabilities != nil {
		execModel = strings.ToLower(strings.TrimSpace(cm.SlotCapabilities.ExecModel))
		if cm.SlotCapabilities.SlotCount > 0 {
			slotCount = cm.SlotCapabilities.SlotCount
		}
		hasScratch = cm.SlotCapabilities.HasScratch
	}
	remappable := execModel == "xip_remap" || execModel == "bank_swap" || execModel == "relocatable"

	// 1. Stage 0 size (power-of-two on Cortex-M; 32 KB minimum on RP2040).
	stage0Target := uint32(32768)
	if writableBytes <= 524288 && !strings.EqualFold(hw.ChipFamily, "rp2040") && !strings.EqualFold(chipName, "rp2040") {
		stage0Target = 16384
	}
	stage0Size := alignUpU32(stage0Target, firstSec)
	if strings.EqualFold(cm.Arch, "cortex-m") {
		stage0Size = nextPow2U32(stage0Size)
	}

	// 2. Stage 1 size per bank.
	var stage1Target uint32
	switch {
	case writableBytes <= 262144:
		stage1Target = 32768
	case writableBytes <= 524288:
		stage1Target = 65536
	case writableBytes <= 1048576:
		stage1Target = 98304
	default:
		stage1Target = 131072
	}
	stage1Size := alignUpU32(stage1Target, maxSec)

	const walSectors uint32 = 4
	tailOverhead := uint64(walSectors+7) * uint64(maxSec)
	bootAndTail := uint64(stage0Size) + 2*uint64(stage1Size) + tailOverhead
	if bootAndTail >= writableBytes {
		return "", fmt.Errorf("FATAL: chip '%s' writable flash (%d bytes) cannot fit Stage0/Stage1/WAL layout",
			chipName, writableBytes)
	}
	remaining := writableBytes - bootAndTail

	// 3. Recovery & Delta settings adapted to physical flash geometry.
	var recoverySize uint32
	if writableBytes >= 1048576 && remaining >= uint64(5*unitAlign) {
		recTarget := uint32(65536)
		if remappable && hw.Flash.AppAlignment >= 65536 {
			recTarget = 65536
		}
		recoverySize = alignUpU32(recTarget, unitAlign)
		remaining -= uint64(recoverySize)
	}

	totalSectors := writableBytes / uint64(maxSec)
	enableDeltas := false
	var scratchSize uint32
	appSlots := uint64(2)
	switch {
	case remappable && slotCount >= 2:
		enableDeltas = true
	case hasScratch && writableBytes >= 1048576 && totalSectors >= 32:
		enableDeltas = true
		appSlots = 3 // App + Staging + full-size Delta Scratch
	case slotCount < 2 && hasScratch:
		// 1-slot swapscratch reserves up to 4 * maxSec scratch.
		scratchOverhead := uint64(4) * uint64(maxSec)
		if remaining > scratchOverhead {
			remaining -= scratchOverhead
		}
		appSlots = 1
	}

	rawPerSlot := remaining / appSlots
	if execModel == "bank_swap" {
		bankCap := writableBytes / 2
		postSlotPerBank := (uint64(recoverySize) + tailOverhead)
		usedBank1 := uint64(stage0Size) + uint64(stage1Size) + postSlotPerBank + 2*uint64(maxSec)
		if bankCap > usedBank1 && bankCap-usedBank1 < rawPerSlot {
			rawPerSlot = bankCap - usedBank1
		}
	}
	if rawPerSlot > 393216 {
		rawPerSlot = 393216
	}
	appSize := alignDownU32(uint32(rawPerSlot), unitAlign)
	if appSize == 0 {
		appSize = unitAlign
	}
	if enableDeltas && !remappable {
		scratchSize = appSize
	}

	var b strings.Builder
	fmt.Fprintf(&b, "name = %q\n", projectName)
	b.WriteString("version = \"v1.0.0\"\n\n")

	b.WriteString("[identity]\n")
	b.WriteString("vendor_id = 0x0001\n")
	b.WriteString("product_id = 0x0001\n")
	b.WriteString("hw_rev = 1\n\n")

	b.WriteString("[device]\n")
	fmt.Fprintf(&b, "chip = %q\n\n", chipName)

	b.WriteString("[driver_config]\n")
	b.WriteString("uart_baudrate = 115200\n\n")

	b.WriteString("[partitions]\n")
	fmt.Fprintf(&b, "stage0_size = %d\n", stage0Size)
	fmt.Fprintf(&b, "stage1_size = %d\n", stage1Size)
	fmt.Fprintf(&b, "app_size = %d\n", appSize)
	if scratchSize > 0 {
		fmt.Fprintf(&b, "scratch_size = %d\n", scratchSize)
	}
	if recoverySize > 0 {
		fmt.Fprintf(&b, "recovery_size = %d\n", recoverySize)
	}
	fmt.Fprintf(&b, "enable_deltas = %v\n", enableDeltas)
	fmt.Fprintf(&b, "wal_sectors = %d\n\n", walSectors)

	b.WriteString("[boot_config]\n")
	b.WriteString("max_retries = 3\n")
	b.WriteString("max_recovery_retries = 5\n")
	b.WriteString("edge_unattended_mode = true\n")
	b.WriteString("backoff_base_s = 10\n")
	b.WriteString("wdt_timeout_ms = 5000\n")

	if cm.Recovery != nil {
		b.WriteString("\n[recovery]\n")
		if cm.Recovery.Console != "" {
			fmt.Fprintf(&b, "console = %q\n", cm.Recovery.Console)
		}
		if cm.Recovery.Flash != "" {
			fmt.Fprintf(&b, "flash = %q\n", cm.Recovery.Flash)
		}
		if cm.Recovery.WDT != "" {
			fmt.Fprintf(&b, "wdt = %q\n", cm.Recovery.WDT)
		}
		if cm.Recovery.Clock != "" {
			fmt.Fprintf(&b, "clock = %q\n", cm.Recovery.Clock)
		}
		if cm.Recovery.RTC != "" {
			fmt.Fprintf(&b, "rtc = %q\n", cm.Recovery.RTC)
		}
		if cm.Recovery.Crypto != nil {
			b.WriteString("\n[recovery.crypto]\n")
			if cm.Recovery.Crypto.Backend != "" {
				fmt.Fprintf(&b, "backend = %q\n", cm.Recovery.Crypto.Backend)
			}
			if cm.Recovery.Crypto.Hash != "" {
				fmt.Fprintf(&b, "hash = %q\n", cm.Recovery.Crypto.Hash)
			}
			if strings.EqualFold(cm.Recovery.Crypto.Backend, "none") || strings.EqualFold(cm.Recovery.Crypto.Hash, "none") {
				fmt.Fprintf(&b, "justification = %q\n", defaultJustification)
			}
		}
	}

	return b.String(), nil
}

func validateGeneratedDeviceToml(content string) error {
	var dt manifest.DeviceToml
	meta, err := toml.Decode(content, &dt)
	if err != nil {
		return fmt.Errorf("generated device.toml failed TOML parse: %w", err)
	}
	if len(meta.Undecoded()) > 0 {
		return fmt.Errorf("generated device.toml contains unknown fields: %v", meta.Undecoded())
	}
	return nil
}
