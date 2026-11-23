package buildrunner

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"github.com/toob-boot/toob/internal/paths"
	"github.com/toob-boot/toob/internal/ports"
	"github.com/toob-boot/toob/internal/ui"
)

const (
	// DefaultCompilerImageRepo is the official Toob compiler container image repository.
	DefaultCompilerImageRepo = "ghcr.io/toob-boot/toob-compiler"

	dockerProtocolLabel      = "toob.protocol_version"
	dockerWorkspaceMount     = "/workspace"
	dockerContainerHome      = "/home/compiler"
	dockerCoreSDKMount       = "/opt/toob-core-sdk"
	dockerPullMaxStderrBytes = 16 * 1024
)

var allowedContainerToobEnvVars = []string{
	"TOOB_REGISTRY_URL",
	"TOOB_HUB_URL",
	"TOOB_CORE_SDK_SHA256",
	"TOOB_NO_UPDATE_CHECK",
	"TOOB_DISABLE_CAS",
}

var allowedProxyEnvVars = []string{
	"HTTP_PROXY",
	"HTTPS_PROXY",
	"NO_PROXY",
	"http_proxy",
	"https_proxy",
	"no_proxy",
}

// DockerOptions configures containerized Toob firmware builds.
type DockerOptions struct {
	ManifestPath  string
	BuildDir      string
	OutDir        string
	Profile       string
	ToolchainPath string
	CompilerImage string
	ContainerArch string
	RegistryURL   string
	Integration   string
	CoreSDKDir    string
	MockValue     string
	MockChanged   bool
	Stage0Only    bool
	Clean         bool
	Locked        bool
	DevMode       bool
	Verbose       bool
	NoCCache      bool
	NoUpdateCheck bool
	SkipChecks    bool
	NoPull        bool
	CLIVersion    string
	Stdout        io.Writer
	Stderr        io.Writer
}

// BuildDockerInputFromOptions resolves workspace, host mounts, Core SDK, and CLI
// forwarding arguments into a ports.DockerBuildInput contract.
func BuildDockerInputFromOptions(opts DockerOptions) (ports.DockerBuildInput, []string, error) {
	effectiveDev := opts.DevMode || paths.IsDevMode()

	if opts.Locked && strings.TrimSpace(opts.ToolchainPath) != "" {
		return ports.DockerBuildInput{}, nil, errors.New("--toolchain-path cannot be combined with --locked builds")
	}

	root, manifestPath, err := ResolveWorkspaceAndManifest(opts.ManifestPath)
	if err != nil {
		return ports.DockerBuildInput{}, nil, err
	}

	workspace := root
	if effectiveDev {
		if monoRoot := findMonorepoWorkspaceRoot(root); monoRoot != "" {
			workspace = monoRoot
		}
	}

	containerArch, err := ResolveContainerArch(opts.ContainerArch)
	if err != nil {
		return ports.DockerBuildInput{}, nil, err
	}

	toobHome, err := paths.ToobHome()
	if err != nil {
		return ports.DockerBuildInput{}, nil, fmt.Errorf("resolve TOOB_HOME: %w", err)
	}

	linuxTCDir := filepath.Join(toobHome, "toolchains", "linux_"+containerArch)
	if mkErr := os.MkdirAll(linuxTCDir, 0o700); mkErr != nil {
		return ports.DockerBuildInput{}, nil, fmt.Errorf("create Linux toolchain mount %s: %w", linuxTCDir, mkErr)
	}

	regDir, err := paths.RegistryDir()
	if err != nil {
		return ports.DockerBuildInput{}, nil, fmt.Errorf("resolve registry directory: %w", err)
	}
	if mkErr := os.MkdirAll(regDir, 0o700); mkErr != nil {
		return ports.DockerBuildInput{}, nil, fmt.Errorf("create registry mount %s: %w", regDir, mkErr)
	}

	image, err := ResolveCompilerImage(opts.CompilerImage, opts.CLIVersion)
	if err != nil {
		return ports.DockerBuildInput{}, nil, err
	}

	coreSDKDir := strings.TrimSpace(opts.CoreSDKDir)
	if coreSDKDir == "" {
		coreSDKDir = strings.TrimSpace(os.Getenv("TOOB_COMPILER_DIR"))
	}
	if coreSDKDir == "" && effectiveDev {
		coreSDKDir = findMonorepoCoreDir(root)
	}

	cManifest, err := ContainerPath(workspace, manifestPath)
	if err != nil {
		return ports.DockerBuildInput{}, nil, fmt.Errorf("map manifest into Docker workspace: %w", err)
	}

	var cmdArgs []string
	if strings.TrimSpace(opts.Profile) != "" {
		cmdArgs = append(cmdArgs, "--profile", strings.TrimSpace(opts.Profile))
	}
	if mockFlag, mockErr := CanonicalizeMockFlagValue(opts.MockValue, opts.MockChanged); mockErr != nil {
		return ports.DockerBuildInput{}, nil, mockErr
	} else if mockFlag != "" {
		cmdArgs = append(cmdArgs, "--mock", mockFlag)
	}
	if opts.Locked {
		cmdArgs = append(cmdArgs, "--locked")
	}
	if opts.SkipChecks {
		cmdArgs = append(cmdArgs, "--skip-checks")
	}
	if opts.Stage0Only {
		cmdArgs = append(cmdArgs, "--stage0")
	}
	if opts.Clean {
		cmdArgs = append(cmdArgs, "--clean")
	}
	if opts.Verbose {
		cmdArgs = append(cmdArgs, "--verbose")
	}
	if opts.NoCCache {
		cmdArgs = append(cmdArgs, "--no-ccache")
	}
	if opts.NoUpdateCheck {
		cmdArgs = append(cmdArgs, "--no-update-check")
	}
	if strings.TrimSpace(opts.RegistryURL) != "" {
		cmdArgs = append(cmdArgs, "--registry", strings.TrimSpace(opts.RegistryURL))
	}
	if strings.TrimSpace(opts.Integration) != "" {
		cmdArgs = append(cmdArgs, "--integration", strings.TrimSpace(opts.Integration))
	}
	if strings.TrimSpace(opts.OutDir) != "" {
		cOutDir, outErr := ContainerPath(workspace, opts.OutDir)
		if outErr != nil {
			return ports.DockerBuildInput{}, nil, fmt.Errorf("map --out-dir into Docker workspace: %w", outErr)
		}
		cmdArgs = append(cmdArgs, "--out-dir", cOutDir)
	}
	if strings.TrimSpace(opts.ToolchainPath) != "" {
		cTCPath, tcErr := ContainerPath(workspace, opts.ToolchainPath)
		if tcErr != nil {
			return ports.DockerBuildInput{}, nil, fmt.Errorf("map --toolchain-path into Docker workspace: %w", tcErr)
		}
		cmdArgs = append(cmdArgs, "--toolchain-path", cTCPath)
	}

	cBuildDir := ""
	if strings.TrimSpace(opts.BuildDir) != "" {
		cBuildDir, err = ContainerPath(workspace, opts.BuildDir)
		if err != nil {
			return ports.DockerBuildInput{}, nil, fmt.Errorf("map --build-dir into Docker workspace: %w", err)
		}
	}

	in := ports.DockerBuildInput{
		Image:         image,
		Workspace:     workspace,
		RegistryDir:   regDir,
		WorkDir:       root,
		Command:       "build",
		CommandArgs:   cmdArgs,
		ToolchainsDir: linuxTCDir,
		CoreSDKDir:    coreSDKDir,
		DevMode:       effectiveDev,
		Manifest:      cManifest,
		BuildDir:      cBuildDir,
		ProxyVars:     collectSafeProxyVars(),
	}

	extraEnv := collectSafeToobEnvFlags(workspace, effectiveDev)
	return in, extraEnv, nil
}

// BuildDockerRunArgs builds deterministic, host-isolated "docker run"
// arguments from ports.DockerBuildInput and optional additional "-e" assignments.
func BuildDockerRunArgs(in ports.DockerBuildInput, extraEnv ...string) ([]string, error) {
	if err := validateDockerImageRef(in.Image); err != nil {
		return nil, err
	}
	if strings.TrimSpace(in.Workspace) == "" {
		return nil, errors.New("docker build: Workspace is required")
	}
	if strings.TrimSpace(in.Command) == "" {
		return nil, errors.New("docker build: Command is required")
	}
	if strings.ContainsAny(in.Workspace, "\r\n\x00") {
		return nil, errors.New("docker build: invalid characters in Workspace path")
	}

	cWorkDir := dockerWorkspaceMount
	if strings.TrimSpace(in.WorkDir) != "" {
		mapped, err := ContainerPath(in.Workspace, in.WorkDir)
		if err != nil {
			return nil, fmt.Errorf("map Docker WorkDir: %w", err)
		}
		cWorkDir = mapped
	}

	args := []string{
		"run", "--rm",
		"-v", in.Workspace + ":" + dockerWorkspaceMount,
		"-w", cWorkDir,
	}

	if strings.TrimSpace(in.RegistryDir) != "" {
		args = append(args, "-v", in.RegistryDir+":"+dockerContainerHome+"/.toob/registry")
	}

	if strings.TrimSpace(in.ToolchainsDir) != "" {
		tcMountHost, tcContainerDir, err := resolveLinuxToolchainMount(in.ToolchainsDir, "")
		if err != nil {
			return nil, err
		}
		args = append(args, "-v", tcMountHost+":"+tcContainerDir)
	}

	if strings.TrimSpace(in.CoreSDKDir) != "" {
		if mapped, mapErr := ContainerPath(in.Workspace, in.CoreSDKDir); mapErr == nil {
			args = append(args, "-e", "TOOB_COMPILER_DIR="+mapped)
		} else {
			if strings.ContainsAny(in.CoreSDKDir, "\r\n\x00") {
				return nil, errors.New("docker build: invalid characters in CoreSDKDir")
			}
			args = append(args,
				"-v", in.CoreSDKDir+":"+dockerCoreSDKMount+":ro",
				"-e", "TOOB_COMPILER_DIR="+dockerCoreSDKMount,
			)
		}
	}

	if in.DevMode {
		args = append(args, "-e", "TOOB_DEV=1")
	}

	proxyKeys := make([]string, 0, len(in.ProxyVars))
	for k := range in.ProxyVars {
		proxyKeys = append(proxyKeys, k)
	}
	slices.Sort(proxyKeys)
	for _, k := range proxyKeys {
		v := in.ProxyVars[k]
		if v == "" || strings.ContainsAny(k+v, "\r\n\x00") {
			continue
		}
		args = append(args, "-e", k+"="+v)
	}

	for _, kv := range extraEnv {
		if kv == "" || strings.ContainsAny(kv, "\r\n\x00") {
			continue
		}
		args = append(args, "-e", kv)
	}

	args = append(args, in.Image, "toob", in.Command)
	if in.DevMode {
		args = append(args, "--dev")
	}
	if strings.TrimSpace(in.Manifest) != "" {
		args = append(args, "--manifest", in.Manifest)
	}
	if strings.TrimSpace(in.BuildDir) != "" {
		args = append(args, "--build-dir", in.BuildDir)
	}
	args = append(args, in.CommandArgs...)

	return args, nil
}

// RunDocker pulls (unless NoPull), verifies container ProtocolVersion, and runs
// the firmware build inside the Toob Linux compiler container.
func RunDocker(ctx context.Context, opts DockerOptions) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	stdout := cmp.Or[io.Writer](opts.Stdout, os.Stdout)
	stderr := cmp.Or[io.Writer](opts.Stderr, os.Stderr)

	in, extraEnv, err := BuildDockerInputFromOptions(opts)
	if err != nil {
		return err
	}

	if !opts.NoPull {
		if pullErr := dockerPull(ctx, in.Image, opts.Verbose, stderr); pullErr != nil {
			return pullErr
		}
	}

	if protoErr := CheckProtocolVersion(ctx, in.Image); protoErr != nil {
		return protoErr
	}

	runArgs, err := BuildDockerRunArgs(in, extraEnv...)
	if err != nil {
		return err
	}

	// #nosec G204 -- args are built and validated via BuildDockerRunArgs without shell expansion.
	cmd := exec.CommandContext(ctx, "docker", runArgs...)
	ring := NewRingBuffer(defaultRingBufferBytes)
	cmd.Stdout = io.MultiWriter(stdout, ring)
	cmd.Stderr = io.MultiWriter(stderr, ring)

	if runErr := cmd.Run(); runErr != nil {
		return fmt.Errorf("docker build failed: %w\n%s", runErr, SanitizeTerminalOutput(ring.String()))
	}
	return nil
}

// CheckProtocolVersion queries the container image's toob.protocol_version label
// and enforces an exact match with ports.ProtocolVersion.
func CheckProtocolVersion(ctx context.Context, image string) error {
	if err := validateDockerImageRef(image); err != nil {
		return err
	}
	// #nosec G204 -- validated Docker image reference with fixed format template.
	cmd := exec.CommandContext(ctx, "docker", "inspect", "--format", fmt.Sprintf("{{index .Config.Labels %q}}", dockerProtocolLabel), image)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &limitedWriter{w: &outBuf, remaining: 1024}
	cmd.Stderr = &limitedWriter{w: &errBuf, remaining: dockerPullMaxStderrBytes}

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("inspect Docker image %s protocol version: %w (%s)", image, err, SanitizeTerminalOutput(errBuf.String()))
	}
	return ParseProtocolVersionOutput(outBuf.String())
}

// ParseProtocolVersionOutput validates a container protocol version string against ports.ProtocolVersion.
func ParseProtocolVersionOutput(raw string) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || trimmed == "<no value>" {
		return fmt.Errorf("compiler container image missing required %q label (expected %d)", dockerProtocolLabel, ports.ProtocolVersion)
	}
	got, err := strconv.Atoi(trimmed)
	if err != nil {
		return fmt.Errorf("invalid %q label %q in compiler container: %w", dockerProtocolLabel, SanitizeTerminalOutput(trimmed), err)
	}
	if got != ports.ProtocolVersion {
		return fmt.Errorf("compiler container protocol version mismatch: container=%d, CLI=%d (update CLI or compiler image)", got, ports.ProtocolVersion)
	}
	return nil
}

// ResolveCompilerImage resolves the full compiler container image reference,
// defaulting to DefaultCompilerImageRepo and honoring opts/TOOB_COMPILER_IMAGE.
func ResolveCompilerImage(imageOpt, cliVersion string) (string, error) {
	raw := strings.TrimSpace(imageOpt)
	if raw == "" {
		raw = strings.TrimSpace(os.Getenv("TOOB_COMPILER_IMAGE"))
	}
	if raw == "" {
		raw = DefaultCompilerImageRepo
	}

	if !hasImageTagOrDigest(raw) {
		raw = raw + ":" + ResolveCompilerImageTag(cliVersion)
	}

	if err := validateDockerImageRef(raw); err != nil {
		return "", err
	}
	return raw, nil
}

// ResolveCompilerImageTag maps CLI version strings to a container tag.
func ResolveCompilerImageTag(cliVersion string) string {
	v := strings.TrimSpace(cliVersion)
	if v == "" || strings.EqualFold(v, "dev") {
		return "latest"
	}
	return v
}

// ResolveContainerArch resolves and validates the Linux container architecture.
func ResolveContainerArch(requested string) (string, error) {
	arch := strings.TrimSpace(requested)
	if arch == "" {
		arch = runtime.GOARCH
	}
	switch strings.ToLower(arch) {
	case "amd64", "x86_64":
		return "amd64", nil
	case "arm64", "aarch64":
		return "arm64", nil
	default:
		return "", fmt.Errorf("unsupported Linux compiler container architecture %q (supported: amd64, arm64)", arch)
	}
}

// ContainerPath translates host targetPath relative to host workspace into a POSIX
// container path beneath /workspace, failing if targetPath escapes workspace.
func ContainerPath(workspace, targetPath string) (string, error) {
	absWork, err := filepath.Abs(workspace)
	if err != nil {
		return "", fmt.Errorf("resolve workspace %q: %w", workspace, err)
	}
	absTarget, err := filepath.Abs(targetPath)
	if err != nil {
		return "", fmt.Errorf("resolve path %q: %w", targetPath, err)
	}

	rel, err := filepath.Rel(absWork, absTarget)
	if err != nil {
		return "", fmt.Errorf("path %s cannot be mapped relative to workspace %s: %w", absTarget, absWork, err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", fmt.Errorf("path %s lies outside workspace %s", absTarget, absWork)
	}
	if rel == "." {
		return dockerWorkspaceMount, nil
	}
	return path.Clean(dockerWorkspaceMount + "/" + filepath.ToSlash(rel)), nil
}

// CanonicalizeMockFlagValue validates and canonicalizes the CLI --mock flag.
func CanonicalizeMockFlagValue(flagVal string, changed bool) (string, error) {
	trimmed := strings.TrimSpace(flagVal)
	if !changed && trimmed == "" {
		return "", nil
	}
	if trimmed == "" {
		return "on", nil
	}
	switch strings.ToLower(trimmed) {
	case "true", "on", "1":
		return "on", nil
	case "false", "off", "0":
		return "off", nil
	default:
		if strings.ContainsAny(trimmed, "\r\n\x00;") {
			return "", fmt.Errorf("invalid --mock value %q", trimmed)
		}
		return trimmed, nil
	}
}

func dockerPull(ctx context.Context, image string, verbose bool, stderr io.Writer) error {
	// #nosec G204 -- image is validated via validateDockerImageRef.
	cmd := exec.CommandContext(ctx, "docker", "pull", image)
	ring := NewRingBuffer(dockerPullMaxStderrBytes)

	var spinner *ui.LiveSpinner
	var sw *SpinnerWriter
	if !verbose {
		spinner = ui.NewSpinner("Pulling compiler container " + image + "...")
		spinner.Start()
		sw = NewSpinnerWriter(spinner)
		cmd.Stdout = io.MultiWriter(sw, ring)
		cmd.Stderr = io.MultiWriter(sw, ring)
	} else {
		cmd.Stdout = io.MultiWriter(stderr, ring)
		cmd.Stderr = io.MultiWriter(stderr, ring)
	}

	err := cmd.Run()
	if sw != nil {
		sw.Flush()
	}
	if spinner != nil {
		spinner.Stop()
	}

	if err != nil {
		return fmt.Errorf("docker pull %s failed: %w (%s)", image, err, SanitizeTerminalOutput(ring.String()))
	}
	return nil
}

func resolveLinuxToolchainMount(hostDir, requestedArch string) (hostPath, containerPath string, err error) {
	clean := filepath.Clean(hostDir)
	base := strings.ToLower(filepath.Base(clean))

	if strings.HasPrefix(base, "windows_") || strings.HasPrefix(base, "darwin_") {
		return "", "", fmt.Errorf("refusing non-Linux host toolchain directory %s for Linux Docker container", clean)
	}

	if base == "linux_amd64" || base == "linux_arm64" {
		return clean, dockerContainerHome + "/.toob/toolchains/" + base, nil
	}

	arch, err := ResolveContainerArch(requestedArch)
	if err != nil {
		return "", "", err
	}
	sub := "linux_" + arch
	return filepath.Join(clean, sub), dockerContainerHome + "/.toob/toolchains/" + sub, nil
}

func collectSafeToobEnvFlags(workspace string, devMode bool) []string {
	var env []string
	for _, key := range allowedContainerToobEnvVars {
		val := strings.TrimSpace(os.Getenv(key))
		if val == "" || strings.ContainsAny(val, "\r\n\x00") {
			continue
		}
		if key == "TOOB_REGISTRY_URL" && !devMode && strings.HasPrefix(strings.ToLower(val), "http://") {
			continue
		}
		env = append(env, key+"="+val)
	}

	if rawRegDir := strings.TrimSpace(os.Getenv("TOOB_REGISTRY_DIR")); rawRegDir != "" {
		if mapped, err := ContainerPath(workspace, rawRegDir); err == nil {
			env = append(env, "TOOB_REGISTRY_DIR="+mapped)
		}
	}
	return env
}

func collectSafeProxyVars() map[string]string {
	out := make(map[string]string)
	for _, key := range allowedProxyEnvVars {
		if val := strings.TrimSpace(os.Getenv(key)); val != "" && !strings.ContainsAny(val, "\r\n\x00") {
			out[key] = val
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func findMonorepoWorkspaceRoot(startDir string) string {
	return findMonorepoCoreDir(startDir)
}

func hasImageTagOrDigest(ref string) bool {
	if strings.Contains(ref, "@") {
		return true
	}
	lastSlash := strings.LastIndex(ref, "/")
	lastColon := strings.LastIndex(ref, ":")
	return lastColon > lastSlash
}

func validateDockerImageRef(ref string) error {
	trimmed := strings.TrimSpace(ref)
	if trimmed == "" {
		return errors.New("compiler container image reference must not be empty")
	}
	if strings.HasPrefix(trimmed, "-") {
		return fmt.Errorf("invalid compiler container image reference %q", trimmed)
	}
	if strings.ContainsAny(trimmed, " \t\r\n\x00\"'`$;|&") {
		return fmt.Errorf("compiler container image reference %q contains disallowed characters", trimmed)
	}
	return nil
}
