package cmd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"os/user"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/toob-boot/toob/internal/lockfile"
	manifestpkg "github.com/toob-boot/toob/internal/manifest"
	"github.com/toob-boot/toob/internal/paths"
	"github.com/toob-boot/toob/internal/ports"
	"github.com/toob-boot/toob/internal/registry"
	"github.com/toob-boot/toob/internal/ui"
)

const (
	dockerImageRepo    = "mannomannx/toob-compiler"
	dockerUnpinnedTag  = "latest"
	containerWorkspace = "/workspace"
	containerHome      = "/home/compiler"
)

func evalExistingAncestors(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return filepath.Clean(p)
	}
	cur := abs
	var suffix []string
	for {
		if resolved, evalErr := filepath.EvalSymlinks(cur); evalErr == nil {
			for i := len(suffix) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, suffix[i])
			}
			return filepath.Clean(resolved)
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return abs
		}
		suffix = append(suffix, filepath.Base(cur))
		cur = parent
	}
}

// containerPath maps a host path below root to its location in the container.
// Anything outside root (including via symlinks) is rejected, not dropped.
func containerPath(root, hostPath, flagName string) (string, error) {
	if err := validateCMakeArgPath(flagName, hostPath); err != nil {
		return "", err
	}
	canonRoot := evalExistingAncestors(root)
	canonHost := evalExistingAncestors(hostPath)
	rel, err := filepath.Rel(canonRoot, canonHost)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", fmt.Errorf("%s %s lies outside the workspace %s, which is the only directory mounted into the container",
			flagName, canonHost, canonRoot)
	}
	return path.Join(containerWorkspace, filepath.ToSlash(rel)), nil
}

func resolveCompilerImageTag(dt *manifestpkg.DeviceToml, lf *lockfile.Lockfile) string {
	if dt != nil && dt.Build.Compiler != "" && dt.Build.Compiler != dockerUnpinnedTag {
		if lf != nil && lf.Environment.Compiler != "" && lf.Environment.Compiler != dt.Build.Compiler {
			return dt.Build.Compiler
		}
	}
	if lf != nil && lf.Environment.Compiler != "" {
		return lf.Environment.Compiler
	}
	if dt != nil && dt.Build.Compiler != "" {
		return dt.Build.Compiler
	}
	return dockerUnpinnedTag
}

func canonicalizeMockFlagValue(raw string) (string, error) {
	var cleanTokens []string
	for _, tok := range strings.Split(raw, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		lower := strings.ToLower(tok)
		if lower != "*" && lower != "all" && lower != "none" && lower != "true" && lower != "false" {
			if err := manifestpkg.ValidateName("mock trait", tok); err != nil {
				return "", err
			}
		}
		cleanTokens = append(cleanTokens, tok)
	}
	if len(cleanTokens) == 0 {
		return "none", nil
	}
	return strings.Join(cleanTokens, ","), nil
}

func runDockerBuild(ctx context.Context, cmd *cobra.Command, root string, dt *manifestpkg.DeviceToml, regOverride string, cache *registry.Cache, lf *lockfile.Lockfile) error {
	if _, err := exec.LookPath("docker"); err != nil {
		return fmt.Errorf("docker is not installed or not in PATH; install Docker or run `toob build --native`")
	}

	devMode := flagDev || isDevEnvEnabled()
	var regDir string
	if regOverride != "" && !strings.HasPrefix(regOverride, "http://") && !strings.HasPrefix(regOverride, "https://") {
		regDir = regOverride
	} else {
		var err error
		regDir, err = paths.RegistryDir()
		if err != nil {
			return fmt.Errorf("cannot locate the registry directory: %w", err)
		}
	}
	absRegDir, err := filepath.Abs(regDir)
	if err != nil {
		return fmt.Errorf("cannot resolve registry path %q: %w", regDir, err)
	}

	compilerTag := resolveCompilerImageTag(dt, lf)
	if err := manifestpkg.ValidateName("compiler tag", compilerTag); err != nil {
		return err
	}

	cmdArgs := []string{"toob", "build", "--native"}
	if devMode {
		cmdArgs = append(cmdArgs, "--dev")
	}
	if flagSkipChecks {
		cmdArgs = append(cmdArgs, "--skip-checks")
	}
	if flagLocked {
		cmdArgs = append(cmdArgs, "--locked")
	}
	if flagProfile != "" {
		if err := manifestpkg.ValidateName("build profile", flagProfile); err != nil {
			return err
		}
		cmdArgs = append(cmdArgs, "--profile", flagProfile)
	}
	if cmd != nil && cmd.Flags().Changed("mock") {
		cleanMock, mErr := canonicalizeMockFlagValue(flagMock)
		if mErr != nil {
			return mErr
		}
		cmdArgs = append(cmdArgs, "--mock", cleanMock)
	} else if cmd != nil && cmd.Flags().Changed("mock-efuses") {
		if flagMockEfuses {
			cmdArgs = append(cmdArgs, "--mock", "keystore")
		} else {
			cmdArgs = append(cmdArgs, "--mock", "none")
		}
	}

	var toolchainsDir string
	if toobHome, homeErr := paths.ToobHome(); homeErr == nil {
		toolchainsDir = filepath.Join(toobHome, "toolchains")
	}

	input := ports.DockerBuildInput{
		Image:         fmt.Sprintf("%s:%s", dockerImageRepo, compilerTag),
		Workspace:     root,
		RegistryDir:   absRegDir,
		ToolchainsDir: toolchainsDir,
		WorkDir:       containerWorkspace,
		Command:       strings.Join(cmdArgs, " "),
		CommandArgs:   cmdArgs,
		DevMode:       devMode,
		Manifest:      flagManifest,
		BuildDir:      flagBuildDir,
		ProxyVars:     make(map[string]string),
	}
	for _, envVar := range []string{"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy"} {
		if val := os.Getenv(envVar); val != "" {
			input.ProxyVars[envVar] = val
		}
	}

	if err := ensureCompilerImage(ctx, input.Image, compilerTag); err != nil {
		return err
	}
	if err := checkProtocolVersion(ctx, input.Image, devMode); err != nil {
		return err
	}

	args, err := dockerRunArgs(root, compilerTag, input)
	if err != nil {
		return err
	}

	ui.Step("Starting Docker container (toob-compiler:%s)", compilerTag)
	if err := run(ctx, root, "docker", nil, args...); err != nil {
		return err
	}
	ui.Tip("Run 'toob build --native' for much faster builds (requires local toolchains).")
	if !flagLocked {
		recordDockerBuild(paths.LockfilePath(root), cache, compilerTag)
	}
	return nil
}

func ensureCompilerImage(ctx context.Context, image, tag string) error {
	if tag == dockerUnpinnedTag {
		ui.Step("Pulling latest compiler image...")
		return dockerPull(ctx, image)
	}
	// #nosec G204 -- image is strictly <dockerImageRepo>:<validated_tag>.
	if err := exec.CommandContext(ctx, "docker", "image", "inspect", image).Run(); err != nil {
		ui.Step("Compiler image %s not found locally. Pulling...", tag)
		return dockerPull(ctx, image)
	}
	return nil
}

func dockerPull(ctx context.Context, image string) error {
	// #nosec G204 -- image is strictly <dockerImageRepo>:<validated_tag>.
	if err := exec.CommandContext(ctx, "docker", "pull", image).Run(); err != nil {
		return fmt.Errorf("failed to pull compiler image %s: %w", image, err)
	}
	return nil
}

func workspaceHash(root string) string {
	abs, err := filepath.Abs(root)
	if err != nil {
		abs = root
	}
	sum := sha256.Sum256([]byte(abs))
	return hex.EncodeToString(sum[:6])
}

// dockerRunArgs derives the `docker run` arguments from the port struct.
func dockerRunArgs(root, compilerTag string, input ports.DockerBuildInput) ([]string, error) {
	args := []string{"run", "--rm", "-i"}
	if stat, err := os.Stdout.Stat(); err == nil && stat.Mode()&os.ModeCharDevice != 0 {
		args = append(args, "-t")
	}
	if runtime.GOOS != "windows" {
		if u, err := user.Current(); err == nil {
			args = append(args, "-u", fmt.Sprintf("%s:%s", u.Uid, u.Gid))
		}
	}

	absWorkspace, err := filepath.Abs(input.Workspace)
	if err != nil {
		return nil, fmt.Errorf("invalid workspace path: %w", err)
	}
	absRegDir, err := filepath.Abs(input.RegistryDir)
	if err != nil {
		return nil, fmt.Errorf("invalid registry directory: %w", err)
	}
	if err := os.MkdirAll(absRegDir, 0o750); err != nil {
		return nil, fmt.Errorf("cannot prepare registry directory for container mount: %w", err)
	}

	args = append(args,
		"-e", "HOME="+containerHome,
		"-v", fmt.Sprintf("%s:%s", absWorkspace, containerWorkspace),
		"-v", fmt.Sprintf("%s:%s/.toob/registry", absRegDir, containerHome),
	)

	if _, directRegErr := os.Stat(filepath.Join(absRegDir, "registry.json")); directRegErr == nil || os.Getenv("TOOB_REGISTRY_DIR") != "" {
		args = append(args, "-e", "TOOB_REGISTRY_DIR="+containerHome+"/.toob/registry")
	}
	if input.DevMode {
		args = append(args, "-e", "TOOB_DEV=1")
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("cannot determine home directory for container mounts: %w", err)
	}

	tcHostDir := input.ToolchainsDir
	if tcHostDir == "" {
		tcHostDir = filepath.Join(home, ".toob", "toolchains")
	}
	absTCDir, err := filepath.Abs(tcHostDir)
	if err != nil {
		return nil, fmt.Errorf("invalid toolchains directory: %w", err)
	}
	for _, sub := range []struct{ host, dst string }{
		{absTCDir, containerHome + "/.toob/toolchains"},
		{filepath.Join(home, ".toob", "cache"), containerHome + "/.toob/cache"},
		{filepath.Join(home, ".toob", "store"), containerHome + "/.toob/store"},
	} {
		if err := os.MkdirAll(sub.host, 0o750); err != nil {
			return nil, fmt.Errorf("cannot prepare %s for container mount: %w", sub.host, err)
		}
		args = append(args, "-v", fmt.Sprintf("%s:%s", sub.host, sub.dst))
	}

	// Scope ccache per compiler tag AND workspace hash so untrusted workspaces cannot poison global object caches.
	ccacheDir := filepath.Join(home, ".toob", "ccache", compilerTag, workspaceHash(absWorkspace))
	if err := os.MkdirAll(ccacheDir, 0o750); err != nil {
		return nil, fmt.Errorf("cannot create ccache directory: %w", err)
	}
	args = append(args, "-v", fmt.Sprintf("%s:/ccache", ccacheDir), "-e", "CCACHE_DIR=/ccache")

	for _, k := range slices.Sorted(maps.Keys(input.ProxyVars)) {
		args = append(args, "-e", fmt.Sprintf("%s=%s", k, input.ProxyVars[k]))
	}
	if len(input.ProxyVars) > 0 && runtime.GOOS == "linux" {
		if _, err := os.Stat("/etc/ssl/certs"); err == nil {
			args = append(args, "-v", "/etc/ssl/certs:/etc/ssl/certs:ro")
		}
	}

	args = append(args, "-w", input.WorkDir, input.Image)
	if len(input.CommandArgs) == 0 {
		return nil, fmt.Errorf("docker build requires discrete CommandArgs")
	}
	args = append(args, input.CommandArgs...)

	for _, flag := range []struct{ name, host string }{
		{"--manifest", input.Manifest},
		{"--build-dir", input.BuildDir},
	} {
		if flag.host == "" {
			continue
		}
		inContainer, err := containerPath(root, flag.host, flag.name)
		if err != nil {
			return nil, err
		}
		args = append(args, flag.name, inContainer)
	}
	return args, nil
}

func recordDockerBuild(lfPath string, cache *registry.Cache, compilerTag string) {
	lf, err := lockfile.Load(lfPath)
	if err != nil {
		ui.Warn("Build succeeded, but the lockfile could not be updated: %v", err)
		return
	}
	if cache != nil && !cache.IsLocalOverride() {
		if regVer, err := cache.HeadCommit(); err == nil && regVer != "" && regVer != "uninitialized" {
			lf.Registry.Commit = regVer
			lf.Registry.Version = regVer
		}
	}
	if compilerTag != dockerUnpinnedTag {
		lf.Environment.Compiler = compilerTag
	} else {
		ui.Warn("Compiler image tag '%s' is not pinned; pin [build] compiler in device.toml for reproducible builds.", compilerTag)
	}
	if err := lf.Save(lfPath); err != nil {
		ui.Warn("Build succeeded, but the lockfile could not be saved: %v", err)
	}
}

// checkProtocolVersion enforces exact protocol_version parity between this CLI
// and the compiler image, failing closed if the label is missing (unless --dev).
func checkProtocolVersion(ctx context.Context, image string, devMode bool) error {
	// #nosec G204 -- image is strictly <dockerImageRepo>:<validated_tag>.
	out, err := exec.CommandContext(ctx, "docker", "inspect",
		"--format", "{{index .Config.Labels \"toob.protocol_version\"}}",
		image,
	).Output()
	if err != nil {
		return fmt.Errorf("cannot inspect compiler image %s for the protocol handshake: %w", image, err)
	}

	label := strings.TrimSpace(string(out))
	if label == "" || label == "<no value>" {
		if devMode {
			ui.Warn("Compiler image %s has no 'toob.protocol_version' label (permitted in --dev mode).", image)
			return nil
		}
		return fmt.Errorf("compiler image %s is missing required 'toob.protocol_version' label (expected v%d); pull an official compiler image or pass --dev",
			image, ports.ProtocolVersion)
	}

	containerVersion, err := strconv.Atoi(label)
	if err != nil {
		return fmt.Errorf("invalid protocol version label on image: %q", label)
	}
	switch {
	case containerVersion == ports.ProtocolVersion:
		return nil
	case containerVersion > ports.ProtocolVersion:
		return fmt.Errorf("protocol mismatch: compiler image speaks protocol v%d, but this CLI only supports v%d (run `toob update`)",
			containerVersion, ports.ProtocolVersion)
	default:
		return fmt.Errorf("protocol mismatch: compiler image speaks protocol v%d, but this CLI requires v%d (run `docker pull %s`)",
			containerVersion, ports.ProtocolVersion, image)
	}
}
