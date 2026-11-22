package cmd

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/toob-boot/toob/internal/apiclient"
	"github.com/toob-boot/toob/internal/ports"
	"github.com/toob-boot/toob/internal/resolve"
)

func TestContainerPath(t *testing.T) {
	root := t.TempDir()

	t.Run("absolute path inside the workspace", func(t *testing.T) {
		got, err := containerPath(root, filepath.Join(root, "build", "out"), "--build-dir")
		if err != nil || got != "/workspace/build/out" {
			t.Fatalf("got %q, %v", got, err)
		}
	})

	t.Run("relative path resolves against the working directory", func(t *testing.T) {
		t.Chdir(root)
		got, err := containerPath(root, filepath.Join("sub", "device.toml"), "--manifest")
		if err != nil || got != "/workspace/sub/device.toml" {
			t.Fatalf("got %q, %v", got, err)
		}
	})

	t.Run("workspace itself", func(t *testing.T) {
		got, err := containerPath(root, root, "--build-dir")
		if err != nil || got != "/workspace" {
			t.Fatalf("got %q, %v", got, err)
		}
	})

	t.Run("outside the workspace", func(t *testing.T) {
		for _, host := range []string{t.TempDir(), filepath.Join(root, "..", "elsewhere")} {
			_, err := containerPath(root, host, "--manifest")
			if err == nil || !strings.Contains(err.Error(), "outside the workspace") {
				t.Errorf("containerPath(%q) = %v, want an outside-workspace error", host, err)
			}
		}
	})
}

func TestDockerRunArgs(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	root := t.TempDir()
	regDir := t.TempDir()
	tcDir := t.TempDir()
	input := ports.DockerBuildInput{
		Image:         "repo:tag",
		Workspace:     root,
		RegistryDir:   regDir,
		ToolchainsDir: tcDir,
		WorkDir:       containerWorkspace,
		Command:       "toob build --native --mock wdt,keystore",
		CommandArgs:   []string{"toob", "build", "--native", "--mock", "wdt,keystore"},
		DevMode:       true,
		Manifest:      filepath.Join(root, "device.toml"),
		ProxyVars:     map[string]string{},
	}

	args, err := dockerRunArgs(root, "tag", input)
	if err != nil {
		t.Fatal(err)
	}
	tail := []string{"-w", containerWorkspace, "repo:tag", "toob", "build", "--native", "--mock", "wdt,keystore", "--manifest", "/workspace/device.toml"}
	if got := args[len(args)-len(tail):]; !slices.Equal(got, tail) {
		t.Fatalf("argument tail = %v, want %v", got, tail)
	}
	if !slices.Contains(args, "CCACHE_DIR=/ccache") {
		t.Fatalf("ccache not configured: %v", args)
	}
	if !slices.Contains(args, "HOME=/home/compiler") {
		t.Fatalf("HOME not pinned to /home/compiler: %v", args)
	}
	if !slices.Contains(args, "TOOB_DEV=1") {
		t.Fatalf("TOOB_DEV=1 expected when DevMode=true: %v", args)
	}

	input.DevMode = false
	argsNoDev, err := dockerRunArgs(root, "tag", input)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(argsNoDev, "TOOB_DEV=1") {
		t.Fatalf("TOOB_DEV=1 must not be set when DevMode=false: %v", argsNoDev)
	}

	input.BuildDir = t.TempDir()
	if _, err := dockerRunArgs(root, "tag", input); err == nil || !strings.Contains(err.Error(), "--build-dir") {
		t.Fatalf("a build dir outside the workspace must fail, got %v", err)
	}
}

func TestReportCombination(t *testing.T) {
	chip := resolve.Chip{Name: "esp32c6", Version: "1.0.0"}
	resp := func(status string) combinationResult {
		return combinationResult{resp: &apiclient.CheckCombinationResponse{Status: status}}
	}

	for _, status := range []string{"FAILED", "failed"} {
		if err := reportCombination(resp(status), chip); err == nil {
			t.Errorf("status %q must abort the build", status)
		}
	}
	for _, status := range []string{"VERIFIED", "UNKNOWN", ""} {
		if err := reportCombination(resp(status), chip); err != nil {
			t.Errorf("status %q must not abort the build: %v", status, err)
		}
	}

	offline := []error{
		errors.New("dial tcp: no such host"),
		errors.New("HTTP 502: <html>bad gateway</html>"),
		errors.New("HTTP 500: " + strings.Repeat("x", 200)),
		errors.New("HTTP 404: not found"),
		errors.New("unexpected"),
	}
	for _, e := range offline {
		if err := reportCombination(combinationResult{err: e}, chip); err != nil {
			t.Errorf("registry error %q must only warn: %v", e, err)
		}
	}
}

func TestFirstNonEmpty(t *testing.T) {
	if got := firstNonEmpty("", "b", "c"); got != "b" {
		t.Errorf("got %q, want b", got)
	}
	if got := firstNonEmpty(); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestWriteFileIfChangedAtomic(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "sub", "toob_config.cmake")

	if err := writeFileIfChanged(target, []byte("set(FOO 1)\n")); err != nil {
		t.Fatalf("initial write failed: %v", err)
	}
	got, err := os.ReadFile(target)
	if err != nil || string(got) != "set(FOO 1)\n" {
		t.Fatalf("got %q, err %v", string(got), err)
	}

	// Unchanged write must succeed without leaving temp files behind.
	if err := writeFileIfChanged(target, []byte("set(FOO 1)\n")); err != nil {
		t.Fatalf("unchanged write failed: %v", err)
	}
	// Overwrite with new contents atomically.
	if err := writeFileIfChanged(target, []byte("set(FOO 2)\n")); err != nil {
		t.Fatalf("overwrite failed: %v", err)
	}
	got, err = os.ReadFile(target)
	if err != nil || string(got) != "set(FOO 2)\n" {
		t.Fatalf("got %q, err %v", string(got), err)
	}
	entries, err := os.ReadDir(filepath.Dir(target))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "toob_config.cmake" {
		t.Fatalf("unexpected files in target dir (temp file leaked?): %v", entries)
	}
}

func TestResolveRegistryOverride_DevGateAndFileURL(t *testing.T) {
	root := t.TempDir()
	localReg := filepath.Join(root, "local-reg")
	if err := os.MkdirAll(localReg, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(localReg, "registry.json"), []byte(`{"version":"2026.04"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, _, err := resolveRegistryOverride("./local-reg", root, false); err == nil || !strings.Contains(err.Error(), "requires --dev") {
		t.Fatalf("expected --dev gate rejection for local path, got: %v", err)
	}
	if _, _, err := resolveRegistryOverride("http://localhost:8080", root, false); err == nil || !strings.Contains(err.Error(), "requires --dev") {
		t.Fatalf("expected --dev gate rejection for plaintext http://, got: %v", err)
	}

	fileURL := "file:///" + strings.TrimPrefix(filepath.ToSlash(localReg), "/")
	if _, _, err := resolveRegistryOverride(fileURL, root, false); err == nil || !strings.Contains(err.Error(), "requires --dev") {
		t.Fatalf("expected --dev gate rejection for file:// URL, got: %v", err)
	}

	override, pin, err := resolveRegistryOverride(fileURL, root, true)
	if err != nil || pin != "" || filepath.Clean(override) != filepath.Clean(localReg) {
		t.Fatalf("resolveRegistryOverride(%q, dev=true) = (%q, %q, %v)", fileURL, override, pin, err)
	}

	override, pin, err = resolveRegistryOverride("2026.04.1", root, false)
	if err != nil || override != "" || pin != "2026.04.1" {
		t.Fatalf("expected version pin 2026.04.1, got (%q, %q, %v)", override, pin, err)
	}
}

func TestValidateCMakeArgPath(t *testing.T) {
	for _, bad := range []string{
		"/tmp/build;evil",
		"C:\\work\\dir;CMAKE_PROJECT_INCLUDE=pwn.cmake",
		"dir\x00nul",
		"dir\nnewline",
	} {
		if err := validateCMakeArgPath("--build-dir", bad); err == nil {
			t.Errorf("expected semicolon/control rejection for %q", bad)
		}
	}
	if err := validateCMakeArgPath("--build-dir", filepath.Join(t.TempDir(), "builds", "esp32c6")); err != nil {
		t.Fatalf("unexpected error on valid path: %v", err)
	}
}

func TestCanonicalizeMockFlagValue(t *testing.T) {
	got, err := canonicalizeMockFlagValue(" wdt , keystore ")
	if err != nil || got != "wdt,keystore" {
		t.Fatalf("canonicalizeMockFlagValue = (%q, %v), want wdt,keystore", got, err)
	}
	if _, err := canonicalizeMockFlagValue("wdt --evil"); err == nil {
		t.Fatalf("expected whitespace/flag injection in mock token to fail")
	}
}
