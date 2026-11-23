package buildrunner

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
)

// BuildToolEnv returns a process environment slice suitable for exec.Cmd.Env.
// On Windows it augments PATH with discovered CMake and Ninja locations
// without mutating process-global environment variables.
func BuildToolEnv(ctx context.Context) []string {
	return FindBuildToolsEnv(ctx, os.Environ())
}

// FindBuildToolsEnv inspects baseEnv and, on Windows, returns a cloned
// environment slice with CMake and Ninja directories appended to PATH if either
// tool is missing from baseEnv's PATH.
func FindBuildToolsEnv(ctx context.Context, baseEnv []string) []string {
	cloned := slices.Clone(baseEnv)
	if runtime.GOOS != "windows" {
		return cloned
	}

	curPath := getEnvFold(cloned, "PATH")
	hasCMake := hasExeInPathList(curPath, "cmake.exe")
	hasNinja := hasExeInPathList(curPath, "ninja.exe")
	if hasCMake && hasNinja {
		return cloned
	}

	candidates := windowsBuildToolCandidates(ctx, cloned)
	var additions []string
	for _, dir := range candidates {
		if !hasCMake && isRegularFile(filepath.Join(dir, "cmake.exe")) {
			additions = appendUniquePath(additions, dir)
			hasCMake = true
		}
		if !hasNinja && isRegularFile(filepath.Join(dir, "ninja.exe")) {
			additions = appendUniquePath(additions, dir)
			hasNinja = true
		}
		if hasCMake && hasNinja {
			break
		}
	}

	if len(additions) == 0 {
		return cloned
	}
	return setEnvFold(cloned, "PATH", mergePathList(curPath, additions, ";"))
}

func windowsBuildToolCandidates(ctx context.Context, env []string) []string {
	pf := getEnvFold(env, "ProgramFiles")
	if pf == "" {
		pf = `C:\Program Files`
	}
	pf86 := getEnvFold(env, "ProgramFiles(x86)")
	if pf86 == "" {
		pf86 = `C:\Program Files (x86)`
	}

	var dirs []string

	// Prefer active Visual Studio instances discovered via vswhere.exe.
	for _, vsDir := range discoverVSInstallations(ctx, pf, pf86) {
		dirs = appendUniquePath(dirs,
			filepath.Join(vsDir, "Common7", "IDE", "CommonExtensions", "Microsoft", "CMake", "CMake", "bin"),
			filepath.Join(vsDir, "Common7", "IDE", "CommonExtensions", "Microsoft", "CMake", "Ninja"),
		)
	}

	// Probe standard VS editions across Enterprise, Professional, Community, and BuildTools.
	for _, base := range []string{pf, pf86} {
		for _, ver := range []string{"2022", "2019", "18"} {
			for _, edition := range []string{"Enterprise", "Professional", "Community", "BuildTools"} {
				vsRoot := filepath.Join(base, "Microsoft Visual Studio", ver, edition)
				dirs = appendUniquePath(dirs,
					filepath.Join(vsRoot, "Common7", "IDE", "CommonExtensions", "Microsoft", "CMake", "CMake", "bin"),
					filepath.Join(vsRoot, "Common7", "IDE", "CommonExtensions", "Microsoft", "CMake", "Ninja"),
				)
			}
		}
		dirs = appendUniquePath(dirs, filepath.Join(base, "CMake", "bin"))
	}

	if progData := getEnvFold(env, "ProgramData"); progData != "" {
		dirs = appendUniquePath(dirs, filepath.Join(progData, "chocolatey", "bin"))
	}
	if localAppData := getEnvFold(env, "LOCALAPPDATA"); localAppData != "" {
		dirs = appendUniquePath(dirs,
			filepath.Join(localAppData, "Microsoft", "WinGet", "Links"),
			filepath.Join(localAppData, "Programs", "Ninja"),
		)
	}
	if userProfile := getEnvFold(env, "USERPROFILE"); userProfile != "" {
		dirs = appendUniquePath(dirs, filepath.Join(userProfile, "scoop", "shims"))
	}

	return dirs
}

func discoverVSInstallations(ctx context.Context, pf, pf86 string) []string {
	vswhereCandidates := []string{
		filepath.Join(pf86, "Microsoft Visual Studio", "Installer", "vswhere.exe"),
		filepath.Join(pf, "Microsoft Visual Studio", "Installer", "vswhere.exe"),
	}

	for _, vswhere := range vswhereCandidates {
		if !isRegularFileInDir(filepath.Dir(vswhere), filepath.Base(vswhere)) {
			continue
		}
		if dirs := queryVSWhere(ctx, vswhere); len(dirs) > 0 {
			return dirs
		}
	}
	return nil
}

func queryVSWhere(ctx context.Context, vswhere string) []string {
	if !filepath.IsAbs(vswhere) || !strings.EqualFold(filepath.Base(vswhere), "vswhere.exe") {
		return nil
	}
	argSets := [][]string{
		{"-latest", "-products", "*", "-requires", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64", "-property", "installationPath"},
		{"-latest", "-products", "*", "-property", "installationPath"},
	}

	var dirs []string
	for _, args := range argSets {
		// #nosec G204,G702 -- validated absolute vswhere.exe path from ProgramFiles invoked without shell.
		out, err := exec.CommandContext(ctx, vswhere, args...).Output()
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(out), "\n") {
			trimmed := strings.TrimSpace(line)
			if trimmed != "" {
				dirs = appendUniquePath(dirs, trimmed)
			}
		}
		if len(dirs) > 0 {
			return dirs
		}
	}
	return dirs
}

func hasExeInPathList(pathList, exeName string) bool {
	for _, dir := range filepath.SplitList(pathList) {
		if dir == "" {
			continue
		}
		if isRegularFileInDir(dir, exeName) {
			return true
		}
	}
	return false
}

func isRegularFileInDir(dir, name string) bool {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return false
	}
	defer func() {
		_ = root.Close()
	}()
	info, err := root.Stat(name)
	return err == nil && info.Mode().IsRegular()
}

func isRegularFile(path string) bool {
	return isRegularFileInDir(filepath.Dir(path), filepath.Base(path))
}

func appendUniquePath(dst []string, items ...string) []string {
	for _, item := range items {
		if item == "" {
			continue
		}
		if !containsPathFold(dst, item) {
			dst = append(dst, item)
		}
	}
	return dst
}

func containsPathFold(list []string, target string) bool {
	cleanTarget := filepath.Clean(target)
	for _, item := range list {
		if strings.EqualFold(filepath.Clean(item), cleanTarget) {
			return true
		}
	}
	return false
}

func getEnvFold(env []string, key string) string {
	prefix := key + "="
	for _, entry := range env {
		if len(entry) >= len(prefix) && strings.EqualFold(entry[:len(prefix)], prefix) {
			return entry[len(prefix):]
		}
	}
	return ""
}

func setEnvFold(env []string, key, value string) []string {
	prefix := key + "="
	entry := prefix + value
	for i, cur := range env {
		if len(cur) >= len(prefix) && strings.EqualFold(cur[:len(prefix)], prefix) {
			env[i] = entry
			return env
		}
	}
	return append(env, entry)
}

func mergePathList(existing string, additions []string, sep string) string {
	curParts := strings.Split(existing, sep)
	var merged []string
	for _, part := range curParts {
		if part != "" {
			merged = append(merged, part)
		}
	}
	for _, add := range additions {
		if !containsPathFold(merged, add) {
			merged = append(merged, add)
		}
	}
	return strings.Join(merged, sep)
}
