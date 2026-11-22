package cmd

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// ensureBuildToolsOnPath looks for CMake and Ninja in standard Windows install locations
// (e.g. Visual Studio / BuildTools) and adds them to PATH if not already discoverable.
func ensureBuildToolsOnPath() {
	if _, err := exec.LookPath("cmake"); err != nil {
		candidates := []string{
			`C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin`,
			`C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin`,
			`C:\Program Files\Microsoft Visual Studio\2022\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin`,
			`C:\Program Files\CMake\bin`,
		}
		for _, c := range candidates {
			if _, err := os.Stat(filepath.Join(c, "cmake.exe")); err == nil {
				_ = os.Setenv("PATH", c+string(os.PathListSeparator)+os.Getenv("PATH"))
				break
			}
		}
	}

	if _, err := exec.LookPath("ninja"); err != nil {
		candidates := []string{
			`C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja`,
			`C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja`,
			`C:\Program Files\Microsoft Visual Studio\2022\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja`,
			`C:\ProgramData\chocolatey\bin`,
		}
		for _, c := range candidates {
			if _, err := os.Stat(filepath.Join(c, "ninja.exe")); err == nil {
				_ = os.Setenv("PATH", c+string(os.PathListSeparator)+os.Getenv("PATH"))
				break
			}
		}
	}
}

// cmd_defaultCtx returns a context with a generous timeout for interactive CLI operations.
// The context is derived from Background() with no parent cancel — it is designed
// for top-level CLI commands where the process lifetime is the natural boundary.
func cmd_defaultCtx() context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	// Register cleanup: in CLI commands, the process exits after RunE completes,
	// so the cancel is effectively a no-op. We still call it to satisfy the linter.
	go func() {
		<-ctx.Done()
		cancel()
	}()
	return ctx
}
