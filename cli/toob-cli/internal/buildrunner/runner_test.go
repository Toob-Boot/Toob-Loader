package buildrunner

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/Toob-Boot/Toob-Loader/toob-go-lib/build"
	"github.com/toob-boot/toob/internal/lockfile"
	"github.com/toob-boot/toob/internal/manifest"
	"github.com/toob-boot/toob/internal/ports"
	"github.com/toob-boot/toob/internal/registry"
	"github.com/toob-boot/toob/internal/resolve"
	"github.com/toob-boot/toob/internal/ui"
)

func TestProvisionToolchainRejectsLockedOverride(t *testing.T) {
	ctx := t.Context()
	plan := &resolve.Plan{
		Toolchain: resolve.Toolchain{
			Name:           "riscv32-esp-elf",
			Prefix:         "riscv32-esp-elf-",
			CompilerBinary: "riscv32-esp-elf-gcc",
		},
	}

	_, err := ProvisionToolchain(ctx, plan, t.TempDir(), t.TempDir(), true)
	if err == nil {
		t.Fatal("expected ProvisionToolchain to reject --toolchain-path when --locked is true")
	}
	if !strings.Contains(err.Error(), "--locked") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifyCompilerVersionVendorTokenAndMinCompiler(t *testing.T) {
	ctx := t.Context()
	ccPath := buildFakeCompilerBinary(t, "riscv32-esp-elf-gcc")

	t.Run("accepts exact pinned vendor release token", func(t *testing.T) {
		t.Setenv("TOOB_FAKE_GCC_VERSION", "riscv32-esp-elf-gcc (crosstool-NG esp-14.2.0_20251107) 14.2.0\nCopyright (C) 2024 Free Software Foundation, Inc.")
		err := VerifyCompilerVersion(ctx, ccPath, resolve.Toolchain{
			Name:            "riscv32-esp-elf",
			MinCompiler:     "14.2.0",
			ExpectedVersion: "esp-14.2.0_20251107",
		})
		if err != nil {
			t.Fatalf("unexpected verification error: %v", err)
		}
	})

	t.Run("rejects mismatched vendor release token when base SemVer matches", func(t *testing.T) {
		t.Setenv("TOOB_FAKE_GCC_VERSION", "riscv32-esp-elf-gcc (crosstool-NG esp-14.2.0_20240401) 14.2.0")
		err := VerifyCompilerVersion(ctx, ccPath, resolve.Toolchain{
			Name:            "riscv32-esp-elf",
			MinCompiler:     "14.2.0",
			ExpectedVersion: "esp-14.2.0_20251107",
		})
		if err == nil {
			t.Fatal("expected verification failure for mismatched vendor release token")
		}
	})

	t.Run("rejects upstream version without pinned vendor token", func(t *testing.T) {
		t.Setenv("TOOB_FAKE_GCC_VERSION", "riscv32-esp-elf-gcc (GCC) 14.2.0")
		err := VerifyCompilerVersion(ctx, ccPath, resolve.Toolchain{
			Name:            "riscv32-esp-elf",
			MinCompiler:     "14.2.0",
			ExpectedVersion: "esp-14.2.0_20251107",
		})
		if err == nil {
			t.Fatal("expected verification failure for upstream GCC missing vendor token")
		}
	})

	t.Run("rejects prefix-extended token", func(t *testing.T) {
		t.Setenv("TOOB_FAKE_GCC_VERSION", "riscv32-esp-elf-gcc (crosstool-NG esp-14.2.0_20251107_rc1) 14.2.0")
		err := VerifyCompilerVersion(ctx, ccPath, resolve.Toolchain{
			Name:            "riscv32-esp-elf",
			MinCompiler:     "14.2.0",
			ExpectedVersion: "esp-14.2.0_20251107",
		})
		if err == nil {
			t.Fatal("expected verification failure when token is only a prefix of esp-14.2.0_20251107_rc1")
		}
	})

	t.Run("enforces min_compiler lower bound", func(t *testing.T) {
		t.Setenv("TOOB_FAKE_GCC_VERSION", "riscv32-esp-elf-gcc (crosstool-NG esp-13.2.0_20240530) 13.2.0")
		err := VerifyCompilerVersion(ctx, ccPath, resolve.Toolchain{
			Name:        "riscv32-esp-elf",
			MinCompiler: "14.2.0",
		})
		if err == nil {
			t.Fatal("expected min_compiler check to fail for 13.2.0 < 14.2.0")
		}
	})

	t.Run("fails closed when binary missing", func(t *testing.T) {
		err := VerifyCompilerVersion(ctx, filepath.Join(t.TempDir(), "nonexistent-gcc"), resolve.Toolchain{
			Name:        "riscv32-esp-elf",
			MinCompiler: "14.2.0",
		})
		if err == nil {
			t.Fatal("expected missing compiler binary to fail closed")
		}
	})

	t.Run("accepts xPack revision pin matching base SemVer and xPack banner", func(t *testing.T) {
		matchingDir := filepath.Join(t.TempDir(), "15.2.1-1.1", "xpack-arm-none-eabi-gcc-15.2.1-1.1", "bin")
		if mkdirErr := os.MkdirAll(matchingDir, 0o750); mkdirErr != nil {
			t.Fatal(mkdirErr)
		}
		matchingCC := filepath.Join(matchingDir, filepath.Base(ccPath))
		if linkErr := os.Link(ccPath, matchingCC); linkErr != nil {
			t.Fatal(linkErr)
		}
		t.Setenv("TOOB_FAKE_GCC_VERSION", "arm-none-eabi-gcc.exe (xPack GNU Arm Embedded GCC x86_64) 15.2.1 20251203\nCopyright (C) 2025 Free Software Foundation, Inc.")
		err := VerifyCompilerVersion(ctx, matchingCC, resolve.Toolchain{
			Name:            "arm-none-eabi",
			MinCompiler:     "12.2.0",
			ExpectedVersion: "15.2.1-1.1",
		})
		if err != nil {
			t.Fatalf("unexpected verification error for xPack pin: %v", err)
		}
	})

	t.Run("rejects non-xPack banner for xPack revision pin", func(t *testing.T) {
		t.Setenv("TOOB_FAKE_GCC_VERSION", "arm-none-eabi-gcc (GNU Arm Embedded) 15.2.1 20251203")
		err := VerifyCompilerVersion(ctx, ccPath, resolve.Toolchain{
			Name:            "arm-none-eabi",
			MinCompiler:     "12.2.0",
			ExpectedVersion: "15.2.1-1.1",
		})
		if err == nil {
			t.Fatal("expected verification failure when xPack banner is missing")
		}
	})

	t.Run("rejects wrong base SemVer for xPack revision pin", func(t *testing.T) {
		t.Setenv("TOOB_FAKE_GCC_VERSION", "arm-none-eabi-gcc (xPack GNU Arm Embedded GCC x86_64) 14.2.1 20241203")
		err := VerifyCompilerVersion(ctx, ccPath, resolve.Toolchain{
			Name:            "arm-none-eabi",
			MinCompiler:     "12.2.0",
			ExpectedVersion: "15.2.1-1.1",
		})
		if err == nil {
			t.Fatal("expected verification failure when base SemVer does not match xPack pin")
		}
	})

	t.Run("rejects conflicting xPack revision in compiler path", func(t *testing.T) {
		for _, relDir := range []string{
			filepath.Join("15.2.1-1.0", "bin"),
			filepath.Join("xpack-arm-none-eabi-gcc-15.2.1-1.0", "bin"),
		} {
			conflictDir := filepath.Join(t.TempDir(), relDir)
			if mkdirErr := os.MkdirAll(conflictDir, 0o750); mkdirErr != nil {
				t.Fatal(mkdirErr)
			}
			conflictCC := filepath.Join(conflictDir, filepath.Base(ccPath))
			if linkErr := os.Link(ccPath, conflictCC); linkErr != nil {
				t.Fatal(linkErr)
			}
			t.Setenv("TOOB_FAKE_GCC_VERSION", "arm-none-eabi-gcc.exe (xPack GNU Arm Embedded GCC x86_64) 15.2.1 20251203")
			err := VerifyCompilerVersion(ctx, conflictCC, resolve.Toolchain{
				Name:            "arm-none-eabi",
				MinCompiler:     "12.2.0",
				ExpectedVersion: "15.2.1-1.1",
			})
			if err == nil {
				t.Fatalf("expected conflicting xPack path %s to fail closed", conflictCC)
			}
		}
	})
}

func TestEnsureCoreSDKDownloadVerifyAndFailClosed(t *testing.T) {
	ctx := t.Context()
	archiveBytes := makeCoreSDKTarGz(t, map[string]string{
		"core-v0.1.0/CMakeLists.txt": "cmake_minimum_required(VERSION 3.20)\nproject(toob_core C)\n",
		"core-v0.1.0/README.md":      "Toob Core SDK",
	})
	sum := sha256.Sum256(archiveBytes)
	archiveSHA := hex.EncodeToString(sum[:])

	var requestedPath string
	var hitCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitCount++
		requestedPath = r.URL.Path
		if r.URL.Path != "/api/v1/releases/core/0.1.0/download/core-source.tar.gz" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(archiveBytes)
	}))
	defer srv.Close()

	toobHome := filepath.Join(t.TempDir(), "toob-home")
	t.Setenv("TOOB_HOME", toobHome)
	t.Setenv("TOOB_DEV", "")
	t.Setenv("TOOB_COMPILER_DIR", "")
	t.Setenv("TOOB_CORE_SDK_SHA256", "")

	projRoot := t.TempDir()
	idx := &registry.Index{
		Ecosystem: &registry.EcosystemVersions{
			CoreSDK: []string{"0.1.0"},
			CoreSDKSha256: map[string]string{
				"0.1.0": archiveSHA,
			},
		},
	}

	dir, gotSHA, err := EnsureCoreSDK(ctx, CoreSDKOptions{
		ProjectRoot: projRoot,
		Version:     "core/v0.1.0",
		RegistryURL: srv.URL,
		Index:       idx,
		DevMode:     false,
		Locked:      false,
	})
	if err != nil {
		t.Fatalf("EnsureCoreSDK failed: %v", err)
	}
	if requestedPath != "/api/v1/releases/core/0.1.0/download/core-source.tar.gz" {
		t.Fatalf("unexpected release download path: %s", requestedPath)
	}
	expectedDir := filepath.Join(toobHome, "core", "0.1.0")
	if filepath.Clean(dir) != filepath.Clean(expectedDir) {
		t.Fatalf("expected TOOB_HOME cache dir %s, got %s", expectedDir, dir)
	}
	if gotSHA != archiveSHA {
		t.Fatalf("expected sha256 %s, got %s", archiveSHA, gotSHA)
	}
	if !isRegularFile(filepath.Join(dir, "CMakeLists.txt")) {
		t.Fatal("expected CMakeLists.txt in extracted Core SDK directory")
	}

	// Second call must hit verified cache without issuing HTTP request.
	prevHits := hitCount
	dir2, gotSHA2, err := EnsureCoreSDK(ctx, CoreSDKOptions{
		ProjectRoot: projRoot,
		Version:     "core/v0.1.0",
		RegistryURL: srv.URL,
		Index:       idx,
		DevMode:     false,
		Locked:      false,
	})
	if err != nil {
		t.Fatalf("cached EnsureCoreSDK failed: %v", err)
	}
	if hitCount != prevHits {
		t.Fatalf("expected cache hit with 0 new downloads, got %d requests", hitCount-prevHits)
	}
	if dir2 != dir || gotSHA2 != archiveSHA {
		t.Fatalf("cached return mismatch: (%s, %s)", dir2, gotSHA2)
	}

	t.Run("fails closed on digest mismatch", func(t *testing.T) {
		homeMismatch := filepath.Join(t.TempDir(), "home-mismatch")
		t.Setenv("TOOB_HOME", homeMismatch)
		badIdx := &registry.Index{
			Ecosystem: &registry.EcosystemVersions{
				CoreSDKSha256: map[string]string{
					"0.1.0": strings.Repeat("a", 64),
				},
			},
		}
		_, _, err := EnsureCoreSDK(ctx, CoreSDKOptions{
			ProjectRoot: projRoot,
			Version:     "core/v0.1.0",
			RegistryURL: srv.URL,
			Index:       badIdx,
			DevMode:     false,
		})
		if err == nil {
			t.Fatal("expected SHA-256 mismatch to fail closed")
		}
	})

	t.Run("fails closed without digest outside dev mode", func(t *testing.T) {
		homeNoDigest := filepath.Join(t.TempDir(), "home-nodigest")
		t.Setenv("TOOB_HOME", homeNoDigest)
		_, _, err := EnsureCoreSDK(ctx, CoreSDKOptions{
			ProjectRoot: projRoot,
			Version:     "core/v0.1.0",
			RegistryURL: srv.URL,
			Index:       &registry.Index{},
			DevMode:     false,
		})
		if err == nil {
			t.Fatal("expected missing digest outside --dev to fail closed")
		}
	})

	t.Run("locked enforces lockfile digest and rejects conflict", func(t *testing.T) {
		lfBad := &lockfile.Lockfile{
			Environment: lockfile.EnvironmentLock{
				CoreSDK:       "0.1.0",
				CoreSDKSHA256: strings.Repeat("b", 64),
			},
		}
		_, _, err := EnsureCoreSDK(ctx, CoreSDKOptions{
			ProjectRoot: projRoot,
			Version:     "0.1.0",
			RegistryURL: srv.URL,
			Index:       idx,
			Lock:        lfBad,
			Locked:      true,
		})
		if err == nil {
			t.Fatal("expected lockfile vs index SHA-256 conflict to fail under --locked")
		}

		lfMissing := &lockfile.Lockfile{
			Environment: lockfile.EnvironmentLock{
				CoreSDK: "0.1.0",
			},
		}
		_, _, err = EnsureCoreSDK(ctx, CoreSDKOptions{
			ProjectRoot: projRoot,
			Version:     "0.1.0",
			RegistryURL: srv.URL,
			Index:       idx,
			Lock:        lfMissing,
			Locked:      true,
		})
		if err == nil {
			t.Fatal("expected empty lockfile CoreSDKSHA256 to fail under --locked")
		}
	})
}

func TestBuildDockerRunArgsAndProtocolVersion(t *testing.T) {
	if DefaultCompilerImageRepo != "ghcr.io/toob-boot/toob-compiler" {
		t.Fatalf("unexpected default compiler repo: %s", DefaultCompilerImageRepo)
	}

	t.Run("honors TOOB_COMPILER_IMAGE", func(t *testing.T) {
		t.Setenv("TOOB_COMPILER_IMAGE", "ghcr.io/example/custom-compiler")
		img, err := ResolveCompilerImage("", "0.4.0")
		if err != nil {
			t.Fatalf("ResolveCompilerImage failed: %v", err)
		}
		if img != "ghcr.io/example/custom-compiler:0.4.0" {
			t.Fatalf("unexpected image ref: %s", img)
		}

		t.Setenv("TOOB_COMPILER_IMAGE", "ghcr.io/example/custom-compiler:pinned")
		img2, err := ResolveCompilerImage("", "0.4.0")
		if err != nil {
			t.Fatalf("ResolveCompilerImage with tag failed: %v", err)
		}
		if img2 != "ghcr.io/example/custom-compiler:pinned" {
			t.Fatalf("unexpected tagged image ref: %s", img2)
		}
	})

	t.Run("mounts linux_<arch> only and forwards flags plus CoreSDKDir", func(t *testing.T) {
		toobHome := filepath.Join(t.TempDir(), "toob-home")
		t.Setenv("TOOB_HOME", toobHome)
		t.Setenv("TOOB_TOKEN", "secret-must-not-forward")
		t.Setenv("TOOB_NO_UPDATE_CHECK", "1")
		t.Setenv("HTTP_PROXY", "http://127.0.0.1:8888")

		ws := t.TempDir()
		proj := filepath.Join(ws, "examples", "esp32c6")
		if err := os.MkdirAll(proj, 0o750); err != nil {
			t.Fatal(err)
		}
		manifestPath := filepath.Join(proj, "device.toml")
		if err := os.WriteFile(manifestPath, []byte("[device]\nchip = \"esp32c6\"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(ws, "CMakeLists.txt"), []byte("# core\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(ws, "toobloader", "core"), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(ws, "toobloader", "core", "hal_contract.json"), []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}

		in, extraEnv, err := BuildDockerInputFromOptions(DockerOptions{
			ManifestPath:  manifestPath,
			ContainerArch: "arm64",
			Profile:       "production",
			MockValue:     "on",
			MockChanged:   true,
			Locked:        true,
			DevMode:       true,
			CLIVersion:    "0.5.0",
		})
		if err != nil {
			t.Fatalf("BuildDockerInputFromOptions failed: %v", err)
		}

		args, err := BuildDockerRunArgs(in, extraEnv...)
		if err != nil {
			t.Fatalf("BuildDockerRunArgs failed: %v", err)
		}
		joined := strings.Join(args, " ")

		expectedMount := filepath.Join(toobHome, "toolchains", "linux_arm64") + ":/home/compiler/.toob/toolchains/linux_arm64"
		if !slices.Contains(args, expectedMount) {
			t.Fatalf("expected Linux-only toolchain mount %q in args: %v", expectedMount, args)
		}
		if strings.Contains(joined, "windows_") || strings.Contains(joined, "darwin_") {
			t.Fatalf("unexpected non-Linux toolchain path in docker args: %s", joined)
		}
		if !slices.Contains(args, "TOOB_COMPILER_DIR=/workspace") {
			t.Fatalf("expected CoreSDKDir forwarding in args: %v", args)
		}
		if !slices.Contains(args, "--locked") || !slices.Contains(args, "--profile") || !slices.Contains(args, "--mock") {
			t.Fatalf("expected --locked, --profile, --mock forwarding in args: %v", args)
		}
		if !slices.Contains(args, "TOOB_NO_UPDATE_CHECK=1") {
			t.Fatalf("expected safe TOOB_* env forwarding in args: %v", args)
		}
		if strings.Contains(joined, "secret-must-not-forward") {
			t.Fatalf("secret env TOOB_TOKEN leaked into docker args: %s", joined)
		}
	})

	t.Run("rejects host non-Linux toolchain mount", func(t *testing.T) {
		ws := t.TempDir()
		_, err := BuildDockerRunArgs(ports.DockerBuildInput{
			Image:         DefaultCompilerImageRepo + ":latest",
			Workspace:     ws,
			WorkDir:       ws,
			Command:       "build",
			ToolchainsDir: filepath.Join(ws, "toolchains", "windows_amd64"),
		})
		if err == nil {
			t.Fatal("expected BuildDockerRunArgs to reject windows_amd64 host toolchain mount")
		}
	})

	t.Run("enforces ports.ProtocolVersion", func(t *testing.T) {
		if err := ParseProtocolVersionOutput(fmt.Sprintf("%d\n", ports.ProtocolVersion)); err != nil {
			t.Fatalf("expected matching ProtocolVersion %d to pass: %v", ports.ProtocolVersion, err)
		}
		for _, bad := range []string{"", "<no value>", "1", "999", "not-an-int"} {
			if err := ParseProtocolVersionOutput(bad); err == nil {
				t.Fatalf("expected ProtocolVersion check to reject %q", bad)
			}
		}
	})
}

func TestCMakeFingerprintInvalidation(t *testing.T) {
	root := t.TempDir()
	outDir := filepath.Join(root, "generated")
	chipDir := filepath.Join(root, "chip")
	buildDir := filepath.Join(root, "build")
	coreDir := filepath.Join(root, "core")
	for _, d := range []string{outDir, chipDir, buildDir, coreDir} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}

	writeFile := func(p, body string) {
		t.Helper()
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	buildCfg := filepath.Join(outDir, "generated_build_config.cmake")
	bootHdr := filepath.Join(outDir, "generated_boot_config.h")
	legacyHdr := filepath.Join(outDir, "boot_generated_config.h")
	linker := filepath.Join(chipDir, "esp32c6_stage1.ld")

	writeFile(filepath.Join(outDir, "toob_config.cmake"), "# cfg\n")
	writeFile(buildCfg, "set(X 1)\n")
	writeFile(bootHdr, "#define A 1U\n")
	writeFile(legacyHdr, "#define B 1U\n")
	writeFile(linker, "MEMORY { iram : org = 0x40800000, len = 64K }\n")

	in := CMakeFingerprintInputs{
		ProjectRoot: root,
		CoreDir:     coreDir,
		OutDir:      outDir,
		ChipName:    "esp32c6",
		ChipArch:    "riscv32",
		ChipDir:     chipDir,
		ChipLinker:  linker,
		Profile:     resolve.ProfileProduction,
	}

	fp1, err := ComputeCMakeFingerprint(in)
	if err != nil {
		t.Fatalf("ComputeCMakeFingerprint failed: %v", err)
	}
	writeFile(filepath.Join(buildDir, "CMakeCache.txt"), "CMAKE_CACHE=1\n")
	if err := WriteCMakeFingerprint(buildDir, fp1); err != nil {
		t.Fatalf("WriteCMakeFingerprint failed: %v", err)
	}
	if FingerprintNeedsConfigure(buildDir, fp1) {
		t.Fatal("expected matching fingerprint + CMakeCache.txt to skip reconfigure")
	}

	for _, tc := range []struct {
		name string
		path string
		next string
	}{
		{"generated_build_config.cmake", buildCfg, "set(X 2)\n"},
		{"generated_boot_config.h", bootHdr, "#define A 2U\n"},
		{"boot_generated_config.h", legacyHdr, "#define B 2U\n"},
		{"chip linker script", linker, "MEMORY { iram : org = 0x40800000, len = 32K }\n"},
	} {
		writeFile(tc.path, tc.next)
		fpNext, fpErr := ComputeCMakeFingerprint(in)
		if fpErr != nil {
			t.Fatalf("recompute fingerprint after %s change: %v", tc.name, fpErr)
		}
		if fpNext == fp1 {
			t.Fatalf("modifying %s did not invalidate CMake fingerprint", tc.name)
		}
		if !FingerprintNeedsConfigure(buildDir, fpNext) {
			t.Fatalf("expected FingerprintNeedsConfigure=true after %s changed", tc.name)
		}
		fp1 = fpNext
		if err := WriteCMakeFingerprint(buildDir, fp1); err != nil {
			t.Fatal(err)
		}
	}
}

func TestTerminalSanitizeAndSpinnerWriter(t *testing.T) {
	t.Run("SanitizeTerminalOutput strips ANSI CSI/OSC/DCS/C0/C1 and keeps UTF-8", func(t *testing.T) {
		raw := "ok \x1b[31;1mred\x1b[0m \x1b]0;evil-title\x07\x1bP1$q\x1b\\✓ über 日本語\x00\x7f\u009b2J\u009d0;c1\x9c\t\n"
		got := SanitizeTerminalOutput(raw)
		want := "ok red ✓ über 日本語\t\n"
		if got != want {
			t.Fatalf("SanitizeTerminalOutput mismatch:\ngot:  %q\nwant: %q", got, want)
		}

		// Invalid raw C1 byte 0x9B without UTF-8 prefix must be stripped cleanly.
		rawBadByte := "safe" + string([]byte{0x9B}) + "[31mdone"
		if gotBad := SanitizeTerminalOutput(rawBadByte); gotBad != "safe[31mdone" {
			t.Fatalf("expected raw invalid 0x9B dropped, got %q", gotBad)
		}
	})

	t.Run("SpinnerWriter buffers partial chunks and UTF-8 across writes", func(t *testing.T) {
		sp := ui.NewSpinner("Building...")
		sp.Start()
		defer sp.Stop()
		sw := NewSpinnerWriter(sp)

		msg := "compiling \x1b[32m✓\x1b[0m driver\n"
		if _, err := sw.Write([]byte(msg[:12])); err != nil {
			t.Fatal(err)
		}
		if _, err := sw.Write([]byte(msg[12:])); err != nil {
			t.Fatal(err)
		}
		if _, err := sw.Write([]byte("tail-without-newline")); err != nil {
			t.Fatal(err)
		}
		sw.Flush()
	})

	t.Run("RingBuffer wraps with slice copy preserving chronological order", func(t *testing.T) {
		rb := NewRingBuffer(5)
		_, _ = rb.Write([]byte("abc"))
		_, _ = rb.Write([]byte("defgh"))
		if got := rb.String(); got != "defgh" {
			t.Fatalf("expected trailing 5 bytes 'defgh', got %q", got)
		}
		_, _ = rb.Write([]byte("ij"))
		if got := rb.String(); got != "fghij" {
			t.Fatalf("expected wrapped bytes 'fghij', got %q", got)
		}
	})
}

func TestResolveRegistryOverrideAndBuildToolEnv(t *testing.T) {
	root := t.TempDir()
	localReg := filepath.Join(root, "local-reg")
	if err := os.MkdirAll(localReg, 0o750); err != nil {
		t.Fatal(err)
	}

	if _, _, err := ResolveRegistryOverride("http://localhost:8080", root, false); err == nil {
		t.Fatal("expected http:// registry to fail outside --dev")
	}
	if _, _, err := ResolveRegistryOverride("./local-reg", root, false); err == nil {
		t.Fatal("expected relative registry path to fail outside --dev")
	}
	if _, _, err := ResolveRegistryOverride("file://"+filepath.ToSlash(localReg), root, false); err == nil {
		t.Fatal("expected file:// registry to fail outside --dev")
	}

	remote, _, err := ResolveRegistryOverride("https://registry.toobboot.dev", root, false)
	if err != nil || remote != "https://registry.toobboot.dev" {
		t.Fatalf("expected https:// override to succeed outside --dev, got (%q, %v)", remote, err)
	}

	_, localResolved, err := ResolveRegistryOverride("./local-reg", root, true)
	if err != nil || filepath.Clean(localResolved) != filepath.Clean(localReg) {
		t.Fatalf("expected relative registry in --dev to resolve to %s, got (%q, %v)", localReg, localResolved, err)
	}

	origPath := os.Getenv("PATH")
	env := FindBuildToolsEnv(t.Context(), []string{"PATH=" + origPath})
	if len(env) == 0 {
		t.Fatal("expected non-empty environment slice")
	}
	if os.Getenv("PATH") != origPath {
		t.Fatal("FindBuildToolsEnv mutated process-global PATH")
	}
}

func TestRunPostLinkGatesFailClosed(t *testing.T) {
	if _, err := RunPostLinkGates(PostLinkGateOptions{}); err == nil {
		t.Fatal("expected empty PostLinkGateOptions to fail")
	}

	buildDir := t.TempDir()
	_, err := RunPostLinkGates(PostLinkGateOptions{
		BuildDir: buildDir,
		Plan:     &resolve.Plan{},
		ManifestResult: &manifest.Result{
			Layout: &manifest.PartitionLayout{
				Stage0: build.PartitionSlot{Budget: 4096},
			},
		},
	})
	if err == nil {
		t.Fatal("expected missing toob_stage0 ELF to fail post-link gates")
	}

	// Verify stageFlashBoundsAndForbidden wires FlashBounds and ForbiddenFlashRegions cleanly.
	layout := &manifest.PartitionLayout{
		FlashBase: 0x08000000,
		Stage0:    build.PartitionSlot{Name: "Stage0", Addr: 0x08000000, Budget: 0x8000},
		Stage1A:   build.PartitionSlot{Name: "Stage1A", Addr: 0x08008000, Budget: 0x8000},
		Wal:       build.PartitionSlot{Name: "WAL", Addr: 0x08010000, Budget: 0x4000},
		App:       build.PartitionSlot{Name: "App", Addr: 0x08020000, Budget: 0x40000},
	}
	fb, forb := stageFlashBoundsAndForbidden(layout, nil, "stage1a")
	if fb == nil || fb.Base != 0x08008000 || fb.Size != 0x8000 {
		t.Fatalf("unexpected Stage1A FlashBounds: %+v", fb)
	}
	if len(forb) < 3 {
		t.Fatalf("expected Stage0, WAL, App in ForbiddenFlashRegions, got %+v", forb)
	}
}

func makeCoreSDKTarGz(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gzw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gzw)

	for name, content := range files {
		hdr := &tar.Header{
			Name: name,
			Mode: 0o644,
			Size: int64(len(content)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func buildFakeCompilerBinary(t *testing.T, baseName string) string {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join(dir, "main.go")
	exeName := baseName
	if runtime.GOOS == "windows" {
		exeName += ".exe"
	}
	outExe := filepath.Join(dir, exeName)

	code := `package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Println(os.Getenv("TOOB_FAKE_GCC_VERSION"))
}
`
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module fakecompiler\n\ngo 1.21\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src, []byte(code), 0o600); err != nil {
		t.Fatal(err)
	}
	// #nosec G204 -- building test helper binary in isolated t.TempDir().
	cmd := exec.CommandContext(t.Context(), "go", "build", "-o", outExe, ".")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to compile fake compiler binary: %v\n%s", err, string(out))
	}
	return outExe
}

func TestLookupExecutableInEnv(t *testing.T) {
	tmpDir := t.TempDir()
	exeName := "cmake"
	if runtime.GOOS == "windows" {
		exeName += ".exe"
	}
	wantPath := filepath.Join(tmpDir, exeName)
	if err := os.WriteFile(wantPath, []byte("stub"), 0o600); err != nil {
		t.Fatal(err)
	}

	env := []string{"PATH=" + tmpDir}
	if !hasExecutableInEnv(env, "cmake") {
		t.Fatalf("expected hasExecutableInEnv to locate %s in custom PATH", exeName)
	}
	gotPath, ok := lookupExecutableInEnv(env, "cmake")
	if !ok || filepath.Clean(gotPath) != filepath.Clean(wantPath) {
		t.Fatalf("lookupExecutableInEnv = (%q, %v), want (%q, true)", gotPath, ok, wantPath)
	}
	if missingPath, missingOK := lookupExecutableInEnv(env, "nonexistent-tool"); missingOK || missingPath != "nonexistent-tool" {
		t.Fatalf("expected fallback for missing binary, got (%q, %v)", missingPath, missingOK)
	}
}

func TestStage1UsesGeneratedFlashLDAndIRAMBounds(t *testing.T) {
	dir := t.TempDir()
	xipLD := filepath.Join(dir, "xip_stage1.ld")
	if err := os.WriteFile(xipLD, []byte("/* XIP wrapper */\nINCLUDE flash_layout.ld\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	iramLD := filepath.Join(dir, "esp32c6_stage1.ld")
	if err := os.WriteFile(iramLD, []byte("MEMORY { iram (rwx) : ORIGIN = 0x40810000, LENGTH = 0x6C000 }\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if !stage1UsesGeneratedFlashLD(&resolve.Plan{}) {
		t.Fatal("expected nil/empty ChipLinker to default to generated flash_layout.ld")
	}
	if !stage1UsesGeneratedFlashLD(&resolve.Plan{ChipLinker: xipLD}) {
		t.Fatal("expected INCLUDE flash_layout.ld wrapper to return true")
	}
	if stage1UsesGeneratedFlashLD(&resolve.Plan{ChipLinker: iramLD}) {
		t.Fatal("expected custom IRAM linker script without flash_layout.ld to return false")
	}

	hw := &manifest.HardwareJson{
		Memory: build.MemorySpec{
			IramBase: "0x40800000",
			IramSize: "0x7C000",
		},
	}
	reg := iramMemoryRegion(hw)
	if reg == nil || reg.Base != 0x40800000 || reg.Size != 0x7C000 || reg.End() != 0x4087C000 {
		t.Fatalf("unexpected iramMemoryRegion: %+v", reg)
	}
}
