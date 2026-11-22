$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path "$PSScriptRoot\..").Path
Push-Location $RepoRoot
try {
    $WorkRoot = if ($env:TOOB_ESP32_WORK_DIR) { $env:TOOB_ESP32_WORK_DIR } else { "D:\ToobStorage\tmp_build\w3b_esp32" }
    $TmpDir   = Join-Path $WorkRoot "tmp"
    $BuildDir = Join-Path $WorkRoot "build_esp32"
    $AppsDir  = Join-Path $WorkRoot "apps"
    $ConfOut  = Join-Path $WorkRoot "conformance_report.json"

    New-Item -ItemType Directory -Force -Path $TmpDir | Out-Null
    $env:TOOB_ESP32_WORK_DIR = $WorkRoot
    $env:TEMP                = $TmpDir
    $env:TMP                 = $TmpDir
    $env:GOTMPDIR            = $TmpDir
    $env:GOCACHE             = "D:\ToobStorage\go_cache"
    $env:TOOB_REGISTRY_DIR   = Join-Path $RepoRoot "toob-infra\registry\packages"

    $ToobExe = if ($env:TOOB_CLI_BIN -and (Test-Path $env:TOOB_CLI_BIN)) {
        $env:TOOB_CLI_BIN
    } elseif (Test-Path (Join-Path $RepoRoot "toob.exe")) {
        Join-Path $RepoRoot "toob.exe"
    } elseif (Test-Path (Join-Path $RepoRoot "cli\toob-cli\toob.exe")) {
        Join-Path $RepoRoot "cli\toob-cli\toob.exe"
    } elseif (Test-Path "D:\ToobStorage\linux_tools\toob.cmd") {
        "D:\ToobStorage\linux_tools\toob.cmd"
    } else {
        throw "toob CLI not found (set TOOB_CLI_BIN or install D:\ToobStorage\linux_tools\toob.cmd)"
    }
    $Cli = $ToobExe
    $IsDockerCli = $Cli.ToLowerInvariant().EndsWith(".cmd")

    function Invoke-ToobCli {
        param([string[]]$CliArgs)
        for ($attempt = 1; $attempt -le 3; $attempt++) {
            & $Cli @CliArgs
            if ($LASTEXITCODE -eq 0) {
                return 0
            }
            if (-not $IsDockerCli -or $attempt -eq 3) {
                return $LASTEXITCODE
            }
            Start-Sleep -Seconds 2
        }
        return 1
    }

    $GccDir = "G:\Espressif\tools\xtensa-esp-elf\esp-15.2.0_20251204\xtensa-esp-elf\bin"
    if (-not (Test-Path $GccDir)) {
        $GccDir = "$env:USERPROFILE\.toob\toolchains\xtensa-esp32-elf\esp-15.2.0_20251204\xtensa-esp-elf\bin"
    }
    if (-not (Test-Path $GccDir)) {
        throw "xtensa-esp32-elf toolchain not found at $GccDir"
    }

    if (-not $env:TOOB_QEMU_XTENSA) {
        $DefaultQemu = "D:\ToobStorage\tools\qemu-esp-xtensa\qemu\bin\qemu-system-xtensa.exe"
        if (Test-Path $DefaultQemu) {
            $env:TOOB_QEMU_XTENSA = $DefaultQemu
        }
    }

    Write-Host "=== [0/4] Running HAL Conformance Audit across chips/esp32 + 9 esp32_* Drivers (10/10) ==="
    $Packages = @(
        "toob-infra\registry\packages\chips\esp32",
        "toob-infra\registry\packages\drivers\uart\esp32_uart",
        "toob-infra\registry\packages\drivers\flash\esp32_rom_spi",
        "toob-infra\registry\packages\drivers\wdt\esp32_timg_wdt",
        "toob-infra\registry\packages\drivers\rtc\esp32_rtc_mem",
        "toob-infra\registry\packages\drivers\clock\esp32_rtc_cntl",
        "toob-infra\registry\packages\drivers\slot\esp32_dport_mmu",
        "toob-infra\registry\packages\drivers\keystore\esp32_efuse_v1",
        "toob-infra\registry\packages\drivers\entropy\esp32_trng",
        "toob-infra\registry\packages\drivers\power\esp32_soc"
    )
    $Reports = @()
    foreach ($Pkg in $Packages) {
        $PkgJson = Join-Path $Pkg "conformance_report.json"
        $PkgMd   = Join-Path $Pkg "conformance_report.md"
        $ExitCode = 1
        try {
            $ExitCode = Invoke-ToobCli -CliArgs @("conformance", $Pkg)
            if (Test-Path $PkgJson) {
                $Reports += (Get-Content -Raw $PkgJson | ConvertFrom-Json)
            }
        } finally {
            if (Test-Path $PkgJson) {
                Remove-Item -Force $PkgJson -ErrorAction SilentlyContinue
            }
            if (Test-Path $PkgMd) {
                Remove-Item -Force $PkgMd -ErrorAction SilentlyContinue
            }
        }
        if ($ExitCode -ne 0) {
            throw "HAL conformance failed for $Pkg"
        }
    }
    $Reports | ConvertTo-Json -Depth 10 | Set-Content -Encoding UTF8 $ConfOut

    Write-Host "=== [1/4] Building ESP32 Bootloader + Recovery OS (production profile) ==="
    $CacheFile = Join-Path $BuildDir "CMakeCache.txt"
    $NinjaFile = Join-Path $BuildDir "build.ninja"
    if (Test-Path $CacheFile) {
        $CacheText = Get-Content -Raw $CacheFile
        $StaleNinja = (Test-Path $NinjaFile) -and ((Get-Content -Raw $NinjaFile) -match 'recovery_layout\.ld')
        if ($StaleNinja -or ($IsDockerCli -and (($CacheText -match '[A-Za-z]:/') -or ($CacheText -match '/root/\.toob/'))) -or ((-not $IsDockerCli) -and (($CacheText -match '/mnt/d/') -or ($CacheText -match '/root/\.toob/')))) {
            Remove-Item -Recurse -Force $BuildDir -ErrorAction SilentlyContinue
        }
    }
    Remove-Item -Force "$BuildDir\toob_recovery*" -ErrorAction SilentlyContinue
    $DockerGccDir = "D:\ToobStorage\linux_tools\xtensa-esp-elf\bin"
    if ($IsDockerCli -and (Test-Path $DockerGccDir)) {
        $ExitCode = Invoke-ToobCli -CliArgs @("build", "--manifest", "test\qemu_esp32\device.toml", "--build-dir", $BuildDir, "--toolchain-path", $DockerGccDir, "--profile", "production", "--native", "--dev", "--skip-checks")
    } elseif ($IsDockerCli) {
        $ExitCode = Invoke-ToobCli -CliArgs @("build", "--manifest", "test\qemu_esp32\device.toml", "--build-dir", $BuildDir, "--profile", "production", "--native", "--dev", "--skip-checks")
    } else {
        $ExitCode = Invoke-ToobCli -CliArgs @("build", "--manifest", "test\qemu_esp32\device.toml", "--build-dir", $BuildDir, "--toolchain-path", $GccDir, "--profile", "production", "--native", "--dev", "--skip-checks")
    }
    if ($ExitCode -ne 0) { throw "toob build failed" }

    $HwJson = "toob-infra\registry\packages\chips\esp32\hardware.json"
    if ((Invoke-ToobCli -CliArgs @("elfaudit", "$BuildDir\toob_stage0", "--profile", "production", "--hardware", $HwJson, "--budget", "61440")) -ne 0) {
        throw "toob elfaudit stage0 failed"
    }
    if ((Invoke-ToobCli -CliArgs @("elfaudit", "$BuildDir\toob_stage1", "--profile", "production", "--hardware", $HwJson, "--budget", "131072")) -ne 0) {
        throw "toob elfaudit stage1 failed"
    }
    if ((Invoke-ToobCli -CliArgs @("elfaudit", "$BuildDir\toob_recovery", "--profile", "production", "--hardware", $HwJson, "--budget", "65536")) -ne 0) {
        throw "toob elfaudit recovery failed"
    }

    Write-Host "=== [2/4] Packing ESP32 Mask-ROM Stage 0 (0x1000) & Ed25519-Signed Stage 1 (0x40090000) ==="
    if ((Invoke-ToobCli -CliArgs @("sign", "stage0", "$BuildDir\toob_stage0", "--chip", "esp32", "-o", "$BuildDir\toob_stage0.esp.bin")) -ne 0) {
        throw "toob sign stage0 failed"
    }
    if ((Invoke-ToobCli -CliArgs @("sign", "stage1", "$BuildDir\toob_stage1.bin", "--entry", "0x40090000", "--mock", "-o", "$BuildDir\toob_stage1.signed.bin")) -ne 0) {
        throw "toob sign stage1 failed"
    }

    Write-Host "=== [3/4] Building Bare-Metal Split IROM/DROM sdk/libtoob Guest Apps (v1, v2, v3, bad_v4) ==="
    & (Join-Path $RepoRoot "test\qemu_esp32\guest_app\build_apps.ps1") -BuildDir $BuildDir -OutDir $AppsDir -GccDir $GccDir -ToobCli $Cli

    Write-Host "=== [4/4] Running Full-System Headless QEMU (-M esp32) E2E Suite ==="
    Push-Location "test\qemu_esp32"
    try {
        go mod tidy
        if ($LASTEXITCODE -ne 0) { throw "go mod tidy failed" }
        go test -v -count=1 -timeout 360s ./...
        if ($LASTEXITCODE -ne 0) { throw "QEMU ESP32 E2E suite failed" }
    } finally {
        Pop-Location
    }
} finally {
    Pop-Location
}
