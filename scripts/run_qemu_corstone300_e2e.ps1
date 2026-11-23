$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path "$PSScriptRoot\..").Path
Push-Location $RepoRoot
try {
    $WorkRoot = if (Test-Path "D:\ToobStorage") {
        "D:\ToobStorage\tmp_build\w3d_corstone300"
    } else {
        Join-Path $RepoRoot "test\qemu_corstone300\builds"
    }
    New-Item -ItemType Directory -Force -Path $WorkRoot | Out-Null

    if (Test-Path "D:\ToobStorage") {
        $env:GOCACHE  = "D:\ToobStorage\go_cache"
        $env:GOTMPDIR = "D:\ToobStorage\tmp_build\w3d_corstone300"
        $env:TEMP     = "D:\ToobStorage\tmp_build\w3d_corstone300"
        $env:TMP      = $env:TEMP
    } else {
        New-Item -ItemType Directory -Force -Path "$WorkRoot\tmp", "$WorkRoot\gotmp" | Out-Null
        $env:TEMP     = "$WorkRoot\tmp"
        $env:TMP      = $env:TEMP
        $env:GOTMPDIR = "$WorkRoot\gotmp"
    }
    $env:TOOB_CORSTONE300_BUILD_ROOT = $WorkRoot
    $env:TOOB_REGISTRY_DIR = Join-Path $RepoRoot "toob-infra\registry\packages"
    $env:CFLAGS  = "-fno-short-enums"
    $env:LDFLAGS = "-Wl,--no-enum-size-warning"

    $GccBin = ""
    $GccCandidates = @(
        "D:\ToobStorage\toolchains\arm-none-eabi\15.2.1-1.1\xpack-arm-none-eabi-gcc-15.2.1-1.1\bin",
        (Join-Path $env:USERPROFILE ".toob\toolchains\arm-none-eabi\15.2.1-1.1\xpack-arm-none-eabi-gcc-15.2.1-1.1\bin")
    )
    foreach ($g in $GccCandidates) {
        if (Test-Path (Join-Path $g "arm-none-eabi-gcc.exe")) {
            $GccBin = $g
            $env:PATH = "$g;$env:PATH"
            break
        }
    }

    if (Test-Path "D:\ToobStorage\tools") {
        foreach ($toolSub in (Get-ChildItem "D:\ToobStorage\tools" -Directory -ErrorAction SilentlyContinue)) {
            foreach ($cm in (Get-ChildItem $toolSub.FullName -Recurse -Filter "cmake.exe" -ErrorAction SilentlyContinue)) {
                $env:PATH = "$($cm.DirectoryName);$env:PATH"
            }
            foreach ($nj in (Get-ChildItem $toolSub.FullName -Recurse -Filter "ninja.exe" -ErrorAction SilentlyContinue)) {
                $env:PATH = "$($nj.DirectoryName);$env:PATH"
            }
        }
    }

    if (-not $env:TOOB_QEMU_ARM_BIN) {
        $QemuCandidates = @(
            "D:\ToobStorage\tools\qemu-arm\xpack-qemu-arm-9.2.4-1\bin\qemu-system-arm.exe",
            "D:\ToobStorage\tools\qemu-arm\qemu-system-arm.exe"
        )
        foreach ($qc in $QemuCandidates) {
            if (Test-Path $qc) {
                $env:TOOB_QEMU_ARM_BIN = $qc
                break
            }
        }
    }

    $ToobExe = if ($env:TOOB_CLI_BIN -and (Test-Path $env:TOOB_CLI_BIN)) {
        $env:TOOB_CLI_BIN
    } elseif (Test-Path (Join-Path $RepoRoot "toob.exe")) {
        Join-Path $RepoRoot "toob.exe"
    } elseif (Test-Path (Join-Path $RepoRoot "cli\toob-cli\toob.exe")) {
        Join-Path $RepoRoot "cli\toob-cli\toob.exe"
    } elseif (Test-Path "D:\ToobStorage\linux_tools\toob.cmd") {
        "D:\ToobStorage\linux_tools\toob.cmd"
    } else {
        $null
    }

    function Invoke-Toob([string[]]$CliArgs) {
        if ($ToobExe) {
            & $ToobExe @CliArgs
        } else {
            Push-Location (Join-Path $RepoRoot "cli\toob-cli")
            try {
                & go run . @CliArgs
            } finally {
                Pop-Location
            }
        }
        if ($LASTEXITCODE -ne 0) {
            throw "toob $($CliArgs -join ' ') failed with exit code $LASTEXITCODE"
        }
    }

    Write-Host "=== [1/5] Running LiteralLint & HAL Conformance (9/9 Corstone-300 Packages) ==="
    $Packages = @(
        "chips\corstone300",
        "drivers\uart\corstone300_cmsdk_uart",
        "drivers\flash\corstone300_qspi_flash",
        "drivers\wdt\corstone300_s32k_wdt",
        "drivers\rtc\corstone300_retention",
        "drivers\clock\corstone300_sysctrl_clk",
        "drivers\keystore\corstone300_otp",
        "drivers\entropy\corstone300_trng",
        "drivers\power\corstone300_tz_soc"
    )
    $ConfReports = @()
    foreach ($pkg in $Packages) {
        $pkgAbs = Join-Path $env:TOOB_REGISTRY_DIR $pkg
        try {
            Invoke-Toob @("literallint", $pkgAbs)
            Invoke-Toob @("conformance", $pkgAbs)
        } finally {
            $repJson = Join-Path $pkgAbs "conformance_report.json"
            if (Test-Path $repJson) {
                $ConfReports += (Get-Content -Raw $repJson | ConvertFrom-Json)
                Remove-Item -Force $repJson -ErrorAction SilentlyContinue
            }
            $repMd = Join-Path $pkgAbs "conformance_report.md"
            if (Test-Path $repMd) {
                Remove-Item -Force $repMd -ErrorAction SilentlyContinue
            }
        }
    }
    $ConfOut = Join-Path $WorkRoot "conformance_report.json"
    $ConfReports | ConvertTo-Json -Depth 12 | Set-Content -Encoding UTF8 $ConfOut
    Write-Host "Saved 9/9 conformance reports to $ConfOut"

    $BuildDir    = Join-Path $WorkRoot "build_corstone300"
    $AppsDir     = Join-Path $WorkRoot "apps"
    $ManifestAbs = Join-Path $RepoRoot "test\qemu_corstone300\device.toml"
    $HwJsonAbs   = Join-Path $RepoRoot "toob-infra\registry\packages\chips\corstone300\hardware.json"

    $CacheFile = Join-Path $BuildDir "CMakeCache.txt"
    $IsDockerCli = ($ToobExe -and $ToobExe.EndsWith(".cmd"))
    if (Test-Path $CacheFile) {
        $HasShortEnums = Select-String -Path $CacheFile -Pattern "-fno-short-enums" -Quiet
        $HasLinuxMount = Select-String -Path $CacheFile -Pattern "/mnt/d/" -Quiet
        $HasEphemeralRoot = Select-String -Path $CacheFile -Pattern "/root/\.toob/" -Quiet
        if ((-not $HasShortEnums) -or ($IsDockerCli -and $HasEphemeralRoot) -or ($IsDockerCli -and (-not $HasLinuxMount)) -or ((-not $IsDockerCli) -and $HasLinuxMount)) {
            Remove-Item -Recurse -Force $BuildDir -ErrorAction SilentlyContinue
        }
    }

    Write-Host "=== [2/5] Building ARM Corstone-300 Secure Bootloader + Recovery OS (production profile) ==="
    Remove-Item -Force "$BuildDir\toob_recovery*" -ErrorAction SilentlyContinue
    $BuildArgs = @("build", "--manifest", $ManifestAbs, "--build-dir", $BuildDir, "--profile", "production", "--native", "--dev", "--skip-checks")
    Invoke-Toob $BuildArgs

    Write-Host "=== [3/5] Auditing Stage 0, Stage 1, and Recovery OS Production ELFs ==="
    Invoke-Toob @("elfaudit", "$BuildDir\toob_stage0", "--profile", "production", "--hardware", $HwJsonAbs, "--budget", "65536")
    Invoke-Toob @("elfaudit", "$BuildDir\toob_stage1", "--profile", "production", "--hardware", $HwJsonAbs, "--budget", "131072")
    Invoke-Toob @("elfaudit", "$BuildDir\toob_recovery", "--profile", "production", "--hardware", $HwJsonAbs, "--budget", "131072")

    Write-Host "=== [4/5] Signing Stage 1 & Recovery OS + Building Non-Secure Cortex-M55 Guest Apps ==="
    Invoke-Toob @("sign", "stage1", "$BuildDir\toob_stage1.bin", "--entry", "0x100", "--mock", "-o", "$BuildDir\toob_stage1.signed.bin")
    Invoke-Toob @("sign", "image", "$BuildDir\toob_recovery.raw.bin", "--entry", "0x100", "--mock", "-o", "$BuildDir\toob_recovery.bin")

    & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $RepoRoot "test\qemu_corstone300\guest_app\build_apps.ps1") -BuildDir $BuildDir -OutDir $AppsDir -ToobCli $ToobExe
    if ($LASTEXITCODE -ne 0) { throw "Guest app build failed" }

    Write-Host "=== [5/5] Running Headless QEMU mps3-an547 ARMv8.1-M TrustZone E2E Suite ==="
    Push-Location (Join-Path $RepoRoot "test\qemu_corstone300")
    try {
        & go mod tidy
        if ($LASTEXITCODE -ne 0) { throw "go mod tidy failed" }
        & go test -v -count=1 -timeout 300s ./...
        if ($LASTEXITCODE -ne 0) { throw "QEMU Corstone-300 TrustZone E2E suite failed" }
    } finally {
        Pop-Location
    }
} finally {
    Pop-Location
}
