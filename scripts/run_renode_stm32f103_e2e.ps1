$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path "$PSScriptRoot\..").Path
Push-Location $RepoRoot
try {
    $WorkRoot = "D:\ToobStorage\tmp_build\w3c_stm32f103"
    if (Test-Path "D:\ToobStorage") {
        New-Item -ItemType Directory -Force -Path "D:\ToobStorage\go_cache", $WorkRoot | Out-Null
        $env:GOCACHE  = "D:\ToobStorage\go_cache"
        $env:GOTMPDIR = "D:\ToobStorage\tmp_build\w3c_stm32f103"
        $env:TEMP     = "D:\ToobStorage\tmp_build\w3c_stm32f103"
        $env:TMP      = $env:TEMP
    } else {
        $WorkRoot     = Join-Path $env:TEMP "w3c_stm32f103"
        New-Item -ItemType Directory -Force -Path $WorkRoot | Out-Null
        $env:GOTMPDIR = $WorkRoot
        $env:TEMP     = $WorkRoot
        $env:TMP      = $env:TEMP
    }
    $BuildDir  = Join-Path $WorkRoot "build_stm32f103"
    $AppsDir   = Join-Path $BuildDir "apps"
    $ConfDir   = Join-Path $WorkRoot "conformance_reports"
    $E2eTmpDir = Join-Path $WorkRoot "e2e_runs"

    foreach ($d in @($WorkRoot, $BuildDir, $AppsDir, $ConfDir, $E2eTmpDir)) {
        New-Item -ItemType Directory -Force -Path $d | Out-Null
    }

    $env:TOOB_REGISTRY_DIR = Join-Path $RepoRoot "toob-infra\registry\packages"
    $env:CFLAGS            = "-fno-short-enums"
    $env:LDFLAGS           = "-Wl,--no-enum-size-warning"

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
    if (-not $ToobExe) {
        throw "toob CLI not found (set TOOB_CLI_BIN, place toob.exe at repository root, or provide D:\ToobStorage\linux_tools\toob.cmd)"
    }

    $GccBin = "D:\ToobStorage\toolchains\arm-none-eabi\15.2.1-1.1\xpack-arm-none-eabi-gcc-15.2.1-1.1\bin"
    if (Test-Path $GccBin) {
        $env:PATH = "$GccBin;$env:PATH"
    }

    Write-Host "=== [1/5] Running 9/9 Package Conformance Gate (chips/stm32f103 + 8 stm32f1_* drivers) ==="
    $Packages = @(
        "toob-infra\registry\packages\chips\stm32f103",
        "toob-infra\registry\packages\drivers\uart\stm32f1_usart",
        "toob-infra\registry\packages\drivers\flash\stm32f1_fpec_flash",
        "toob-infra\registry\packages\drivers\wdt\stm32f1_iwdg",
        "toob-infra\registry\packages\drivers\rtc\stm32f1_bkp",
        "toob-infra\registry\packages\drivers\clock\stm32f1_rcc_csr",
        "toob-infra\registry\packages\drivers\keystore\stm32f1_opt_key",
        "toob-infra\registry\packages\drivers\entropy\stm32f1_adc_rng",
        "toob-infra\registry\packages\drivers\power\stm32f1_soc"
    )
    $ConfHelp = (& $ToobExe conformance --help 2>&1) | Out-String
    $HasOutFlag = $ConfHelp -match "--out"

    foreach ($pkg in $Packages) {
        $leaf = Split-Path $pkg -Leaf
        $outJson = if ($leaf -eq "stm32f103") {
            Join-Path $WorkRoot "conformance_report.json"
        } else {
            Join-Path $ConfDir "$leaf.conformance_report.json"
        }

        if ($HasOutFlag) {
            & $ToobExe conformance $pkg --out $outJson
        } else {
            & $ToobExe conformance $pkg
        }
        if ($LASTEXITCODE -ne 0) {
            throw "toob conformance failed for $pkg"
        }

        $pkgJson = Join-Path $pkg "conformance_report.json"
        $pkgMd   = Join-Path $pkg "conformance_report.md"
        if (Test-Path $pkgJson) {
            if (-not $HasOutFlag) {
                Copy-Item -Force $pkgJson $outJson
            }
            Move-Item -Force $pkgJson (Join-Path $ConfDir "$leaf.conformance_report.json")
        }
        if (Test-Path $pkgMd) {
            Move-Item -Force $pkgMd (Join-Path $ConfDir "$leaf.conformance_report.md")
        }
        Remove-Item -Force (Join-Path $pkg "conformance_report.*") -ErrorAction SilentlyContinue
    }

    Write-Host "=== [2/5] Building STMicroelectronics STM32F103 (Cortex-M3, 1 KB/16-Bit FPEC) Bootloader + Recovery OS ==="
    $CacheFile = Join-Path $BuildDir "CMakeCache.txt"
    $IsLinuxDockerCli = ($ToobExe -like "*.cmd")
    if (Test-Path $CacheFile) {
        $HasShortEnums = Select-String -Path $CacheFile -Pattern "-fno-short-enums" -Quiet
        $HasContainerPath = Select-String -Path $CacheFile -Pattern "/workspace" -Quiet
        if ((-not $HasShortEnums) -or ($IsLinuxDockerCli -xor $HasContainerPath)) {
            Remove-Item -Recurse -Force $BuildDir -ErrorAction SilentlyContinue
            New-Item -ItemType Directory -Force -Path $BuildDir, $AppsDir | Out-Null
        }
    }
    Remove-Item -Force "$BuildDir\toob_recovery*" -ErrorAction SilentlyContinue
    & $ToobExe build --manifest "test\renode_stm32f103\device.toml" --build-dir $BuildDir --profile production --native --dev --skip-checks
    if ($LASTEXITCODE -ne 0) { throw "toob build failed" }

    Write-Host "=== [3/5] Running 3/3 Production ELF Audit Gate (Stage 0, Stage 1, Recovery OS) ==="
    & $ToobExe elfaudit "$BuildDir\toob_stage0" --profile production --hardware "toob-infra\registry\packages\chips\stm32f103\hardware.json" --budget 32768
    if ($LASTEXITCODE -ne 0) { throw "Stage 0 elfaudit failed" }
    & $ToobExe elfaudit "$BuildDir\toob_stage1" --profile production --hardware "toob-infra\registry\packages\chips\stm32f103\hardware.json" --budget 81920
    if ($LASTEXITCODE -ne 0) { throw "Stage 1 elfaudit failed" }
    & $ToobExe elfaudit "$BuildDir\toob_recovery" --profile production --hardware "toob-infra\registry\packages\chips\stm32f103\hardware.json" --budget 24576
    if ($LASTEXITCODE -ne 0) { throw "Recovery OS elfaudit failed" }

    Write-Host "=== [4/5] Signing XIP Stage 1 & Recovery OS (256-Byte Header, Cortex-M3 VTOR Entry 0x100) + Guest Apps ==="
    & $ToobExe sign stage1 "$BuildDir\toob_stage1.bin" --entry 0x100 --mock -o "$BuildDir\toob_stage1.signed.bin"
    if ($LASTEXITCODE -ne 0) { throw "toob sign stage1 failed" }
    & $ToobExe sign image "$BuildDir\toob_recovery.raw.bin" --entry 0x100 --mock -o "$BuildDir\toob_recovery.bin"
    if ($LASTEXITCODE -ne 0) { throw "toob sign recovery failed" }

    powershell -ExecutionPolicy Bypass -File "test\renode_stm32f103\guest_app\build_apps.ps1" -BuildDir $BuildDir -OutDir $AppsDir -ToobCli $ToobExe
    if ($LASTEXITCODE -ne 0) { throw "Guest app build failed" }

    Write-Host "=== [5/5] Running Full-System Headless Renode 1.17.0 STM32F103 (Cortex-M3, 1 KB FPEC, BKP->DR1..DR4) E2E Suite ==="
    $env:TOOB_STM32F103_BUILD_DIR = $BuildDir
    $env:TOOB_STM32F103_APPS_DIR  = $AppsDir
    $env:TOOB_STM32F103_TMP_ROOT  = $E2eTmpDir

    Push-Location "test\renode_stm32f103"
    try {
        go mod tidy
        if ($LASTEXITCODE -ne 0) { throw "go mod tidy failed" }
        go test -v -count=1 -timeout 1500s ./...
        if ($LASTEXITCODE -ne 0) { throw "Renode STM32F103 E2E suite failed" }
    } finally {
        Pop-Location
    }
} finally {
    Pop-Location
}
