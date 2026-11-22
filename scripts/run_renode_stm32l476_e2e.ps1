$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path "$PSScriptRoot\..").Path
Push-Location $RepoRoot
try {
    $env:TOOB_REGISTRY_DIR = Join-Path $RepoRoot "toob-infra\registry\packages"
    $env:CFLAGS  = "-fno-short-enums"
    $env:LDFLAGS = "-Wl,--no-enum-size-warning"

    if ($env:TOOB_CLI_BIN -and (Test-Path $env:TOOB_CLI_BIN)) {
        $ToobExe = (Resolve-Path $env:TOOB_CLI_BIN).Path
    } else {
        $ToobExe = Join-Path $RepoRoot "toob.exe"
        if (Test-Path (Join-Path $RepoRoot "cli\toob-cli\toob.exe")) {
            $CliCandidate = Get-Item (Join-Path $RepoRoot "cli\toob-cli\toob.exe")
            if ((-not (Test-Path $ToobExe)) -or ($CliCandidate.LastWriteTimeUtc -gt (Get-Item $ToobExe).LastWriteTimeUtc)) {
                $ToobExe = $CliCandidate.FullName
            }
        }
    }

    if (Test-Path "D:\ToobStorage") {
        $BuildDir = "D:\ToobStorage\tmp_build\stm32l476_work\build_stm32l476"
    } else {
        $BuildDir = Join-Path $RepoRoot "test\renode_stm32l476\builds\build_stm32l476"
    }
    $AppsDir = Join-Path $BuildDir "apps"
    $env:TOOB_STM32L476_BUILD_DIR = $BuildDir
    $env:TOOB_STM32L476_APPS_DIR  = $AppsDir

    if (-not $env:TOOB_RENODE_BIN) {
        $RenodeCandidates = @(
            "D:\ToobStorage\tools\renode-1.17.0\renode_1.17.0-portable\Renode.exe",
            "D:\ToobStorage\tools\renode\renode_1.17.0_portable\Renode.exe",
            "$env:USERPROFILE\.toob\tools\renode\renode_1.17.0-portable\renode.exe"
        )
        foreach ($cand in $RenodeCandidates) {
            if (Test-Path $cand) {
                $env:TOOB_RENODE_BIN = $cand
                break
            }
        }
    }

    $CacheFile = Join-Path $BuildDir "CMakeCache.txt"
    if ((Test-Path $CacheFile) -and -not (Select-String -Path $CacheFile -Pattern "-fno-short-enums" -Quiet)) {
        Remove-Item -Recurse -Force $BuildDir -ErrorAction SilentlyContinue
    }

    Write-Host "=== [1/4] Building STMicroelectronics STM32L476RG Bootloader + Recovery OS (production profile) ==="
    Remove-Item -Force "$BuildDir\toob_recovery*" -ErrorAction SilentlyContinue
    & $ToobExe build --manifest "test\renode_stm32l476\device.toml" --build-dir $BuildDir --profile production --native --dev
    if ($LASTEXITCODE -ne 0) { throw "toob build failed" }

    & $ToobExe elfaudit "$BuildDir\toob_stage0" --profile production --hardware "toob-infra\registry\packages\chips\stm32l476\hardware.json" --budget 32768
    if ($LASTEXITCODE -ne 0) { throw "Stage 0 elfaudit failed" }
    & $ToobExe elfaudit "$BuildDir\toob_stage1" --profile production --hardware "toob-infra\registry\packages\chips\stm32l476\hardware.json" --budget 98304
    if ($LASTEXITCODE -ne 0) { throw "Stage 1 elfaudit failed" }
    & $ToobExe elfaudit "$BuildDir\toob_recovery" --profile production --hardware "toob-infra\registry\packages\chips\stm32l476\hardware.json" --budget 65536
    if ($LASTEXITCODE -ne 0) { throw "Recovery OS elfaudit failed" }

    Write-Host "=== [2/4] Signing XIP Stage 1 & Recovery OS (256-Byte SCB->VTOR Entry 0x100) ==="
    & $ToobExe sign stage1 "$BuildDir\toob_stage1.bin" --entry 0x100 --mock -o "$BuildDir\toob_stage1.signed.bin"
    if ($LASTEXITCODE -ne 0) { throw "toob sign stage1 failed" }
    & $ToobExe sign image "$BuildDir\toob_recovery.raw.bin" --entry 0x100 -o "$BuildDir\toob_recovery.bin"
    if ($LASTEXITCODE -ne 0) { throw "toob sign recovery failed" }

    Write-Host "=== [3/4] Building Bare-Metal Cortex-M4 sdk/libtoob Guest Apps (v1.0.0, v2.0.0, v3.0.0, bad_v4) ==="
    powershell -ExecutionPolicy Bypass -File "test\renode_stm32l476\guest_app\build_apps.ps1" -BuildDir $BuildDir -OutDir $AppsDir -ToobCli $ToobExe
    if ($LASTEXITCODE -ne 0) { throw "Guest app build failed" }

    Write-Host "=== [4/4] Running Full-System Headless Renode 1.17.0 STM32L476RG E2E Suite ==="
    Push-Location "test\renode_stm32l476"
    try {
        go mod tidy
        if ($LASTEXITCODE -ne 0) { throw "go mod tidy failed" }
        go test -v -count=1 -timeout 240s ./...
        if ($LASTEXITCODE -ne 0) { throw "Renode STM32L476 E2E suite failed" }
    } finally {
        Pop-Location
    }
} finally {
    Pop-Location
}

