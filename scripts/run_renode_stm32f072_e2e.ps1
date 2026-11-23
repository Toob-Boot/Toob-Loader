$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path "$PSScriptRoot\..").Path
Push-Location $RepoRoot
try {
    $env:TOOB_REGISTRY_DIR = Join-Path $RepoRoot "toob-infra\registry\packages"
    $env:CFLAGS  = "-fno-short-enums"
    $env:LDFLAGS = "-Wl,--no-enum-size-warning"

    $ToobExe = Join-Path $RepoRoot "toob.exe"
    if (Test-Path (Join-Path $RepoRoot "cli\toob-cli\toob.exe")) {
        $CliCandidate = Get-Item (Join-Path $RepoRoot "cli\toob-cli\toob.exe")
        if ((-not (Test-Path $ToobExe)) -or ($CliCandidate.LastWriteTimeUtc -gt (Get-Item $ToobExe).LastWriteTimeUtc)) {
            $ToobExe = $CliCandidate.FullName
        }
    }

    # Keep heavy CMake/Ninja object intermediates on D:\ToobStorage to preserve C: free space
    $BuildDir = "D:\ToobStorage\build_stm32f072"
    if (-not (Test-Path "D:\ToobStorage")) {
        $BuildDir = Join-Path $RepoRoot "test\renode_stm32f072\builds\build_stm32f072"
    }
    $CacheFile = Join-Path $BuildDir "CMakeCache.txt"
    if ((Test-Path $CacheFile) -and -not (Select-String -Path $CacheFile -Pattern "-fno-short-enums" -Quiet)) {
        Remove-Item -Recurse -Force $BuildDir -ErrorAction SilentlyContinue
    }

    Write-Host "=== [1/4] Building STMicroelectronics STM32F072 (Cortex-M0 ARMv6-M, No-VTOR) Bootloader + Recovery OS ==="
    Remove-Item -Force "$BuildDir\toob_recovery*" -ErrorAction SilentlyContinue
    & $ToobExe build --manifest "test\renode_stm32f072\device.toml" --build-dir $BuildDir --profile production --native --dev --skip-checks
    if ($LASTEXITCODE -ne 0) { throw "toob build failed" }

    & $ToobExe elfaudit "$BuildDir\toob_stage0" --profile production --hardware "toob-infra\registry\packages\chips\stm32f072\hardware.json" --budget 28672
    if ($LASTEXITCODE -ne 0) { throw "Stage 0 elfaudit failed" }
    & $ToobExe elfaudit "$BuildDir\toob_stage1" --profile production --hardware "toob-infra\registry\packages\chips\stm32f072\hardware.json" --budget 73728
    if ($LASTEXITCODE -ne 0) { throw "Stage 1 elfaudit failed" }
    & $ToobExe elfaudit "$BuildDir\toob_recovery" --profile production --hardware "toob-infra\registry\packages\chips\stm32f072\hardware.json" --budget 20480
    if ($LASTEXITCODE -ne 0) { throw "Recovery OS elfaudit failed" }

    Write-Host "=== [2/4] Signing XIP Stage 1 & Recovery OS (256-Byte Header, ARMv6-M SRAM Vector Remap Entry 0x100) ==="
    & $ToobExe sign stage1 "$BuildDir\toob_stage1.bin" --entry 0x100 --mock -o "$BuildDir\toob_stage1.signed.bin"
    if ($LASTEXITCODE -ne 0) { throw "toob sign stage1 failed" }
    & $ToobExe sign image "$BuildDir\toob_recovery.raw.bin" --entry 0x100 --mock -o "$BuildDir\toob_recovery.bin"
    if ($LASTEXITCODE -ne 0) { throw "toob sign recovery failed" }

    $BootOutDir = Join-Path $RepoRoot "test\renode_stm32f072\builds\boot"
    New-Item -ItemType Directory -Force -Path $BootOutDir | Out-Null
    Copy-Item -Force "$BuildDir\toob_stage0.bin" "$BootOutDir\toob_stage0.bin"
    Copy-Item -Force "$BuildDir\toob_stage1.signed.bin" "$BootOutDir\toob_stage1.signed.bin"
    Copy-Item -Force "$BuildDir\toob_recovery.bin" "$BootOutDir\toob_recovery.bin"

    Write-Host "=== [3/4] Building Bare-Metal Cortex-M0 sdk/libtoob Guest Apps (v1.0.0, v2.0.0, v3.0.0, bad_v4) ==="
    powershell -ExecutionPolicy Bypass -File "test\renode_stm32f072\guest_app\build_apps.ps1" -BuildDir $BuildDir -ToobCli $ToobExe
    if ($LASTEXITCODE -ne 0) { throw "Guest app build failed" }

    Write-Host "=== [4/4] Running Full-System Headless Renode 1.17.0 STM32F072 (Cortex-M0 No-VTOR) E2E Suite ==="
    Push-Location "test\renode_stm32f072"
    try {
        go mod tidy
        if ($LASTEXITCODE -ne 0) { throw "go mod tidy failed" }
        go test -v -count=1 -timeout 300s ./...
        if ($LASTEXITCODE -ne 0) { throw "Renode STM32F072 E2E suite failed" }
    } finally {
        Pop-Location
    }
} finally {
    Pop-Location
}
