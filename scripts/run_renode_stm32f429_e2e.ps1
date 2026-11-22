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

    $BuildDir = "test\renode_stm32f429\builds\build_stm32f429"
    $CacheFile = Join-Path $BuildDir "CMakeCache.txt"
    if ((Test-Path $CacheFile) -and -not (Select-String -Path $CacheFile -Pattern "-fno-short-enums" -Quiet)) {
        Remove-Item -Recurse -Force $BuildDir -ErrorAction SilentlyContinue
    }

    Write-Host "=== [1/4] Building STMicroelectronics STM32F429 Bootloader + Recovery OS (production profile) ==="
    Remove-Item -Force "$BuildDir\toob_recovery*" -ErrorAction SilentlyContinue
    & $ToobExe build --manifest "test\renode_stm32f429\device.toml" --build-dir $BuildDir --profile production --native --dev --skip-checks
    if ($LASTEXITCODE -ne 0) { throw "toob build failed" }

    & $ToobExe elfaudit "$BuildDir\toob_stage0" --profile production --hardware "toob-infra\registry\packages\chips\stm32f429\hardware.json" --budget 65536
    if ($LASTEXITCODE -ne 0) { throw "Stage 0 elfaudit failed" }
    & $ToobExe elfaudit "$BuildDir\toob_stage1" --profile production --hardware "toob-infra\registry\packages\chips\stm32f429\hardware.json" --budget 131072
    if ($LASTEXITCODE -ne 0) { throw "Stage 1 elfaudit failed" }
    & $ToobExe elfaudit "$BuildDir\toob_recovery" --profile production --hardware "toob-infra\registry\packages\chips\stm32f429\hardware.json" --budget 131072
    if ($LASTEXITCODE -ne 0) { throw "Recovery OS elfaudit failed" }

    Write-Host "=== [2/4] Signing XIP Stage 1 & Recovery OS (256-Byte SCB->VTOR Entry 0x100) ==="
    & $ToobExe sign stage1 "$BuildDir\toob_stage1.bin" --entry 0x100 --mock -o "$BuildDir\toob_stage1.signed.bin"
    if ($LASTEXITCODE -ne 0) { throw "toob sign stage1 failed" }
    & $ToobExe sign image "$BuildDir\toob_recovery.raw.bin" --entry 0x100 -o "$BuildDir\toob_recovery.bin"
    if ($LASTEXITCODE -ne 0) { throw "toob sign recovery failed" }

    Write-Host "=== [3/4] Building Bare-Metal Cortex-M4 sdk/libtoob Guest Apps (v1.0.0, v2.0.0, v3.0.0, bad_v4) ==="
    powershell -ExecutionPolicy Bypass -File "test\renode_stm32f429\guest_app\build_apps.ps1" -ToobCli $ToobExe
    if ($LASTEXITCODE -ne 0) { throw "Guest app build failed" }

    Write-Host "=== [4/4] Running Full-System Headless Renode 1.17.0 STM32F429 E2E Suite ==="
    Push-Location "test\renode_stm32f429"
    try {
        go mod tidy
        if ($LASTEXITCODE -ne 0) { throw "go mod tidy failed" }
        go test -v -count=1 -timeout 240s ./...
        if ($LASTEXITCODE -ne 0) { throw "Renode STM32F429 E2E suite failed" }
    } finally {
        Pop-Location
    }
} finally {
    Pop-Location
}
