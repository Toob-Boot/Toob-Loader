$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path "$PSScriptRoot\..").Path
Push-Location $RepoRoot
try {
    $env:TOOB_REGISTRY_DIR = Join-Path $RepoRoot "toob-infra\registry\packages"
    $env:CFLAGS  = "-fno-short-enums"
    $env:LDFLAGS = "-Wl,--no-enum-size-warning"

    if (-not $env:TOOB_RENODE_BIN) {
        $RenodeCandidates = @(
            "$env:USERPROFILE\.toob\tools\renode\renode_1.17.0-portable\Renode.exe",
            "D:\ToobStorage\tools\renode-1.17.0\renode_1.17.0-portable\Renode.exe",
            "D:\ToobStorage\tools\renode\renode_1.17.0_portable\Renode.exe"
        )
        foreach ($cand in $RenodeCandidates) {
            if (Test-Path $cand) {
                $env:TOOB_RENODE_BIN = $cand
                break
            }
        }
    }

    if (Test-Path "D:\ToobStorage") {
        $HeavyTmp = "D:\ToobStorage\tmp_rp2040_go"
        New-Item -ItemType Directory -Force -Path $HeavyTmp | Out-Null
        $env:GOTMPDIR = $HeavyTmp
    }

    $BuildDir = "test\renode_rp2040\builds\build_rp2040"
    $CacheFile = Join-Path $BuildDir "CMakeCache.txt"
    if ((Test-Path $CacheFile) -and -not (Select-String -Path $CacheFile -Pattern "-fno-short-enums" -Quiet)) {
        Remove-Item -Recurse -Force $BuildDir -ErrorAction SilentlyContinue
    }

    Write-Host "=== [1/4] Building Raspberry Pi RP2040 Bootloader + Recovery OS (production profile) ==="
    Remove-Item -Force "$BuildDir\toob_recovery*" -ErrorAction SilentlyContinue
    .\toob.exe build --manifest "test\renode_rp2040\device.toml" --build-dir $BuildDir --profile production --native --dev --skip-checks
    if ($LASTEXITCODE -ne 0) { throw "toob build failed" }

    .\toob.exe elfaudit "$BuildDir\toob_stage0" --profile production --hardware "toob-infra\registry\packages\chips\rp2040\hardware.json" --budget 32768
    if ($LASTEXITCODE -ne 0) { throw "Stage 0 elfaudit failed" }
    .\toob.exe elfaudit "$BuildDir\toob_stage1" --profile production --hardware "toob-infra\registry\packages\chips\rp2040\hardware.json" --budget 98304
    if ($LASTEXITCODE -ne 0) { throw "Stage 1 elfaudit failed" }
    .\toob.exe elfaudit "$BuildDir\toob_recovery" --profile production --hardware "toob-infra\registry\packages\chips\rp2040\hardware.json" --budget 65536
    if ($LASTEXITCODE -ne 0) { throw "Recovery OS elfaudit failed" }

    Write-Host "=== [2/4] Packing RP2040 Stage 0 boot2 (MPEG-2 CRC-32) & Signing XIP Stage 1 / Recovery OS ==="
    .\toob.exe sign stage0 "$BuildDir\toob_stage0" --chip rp2040 -o "$BuildDir\toob_stage0_boot2.bin"
    if ($LASTEXITCODE -ne 0) { throw "toob sign stage0 failed" }
    .\toob.exe sign stage1 "$BuildDir\toob_stage1.bin" --entry 0x100 --mock -o "$BuildDir\toob_stage1.signed.bin"
    if ($LASTEXITCODE -ne 0) { throw "toob sign stage1 failed" }
    .\toob.exe sign image "$BuildDir\toob_recovery.raw.bin" --entry 0x100 --mock -o "$BuildDir\toob_recovery.bin"
    if ($LASTEXITCODE -ne 0) { throw "toob sign recovery failed" }

    Write-Host "=== [3/4] Building Bare-Metal Cortex-M0+ sdk/libtoob Guest Apps (v1.0.0, v2.0.0, v3.0.0, bad_v4) ==="
    powershell -ExecutionPolicy Bypass -File "test\renode_rp2040\guest_app\build_apps.ps1"
    if ($LASTEXITCODE -ne 0) { throw "Guest app build failed" }

    Write-Host "=== [4/4] Running Full-System Headless Renode 1.17.0 RP2040 Dual Cortex-M0+ E2E Suite ==="
    Push-Location "test\renode_rp2040"
    try {
        go mod tidy
        if ($LASTEXITCODE -ne 0) { throw "go mod tidy failed" }
        go test -v -count=1 -timeout 300s ./...
        if ($LASTEXITCODE -ne 0) { throw "Renode RP2040 E2E suite failed" }
    } finally {
        Pop-Location
    }
} finally {
    Pop-Location
}

