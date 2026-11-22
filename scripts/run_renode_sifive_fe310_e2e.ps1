$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path "$PSScriptRoot\..").Path
Push-Location $RepoRoot
try {
    $env:TOOB_REGISTRY_DIR = Join-Path $RepoRoot "toob-infra\registry\packages"
    $BuildDir = "test\renode_sifive_fe310\builds\build_sifive_fe310"

    Write-Host "=== [1/4] Building SiFive FE310-G002 Bootloader + Recovery OS (production profile) ==="
    Remove-Item -Force "$BuildDir\toob_recovery*" -ErrorAction SilentlyContinue
    .\toob.exe build --manifest "test\renode_sifive_fe310\device.toml" --build-dir $BuildDir --profile production --native --dev --skip-checks
    if ($LASTEXITCODE -ne 0) { throw "toob build failed" }

    .\toob.exe elfaudit "$BuildDir\toob_stage0" --profile production --hardware "toob-infra\registry\packages\chips\sifive_fe310\hardware.json" --budget 65536
    if ($LASTEXITCODE -ne 0) { throw "Stage 0 elfaudit failed" }
    .\toob.exe elfaudit "$BuildDir\toob_stage1" --profile production --hardware "toob-infra\registry\packages\chips\sifive_fe310\hardware.json" --budget 131072
    if ($LASTEXITCODE -ne 0) { throw "Stage 1 elfaudit failed" }
    .\toob.exe elfaudit "$BuildDir\toob_recovery" --profile production --hardware "toob-infra\registry\packages\chips\sifive_fe310\hardware.json" --budget 131072
    if ($LASTEXITCODE -ne 0) { throw "Recovery OS elfaudit failed" }

    Write-Host "=== [2/4] Signing SiFive FE310-G002 XIP Stage 1 (--entry 0x14) ==="
    .\toob.exe sign stage1 "$BuildDir\toob_stage1.bin" --entry 0x14 --mock -o "$BuildDir\toob_stage1.signed.bin"
    if ($LASTEXITCODE -ne 0) { throw "toob sign stage1 failed" }

    Write-Host "=== [3/4] Building Bare-Metal sdk/libtoob Guest Apps (v1.0.0, v2.0.0, v3.0.0, bad_v4) ==="
    powershell -ExecutionPolicy Bypass -File "test\renode_sifive_fe310\guest_app\build_apps.ps1"
    if ($LASTEXITCODE -ne 0) { throw "Guest app build failed" }

    Write-Host "=== [4/4] Running Full-System Renode 1.17.0 SiFive FE310-G002 E2E Suite ==="
    Push-Location "test\renode_sifive_fe310"
    try {
        go test -v -count=1 -timeout 240s ./...
        if ($LASTEXITCODE -ne 0) { throw "Renode E2E suite failed" }
    } finally {
        Pop-Location
    }
} finally {
    Pop-Location
}
