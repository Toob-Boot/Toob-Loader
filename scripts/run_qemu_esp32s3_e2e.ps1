$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path "$PSScriptRoot\..").Path
Push-Location $RepoRoot
try {
    $env:TOOB_REGISTRY_DIR = Join-Path $RepoRoot "toob-infra\registry\packages"

    Write-Host "=== [1/4] Building ESP32-S3 Bootloader + Recovery OS (production profile) ==="
    Remove-Item -Force "test\qemu_esp32s3\builds\build_esp32s3\toob_recovery*" -ErrorAction SilentlyContinue
    .\toob.exe build --manifest "test\qemu_esp32s3\device.toml" --build-dir "test\qemu_esp32s3\builds\build_esp32s3" --profile production --native --dev --skip-checks
    if ($LASTEXITCODE -ne 0) { throw "toob build failed" }
    .\toob.exe elfaudit "test\qemu_esp32s3\builds\build_esp32s3\toob_stage0" --profile production --hardware "toob-infra\registry\packages\chips\esp32s3\hardware.json" --budget 32768
    if ($LASTEXITCODE -ne 0) { throw "toob elfaudit stage0 failed" }
    .\toob.exe elfaudit "test\qemu_esp32s3\builds\build_esp32s3\toob_stage1" --profile production --hardware "toob-infra\registry\packages\chips\esp32s3\hardware.json" --budget 131072
    if ($LASTEXITCODE -ne 0) { throw "toob elfaudit stage1 failed" }

    Write-Host "=== [2/4] Packing ESP32-S3 Mask-ROM Stage 0 & Ed25519-Signed Stage 1 ==="
    .\toob.exe sign stage0 "test\qemu_esp32s3\builds\build_esp32s3\toob_stage0" --chip esp32s3 -o "test\qemu_esp32s3\builds\build_esp32s3\toob_stage0.esp.bin"
    if ($LASTEXITCODE -ne 0) { throw "toob sign stage0 failed" }
    .\toob.exe sign stage1 "test\qemu_esp32s3\builds\build_esp32s3\toob_stage1.bin" --entry 0x40398000 --mock -o "test\qemu_esp32s3\builds\build_esp32s3\toob_stage1.signed.bin"
    if ($LASTEXITCODE -ne 0) { throw "toob sign stage1 failed" }

    Write-Host "=== [3/4] Building Bare-Metal sdk/libtoob Guest Apps (v1.0.0, v2.0.0, v3.0.0, bad_v4) ==="
    powershell -ExecutionPolicy Bypass -File "test\qemu_esp32s3\guest_app\build_apps.ps1"
    if ($LASTEXITCODE -ne 0) { throw "Guest app build failed" }

    Write-Host "=== [4/4] Running Full-System QEMU ESP32-S3 E2E Suite ==="
    Push-Location "test\qemu_esp32s3"
    try {
        go test -v -count=1 -timeout 240s ./...
        if ($LASTEXITCODE -ne 0) { throw "QEMU E2E suite failed" }
    } finally {
        Pop-Location
    }
} finally {
    Pop-Location
}
