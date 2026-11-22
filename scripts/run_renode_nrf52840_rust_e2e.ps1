$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path "$PSScriptRoot\..").Path
Push-Location $RepoRoot
try {
    $CargoExe = "G:\rust\.cargo\bin\cargo.exe"
    if (-not (Test-Path $CargoExe)) {
        $CargoExe = "cargo"
    }

    $env:CARGO_TARGET_DIR = "D:\ToobStorage\cargo_target_sdk"
    $env:TOOB_RUST_APPS_DIR = "D:\ToobStorage\renode_rust_build\apps"

    $BootBuildDir = Join-Path $RepoRoot "test\renode_nrf52840\builds\build_nrf52840"
    foreach ($req in @("toob_stage0.bin", "toob_stage1.signed.bin", "toob_recovery.bin", "generated\generated_boot_config.h")) {
        $fullReq = Join-Path $BootBuildDir $req
        if (-not (Test-Path $fullReq)) {
            throw "Required nRF52840 bootloader artifact missing at $fullReq (build test/renode_nrf52840 first)."
        }
    }

    Write-Host "=== [1/3] Running Rust SDK Host FFI Tests & 32-Bit MCU ABI Checks ==="
    Push-Location "sdk\rust"
    try {
        & $CargoExe test --offline
        if ($LASTEXITCODE -ne 0) { throw "sdk/rust cargo test failed" }

        & $CargoExe check --offline --target thumbv7em-none-eabihf
        if ($LASTEXITCODE -ne 0) { throw "cargo check thumbv7em-none-eabihf failed" }

        & $CargoExe check --offline --target riscv32imac-unknown-none-elf
        if ($LASTEXITCODE -ne 0) { throw "cargo check riscv32imac-unknown-none-elf failed" }
    } finally {
        Pop-Location
    }

    Write-Host "=== [2/3] Building #![no_std] Cortex-M4F Rust Guest Apps (v1.0.0, v2.0.0, v3.0.0, bad_v4) ==="
    powershell -ExecutionPolicy Bypass -File "test\renode_nrf52840_rust\build_rust_apps.ps1" `
        -GeneratedConfigDir "$BootBuildDir\generated" `
        -OutDir $env:TOOB_RUST_APPS_DIR `
        -CargoTargetDir $env:CARGO_TARGET_DIR `
        -CargoExe $CargoExe
    if ($LASTEXITCODE -ne 0) { throw "Rust guest app build failed" }

    Write-Host "=== [3/3] Running Headless Renode 1.17.0 nRF52840 Rust Guest E2E Suite ==="
    Push-Location "test\renode_nrf52840_rust"
    try {
        go mod tidy
        if ($LASTEXITCODE -ne 0) { throw "go mod tidy failed" }
        go test -v -count=1 -timeout 240s ./...
        if ($LASTEXITCODE -ne 0) { throw "Renode nRF52840 Rust E2E suite failed" }
    } finally {
        Pop-Location
    }
} finally {
    Pop-Location
}
