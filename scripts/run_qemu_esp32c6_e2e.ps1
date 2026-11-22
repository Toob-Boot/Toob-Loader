$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path "$PSScriptRoot\..").Path
Push-Location $RepoRoot
try {
    $env:TOOB_REGISTRY_DIR = Join-Path $RepoRoot "toob-infra\registry\packages"

    $ToobCli = if ($env:TOOB_CLI_BIN -and (Test-Path $env:TOOB_CLI_BIN)) {
        $env:TOOB_CLI_BIN
    } elseif (Test-Path (Join-Path $RepoRoot "toob.exe")) {
        Join-Path $RepoRoot "toob.exe"
    } elseif (Test-Path (Join-Path $RepoRoot "cli\toob-cli\toob.exe")) {
        Join-Path $RepoRoot "cli\toob-cli\toob.exe"
    } elseif (Test-Path "D:\ToobStorage\linux_tools\toob.cmd") {
        "D:\ToobStorage\linux_tools\toob.cmd"
    } else {
        throw "toob CLI not found (set TOOB_CLI_BIN, place toob.exe in repo root, or install D:\ToobStorage\linux_tools\toob.cmd)"
    }

    $WorkRoot = if ($env:TOOB_ESP32C6_BUILD_ROOT) {
        $env:TOOB_ESP32C6_BUILD_ROOT
    } elseif (Test-Path "D:\ToobStorage") {
        "D:\ToobStorage\tmp_build\w3a_esp32c6\e2e_c6"
    } else {
        Join-Path $RepoRoot "test\qemu_esp32c6\builds"
    }
    New-Item -ItemType Directory -Force -Path "$WorkRoot\tmp" | Out-Null
    $env:TOOB_ESP32C6_BUILD_ROOT = $WorkRoot
    $env:TEMP = "$WorkRoot\tmp"
    $env:TMP = "$WorkRoot\tmp"
    $env:GOTMPDIR = "$WorkRoot\tmp"
    if (-not $env:GOCACHE -and (Test-Path "D:\ToobStorage")) {
        $env:GOCACHE = "D:\ToobStorage\go_cache"
    }

    $BuildDir = Join-Path $WorkRoot "build_esp32c6"
    $AppsDir  = Join-Path $WorkRoot "apps"

    $useDockerCli = $ToobCli.EndsWith(".cmd", [System.StringComparison]::OrdinalIgnoreCase)
    if (Test-Path "$BuildDir\CMakeCache.txt") {
        $cacheRaw = Get-Content "$BuildDir\CMakeCache.txt" -Raw -ErrorAction SilentlyContinue
        if (($useDockerCli -and $cacheRaw -match '[A-Za-z]:/') -or (-not $useDockerCli -and $cacheRaw -match '/workspace/')) {
            Remove-Item -Recurse -Force $BuildDir -ErrorAction SilentlyContinue
        }
    }

    Write-Host "=== [1/4] Building ESP32-C6 Bootloader + Recovery OS (production profile) ==="
    Remove-Item -Force "$BuildDir\toob_recovery*" -ErrorAction SilentlyContinue
    & $ToobCli build --manifest "test\qemu_esp32c6\device.toml" --build-dir $BuildDir --profile production --native --dev --skip-checks
    if ($LASTEXITCODE -ne 0) { throw "toob build failed" }

    & $ToobCli elfaudit "$BuildDir\toob_stage0" --profile production --hardware "toob-infra\registry\packages\chips\esp32c6\hardware.json" --budget 32768
    if ($LASTEXITCODE -ne 0) { throw "toob elfaudit stage0 failed" }
    & $ToobCli elfaudit "$BuildDir\toob_stage1" --profile production --hardware "toob-infra\registry\packages\chips\esp32c6\hardware.json" --budget 131072
    if ($LASTEXITCODE -ne 0) { throw "toob elfaudit stage1 failed" }
    & $ToobCli elfaudit "$BuildDir\toob_recovery" --profile production --hardware "toob-infra\registry\packages\chips\esp32c6\hardware.json" --budget 65536
    if ($LASTEXITCODE -ne 0) { throw "toob elfaudit recovery failed" }

    Write-Host "=== [2/4] Packing ESP32-C6 Mask-ROM Stage 0 & Ed25519-Signed Stage 1 ==="
    & $ToobCli sign stage0 "$BuildDir\toob_stage0" --chip esp32c6 -o "$BuildDir\toob_stage0.esp.bin"
    if ($LASTEXITCODE -ne 0) { throw "toob sign stage0 failed" }
    & $ToobCli sign stage1 "$BuildDir\toob_stage1.bin" --entry 0x40810000 --mock -o "$BuildDir\toob_stage1.signed.bin"
    if ($LASTEXITCODE -ne 0) { throw "toob sign stage1 failed" }

    Write-Host "=== [3/4] Building Bare-Metal sdk/libtoob Guest Apps (v1.0.0, v2.0.0, v3.0.0, bad_v4) ==="
    powershell -ExecutionPolicy Bypass -File "test\qemu_esp32c6\guest_app\build_apps.ps1" -BuildDir $BuildDir -OutDir $AppsDir -ToobCli $ToobCli
    if ($LASTEXITCODE -ne 0) { throw "Guest app build failed" }

    Write-Host "=== [4/4] Running Full-System QEMU ESP32-C6 E2E Suite ==="
    Push-Location "test\qemu_esp32c6"
    try {
        go test -v -count=1 -timeout 240s ./...
        if ($LASTEXITCODE -ne 0) { throw "QEMU ESP32-C6 E2E suite failed" }
    } finally {
        Pop-Location
    }
} finally {
    Pop-Location
}
