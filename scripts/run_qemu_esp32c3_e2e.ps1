$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path "$PSScriptRoot\..").Path

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

$WorkBase = if ($env:TOOB_E2E_WORK_DIR) {
    $env:TOOB_E2E_WORK_DIR
} elseif (Test-Path "D:\ToobStorage") {
    "D:\ToobStorage\tmp_build\w3a_esp32c6\e2e_c3"
} else {
    Join-Path $RepoRoot "test\qemu_esp32c3\builds"
}

$BuildDir = Join-Path $WorkBase "build_esp32c3"
$AppsDir  = Join-Path $WorkBase "apps"
$TmpDir   = Join-Path $WorkBase "tmp"
New-Item -ItemType Directory -Force -Path $BuildDir, $AppsDir, $TmpDir | Out-Null

Push-Location $RepoRoot
try {
    $env:TOOB_REGISTRY_DIR = Join-Path $RepoRoot "toob-infra\registry\packages"
    $env:TEMP = $TmpDir
    $env:TMP  = $TmpDir
    $env:GOTMPDIR = $TmpDir
    if (-not $env:GOCACHE -and (Test-Path "D:\ToobStorage")) {
        $env:GOCACHE = "D:\ToobStorage\go_cache"
    }
    $env:TOOB_C3_BUILD_ROOT = $WorkBase
    $env:TOOB_E2E_TMPDIR = $TmpDir

    $useDockerCli = $ToobCli.EndsWith(".cmd", [System.StringComparison]::OrdinalIgnoreCase)
    if (Test-Path "$BuildDir\CMakeCache.txt") {
        $cacheRaw = Get-Content "$BuildDir\CMakeCache.txt" -Raw -ErrorAction SilentlyContinue
        if (($useDockerCli -and $cacheRaw -match '[A-Za-z]:/') -or (-not $useDockerCli -and $cacheRaw -match '/workspace/')) {
            Remove-Item -Recurse -Force $BuildDir -ErrorAction SilentlyContinue
            New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null
        }
    }

    Write-Host "=== [1/4] Building ESP32-C3 Bootloader + Recovery OS (production profile) ==="
    Remove-Item -Force "$BuildDir\toob_recovery*" -ErrorAction SilentlyContinue
    & $ToobCli build --manifest "test\qemu_esp32c3\device.toml" --build-dir $BuildDir --profile production --native --dev --skip-checks
    if ($LASTEXITCODE -ne 0) { throw "toob build failed" }

    & $ToobCli elfaudit "$BuildDir\toob_stage0" --profile production --hardware "toob-infra\registry\packages\chips\esp32c3\hardware.json" --budget 32768
    if ($LASTEXITCODE -ne 0) { throw "elfaudit stage0 failed" }
    & $ToobCli elfaudit "$BuildDir\toob_stage1" --profile production --hardware "toob-infra\registry\packages\chips\esp32c3\hardware.json" --budget 131072
    if ($LASTEXITCODE -ne 0) { throw "elfaudit stage1 failed" }

    Write-Host "=== [2/4] Packing ESP32-C3 Mask-ROM Stage 0 & Ed25519-Signed Stage 1 ==="
    & $ToobCli sign stage0 "$BuildDir\toob_stage0" --chip esp32c3 -o "$BuildDir\toob_stage0.esp.bin"
    if ($LASTEXITCODE -ne 0) { throw "sign stage0 failed" }
    & $ToobCli sign stage1 "$BuildDir\toob_stage1.bin" --entry 0x40390000 --mock -o "$BuildDir\toob_stage1.signed.bin"
    if ($LASTEXITCODE -ne 0) { throw "sign stage1 failed" }

    Write-Host "=== [3/4] Building Bare-Metal sdk/libtoob Guest Apps (v1.0.0, v2.0.0, v3.0.0, bad_v4) ==="
    powershell -ExecutionPolicy Bypass -File "test\qemu_esp32c3\guest_app\build_apps.ps1" -BuildDir $BuildDir -OutDir $AppsDir -ToobCli $ToobCli
    if ($LASTEXITCODE -ne 0) { throw "Guest app build failed" }

    Write-Host "=== [4/4] Running Full-System QEMU ESP32-C3 E2E Suite ==="
    Push-Location "test\qemu_esp32c3"
    try {
        go test -v -count=1 -timeout 240s ./...
        if ($LASTEXITCODE -ne 0) { throw "QEMU E2E suite failed" }
    } finally {
        Pop-Location
    }
} finally {
    Pop-Location
}
