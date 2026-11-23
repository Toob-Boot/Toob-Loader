$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path "$PSScriptRoot\..").Path

$ToobExe = if ($env:TOOB_CLI_BIN -and (Test-Path $env:TOOB_CLI_BIN)) {
    $env:TOOB_CLI_BIN
} elseif (Test-Path (Join-Path $RepoRoot "toob.exe")) {
    Join-Path $RepoRoot "toob.exe"
} elseif (Test-Path (Join-Path $RepoRoot "cli\toob-cli\toob.exe")) {
    Join-Path $RepoRoot "cli\toob-cli\toob.exe"
} elseif (Test-Path "D:\ToobStorage\linux_tools\toob.cmd") {
    "D:\ToobStorage\linux_tools\toob.cmd"
} else {
    throw "Toob CLI binary not found (set TOOB_CLI_BIN or install D:\ToobStorage\linux_tools\toob.cmd)"
}

function Invoke-ToobCli {
    & $ToobExe @args
}

$WorkRoot = if ($env:TOOB_ESPIDF_BUILD_ROOT) {
    $env:TOOB_ESPIDF_BUILD_ROOT
} else {
    "D:\ToobStorage\tmp_build\r2_espidf"
}

$GoCacheDir   = "D:\ToobStorage\go_cache"
$IdfPath      = if ($env:IDF_PATH) { $env:IDF_PATH } else { "G:\esp\v6.1-beta1\esp-idf" }
$IdfVenvDir   = "G:\Espressif\tools\python\v6.1-beta1\venv"
$IdfPython    = Join-Path $IdfVenvDir "Scripts\python.exe"
$ToolchainBin = "G:\Espressif\tools\riscv32-esp-elf\esp-15.2.0_20251204\riscv32-esp-elf\bin"
$CmakeBin     = "G:\Espressif\tools\cmake\4.0.3\bin"
$NinjaBin     = "G:\Espressif\tools\ninja\1.12.1"

foreach ($reqPath in @($IdfPath, $IdfPython, $ToolchainBin, $CmakeBin, $NinjaBin)) {
    if (-not (Test-Path $reqPath)) {
        throw "Required ESP-IDF v6.1 host tool missing: $reqPath"
    }
}

$BootBuildDir = Join-Path $WorkRoot "boot_build"
$IdfBuildDir  = Join-Path $WorkRoot "idf_build"
$AppsOutDir   = Join-Path $WorkRoot "apps"

foreach ($d in @($WorkRoot, $GoCacheDir, $BootBuildDir, $IdfBuildDir, $AppsOutDir)) {
    New-Item -ItemType Directory -Force -Path $d | Out-Null
}

$env:GOCACHE                = $GoCacheDir
$env:GOTMPDIR               = $WorkRoot
$env:TEMP                   = $WorkRoot
$env:TMP                    = $env:TEMP
$env:PYTHONDONTWRITEBYTECODE = "1"
$env:TOOB_ESPIDF_BUILD_ROOT = $WorkRoot
$env:TOOB_REGISTRY_DIR      = Join-Path $RepoRoot "toob-infra\registry\packages"
$env:IDF_PATH                     = $IdfPath
$env:IDF_TOOLS_PATH               = "G:\Espressif"
$env:IDF_PYTHON_ENV_PATH          = $IdfVenvDir
$env:ESP_IDF_VERSION              = "6.1"
$env:IDF_COMPONENT_MANAGER        = "0"
$env:IDF_PYTHON_CHECK_CONSTRAINTS = "no"
$env:IDF_TARGET                   = "esp32c3"
if (Test-Path "G:\Espressif\tools\esp-rom-elfs\20241011") {
    $env:ESP_ROM_ELF_DIR          = "G:\Espressif\tools\esp-rom-elfs\20241011"
}
$env:PATH                   = "$ToolchainBin;$CmakeBin;$NinjaBin;$IdfVenvDir\Scripts;$env:PATH"

Push-Location $RepoRoot
try {
    Write-Host "=== [1/4] Building Toob ESP32-C3 Stage 0 + Stage 1 + Recovery OS ==="
    $bootCache = Join-Path $BootBuildDir "CMakeCache.txt"
    if (Test-Path $bootCache) {
        $isDockerCache = Select-String -Quiet -Path $bootCache -Pattern "CMAKE_HOME_DIRECTORY:INTERNAL=/workspace"
        $usingDockerCli = ($ToobExe -like "*.cmd")
        if ([bool]$isDockerCache -ne [bool]$usingDockerCli) {
            Remove-Item -Recurse -Force (Join-Path $BootBuildDir "CMakeFiles") -ErrorAction SilentlyContinue
            Remove-Item -Force $bootCache, (Join-Path $BootBuildDir "build.ninja"), (Join-Path $BootBuildDir "cmake_install.cmake") -ErrorAction SilentlyContinue
        }
    }
    Remove-Item -Force (Join-Path $BootBuildDir "toob_recovery*") -ErrorAction SilentlyContinue
    Push-Location (Join-Path $RepoRoot "test\qemu_espidf_esp32c3")
    try {
        Invoke-ToobCli build `
            --build-dir $BootBuildDir `
            --profile production `
            --native `
            --dev `
            --skip-checks
        if ($LASTEXITCODE -ne 0) { throw "toob build failed" }
    } finally {
        Pop-Location
    }

    Invoke-ToobCli elfaudit (Join-Path $BootBuildDir "toob_stage1") `
        --profile production `
        --hardware "toob-infra\registry\packages\chips\esp32c3\hardware.json" `
        --budget 131072
    if ($LASTEXITCODE -ne 0) { throw "toob elfaudit failed" }

    Invoke-ToobCli sign stage0 (Join-Path $BootBuildDir "toob_stage0") `
        --chip esp32c3 `
        -o (Join-Path $BootBuildDir "toob_stage0.esp.bin")
    if ($LASTEXITCODE -ne 0) { throw "toob sign stage0 failed" }

    Invoke-ToobCli sign stage1 (Join-Path $BootBuildDir "toob_stage1.bin") `
        --entry 0x40390000 `
        --mock `
        -o (Join-Path $BootBuildDir "toob_stage1.signed.bin")
    if ($LASTEXITCODE -ne 0) { throw "toob sign stage1 failed" }

    Write-Host "=== [2/4] Building Real ESP-IDF v6.1 FreeRTOS Apps (v1.0.0, v2.0.0, bad_v3) ==="
    $AppSrcDir = Join-Path $RepoRoot "test\qemu_espidf_esp32c3\espidf_app"
    $BootGenDir = (Join-Path $BootBuildDir "generated") -replace "\\", "/"
    $IdfPy = Join-Path $IdfPath "tools\idf.py"

    $variants = @(
        @{ Name = "app_v1";     Ver = "1.0.0"; Hang = "0" },
        @{ Name = "app_v2";     Ver = "2.0.0"; Hang = "0" },
        @{ Name = "app_bad_v3"; Ver = "3.0.0"; Hang = "1" }
    )

    foreach ($v in $variants) {
        Write-Host ("--- Building ESP-IDF variant {0} (ver={1}, hang={2}) ---" -f $v.Name, $v.Ver, $v.Hang)
        & $IdfPython $IdfPy `
            -C $AppSrcDir `
            -B $IdfBuildDir `
            "-DTOOB_BOOT_GENERATED_DIR=$BootGenDir" `
            "-DAPP_FW_VER_STR=$($v.Ver)" `
            "-DAPP_SIMULATE_HANG=$($v.Hang)" `
            build
        if ($LASTEXITCODE -ne 0) { throw "idf.py build failed for $($v.Name)" }

        $elfSrc = Join-Path $IdfBuildDir "toob_espidf_qemu_app.elf"
        $xipRaw = Join-Path $IdfBuildDir "toob_espidf_qemu_app.xip.raw.bin"
        $elfDst = Join-Path $AppsOutDir "$($v.Name).elf"
        $toobDst = Join-Path $AppsOutDir "$($v.Name).toob"

        Copy-Item -Force $elfSrc $elfDst
        Invoke-ToobCli sign image $xipRaw -o $toobDst --entry 0x18 --mock
        if ($LASTEXITCODE -ne 0) { throw "toob sign image failed for $($v.Name)" }
    }

    Copy-Item -Force (Join-Path $IdfBuildDir "partition_table\partition-table.bin") (Join-Path $AppsOutDir "partition-table.bin")

    Write-Host "=== [3/4] Auditing ESP-IDF v6.1 ELF Symbols & RTC .noinit Pinning ==="
    $NmExe = Join-Path $ToolchainBin "riscv32-esp-elf-nm.exe"
    $nmOut = & $NmExe (Join-Path $AppsOutDir "app_v1.elf")
    if ($LASTEXITCODE -ne 0) { throw "riscv32-esp-elf-nm failed" }

    $requiredSymbols = @(
        "app_main",
        "s_toob_mutex_buf",
        "nvs_open",
        "nvs_set_blob",
        "toob_os_confirm_rtc_write",
        "toob_network_trigger_ota",
        "_toob_xip_start"
    )
    foreach ($sym in $requiredSymbols) {
        if (-not ($nmOut | Select-String -Quiet -Pattern "\b$sym\b")) {
            throw "Required symbol '$sym' missing from app_v1.elf!"
        }
    }

    $expectedAddrs = @{
        "toob_handoff_state"      = "50000000"
        "toob_diag_state"         = "50000050"
        "g_toob_ota_resume_state" = "500000d8"
    }
    foreach ($kv in $expectedAddrs.GetEnumerator()) {
        $pattern = "^0*$($kv.Value)\s+\w\s+$($kv.Key)$"
        if (-not ($nmOut | Select-String -Quiet -Pattern $pattern)) {
            throw "RTC symbol '$($kv.Key)' not pinned at 0x$($kv.Value)!"
        }
    }
    Write-Host "ELF audit PASSED: app_main, s_toob_mutex_buf, nvs_flash, sdk/os_client, and RTC 0x50000000/50/D8 verified!"

    Write-Host "=== [4/4] Running Headless QEMU ESP32-C3 ESP-IDF v6.1 E2E Suite ==="
    Push-Location (Join-Path $RepoRoot "test\qemu_espidf_esp32c3")
    try {
        go test -v -count=1 -timeout 240s ./...
        if ($LASTEXITCODE -ne 0) { throw "QEMU ESP-IDF E2E suite failed" }
    } finally {
        Pop-Location
    }
} finally {
    Pop-Location
}
