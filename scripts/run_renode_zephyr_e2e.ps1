$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path "$PSScriptRoot\..").Path

$ToobExe = $null
foreach ($cand in @(
    $env:TOOB_CLI_BIN,
    (Join-Path $RepoRoot "toob.exe"),
    (Join-Path $RepoRoot "cli\toob-cli\toob.exe"),
    "D:\ToobStorage\linux_tools\toob.cmd"
)) {
    if ($cand -and (Test-Path $cand)) {
        $ToobExe = $cand
        break
    }
}
if (-not $ToobExe) {
    throw "toob CLI not found in TOOB_CLI_BIN, repository root, cli\toob-cli\toob.exe, or D:\ToobStorage\linux_tools\toob.cmd."
}

$WorkRoot     = if ($env:TOOB_ZEPHYR_WORK_DIR) { $env:TOOB_ZEPHYR_WORK_DIR } else { "D:\ToobStorage\tmp_build\r1_zephyr" }
$PipCacheDir  = Join-Path $WorkRoot "pip_cache"
$GoCacheDir   = "D:\ToobStorage\go_cache"
$BootBuildDir = Join-Path $WorkRoot "build_nrf52840"
$AppsOutDir   = Join-Path $WorkRoot "apps"

foreach ($d in @($WorkRoot, $PipCacheDir, $GoCacheDir, $AppsOutDir)) {
    New-Item -ItemType Directory -Force -Path $d | Out-Null
}

$ToolchainRoot = if ($env:GNUARMEMB_TOOLCHAIN_PATH) {
    $env:GNUARMEMB_TOOLCHAIN_PATH
} else {
    "D:\ToobStorage\toolchains\arm-none-eabi\15.2.1-1.1\xpack-arm-none-eabi-gcc-15.2.1-1.1"
}
$ToolchainBin = Join-Path $ToolchainRoot "bin"
$NmExe        = Join-Path $ToolchainBin "arm-none-eabi-nm.exe"

$ZephyrVenvScripts = "D:\ToobStorage\tools\zephyr_venv\Scripts"
$PythonExe         = Join-Path $ZephyrVenvScripts "python.exe"
$CmakeBin          = "G:\Espressif\tools\cmake\4.0.3\bin"
$NinjaBin          = "G:\Espressif\tools\ninja\1.12.1"
$RenodeBin         = if ($env:TOOB_RENODE_BIN) {
    $env:TOOB_RENODE_BIN
} else {
    "D:\ToobStorage\tools\renode-1.17.0\renode_1.17.0-portable\Renode.exe"
}

Push-Location $RepoRoot
try {
    $env:GOCACHE                  = "D:\ToobStorage\go_cache"
    $env:GOTMPDIR                 = "D:\ToobStorage\tmp_build\r1_zephyr"
    $env:TEMP                     = "D:\ToobStorage\tmp_build\r1_zephyr"
    $env:TMP                      = $env:TEMP
    $env:PIP_CACHE_DIR            = $PipCacheDir
    $env:TOOB_CLI_BIN             = $ToobExe
    $env:TOOB_REGISTRY_DIR        = Join-Path $RepoRoot "toob-infra\registry\packages"
    $env:ZEPHYR_BASE              = "D:\ToobStorage\tools\zephyr_ws\zephyr"
    $env:ZEPHYR_TOOLCHAIN_VARIANT = "gnuarmemb"
    $env:GNUARMEMB_TOOLCHAIN_PATH = $ToolchainRoot
    $env:TOOB_RENODE_BIN          = $RenodeBin
    $env:TOOB_ZEPHYR_BOOT_DIR     = $BootBuildDir
    $env:TOOB_ZEPHYR_APPS_DIR     = $AppsOutDir
    $env:PATH                     = "$ZephyrVenvScripts;$CmakeBin;$NinjaBin;$ToolchainBin;$env:PATH"

    $ManifestPath = Join-Path $RepoRoot "test\renode_zephyr_nrf52840\device.toml"
    $HardwarePath = Join-Path $RepoRoot "toob-infra\registry\packages\chips\nrf52840\hardware.json"

    Write-Host "=== [1/4] Building Nordic nRF52840 Stage 0 + Stage 1 + Recovery OS (production profile) ==="
    $savedCflags  = $env:CFLAGS
    $savedLdflags = $env:LDFLAGS
    try {
        $env:CFLAGS  = "-fno-short-enums"
        $env:LDFLAGS = "-Wl,--no-enum-size-warning"

        $CacheFile = Join-Path $BootBuildDir "CMakeCache.txt"
        $isDockerCli = $ToobExe.EndsWith(".cmd", [System.StringComparison]::OrdinalIgnoreCase)
        $CliToolchainBin = if ($isDockerCli) {
            "D:\ToobStorage\linux_tools\xpack-arm-none-eabi-gcc-15.2.1-1.1\bin"
        } else {
            $ToolchainBin
        }
        if (Test-Path $CacheFile) {
            $hasShortEnums = Select-String -Path $CacheFile -SimpleMatch -Pattern "-fno-short-enums" -Quiet
            $hasLinuxCache = Select-String -Path $CacheFile -SimpleMatch -Pattern "/mnt/d/" -Quiet
            if ((-not $hasShortEnums) -or ($isDockerCli -ne $hasLinuxCache)) {
                Remove-Item -Recurse -Force $BootBuildDir -ErrorAction SilentlyContinue
            }
        }
        Remove-Item -Force "$BootBuildDir\toob_recovery*" -ErrorAction SilentlyContinue

        & $ToobExe build `
            --manifest $ManifestPath `
            --build-dir $BootBuildDir `
            --toolchain-path $CliToolchainBin `
            --profile production `
            --native `
            --dev `
            --skip-checks
        if ($LASTEXITCODE -ne 0) { throw "toob build failed" }
    } finally {
        $env:CFLAGS  = $savedCflags
        $env:LDFLAGS = $savedLdflags
    }

    & $ToobExe elfaudit "$BootBuildDir\toob_stage0" --profile production --hardware $HardwarePath --budget 32768
    if ($LASTEXITCODE -ne 0) { throw "Stage 0 elfaudit failed" }
    & $ToobExe elfaudit "$BootBuildDir\toob_stage1" --profile production --hardware $HardwarePath --budget 98304
    if ($LASTEXITCODE -ne 0) { throw "Stage 1 elfaudit failed" }
    & $ToobExe elfaudit "$BootBuildDir\toob_recovery" --profile production --hardware $HardwarePath --budget 65536
    if ($LASTEXITCODE -ne 0) { throw "Recovery OS elfaudit failed" }

    Write-Host "=== [2/4] Signing XIP Stage 1 & Recovery OS (256-Byte SCB->VTOR Entry 0x100) ==="
    & $ToobExe sign stage1 "$BootBuildDir\toob_stage1.bin" --entry 0x100 --mock -o "$BootBuildDir\toob_stage1.signed.bin"
    if ($LASTEXITCODE -ne 0) { throw "toob sign stage1 failed" }
    & $ToobExe sign image "$BootBuildDir\toob_recovery.raw.bin" --entry 0x100 -o "$BootBuildDir\toob_recovery.bin"
    if ($LASTEXITCODE -ne 0) { throw "toob sign recovery failed" }

    Write-Host "=== [3/4] Building Real Multi-Threaded Zephyr 4.0 Kernel Apps (v1.0.0, v2.0.0, bad_v3) ==="
    $GeneratedDir = Join-Path $BootBuildDir "generated"
    $AppSrcDir    = Join-Path $RepoRoot "test\renode_zephyr_nrf52840\app"
    $zBuildDir    = Join-Path $WorkRoot "zephyr_v1"
    $zNinjaFile   = Join-Path $zBuildDir "build.ninja"
    $zCacheFile   = Join-Path $zBuildDir "CMakeCache.txt"

    $needsConfigure = -not (Test-Path $zNinjaFile)
    $zDotConfig     = Join-Path $zBuildDir "zephyr\.config"
    if (-not $needsConfigure -and (Test-Path $zCacheFile)) {
        $genSlash = $GeneratedDir.Replace('\', '/')
        if (-not (Select-String -Path $zCacheFile -SimpleMatch -Pattern $genSlash -Quiet) -and
            -not (Select-String -Path $zCacheFile -SimpleMatch -Pattern $GeneratedDir -Quiet)) {
            $needsConfigure = $true
        }
    }
    if (-not $needsConfigure -and (Test-Path $zDotConfig)) {
        $cfgMtime = (Get-Item $zDotConfig).LastWriteTimeUtc
        foreach ($cfgSrc in @(
            (Join-Path $AppSrcDir "prj.conf"),
            (Join-Path $AppSrcDir "boards\nrf52840dk_nrf52840.overlay"),
            (Join-Path $RepoRoot "toob-infra\registry\packages\integrations\zephyr\files\app.overlay"),
            (Join-Path $RepoRoot "toob-infra\registry\packages\integrations\zephyr\files\Kconfig")
        )) {
            if ((Test-Path $cfgSrc) -and ((Get-Item $cfgSrc).LastWriteTimeUtc -gt $cfgMtime)) {
                $needsConfigure = $true
                break
            }
        }
    }

    if ($needsConfigure) {
        if (Test-Path $zBuildDir) {
            Remove-Item -Recurse -Force $zBuildDir -ErrorAction SilentlyContinue
        }
        Write-Host "--- Configuring Zephyr 4.0 Kernel in $zBuildDir ---"
        & cmake -B $zBuildDir -S $AppSrcDir `
            -GNinja `
            -DBOARD=nrf52840dk/nrf52840 `
            -DPython3_EXECUTABLE="$PythonExe" `
            -DTOOB_GENERATED_CONFIG_DIR="$GeneratedDir"
        if ($LASTEXITCODE -ne 0) { throw "CMake configure failed for Zephyr app" }
    }

    $Variants = @(
        @{ Name = "zephyr_v1";     Ver = "1.0.0"; Bad = 0 },
        @{ Name = "zephyr_v2";     Ver = "2.0.0"; Bad = 0 },
        @{ Name = "zephyr_bad_v3"; Ver = "3.0.0"; Bad = 1 }
    )

    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    $variantHdrPath = Join-Path $zBuildDir "app_variant_cfg.h"

    foreach ($v in $Variants) {
        Write-Host "--- Building $($v.Name) (ver=$($v.Ver), bad=$($v.Bad)) ---"
        $hdrContent = "#define APP_FW_VERSION_STR `"$($v.Ver)`"`n#define APP_BAD_UNCONFIRMED $($v.Bad)`n"
        [System.IO.File]::WriteAllText($variantHdrPath, $hdrContent, $utf8NoBom)
        Remove-Item -Force (Join-Path $zBuildDir "CMakeFiles\app.dir\src\main.c.obj") -ErrorAction SilentlyContinue

        & ninja -C $zBuildDir
        if ($LASTEXITCODE -ne 0) { throw "Ninja build failed for $($v.Name)" }

        $elfPath = Join-Path $zBuildDir "zephyr\zephyr.elf"
        $rawPath = Join-Path $zBuildDir "zephyr\zephyr.toob.raw.bin"
        $outElf  = Join-Path $AppsOutDir ($v.Name + ".elf")
        $outRaw  = Join-Path $AppsOutDir ($v.Name + ".raw.bin")
        $outToob = Join-Path $AppsOutDir ($v.Name + ".toob")

        $symText = (& $NmExe -n $elfPath) -join "`n"
        foreach ($reqSym in @(
            @{ Addr = "00038100"; Name = "_vector_start" },
            @{ Addr = "2003f000"; Name = "toob_handoff_state" },
            @{ Addr = "2003f050"; Name = "toob_diag_state" },
            @{ Addr = "2003f0d8"; Name = "g_toob_ota_resume_state" }
        )) {
            if ($symText -notmatch "(?m)^$($reqSym.Addr)\s+\w\s+$($reqSym.Name)\s*$") {
                throw "ELF ABI symbol verification failed for $($v.Name): expected $($reqSym.Name) at 0x$($reqSym.Addr)"
            }
        }

        if (-not (Test-Path $rawPath)) {
            throw "Missing POST_BUILD Toob payload binary $rawPath"
        }

        Copy-Item -Force $elfPath $outElf
        Copy-Item -Force $rawPath $outRaw

        & $ToobExe sign image $outRaw --entry 0x100 -o $outToob
        if ($LASTEXITCODE -ne 0) { throw "toob sign image failed for $($v.Name)" }
    }

    Write-Host "=== [4/4] Running Full-System Headless Renode 1.17.0 Zephyr nRF52840 E2E Suite ==="
    Push-Location "test\renode_zephyr_nrf52840"
    try {
        go mod tidy
        if ($LASTEXITCODE -ne 0) { throw "go mod tidy failed" }
        go test -v -count=1 -timeout 240s ./...
        if ($LASTEXITCODE -ne 0) { throw "Renode Zephyr nRF52840 E2E suite failed" }
    } finally {
        Pop-Location
    }
} finally {
    Pop-Location
}
