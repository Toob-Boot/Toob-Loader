param(
    [string]$FreeRtosDir   = "D:\ToobStorage\tools\FreeRTOS-Kernel",
    [string]$BuildRoot     = "D:\ToobStorage\renode_freertos_build",
    [string]$BootBuildDir  = "$PSScriptRoot\..\test\renode_nrf52840\builds\build_nrf52840",
    [string]$GccDir        = "$env:USERPROFILE\.toob\toolchains\arm-none-eabi\15.2.1-1.1\xpack-arm-none-eabi-gcc-15.2.1-1.1\bin"
)

$ErrorActionPreference = "Stop"
$Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$RepoRoot = (Resolve-Path "$PSScriptRoot\..").Path
$BootBuildDir = (Resolve-Path $BootBuildDir).Path

Write-Host "=== [1/4] Verifying FreeRTOS-Kernel Checkout ($FreeRtosDir) ==="
if (-not (Test-Path (Join-Path $FreeRtosDir "tasks.c"))) {
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $FreeRtosDir) | Out-Null
    git clone --depth 1 https://github.com/FreeRTOS/FreeRTOS-Kernel.git $FreeRtosDir
    if ($LASTEXITCODE -ne 0) { throw "Failed to shallow-clone FreeRTOS-Kernel into $FreeRtosDir" }
}

$ObjDir  = Join-Path $BuildRoot "obj"
$AppsDir = Join-Path $BuildRoot "apps"
if (Test-Path $BuildRoot) {
    Remove-Item -Recurse -Force $BuildRoot
}
New-Item -ItemType Directory -Force -Path $ObjDir  | Out-Null
New-Item -ItemType Directory -Force -Path $AppsDir | Out-Null

$Gcc     = Join-Path $GccDir "arm-none-eabi-gcc.exe"
$Objcopy = Join-Path $GccDir "arm-none-eabi-objcopy.exe"
$SizeExe = Join-Path $GccDir "arm-none-eabi-size.exe"
$NmExe   = Join-Path $GccDir "arm-none-eabi-nm.exe"

$FwSrcDir      = Join-Path $RepoRoot "test\renode_freertos_nrf52840\firmware"
$FreertosHooks = Join-Path $RepoRoot "toob-infra\registry\packages\integrations\freertos\files"

$CpuAndWarnFlags = @(
    "-mcpu=cortex-m4",
    "-mthumb",
    "-mfpu=fpv4-sp-d16",
    "-mfloat-abi=hard",
    "-fno-short-enums",
    "-Os",
    "-ffunction-sections",
    "-fdata-sections",
    "-fno-common",
    "-fno-exceptions",
    "-fno-unwind-tables",
    "-Wall",
    "-Wextra",
    "-Werror"
)

$IncludeFlags = @(
    "-I$FwSrcDir",
    "-I$BootBuildDir\generated",
    "-I$FreeRtosDir\include",
    "-I$FreeRtosDir\portable\GCC\ARM_CM4F",
    "-I$RepoRoot\sdk\libtoob\include",
    "-I$RepoRoot\sdk\os_client\include",
    "-I$RepoRoot\common\include",
    "-I$RepoRoot\toobloader\core\utils\include",
    "-I$RepoRoot\toob-infra\registry\packages\chips\nrf52840",
    "-I$RepoRoot\toob-infra\registry\packages\crypto\hash\sha256_sw"
)

Write-Host "=== [2/4] Compiling FreeRTOS Kernel (ARM_CM4F) + sdk/libtoob + integrations/freertos ==="
$SharedSources = @(
    @{ Name = "rtos_tasks";          Src = "$FreeRtosDir\tasks.c" },
    @{ Name = "rtos_queue";          Src = "$FreeRtosDir\queue.c" },
    @{ Name = "rtos_list";           Src = "$FreeRtosDir\list.c" },
    @{ Name = "rtos_timers";         Src = "$FreeRtosDir\timers.c" },
    @{ Name = "rtos_port_cm4f";      Src = "$FreeRtosDir\portable\GCC\ARM_CM4F\port.c" },
    @{ Name = "rtos_heap_4";         Src = "$FreeRtosDir\portable\MemMang\heap_4.c" },
    @{ Name = "libtoob_confirm";     Src = "$RepoRoot\sdk\libtoob\toob_confirm.c" },
    @{ Name = "libtoob_crc32";       Src = "$RepoRoot\sdk\libtoob\toob_crc32.c" },
    @{ Name = "libtoob_diag";        Src = "$RepoRoot\sdk\libtoob\toob_diag.c" },
    @{ Name = "libtoob_handoff";     Src = "$RepoRoot\sdk\libtoob\toob_handoff.c" },
    @{ Name = "libtoob_mailbox";     Src = "$RepoRoot\sdk\libtoob\toob_mailbox.c" },
    @{ Name = "libtoob_ota";         Src = "$RepoRoot\sdk\libtoob\toob_ota.c" },
    @{ Name = "libtoob_update";      Src = "$RepoRoot\sdk\libtoob\toob_update.c" },
    @{ Name = "libtoob_cloud";       Src = "$RepoRoot\sdk\libtoob\toob_cloud_submit.c" },
    @{ Name = "boot_zeroize";        Src = "$RepoRoot\toobloader\core\utils\boot_secure_zeroize.S" },
    @{ Name = "crypto_sha256";       Src = "$RepoRoot\toob-infra\registry\packages\crypto\hash\sha256_sw\sha256.c" },
    @{ Name = "integ_toob_hooks";    Src = "$FreertosHooks\toob_hooks.c" },
    @{ Name = "integ_rtos_glue";     Src = "$FreertosHooks\rtos_glue.c" },
    @{ Name = "integ_rtos_http";     Src = "$FreertosHooks\rtos_http.c" }
)

$SharedObjects = @()
foreach ($item in $SharedSources) {
    $obj = Join-Path $ObjDir ($item.Name + ".o")
    $compileArgs = @() + $CpuAndWarnFlags + $IncludeFlags + @("-c", $item.Src, "-o", $obj)
    & $Gcc @compileArgs
    if ($LASTEXITCODE -ne 0) { throw "Compilation failed for $($item.Src)" }
    $SharedObjects += $obj
}

Write-Host "=== [3/4] Linking Cortex-M4F Multi-Task FreeRTOS Guest Firmwares (v1.0.0, v2.0.0, bad_v3.0.0) ==="
$Variants = @(
    @{ Name = "freertos_v1";     Ver = "1.0.0"; Deadlock = 0 },
    @{ Name = "freertos_v2";     Ver = "2.0.0"; Deadlock = 0 },
    @{ Name = "freertos_bad_v3"; Ver = "3.0.0"; Deadlock = 1 }
)

$LinkFlags = @(
    "--specs=nano.specs",
    "--specs=nosys.specs",
    "-nostartfiles",
    "-Wl,--gc-sections",
    "-Wl,--no-enum-size-warning",
    "-L$BootBuildDir\generated",
    "-T$FwSrcDir\freertos_nrf52840.ld"
)

foreach ($v in $Variants) {
    $mainObj = Join-Path $ObjDir ("main_" + $v.Name + ".o")
    $elf     = Join-Path $AppsDir ($v.Name + ".elf")
    $raw     = Join-Path $AppsDir ($v.Name + ".raw.bin")

    $mainArgs = @() + $CpuAndWarnFlags + $IncludeFlags + @(
        "-DAPP_VERSION_RAW=$($v.Ver)",
        "-DAPP_SIMULATE_DEADLOCK=$($v.Deadlock)",
        "-c", "$FwSrcDir\main_freertos.c",
        "-o", $mainObj
    )
    & $Gcc @mainArgs
    if ($LASTEXITCODE -ne 0) { throw "Compilation failed for main_freertos.c ($($v.Name))" }

    $linkArgs = @() + $CpuAndWarnFlags + $LinkFlags + @($mainObj) + $SharedObjects + @("-o", $elf)
    & $Gcc @linkArgs
    if ($LASTEXITCODE -ne 0) { throw "Linking failed for $($v.Name)" }

    & $Objcopy -O binary $elf $raw
    if ($LASTEXITCODE -ne 0) { throw "objcopy failed for $($v.Name)" }

    & $SizeExe $elf
    if ($LASTEXITCODE -ne 0) { throw "arm-none-eabi-size failed for $($v.Name)" }
}

# Verify strong StaticSemaphore_t mutex symbol from integrations/freertos/files/toob_hooks.c is linked
$nmOut = & $NmExe (Join-Path $AppsDir "freertos_v1.elf")
if (-not ($nmOut -match "s_toob_mutex_buf")) {
    throw "Expected StaticSemaphore_t s_toob_mutex_buf from integrations/freertos/files/toob_hooks.c in freertos_v1.elf!"
}

Write-Host "=== [4/4] Running Headless Renode 1.17.0 Cortex-M4F FreeRTOS E2E Suite ==="
$env:TOOB_FREERTOS_BUILD_DIR   = $BuildRoot
$env:TOOB_BOOTLOADER_BUILD_DIR = $BootBuildDir

$RenodeCandidates = @(
    $env:TOOB_RENODE_BIN,
    "D:\ToobStorage\tools\renode-1.17.0\renode_1.17.0-portable\renode.exe",
    "$env:USERPROFILE\.toob\tools\renode\renode_1.17.0-portable\renode.exe"
)
foreach ($cand in $RenodeCandidates) {
    if ($cand -and (Test-Path $cand)) {
        $env:TOOB_RENODE_BIN = $cand
        break
    }
}

Push-Location (Join-Path $RepoRoot "test\renode_freertos_nrf52840")
try {
    go mod tidy
    if ($LASTEXITCODE -ne 0) { throw "go mod tidy failed" }
    go test -v -count=1 -timeout 240s ./...
    if ($LASTEXITCODE -ne 0) { throw "Headless Renode FreeRTOS E2E suite failed" }
} finally {
    Pop-Location
}

$Stopwatch.Stop()
Write-Host ("=== FreeRTOS Cortex-M4F E2E Suite PASSED in {0:N2}s ===" -f $Stopwatch.Elapsed.TotalSeconds)
