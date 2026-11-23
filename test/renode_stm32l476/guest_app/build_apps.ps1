param(
    [string]$BuildDir = "D:\ToobStorage\tmp_build\stm32l476_work\build_stm32l476",
    [string]$OutDir   = "D:\ToobStorage\tmp_build\stm32l476_work\build_stm32l476\apps",
    [string]$GccDir   = "$env:USERPROFILE\.toob\toolchains\arm-none-eabi\15.2.1-1.1\xpack-arm-none-eabi-gcc-15.2.1-1.1\bin",
    [string]$ToobCli  = "$PSScriptRoot\..\..\..\toob.exe"
)

$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path "$PSScriptRoot\..\..\..").Path
$BuildDir = (Resolve-Path $BuildDir).Path
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$OutDir = (Resolve-Path $OutDir).Path

if (-not (Test-Path (Join-Path $GccDir "arm-none-eabi-gcc.exe"))) {
    $AltGccDir = "D:\ToobStorage\toolchains\arm-none-eabi\15.2.1-1.1\xpack-arm-none-eabi-gcc-15.2.1-1.1\bin"
    if (Test-Path (Join-Path $AltGccDir "arm-none-eabi-gcc.exe")) {
        $GccDir = $AltGccDir
    }
}

$Gcc     = Join-Path $GccDir "arm-none-eabi-gcc.exe"
$Objcopy = Join-Path $GccDir "arm-none-eabi-objcopy.exe"

$CommonFlags = @(
    "-mcpu=cortex-m4",
    "-mthumb",
    "-mfloat-abi=soft",
    "-fno-short-enums",
    "-Os",
    "-ffunction-sections",
    "-fdata-sections",
    "-fno-common",
    "-fno-builtin",
    "-Wall",
    "-Wextra",
    "-Werror",
    "--specs=nano.specs",
    "--specs=nosys.specs",
    "-nostartfiles",
    "-Wl,--gc-sections",
    "-Wl,--no-enum-size-warning",
    "-L$BuildDir\generated",
    "-T$PSScriptRoot\app_stm32l476.ld",
    "-I$BuildDir\generated",
    "-I$RepoRoot\sdk\libtoob\include",
    "-I$RepoRoot\common\include",
    "-I$RepoRoot\toob-infra\registry\packages\chips\stm32l476",
    "-I$RepoRoot\toob-infra\registry\packages\crypto\hash\sha256_sw"
)

# Slot 0 XIP origin = 0x08038000; Slot 1 XIP origin = 0x08058000 (from generated/boot_layout.h)
$Variants = @(
    @{ Name = "app_v1";       Ver = "1.0.0"; Crash = 0; Origin = "0x08038000" },
    @{ Name = "app_v2";       Ver = "2.0.0"; Crash = 0; Origin = "0x08058000" },
    @{ Name = "app_v3";       Ver = "3.0.0"; Crash = 0; Origin = "0x08038000" },
    @{ Name = "app_v3_slot1"; Ver = "3.0.0"; Crash = 0; Origin = "0x08058000" },
    @{ Name = "app_bad_v4";   Ver = "4.0.0"; Crash = 1; Origin = "0x08058000" }
)

foreach ($v in $Variants) {
    $elf  = Join-Path $OutDir ($v.Name + ".elf")
    $raw  = Join-Path $OutDir ($v.Name + ".raw.bin")
    $toob = Join-Path $OutDir ($v.Name + ".toob")

    $argsList = @() + $CommonFlags + @(
        "-Wl,--defsym,APP_FLASH_ORIGIN=$($v.Origin)",
        "-DAPP_VERSION_RAW=$($v.Ver)",
        "-DAPP_CRASH_ON_BOOT=$($v.Crash)",
        "$PSScriptRoot\app_main.c",
        "$RepoRoot\toobloader\core\utils\boot_secure_zeroize.S",
        "$BuildDir\libtoob_libtoob.a",
        "$BuildDir\libtoob_crypto_upstream.a",
        "-o", $elf
    )

    & $Gcc @argsList
    if ($LASTEXITCODE -ne 0) { throw "GCC failed for $($v.Name)" }

    & $Objcopy -O binary $elf $raw
    if ($LASTEXITCODE -ne 0) { throw "objcopy failed for $($v.Name)" }

    & $ToobCli sign image $raw -o $toob --entry 0x100 --mock
    if ($LASTEXITCODE -ne 0) { throw "toob sign image failed for $($v.Name)" }
}

Write-Host "Built all 5 STM32L476 bare-metal guest apps in $OutDir"

