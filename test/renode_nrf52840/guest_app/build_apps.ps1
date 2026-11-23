param(
    [string]$BuildDir = "$PSScriptRoot\..\builds\build_nrf52840",
    [string]$OutDir   = "$PSScriptRoot\..\builds\apps",
    [string]$GccDir   = "$env:USERPROFILE\.toob\toolchains\arm-none-eabi\15.2.1-1.1\xpack-arm-none-eabi-gcc-15.2.1-1.1\bin",
    [string]$ToobCli  = "$PSScriptRoot\..\..\..\toob.exe"
)

$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path "$PSScriptRoot\..\..\..").Path
$BuildDir = (Resolve-Path $BuildDir).Path
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$OutDir = (Resolve-Path $OutDir).Path

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
    "-T$PSScriptRoot\app_nrf52840.ld",
    "-I$BuildDir\generated",
    "-I$RepoRoot\sdk\libtoob\include",
    "-I$RepoRoot\common\include",
    "-I$RepoRoot\toob-infra\registry\packages\chips\nrf52840",
    "-I$RepoRoot\toob-infra\registry\packages\crypto\hash\sha256_sw"
)

$Variants = @(
    @{ Name = "app_v1";     Ver = "1.0.0"; Crash = 0 },
    @{ Name = "app_v2";     Ver = "2.0.0"; Crash = 0 },
    @{ Name = "app_v3";     Ver = "3.0.0"; Crash = 0 },
    @{ Name = "app_bad_v4"; Ver = "4.0.0"; Crash = 1 }
)

foreach ($v in $Variants) {
    $elf  = Join-Path $OutDir ($v.Name + ".elf")
    $raw  = Join-Path $OutDir ($v.Name + ".raw.bin")
    $toob = Join-Path $OutDir ($v.Name + ".toob")

    $argsList = @() + $CommonFlags + @(
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

Write-Host "Built all 4 nRF52840 bare-metal guest apps in $OutDir"
