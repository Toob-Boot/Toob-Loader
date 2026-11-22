param(
    [string]$BuildDir = "$PSScriptRoot\..\builds\build_esp32c3",
    [string]$OutDir   = "$PSScriptRoot\..\builds\apps",
    [string]$GccDir   = "$env:USERPROFILE\.toob\toolchains\riscv32-esp-elf\13.2.0_20230928\riscv32-esp-elf\bin",
    [string]$ToobCli  = ""
)

$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path "$PSScriptRoot\..\..\..").Path
if (-not $ToobCli) {
    $ToobCli = if ($env:TOOB_CLI_BIN -and (Test-Path $env:TOOB_CLI_BIN)) {
        $env:TOOB_CLI_BIN
    } elseif (Test-Path (Join-Path $RepoRoot "toob.exe")) {
        Join-Path $RepoRoot "toob.exe"
    } elseif (Test-Path (Join-Path $RepoRoot "cli\toob-cli\toob.exe")) {
        Join-Path $RepoRoot "cli\toob-cli\toob.exe"
    } else {
        "D:\ToobStorage\linux_tools\toob.cmd"
    }
}
$BuildDir = (Resolve-Path $BuildDir).Path
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$OutDir = (Resolve-Path $OutDir).Path

$Gcc     = Join-Path $GccDir "riscv32-esp-elf-gcc.exe"
$Objcopy = Join-Path $GccDir "riscv32-esp-elf-objcopy.exe"

$CommonFlags = @(
    "-march=rv32imc_zicsr_zifencei",
    "-mabi=ilp32",
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
    "-L$BuildDir\generated",
    "-T$PSScriptRoot\app_esp32c3.ld",
    "-I$BuildDir\generated",
    "-I$RepoRoot\sdk\libtoob\include",
    "-I$RepoRoot\common\include",
    "-I$RepoRoot\toob-infra\registry\packages\soc\esp\include",
    "-I$RepoRoot\toob-infra\registry\packages\chips\esp32c3",
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

    & $ToobCli sign image $raw -o $toob --entry 0x14
    if ($LASTEXITCODE -ne 0) { throw "toob sign image failed for $($v.Name)" }
}

Write-Host "Built all 4 ESP32-C3 bare-metal guest apps in $OutDir"
