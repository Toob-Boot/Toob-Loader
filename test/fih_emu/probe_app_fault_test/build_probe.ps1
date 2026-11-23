param(
    [string]$BuildDir = "$PSScriptRoot\..\..\..\test\renode_nrf52840\builds\build_nrf52840",
    [string]$OutDir   = "D:\ToobStorage\tmp_build\w2sec\fih_emu\probe_app",
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

if (-not (Test-Path $Gcc)) { throw "Missing arm-none-eabi-gcc: $Gcc" }
if (-not (Test-Path $ToobCli)) { throw "Missing toob CLI: $ToobCli" }

$elf  = Join-Path $OutDir "probe_app_fault_test.elf"
$raw  = Join-Path $OutDir "probe_app_fault_test.raw.bin"
$toob = Join-Path $OutDir "probe_app_fault_test.toob"

$flags = @(
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
    "-T$PSScriptRoot\probe_nrf52840.ld",
    "-I$BuildDir\generated",
    "-I$RepoRoot\sdk\libtoob\include",
    "-I$RepoRoot\common\include",
    "-I$RepoRoot\toob-infra\registry\packages\chips\nrf52840",
    "-I$RepoRoot\toob-infra\registry\packages\crypto\hash\sha256_sw",
    "$PSScriptRoot\probe_main.c",
    "$RepoRoot\toobloader\core\utils\boot_secure_zeroize.S",
    "$BuildDir\libtoob_libtoob.a",
    "$BuildDir\libtoob_crypto_upstream.a",
    "-o", $elf
)

& $Gcc @flags
if ($LASTEXITCODE -ne 0) { throw "GCC failed for probe_app_fault_test" }

& $Objcopy -O binary $elf $raw
if ($LASTEXITCODE -ne 0) { throw "objcopy failed for probe_app_fault_test" }

& $ToobCli sign image $raw -o $toob --entry 0x100 --mock
if ($LASTEXITCODE -ne 0) { throw "toob sign image failed for probe_app_fault_test" }

Write-Host "Built and signed probe_app_fault_test -> $toob"
