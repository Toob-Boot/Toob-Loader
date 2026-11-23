param(
    [string]$BuildDir = "D:\ToobStorage\tmp_build\w3d_corstone300\build_corstone300",
    [string]$OutDir   = "D:\ToobStorage\tmp_build\w3d_corstone300\apps",
    [string]$GccDir   = "",
    [string]$ToobCli  = ""
)

$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path "$PSScriptRoot\..\..\..").Path
$BuildDir = (Resolve-Path $BuildDir).Path
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$OutDir = (Resolve-Path $OutDir).Path

if (-not $GccDir) {
    $GccCandidates = @(
        "D:\ToobStorage\toolchains\arm-none-eabi\15.2.1-1.1\xpack-arm-none-eabi-gcc-15.2.1-1.1\bin",
        "$env:USERPROFILE\.toob\toolchains\arm-none-eabi\15.2.1-1.1\xpack-arm-none-eabi-gcc-15.2.1-1.1\bin"
    )
    foreach ($cand in $GccCandidates) {
        if (Test-Path (Join-Path $cand "arm-none-eabi-gcc.exe")) {
            $GccDir = $cand
            break
        }
    }
}
if (-not $GccDir) {
    throw "arm-none-eabi-gcc.exe not found in D:\ToobStorage or ~/.toob"
}

if (-not $ToobCli) {
    $ToobCli = if ($env:TOOB_CLI_BIN -and (Test-Path $env:TOOB_CLI_BIN)) {
        $env:TOOB_CLI_BIN
    } elseif (Test-Path (Join-Path $RepoRoot "toob.exe")) {
        Join-Path $RepoRoot "toob.exe"
    } elseif (Test-Path (Join-Path $RepoRoot "cli\toob-cli\toob.exe")) {
        Join-Path $RepoRoot "cli\toob-cli\toob.exe"
    } elseif (Test-Path "D:\ToobStorage\linux_tools\toob.cmd") {
        "D:\ToobStorage\linux_tools\toob.cmd"
    } else {
        ""
    }
}

function Invoke-ToobSign([string[]]$SignArgs) {
    if ($ToobCli -and (Test-Path $ToobCli)) {
        & $ToobCli @SignArgs
    } else {
        Push-Location "$RepoRoot\cli\toob-cli"
        try {
            & go run . @SignArgs
        } finally {
            Pop-Location
        }
    }
    if ($LASTEXITCODE -ne 0) {
        throw "toob $($SignArgs -join ' ') failed"
    }
}

$Gcc     = Join-Path $GccDir "arm-none-eabi-gcc.exe"
$Objcopy = Join-Path $GccDir "arm-none-eabi-objcopy.exe"

$CommonFlags = @(
    "-mcpu=cortex-m55",
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
    "-T$PSScriptRoot\app_corstone300.ld",
    "-I$BuildDir\generated",
    "-I$RepoRoot\sdk\libtoob\include",
    "-I$RepoRoot\common\include",
    "-I$RepoRoot\toob-infra\registry\packages\chips\corstone300",
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

    Invoke-ToobSign @("sign", "image", $raw, "-o", $toob, "--entry", "0x100", "--mock")
}

Write-Host "Built all 4 Corstone-300 Cortex-M55 Non-Secure guest apps in $OutDir"
