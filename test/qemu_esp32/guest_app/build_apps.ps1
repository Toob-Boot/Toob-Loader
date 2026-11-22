param(
    [string]$BuildDir = "D:\ToobStorage\tmp_build\w3b_esp32\build_esp32",
    [string]$OutDir   = "D:\ToobStorage\tmp_build\w3b_esp32\apps",
    [string]$GccDir   = "G:\Espressif\tools\xtensa-esp-elf\esp-15.2.0_20251204\xtensa-esp-elf\bin",
    [string]$ToobCli  = ""
)

$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path "$PSScriptRoot\..\..\..").Path

if (-not (Test-Path $GccDir)) {
    $FallbackGcc = "$env:USERPROFILE\.toob\toolchains\xtensa-esp32-elf\esp-15.2.0_20251204\xtensa-esp-elf\bin"
    if (Test-Path $FallbackGcc) {
        $GccDir = $FallbackGcc
    } else {
        throw "xtensa-esp32-elf toolchain not found at $GccDir"
    }
}

if ([string]::IsNullOrWhiteSpace($ToobCli)) {
    if ($env:TOOB_CLI_BIN -and (Test-Path $env:TOOB_CLI_BIN)) {
        $ToobCli = $env:TOOB_CLI_BIN
    } elseif (Test-Path (Join-Path $RepoRoot "toob.exe")) {
        $ToobCli = Join-Path $RepoRoot "toob.exe"
    } elseif (Test-Path (Join-Path $RepoRoot "cli\toob-cli\toob.exe")) {
        $ToobCli = Join-Path $RepoRoot "cli\toob-cli\toob.exe"
    } elseif (Test-Path "D:\ToobStorage\linux_tools\toob.cmd") {
        $ToobCli = "D:\ToobStorage\linux_tools\toob.cmd"
    } else {
        throw "toob CLI binary not found (set TOOB_CLI_BIN or pass -ToobCli)"
    }
}

$BuildDir = (Resolve-Path $BuildDir).Path
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$OutDir = (Resolve-Path $OutDir).Path

$Gcc     = Join-Path $GccDir "xtensa-esp32-elf-gcc.exe"
$Objcopy = Join-Path $GccDir "xtensa-esp32-elf-objcopy.exe"

$CommonFlags = @(
    "-mlongcalls",
    "-mtext-section-literals",
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
    "-T$PSScriptRoot\app_esp32.ld",
    "-I$BuildDir\generated",
    "-I$RepoRoot\sdk\libtoob\include",
    "-I$RepoRoot\common\include",
    "-I$RepoRoot\toob-infra\registry\packages\soc\esp\include",
    "-I$RepoRoot\toob-infra\registry\packages\chips\esp32",
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

    $signedOk = $false
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        & $ToobCli sign image $raw -o $toob --entry 0x14
        if ($LASTEXITCODE -eq 0) {
            $signedOk = $true
            break
        }
        Start-Sleep -Seconds 2
    }
    if (-not $signedOk) { throw "toob sign image failed for $($v.Name)" }
}

Write-Host "Built all 4 ESP32 (Xtensa LX6) Split IROM/DROM guest apps in $OutDir"
