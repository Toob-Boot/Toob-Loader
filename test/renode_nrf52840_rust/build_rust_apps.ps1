param(
    [string]$GeneratedConfigDir = "$PSScriptRoot\..\renode_nrf52840\builds\build_nrf52840\generated",
    [string]$OutDir             = "D:\ToobStorage\renode_rust_build\apps",
    [string]$CargoTargetDir     = "D:\ToobStorage\cargo_target_sdk",
    [string]$CargoExe           = "G:\rust\.cargo\bin\cargo.exe",
    [string]$GccDir             = "$env:USERPROFILE\.toob\toolchains\arm-none-eabi\15.2.1-1.1\xpack-arm-none-eabi-gcc-15.2.1-1.1\bin"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $GccDir)) {
    $altGcc = "D:\ToobStorage\toolchains\arm-none-eabi\15.2.1-1.1\xpack-arm-none-eabi-gcc-15.2.1-1.1\bin"
    if (Test-Path $altGcc) { $GccDir = $altGcc }
}
$Objcopy = Join-Path $GccDir "arm-none-eabi-objcopy.exe"
if (-not (Test-Path $Objcopy)) {
    throw "arm-none-eabi-objcopy.exe not found at $Objcopy"
}

$GeneratedConfigDir = (Resolve-Path $GeneratedConfigDir).Path
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$OutDir = (Resolve-Path $OutDir).Path

$GuestCrateDir = Join-Path $PSScriptRoot "guest_app_rust"
$LdScriptPath  = Join-Path $GuestCrateDir "app_nrf52840_rust.ld"

function New-ToobTaggedImage {
    param(
        [byte[]]$RawBytes,
        [uint32]$EntryOffset = 0x100
    )

    $pad = (4 - ($RawBytes.Length % 4)) % 4
    if ($pad -gt 0) {
        $padded = New-Object byte[] ($RawBytes.Length + $pad)
        [Array]::Copy($RawBytes, 0, $padded, 0, $RawBytes.Length)
        for ($i = $RawBytes.Length; $i -lt $padded.Length; $i++) {
            $padded[$i] = 0xFF
        }
        $RawBytes = $padded
    }

    $headerLen = 20
    $totalSize = [uint32]($headerLen + $RawBytes.Length)
    $header    = New-Object byte[] $headerLen

    [Array]::Copy([BitConverter]::GetBytes([uint32]0x544F4F42), 0, $header, 0, 4)
    [Array]::Copy([BitConverter]::GetBytes($totalSize),         0, $header, 4, 4)
    [Array]::Copy([BitConverter]::GetBytes($EntryOffset),       0, $header, 8, 4)

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $fp = $sha.ComputeHash($RawBytes)
    } finally {
        $sha.Dispose()
    }
    [Array]::Copy($fp, 0, $header, 12, 8)

    $combined = New-Object byte[] $totalSize
    [Array]::Copy($header,   0, $combined, 0,          $headerLen)
    [Array]::Copy($RawBytes, 0, $combined, $headerLen, $RawBytes.Length)
    return $combined
}

$Variants = @(
    @{ Name = "rust_app_v1";     Ver = "1.0.0"; Crash = "0" },
    @{ Name = "rust_app_v2";     Ver = "2.0.0"; Crash = "0" },
    @{ Name = "rust_app_v3";     Ver = "3.0.0"; Crash = "0" },
    @{ Name = "rust_app_bad_v4"; Ver = "4.0.0"; Crash = "1" }
)

Push-Location $GuestCrateDir
try {
    $env:CARGO_TARGET_DIR          = $CargoTargetDir
    $env:TOOB_GENERATED_CONFIG_DIR = $GeneratedConfigDir
    $env:RUSTFLAGS                 = "-C link-arg=-T$LdScriptPath -C link-arg=--gc-sections"

    foreach ($v in $Variants) {
        $env:TOOB_RUST_APP_VER       = $v.Ver
        $env:TOOB_RUST_CRASH_ON_BOOT = $v.Crash

        & $CargoExe build --offline --release --target thumbv7em-none-eabihf
        if ($LASTEXITCODE -ne 0) { throw "cargo build failed for $($v.Name)" }

        $builtElf = Join-Path $CargoTargetDir "thumbv7em-none-eabihf\release\guest_app_rust"
        if (-not (Test-Path $builtElf)) {
            $builtElf = "$builtElf.exe"
        }

        $outElf  = Join-Path $OutDir ($v.Name + ".elf")
        $outRaw  = Join-Path $OutDir ($v.Name + ".raw.bin")
        $outToob = Join-Path $OutDir ($v.Name + ".toob")

        Copy-Item -Force $builtElf $outElf
        & $Objcopy -O binary $outElf $outRaw
        if ($LASTEXITCODE -ne 0) { throw "objcopy failed for $($v.Name)" }

        $rawBytes  = [System.IO.File]::ReadAllBytes($outRaw)
        $toobBytes = New-ToobTaggedImage -RawBytes $rawBytes -EntryOffset 0x100
        [System.IO.File]::WriteAllBytes($outToob, $toobBytes)
    }
} finally {
    Remove-Item Env:\TOOB_RUST_APP_VER       -ErrorAction SilentlyContinue
    Remove-Item Env:\TOOB_RUST_CRASH_ON_BOOT -ErrorAction SilentlyContinue
    Remove-Item Env:\RUSTFLAGS               -ErrorAction SilentlyContinue
    Pop-Location
}

Write-Host "Built all 4 #![no_std] Cortex-M4F Rust guest apps in $OutDir"
