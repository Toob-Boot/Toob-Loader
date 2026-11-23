param(
    [ValidateSet("regression", "judge")]
    [string]$Mode = "regression",
    [string]$Filter = "",
    [string]$Backend = "",
    [string]$SubmissionsDir = "",
    [switch]$Quick,
    [switch]$VerifyCleanTarget
)

$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

Push-Location $RepoRoot
try {
    $WorkBase = if (Test-Path "D:\ToobStorage") {
        "D:\ToobStorage\tmp_build\attack_corpus"
    } else {
        Join-Path $RepoRoot "build_attack_corpus"
    }
    New-Item -ItemType Directory -Force -Path $WorkBase | Out-Null
    $env:TMP = $WorkBase
    $env:TEMP = $WorkBase
    $env:TMPDIR = $WorkBase

    if (-not $env:TOOB_RENODE_BIN -and (Test-Path "D:\ToobStorage\tools\renode-1.17.0\renode_1.17.0-portable\renode.exe")) {
        $env:TOOB_RENODE_BIN = "D:\ToobStorage\tools\renode-1.17.0\renode_1.17.0-portable\renode.exe"
    }
    if (-not $env:TOOB_QEMU_ESP_DEV_BIN -and (Test-Path "D:\ToobStorage\tools\qemu-esp-dev\bin\qemu-system-riscv32.exe")) {
        $env:TOOB_QEMU_ESP_DEV_BIN = "D:\ToobStorage\tools\qemu-esp-dev\bin\qemu-system-riscv32.exe"
    }
    $clangRt = "C:\Program Files\LLVM\lib\clang\22\lib\windows"
    if ((Test-Path $clangRt) -and ($env:PATH -notlike "*$clangRt*")) {
        $env:PATH = "$clangRt;C:\Program Files\LLVM\bin;$env:PATH"
    }

    $pyArgs = @(
        "-B", "-u",
        (Join-Path $RepoRoot "test\attack_corpus\judge_runner.py"),
        "--mode", $Mode,
        "--work-dir", $WorkBase
    )
    if ($Filter) { $pyArgs += @("--filter", $Filter) }
    if ($Backend) { $pyArgs += @("--backend", $Backend) }
    if ($SubmissionsDir) { $pyArgs += @("--submissions-dir", $SubmissionsDir) }
    if ($Quick) { $pyArgs += "--quick" }
    if ($VerifyCleanTarget) { $pyArgs += "--verify-clean-target" }

    & python @pyArgs
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
} finally {
    Pop-Location
}
