[CmdletBinding()]
param(
    [switch]$Quick,
    [switch]$Full
)

$ErrorActionPreference = "Stop"

if ($Quick -and $Full) {
    throw "Specify either -Quick or -Full, not both."
}
$RunFull = [bool]$Full
$ModeLabel = if ($RunFull) { "Full" } else { "Quick" }
$FuzzIters = if ($RunFull) { 4096 } else { 1024 }

$RepoRoot = (Resolve-Path "$PSScriptRoot\..").Path
Push-Location $RepoRoot
try {
    $WorkBase = if ($env:TOOB_SEC_WORKDIR) { $env:TOOB_SEC_WORKDIR } else { "D:\ToobStorage\tmp_build\w2sec" }
    New-Item -ItemType Directory -Force -Path $WorkBase | Out-Null
    $env:TMP = $WorkBase
    $env:TEMP = $WorkBase
    $env:TMPDIR = $WorkBase

    $ClangExe = "C:\Program Files\LLVM\bin\clang.exe"
    $ClangRtDir = "C:\Program Files\LLVM\lib\clang\22\lib\windows"
    $GccExe = "C:\msys64\ucrt64\bin\gcc.exe"

    $UseClang = Test-Path $ClangExe
    if (-not $UseClang -and -not (Test-Path $GccExe)) {
        $clangCmd = Get-Command clang -ErrorAction SilentlyContinue
        $gccCmd = Get-Command gcc -ErrorAction SilentlyContinue
        if ($clangCmd) {
            $ClangExe = $clangCmd.Source
            $UseClang = $true
        } elseif ($gccCmd) {
            $GccExe = $gccCmd.Source
        } else {
            throw "No supported C17 host compiler found (clang or gcc)."
        }
    }

    if ($UseClang) {
        $Cc = $ClangExe
        $SanFlags = @('-fsanitize=address,undefined', '-fno-omit-frame-pointer')
        $WinCrtDefs = @('-D_CRT_SECURE_NO_WARNINGS=1')
        if (Test-Path $ClangRtDir) {
            $env:PATH = "$ClangRtDir;$(Split-Path $ClangExe);" + $env:PATH
        }
    } else {
        $Cc = $GccExe
        $SanFlags = @()
        $WinCrtDefs = @()
        $env:PATH = "$(Split-Path $GccExe);" + $env:PATH
    }

    $PythonExe = (Get-Command python -ErrorAction SilentlyContinue).Source
    if (-not $PythonExe) {
        foreach ($cand in @("C:\Python314\python.exe", "C:\msys64\ucrt64\bin\python.exe")) {
            if (Test-Path $cand) { $PythonExe = $cand; break }
        }
    }
    if (-not $PythonExe) {
        throw "Python interpreter not found."
    }

    Write-Host "=== Toob-Loader Security Suite ($ModeLabel) ==="
    Write-Host "Compiler: $Cc (Sanitizers: $($SanFlags -join ' '))"
    Write-Host "WorkDir : $WorkBase"

    # -----------------------------------------------------------------------
    # Verify required directories & Tier 1 seed corpora
    # -----------------------------------------------------------------------
    $RequiredCorpus = @("tbm1", "tcc1", "kdm", "wal_journal", "cobs_mailbox", "xmodem", "decomp_delta", "multiimage")
    foreach ($cName in $RequiredCorpus) {
        $cPath = Join-Path $RepoRoot "test\fuzz\corpus\$cName"
        if (-not (Test-Path $cPath) -or ((Get-ChildItem $cPath -File).Count -eq 0)) {
            throw "Missing or empty fuzz corpus directory: $cPath"
        }
    }

    # -----------------------------------------------------------------------
    # Shared object compilation (Third-Party + Fuzz Common)
    # -----------------------------------------------------------------------
    $BuildDir = Join-Path $WorkBase "suite_$($ModeLabel.ToLowerInvariant())"
    New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null

    $FuzzIncs = @(
        "-Itest/fuzz",
        "-Itest/fuzz/include",
        "-Icommon/include",
        "-Icommon/lib/heatshrink",
        "-Itoobloader/core/include",
        "-Itoobloader/core/utils/include",
        "-Isdk/libtoob",
        "-Isdk/libtoob/include",
        "-Irecovery",
        "-Itoob-infra/registry/packages/crypto/backend/monocypher",
        "-Itoob-infra/registry/packages/crypto/hash/sha256_sw"
    )
    $FuzzDefs = @(
        "-DHEATSHRINK_DYNAMIC_ALLOC=0",
        "-DHEATSHRINK_STATIC_INPUT_BUFFER_SIZE=128",
        "-DHEATSHRINK_STATIC_WINDOW_BITS=8",
        "-DHEATSHRINK_STATIC_LOOKAHEAD_BITS=4"
    ) + $WinCrtDefs

    $ThirdPartySrcs = @(
        "common/lib/heatshrink/heatshrink_decoder.c",
        "toob-infra/registry/packages/crypto/backend/monocypher/monocypher.c",
        "toob-infra/registry/packages/crypto/backend/monocypher/monocypher-ed25519.c",
        "toob-infra/registry/packages/crypto/backend/monocypher/crypto_monocypher.c",
        "toob-infra/registry/packages/crypto/hash/sha256_sw/sha256.c",
        "toob-infra/registry/packages/crypto/hash/sha256_sw/crypto_sha256.c"
    )
    $FuzzCommonSrcs = @(
        "test/fuzz/fuzz_platform.c",
        "toobloader/core/utils/boot_crc32.c",
        "toobloader/core/utils/boot_identity.c",
        "toobloader/core/utils/boot_secure_zeroize_host.c"
    )

    $TpObjs = @()
    foreach ($src in $ThirdPartySrcs) {
        if (-not (Test-Path $src)) { throw "Missing source file: $src" }
        $obj = Join-Path $BuildDir (([System.IO.Path]::GetFileNameWithoutExtension($src)) + "_tp.o")
        & $Cc -std=c17 -O1 -g @SanFlags @FuzzIncs @FuzzDefs -c $src -o $obj
        if ($LASTEXITCODE -ne 0) { throw "Compilation failed for third-party source: $src" }
        $TpObjs += $obj
    }

    $CmObjs = @()
    foreach ($src in $FuzzCommonSrcs) {
        if (-not (Test-Path $src)) { throw "Missing source file: $src" }
        $obj = Join-Path $BuildDir (([System.IO.Path]::GetFileNameWithoutExtension($src)) + "_cm.o")
        & $Cc -std=c17 -Wall -Wextra -Werror -O1 -g @SanFlags @FuzzIncs @FuzzDefs -c $src -o $obj
        if ($LASTEXITCODE -ne 0) { throw "Compilation failed for fuzz common source: $src" }
        $CmObjs += $obj
    }

    # -----------------------------------------------------------------------
    # TIER 1: 8 Fuzz Targets (Corpus Replay + Structured Mutations)
    # -----------------------------------------------------------------------
    Write-Host "`n--- [Tier 1] Compiling & Executing 8 Fuzz Harnesses (iters=$FuzzIters) ---"
    $FuzzTargets = @(
        @{ Name = "fuzz_tbm1"; Srcs = @("test/fuzz/fuzz_tbm1.c", "toobloader/core/boot_tbm1.c", "toobloader/core/boot_verify.c") },
        @{ Name = "fuzz_tcc1"; Srcs = @("test/fuzz/fuzz_tcc1.c", "toobloader/core/boot_cloud_cmd.c", "toobloader/core/boot_journal.c", "toobloader/core/boot_rstore.c") },
        @{ Name = "fuzz_kdm"; Srcs = @("test/fuzz/fuzz_kdm.c", "toobloader/core/boot_cloud_cmd.c", "toobloader/core/boot_journal.c", "toobloader/core/boot_rstore.c", "toobloader/core/utils/boot_cobs.c") },
        @{ Name = "fuzz_wal_journal"; Srcs = @("test/fuzz/fuzz_wal_journal.c", "toobloader/core/boot_journal.c") },
        @{ Name = "fuzz_cobs_mailbox"; Srcs = @("test/fuzz/fuzz_cobs_mailbox.c", "toobloader/core/utils/boot_cobs.c", "toobloader/core/boot_mailbox.c", "toobloader/core/boot_journal.c") },
        @{ Name = "fuzz_xmodem"; Srcs = @("test/fuzz/fuzz_xmodem.c", "sdk/libtoob/toob_ota.c", "sdk/libtoob/toob_update.c", "sdk/libtoob/toob_mailbox.c", "sdk/libtoob/toob_handoff.c", "sdk/libtoob/toob_crc32.c") },
        @{ Name = "fuzz_decomp_delta"; Srcs = @("test/fuzz/fuzz_decomp_delta.c", "toobloader/core/boot_decomp.c", "toobloader/core/boot_delta.c", "toobloader/core/boot_swap.c", "toobloader/core/boot_effect.c", "toobloader/core/boot_journal.c") },
        @{ Name = "fuzz_multiimage"; Srcs = @("test/fuzz/fuzz_multiimage.c", "toobloader/core/boot_multiimage.c", "toobloader/core/boot_verify.c", "toobloader/core/boot_swap.c", "toobloader/core/boot_effect.c", "toobloader/core/boot_journal.c") }
    )

    $Tier1Passed = 0
    foreach ($tgt in $FuzzTargets) {
        foreach ($s in $tgt.Srcs) {
            if (-not (Test-Path $s)) { throw "Missing Tier 1 target source: $s" }
        }
        $exe = Join-Path $BuildDir ($tgt.Name + ".exe")
        & $Cc -std=c17 -Wall -Wextra -Werror -O1 -g @SanFlags -DTOOB_FUZZ_STANDALONE=1 @FuzzIncs @FuzzDefs @($tgt.Srcs) @CmObjs @TpObjs -o $exe
        if ($LASTEXITCODE -ne 0) { throw "Tier 1 build failed for $($tgt.Name)" }

        $out = & $exe "--iters=$FuzzIters"
        if ($LASTEXITCODE -ne 0) { throw "Tier 1 execution failed for $($tgt.Name)" }
        $outLines = ($out | Out-String).Trim()
        Write-Host "  $outLines"
        if ($outLines -notmatch "status=PASS") {
            throw "Tier 1 target $($tgt.Name) did not report status=PASS"
        }
        $Tier1Passed++
    }

    # -----------------------------------------------------------------------
    # TIER 3C: Vendor-Agnostic HAL Security Qualification Suite
    # -----------------------------------------------------------------------
    Write-Host "`n--- [Tier 3C] Compiling & Executing HAL Security Qualification Suite ---"
    $HqIncs = @(
        "-Itest/hal_qual",
        "-Itest/fuzz/include",
        "-Icommon/include",
        "-Itoobloader/core/include",
        "-Itoobloader/core/utils/include",
        "-Isdk/libtoob/include",
        "-Itoob-infra/registry/packages/crypto/backend/monocypher",
        "-Itoob-infra/registry/packages/crypto/hash/sha256_sw"
    )
    $HqLibSrcs = @(
        "test/hal_qual/qual_crypto.c",
        "test/hal_qual/qual_entropy.c",
        "test/hal_qual/qual_flash.c",
        "test/hal_qual/qual_keystore_soc.c"
    )
    $HqMainSrcs = @(
        "test/hal_qual/hal_qual_main.c",
        "toobloader/core/utils/boot_crc32.c",
        "toobloader/core/utils/boot_identity.c",
        "toobloader/core/utils/boot_secure_zeroize_host.c"
    )

    $HqObjs = @()
    foreach ($src in $HqLibSrcs) {
        if (-not (Test-Path $src)) { throw "Missing Tier 3C source: $src" }
        $obj = Join-Path $BuildDir (([System.IO.Path]::GetFileNameWithoutExtension($src)) + "_hq.o")
        & $Cc -std=c17 -Wall -Wextra -Werror -Wconversion -Wshadow -O1 -g @SanFlags @HqIncs @WinCrtDefs -c $src -o $obj
        if ($LASTEXITCODE -ne 0) { throw "Tier 3C library compile failed: $src" }
        $HqObjs += $obj
    }

    $HqExe = Join-Path $BuildDir "hal_qual_selftest.exe"
    & $Cc -std=c17 -Wall -Wextra -Werror -O1 -g @SanFlags @HqIncs @WinCrtDefs @HqMainSrcs @HqObjs @TpObjs -o $HqExe
    if ($LASTEXITCODE -ne 0) { throw "Tier 3C selftest link failed" }

    $hqOut = & $HqExe
    if ($LASTEXITCODE -ne 0) { throw "Tier 3C HAL Qualification failed" }
    $hqText = ($hqOut | Out-String).Trim()
    Write-Host "  $hqText"
    if ($hqText -notmatch "status=PASS") {
        throw "Tier 3C HAL Qualification did not report status=PASS"
    }

    # -----------------------------------------------------------------------
    # TIER 2: Renode FIH Campaign, SRAM Audit, Probe App & Negative E2E
    # -----------------------------------------------------------------------
    Write-Host "`n--- [Tier 2] Executing FIH & Negative Security Verification ($ModeLabel) ---"
    $FihScript = Join-Path $RepoRoot "test\fih_emu\fih_fault_campaign.py"
    if (-not (Test-Path $FihScript)) {
        throw "Missing Tier 2 script: $FihScript"
    }
    $FihWorkDir = Join-Path $WorkBase "fih_emu"
    $FihFlag = if ($RunFull) { "--full" } else { "--dry-run" }

    & $PythonExe -B -u $FihScript $FihFlag --work-dir $FihWorkDir
    if ($LASTEXITCODE -ne 0) {
        throw "Tier 2 campaign ($FihFlag) failed with exit code $LASTEXITCODE"
    }

    Write-Host "`nSECURITY_SUITE_SUMMARY mode=$ModeLabel tier1_fuzzers=$Tier1Passed/8 tier2=$FihFlag tier3c=PASS status=PASS"
}
finally {
    Pop-Location
}
