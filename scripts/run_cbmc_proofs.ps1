param(
    [string]$Filter = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

# ---------------------------------------------------------------------------
# 1. Disk & Toolchain Isolation (Zero writes to C:; route all build/temp to D:)
# ---------------------------------------------------------------------------
$RepoRoot   = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$BuildRoot  = "D:\ToobStorage\tmp_build\f1_cbmc"
$TmpDir     = Join-Path $BuildRoot "tmp"
$LogDir     = Join-Path $BuildRoot "logs"
$CbmcShim   = "D:\ToobStorage\tools\cbmc\shim"
$CbmcBin    = "D:\ToobStorage\tools\cbmc\cbmc\bin"

New-Item -ItemType Directory -Force -Path $BuildRoot, $TmpDir, $LogDir | Out-Null
$env:TEMP = $TmpDir
$env:TMP  = $TmpDir
$env:PATH = "$CbmcShim;$CbmcBin;$env:PATH"

$CbmcExe = Join-Path $CbmcBin "cbmc.exe"
$GotoInstExe = Join-Path $CbmcBin "goto-instrument.exe"

if (-not (Test-Path $CbmcExe)) {
    throw "cbmc.exe not found at $CbmcExe"
}
if (-not (Test-Path $GotoInstExe)) {
    throw "goto-instrument.exe not found at $GotoInstExe"
}

# ---------------------------------------------------------------------------
# 2. UTF-8 No-BOM Sanity Gate Across Owned Formal Files
# ---------------------------------------------------------------------------
$OwnedFiles = @(Get-ChildItem -Path (Join-Path $RepoRoot "test\formal\cbmc") -Recurse -File -Include *.c, *.h) +
              @(Get-Item -Path $PSCommandPath)
foreach ($f in $OwnedFiles) {
    $bytes = [System.IO.File]::ReadAllBytes($f.FullName)
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        throw "UTF-8 BOM forbidden in $($f.FullName)"
    }
}

# ---------------------------------------------------------------------------
# 3. Mandatory CBMC Verification Flags & Shared Contracts
# ---------------------------------------------------------------------------
$MandatoryChecks = @(
    "--drop-unused-functions",
    "--object-bits", "10",
    "--bounds-check",
    "--pointer-check",
    "--signed-overflow-check",
    "--unsigned-overflow-check",
    "--div-by-zero-check",
    "--pointer-overflow-check",
    "--unwinding-assertions"
)

$BaseIncludes = @(
    "-Itest/formal/cbmc",
    "-Itest/formal/cbmc/include",
    "-Icommon/include",
    "-Itoobloader/include",
    "-Itoobloader/core/include",
    "-Itoobloader/core/utils/include",
    "-Isdk/libtoob/include",
    "-Isdk/libtoob",
    "-Icommon/lib/heatshrink",
    "-Itoobloader/stage0",
    "-Itoobloader/stage0/include",
    "-Irecovery",
    "-Isdk/os_client/include"
)

$StdCoreContracts = @{
    "cfi_derive"                        = "cbmc_cfi_derive_mod32"
    "boot_proof_mix"                    = "cbmc_boot_proof_mix_mod32"
    "constant_time_memcmp_glitch_safe"  = "cbmc_ct_memcmp_contract"
    "verify_not_all_zeros_glitch_safe"  = "cbmc_verify_not_all_zeros_contract"
    "is_fully_erased_constant_time"     = "cbmc_is_fully_erased_contract"
    "boot_crc32_update"                 = "cbmc_boot_crc32_update_contract"
    "compute_boot_crc32"                = "cbmc_compute_boot_crc32_contract"
    "boot_crc32_fill"                   = "cbmc_boot_crc32_fill_contract"
    "boot_crc32_flash_stream"           = "cbmc_boot_crc32_flash_stream_contract"
    "boot_flash_is_erased"              = "cbmc_boot_flash_is_erased_contract"
    "boot_random_safe"                  = "cbmc_boot_random_safe_contract"
}

$HsdContracts = @{
    "heatshrink_decoder_reset"  = "cbmc_hsd_reset_contract"
    "heatshrink_decoder_sink"   = "cbmc_hsd_sink_contract"
    "heatshrink_decoder_poll"   = "cbmc_hsd_poll_contract"
    "heatshrink_decoder_finish" = "cbmc_hsd_finish_contract"
}

$SectorCopyContracts = @{
    "stream_write_skip_erased"   = "cbmc_write_skip_erased_contract"
    "effect_write_skip_erased"   = "cbmc_write_skip_erased_contract"
    "stream_copy"                = "cbmc_stream_copy_contract"
    "boot_swap_blocks_identical" = "cbmc_swap_blocks_identical_contract"
}

function Merge-Hashtable([hashtable]$Base, [hashtable]$Extra) {
    $m = @{}
    foreach ($k in $Base.Keys)  { $m[$k] = $Base[$k] }
    foreach ($k in $Extra.Keys) { $m[$k] = $Extra[$k] }
    return $m
}

$script:TotalPassed = 0
$script:TotalFailed = 0
$script:SuiteTimer  = [System.Diagnostics.Stopwatch]::StartNew()
$script:Results     = New-Object System.Collections.Generic.List[object]

function Invoke-ProofBundle {
    param(
        [Parameter(Mandatory = $true)][string]$BundleName,
        [Parameter(Mandatory = $true)][string[]]$Sources,
        [string[]]$Defines = @(),
        [Parameter(Mandatory = $true)][array]$Profiles
    )

    # Check if any proof in this bundle matches $Filter
    $matchingProfiles = @()
    foreach ($prof in $Profiles) {
        $matchingRuns = @()
        foreach ($run in $prof.Runs) {
            $fullId = "$BundleName::$($run.Label)"
            if ([string]::IsNullOrEmpty($Filter) -or ($fullId -like "*$Filter*")) {
                $matchingRuns += $run
            }
        }
        if ($matchingRuns.Count -gt 0) {
            $matchingProfiles += @{
                ReplaceCalls = $prof.ReplaceCalls
                Runs         = $matchingRuns
            }
        }
    }
    if ($matchingProfiles.Count -eq 0) {
        return
    }

    $safeBundle = ($BundleName -replace '[^A-Za-z0-9_.-]', '_')
    $rawGb      = Join-Path $BuildRoot "$safeBundle.raw.gb"
    $compileLog = Join-Path $LogDir "$safeBundle.compile.log"

    Push-Location $RepoRoot
    try {
        $compileArgs = @(
            "--gcc", "--arch", "arm", "--os", "linux", "--c17",
            "--object-bits", "10",
            "--no-standard-checks",
            "-DHEATSHRINK_DYNAMIC_ALLOC=0"
        ) + $Defines + $BaseIncludes + $Sources + @("--export-symex-ready-goto", $rawGb)

        $prevEap = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        $compileOut = & $CbmcExe @compileArgs 2>&1
        $compileExit = $LASTEXITCODE
        $ErrorActionPreference = $prevEap
        [System.IO.File]::WriteAllText($compileLog, ($compileOut | Out-String), [System.Text.UTF8Encoding]::new($false))
        if ($compileExit -ne 0 -or -not (Test-Path $rawGb)) {
            Write-Host "[FAIL-COMPILE] $BundleName (exit=$compileExit) -> $compileLog" -ForegroundColor Red
            $script:TotalFailed++
            $script:Results.Add([PSCustomObject]@{
                Proof    = "$BundleName [COMPILE]"
                Status   = "FAIL"
                Seconds  = 0.0
                Log      = $compileLog
            })
            return
        }

        $prevEap = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        $fnList = & $GotoInstExe --list-goto-functions $rawGb 2>&1
        $ErrorActionPreference = $prevEap

        $profIdx = 0
        foreach ($prof in $matchingProfiles) {
            $profIdx++
            $instGb = Join-Path $BuildRoot "$safeBundle.inst$profIdx.gb"
            try {
                $repPairs = New-Object System.Collections.Generic.List[string]
                $map = $prof.ReplaceCalls
                if ($null -ne $map -and $map.Count -gt 0) {
                    foreach ($line in $fnList) {
                        $s = [string]$line
                        foreach ($orig in $map.Keys) {
                            $escaped = [Regex]::Escape($orig)
                            $rx = '^\s*(?:[A-Za-z0-9_.]+\$\$)?' + $escaped + '(?:\$link\d+)?\s*/\*\s*([^\s*,]+)\s*(?:,|\*/)'
                            if ($s -match $rx) {
                                $sym = $Matches[1]
                                $target = $map[$orig]
                                $pair = "${sym}:${target}"
                                if (-not $repPairs.Contains($pair)) {
                                    $repPairs.Add($pair)
                                }
                            }
                        }
                    }
                }

                if ($repPairs.Count -gt 0) {
                    $instArgs = @()
                    foreach ($p in $repPairs) {
                        $instArgs += @("--replace-calls", $p)
                    }
                    $instArgs += @($rawGb, $instGb)
                    $prevEap = $ErrorActionPreference
                    $ErrorActionPreference = "Continue"
                    $instOut  = & $GotoInstExe @instArgs 2>&1
                    $instExit = $LASTEXITCODE
                    $ErrorActionPreference = $prevEap
                    if ($instExit -ne 0 -or -not (Test-Path $instGb)) {
                        $instLog = Join-Path $LogDir "$safeBundle.inst$profIdx.log"
                        [System.IO.File]::WriteAllText($instLog, ($instOut | Out-String), [System.Text.UTF8Encoding]::new($false))
                        Write-Host "[FAIL-INST] $BundleName profile #$profIdx -> $instLog" -ForegroundColor Red
                        $script:TotalFailed++
                        continue
                    }
                } else {
                    Copy-Item -Path $rawGb -Destination $instGb -Force
                }

                foreach ($run in $prof.Runs) {
                    $fullLabel = "$BundleName::$($run.Label)"
                    $safeRun   = ($fullLabel -replace '[^A-Za-z0-9_.-]', '_')
                    $runLog    = Join-Path $LogDir "$safeRun.log"

                    $objBits = if ($run.ContainsKey("ObjectBits") -and $run.ObjectBits -gt 0) { [string]$run.ObjectBits } else { "10" }
                    $verifyArgs = @("--gcc", "--arch", "arm", "--os", "linux", "--object-bits", $objBits, $instGb)
                    if ($run.ContainsKey("Function") -and -not [string]::IsNullOrEmpty($run.Function)) {
                        $verifyArgs += @("--function", $run.Function)
                    }
                    if ($run.ContainsKey("NoSatPrep") -and $run.NoSatPrep) {
                        $verifyArgs += "--no-sat-preprocessor"
                    }
                    if ($run.ContainsKey("NoArrayFieldSens") -and $run.NoArrayFieldSens) {
                        $verifyArgs += @("--no-array-field-sensitivity", "--slice-formula")
                    }
                    $verifyArgs += $MandatoryChecks
                    $verifyArgs += @("--unwind", [string]$run.Unwind)
                    if ($run.ContainsKey("UnwindSet") -and -not [string]::IsNullOrEmpty($run.UnwindSet)) {
                        $verifyArgs += @("--unwindset", $run.UnwindSet)
                    }

                    $quotedArgs = ($verifyArgs | ForEach-Object {
                        if ($_ -match '[\s"]') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ }
                    }) -join ' '
                    $cmdLine = '""' + $CbmcExe + '" ' + $quotedArgs + ' > "' + $runLog + '" 2>&1"'

                    $psi = New-Object System.Diagnostics.ProcessStartInfo
                    $psi.FileName = "cmd.exe"
                    $psi.Arguments = "/d /s /c $cmdLine"
                    $psi.WorkingDirectory = $RepoRoot
                    $psi.UseShellExecute = $false
                    $psi.CreateNoWindow = $true

                    $sw = [System.Diagnostics.Stopwatch]::StartNew()
                    $proc = [System.Diagnostics.Process]::Start($psi)
                    $finished = $proc.WaitForExit(45000)
                    $sw.Stop()
                    $sec = [Math]::Round($sw.Elapsed.TotalSeconds, 2)

                    if (-not $finished) {
                        $prevEap = $ErrorActionPreference
                        $ErrorActionPreference = "Continue"
                        & taskkill.exe /T /F /PID $proc.Id 2>&1 | Out-Null
                        $ErrorActionPreference = $prevEap
                        $proc.Dispose()
                        Write-Host ("[TIMEOUT] {0} (>45s) -> {1}" -f $fullLabel, $runLog) -ForegroundColor Red
                        $script:TotalFailed++
                        $script:Results.Add([PSCustomObject]@{
                            Proof   = $fullLabel
                            Status  = "TIMEOUT"
                            Seconds = $sec
                            Log     = $runLog
                        })
                        continue
                    }

                    $proc.WaitForExit()
                    $exitCode = $proc.ExitCode
                    $proc.Dispose()
                    $outText  = if (Test-Path $runLog) { [System.IO.File]::ReadAllText($runLog) } else { "" }

                    $hasSuccess = $outText.Contains("VERIFICATION SUCCESSFUL")
                    $hasFailed  = $outText.Contains("VERIFICATION FAILED")

                    if ($exitCode -eq 0 -and $hasSuccess -and (-not $hasFailed)) {
                        Write-Host ("[PASS] {0} ({1:N2}s)" -f $fullLabel, $sec) -ForegroundColor Green
                        $script:TotalPassed++
                        $script:Results.Add([PSCustomObject]@{
                            Proof   = $fullLabel
                            Status  = "PASS"
                            Seconds = $sec
                            Log     = $runLog
                        })
                    } else {
                        Write-Host ("[FAIL] {0} ({1:N2}s, exit={2}) -> {3}" -f $fullLabel, $sec, $exitCode, $runLog) -ForegroundColor Red
                        $script:TotalFailed++
                        $script:Results.Add([PSCustomObject]@{
                            Proof   = $fullLabel
                            Status  = "FAIL"
                            Seconds = $sec
                            Log     = $runLog
                        })
                    }
                }
            } finally {
                if (Test-Path $instGb) { Remove-Item -Force $instGb -ErrorAction SilentlyContinue }
            }
        }
    } finally {
        Pop-Location
        if (Test-Path $rawGb) { Remove-Item -Force $rawGb -ErrorAction SilentlyContinue }
    }
}

# ===========================================================================
# PART 1: WAVE 5A HARNESSES (1 .. 8)
# ===========================================================================

# 1. proof_boot_tbm1.c
Invoke-ProofBundle `
    -BundleName "W5A_01_tbm1" `
    -Sources @(
        "test/formal/cbmc/proof_boot_tbm1.c",
        "toobloader/core/boot_tbm1.c",
        "toobloader/core/utils/boot_crc32.c"
    ) `
    -Profiles @(
        @{
            ReplaceCalls = @{
                "cfi_derive"         = "cbmc_cfi_derive_mod32"
                "boot_proof_mix"     = "cbmc_boot_proof_mix_mod32"
                "boot_crc32_update"  = "cbmc_boot_crc32_update_contract"
                "compute_boot_crc32" = "cbmc_compute_boot_crc32_contract"
            }
            Runs = @(
                @{ Label = "ct_utils_contracts"; Function = "prove_ct_utils_functional_contracts"; Unwind = 10 },
                @{ Label = "pointer_enum_guards"; Function = "prove_tbm1_pointer_and_enum_guards"; Unwind = 6 },
                @{ Label = "staged_pipeline"; Function = "prove_tbm1_staged_pipeline"; Unwind = 10 },
                @{ Label = "validate_facade"; Function = "prove_tbm1_validate_facade"; Unwind = 10 }
            )
        }
    )

# 2. proof_boot_delta.c
$DeltaWriterContracts = @{
    "boot_stream_writer_flush"     = "cbmc_delta_writer_flush_contract"
    "boot_stream_writer_drain_hsd" = "cbmc_delta_writer_drain_hsd_contract"
}
Invoke-ProofBundle `
    -BundleName "W5A_02_delta" `
    -Defines @("-DCBMC_WITH_HSD_CONTRACTS=1") `
    -Sources @(
        "test/formal/cbmc/proof_boot_delta.c",
        "toobloader/core/boot_delta.c",
        "toobloader/core/boot_swap.c",
        "toobloader/core/boot_effect.c",
        "toobloader/core/utils/boot_crc32.c",
        "common/lib/heatshrink/heatshrink_decoder.c"
    ) `
    -Profiles @(
        @{
            ReplaceCalls = (Merge-Hashtable (Merge-Hashtable (Merge-Hashtable $StdCoreContracts $HsdContracts) $SectorCopyContracts) $DeltaWriterContracts)
            Runs = @(
                @{ Label = "delta_apply_sdvm"; Function = "main"; Unwind = 3; NoArrayFieldSens = $true; NoSatPrep = $true; UnwindSet = "boot_stream_writer_init.0:2,verify_ghost_base.0:2" }
            )
        }
    )

# 3. proof_boot_decomp.c (3A: concrete Heatshrink LZSS decoder; 3B: streaming flash pipeline)
Invoke-ProofBundle `
    -BundleName "W5A_03_decomp" `
    -Defines @("-DCBMC_WITH_HSD_CONTRACTS=1") `
    -Sources @(
        "test/formal/cbmc/proof_boot_decomp.c",
        "toobloader/core/boot_decomp.c",
        "toobloader/core/boot_swap.c",
        "toobloader/core/boot_effect.c",
        "toobloader/core/utils/boot_crc32.c",
        "common/lib/heatshrink/heatshrink_decoder.c"
    ) `
    -Profiles @(
        @{
            ReplaceCalls = $StdCoreContracts
            Runs = @(
                @{ Label = "heatshrink_bitreader_window"; Function = "prove_heatshrink_bitreader_and_window_bounds"; Unwind = 3; NoSatPrep = $true; UnwindSet = "heatshrink_decoder_poll.0:7,get_bits.0:9,st_yield_backref.0:3" }
            )
        },
        @{
            ReplaceCalls = (Merge-Hashtable (Merge-Hashtable $StdCoreContracts $HsdContracts) $SectorCopyContracts)
            Runs = @(
                @{ Label = "decomp_streaming_pipeline"; Function = "prove_boot_decomp_streaming_pipeline"; Unwind = 3; NoArrayFieldSens = $true; UnwindSet = "stream_erase_ahead.0:2,stream_verify_readback.1:2,boot_stream_writer_flush.0:2,boot_stream_writer_init.0:2" }
            )
        }
    )

# 4. proof_boot_mailbox.c (HIGH-31)
Invoke-ProofBundle `
    -BundleName "W5A_04_mailbox" `
    -Sources @(
        "test/formal/cbmc/proof_boot_mailbox.c",
        "toobloader/core/boot_mailbox.c",
        "toobloader/core/utils/boot_crc32.c"
    ) `
    -Profiles @(
        @{
            ReplaceCalls = $StdCoreContracts
            Runs = @(
                @{ Label = "mailbox_consume_high31"; Function = "main"; Unwind = 6 }
            )
        }
    )

# 5. proof_boot_cloud_cmd.c
Invoke-ProofBundle `
    -BundleName "W5A_05_cloud_cmd" `
    -Sources @(
        "test/formal/cbmc/proof_boot_cloud_cmd.c",
        "toobloader/core/boot_cloud_cmd.c",
        "toobloader/core/boot_rstore.c",
        "toobloader/core/utils/boot_identity.c",
        "toobloader/core/utils/boot_crc32.c"
    ) `
    -Profiles @(
        @{
            ReplaceCalls = $StdCoreContracts
            Runs = @(
                @{ Label = "evaluate_buffer"; Function = "prove_cloud_cmd_buffer"; Unwind = 5 },
                @{ Label = "evaluate_flash";  Function = "prove_cloud_cmd_flash";  Unwind = 5 }
            )
        }
    )

# 6. proof_boot_journal_align.c across CBMC_ASYMMETRIC_SECTORS={0,1} x CHIP_FLASH_WRITE_ALIGNMENT={1U,4U,8U,32U}
$JournalCoreContracts = Merge-Hashtable $StdCoreContracts @{
    "compute_tmr_mac"    = "cbmc_compute_tmr_mac_contract"
    "compute_entry_mac"  = "cbmc_compute_entry_mac_contract"
}
$JournalInitContracts = Merge-Hashtable $JournalCoreContracts @{
    "boot_journal_update_tmr" = "cbmc_update_tmr_contract"
}
$JournalFastContracts = Merge-Hashtable $JournalCoreContracts @{
    "read_header"             = "cbmc_journal_read_header_contract"
    "boot_derive_journal_key" = "cbmc_derive_journal_key_contract"
}
$JournalTmrContracts = Merge-Hashtable $JournalFastContracts @{
    "boot_journal_reconstruct_txn" = "cbmc_reconstruct_txn_contract"
}
$JournalReconstructUnwind = "boot_journal_reconstruct_txn.1:2,boot_journal_reconstruct_txn.2:2,boot_journal_reconstruct_aux_heal.0:2,boot_journal_reconstruct_aux_heal.1:2,scan_for_frontier_linear.0:3"
foreach ($asym in @(0, 1)) {
    foreach ($align in @(1, 4, 8, 32)) {
        Invoke-ProofBundle `
            -BundleName "W5A_06_journal_asym${asym}_align${align}" `
            -Defines @(
                "-DCBMC_ASYMMETRIC_SECTORS=$asym",
                "-DCHIP_FLASH_WRITE_ALIGNMENT=${align}U"
            ) `
            -Sources @(
                "test/formal/cbmc/proof_boot_journal_align.c",
                "toobloader/core/boot_journal.c",
                "toobloader/core/boot_rstore.c",
                "toobloader/core/utils/boot_identity.c",
                "toobloader/core/utils/boot_crc32.c"
            ) `
            -Profiles @(
                @{
                    ReplaceCalls = $JournalInitContracts
                    Runs = @(
                        @{ Label = "journal_init";   Function = "prove_journal_init";           Unwind = 5; NoArrayFieldSens = $true; UnwindSet = "scan_for_frontier_linear.0:3" },
                        @{ Label = "rstore_padding"; Function = "prove_journal_rstore_padding"; Unwind = 5; NoArrayFieldSens = $true }
                    )
                },
                @{
                    ReplaceCalls = $JournalFastContracts
                    Runs = @(
                        @{ Label = "wal_append";     Function = "prove_journal_wal_append";     Unwind = 5; NoArrayFieldSens = $true; UnwindSet = "scan_for_frontier_linear.0:3" },
                        @{ Label = "reconstruct";    Function = "prove_journal_reconstruct";    Unwind = 5; NoArrayFieldSens = $true; UnwindSet = $JournalReconstructUnwind }
                    )
                },
                @{
                    ReplaceCalls = $JournalTmrContracts
                    Runs = @(
                        @{ Label = "tmr_update";     Function = "prove_journal_tmr_update";     Unwind = 5; NoArrayFieldSens = $true; UnwindSet = "scan_for_frontier_linear.0:3" }
                    )
                }
            )
    }
}

# 7. proof_boot_swap_bounds.c across SWAPSCRATCH/SWAPMOVE/ONEWAY x ASYMMETRIC={0,1} + ALIGN={1,4,8,32}
$SwapMatrix = @(
    @{ Name = "SWAPSCRATCH"; Macro = "TOOB_TRANSPORT_SWAPSCRATCH"; Tu = "toobloader/core/boot_transport_swapscratch.c"; Asym = 0; Align = 1 },
    @{ Name = "SWAPSCRATCH"; Macro = "TOOB_TRANSPORT_SWAPSCRATCH"; Tu = "toobloader/core/boot_transport_swapscratch.c"; Asym = 0; Align = 4 },
    @{ Name = "SWAPSCRATCH"; Macro = "TOOB_TRANSPORT_SWAPSCRATCH"; Tu = "toobloader/core/boot_transport_swapscratch.c"; Asym = 0; Align = 8 },
    @{ Name = "SWAPSCRATCH"; Macro = "TOOB_TRANSPORT_SWAPSCRATCH"; Tu = "toobloader/core/boot_transport_swapscratch.c"; Asym = 0; Align = 32 },
    @{ Name = "SWAPSCRATCH"; Macro = "TOOB_TRANSPORT_SWAPSCRATCH"; Tu = "toobloader/core/boot_transport_swapscratch.c"; Asym = 1; Align = 8 },
    @{ Name = "SWAPSCRATCH"; Macro = "TOOB_TRANSPORT_SWAPSCRATCH"; Tu = "toobloader/core/boot_transport_swapscratch.c"; Asym = 1; Align = 32 },
    @{ Name = "SWAPMOVE";    Macro = "TOOB_TRANSPORT_SWAPMOVE";    Tu = "toobloader/core/boot_transport_swapmove.c";    Asym = 0; Align = 8 },
    @{ Name = "SWAPMOVE";    Macro = "TOOB_TRANSPORT_SWAPMOVE";    Tu = "toobloader/core/boot_transport_swapmove.c";    Asym = 1; Align = 8 },
    @{ Name = "ONEWAY";      Macro = "TOOB_TRANSPORT_ONEWAY";      Tu = "toobloader/core/boot_transport_oneway.c";      Asym = 0; Align = 8 },
    @{ Name = "ONEWAY";      Macro = "TOOB_TRANSPORT_ONEWAY";      Tu = "toobloader/core/boot_transport_oneway.c";      Asym = 1; Align = 32 }
)
foreach ($cfg in $SwapMatrix) {
    $effBound  = if ($cfg.Align -eq 1) { 4.0 } elseif ($cfg.Align -ge 32) { 32.0 } else { 16.0 }
    $effInner  = [int]([Math]::Ceiling($effBound / $cfg.Align)) + 2
    $tpUnwind  = '.iram1$$boot_swap_apply.0:2,boot_swap_erase_tracked.0:4,boot_effect_execute.4:7'
    $tpRuns    = @(
        @{ Label = "transport_provider"; Function = "prove_swap_transport_provider"; Unwind = 3; UnwindSet = $tpUnwind }
    )
    if ($cfg.Name -eq "SWAPSCRATCH" -or ($cfg.Name -eq "SWAPMOVE" -and $cfg.Asym -eq 0)) {
        $tpRuns += @{ Label = "transport_resume"; Function = "prove_swap_transport_resume"; Unwind = 3; UnwindSet = $tpUnwind }
    }
    Invoke-ProofBundle `
        -BundleName "W5A_07_swap_$($cfg.Name)_asym$($cfg.Asym)_align$($cfg.Align)" `
        -Defines @(
            "-DTOOB_TRANSPORT_PROVIDER=$($cfg.Macro)",
            "-DCBMC_ASYMMETRIC_SECTORS=$($cfg.Asym)",
            "-DCHIP_FLASH_WRITE_ALIGNMENT=$($cfg.Align)U"
        ) `
        -Sources @(
            "test/formal/cbmc/proof_boot_swap_bounds.c",
            "toobloader/core/boot_swap.c",
            "toobloader/core/boot_effect.c",
            "toobloader/core/boot_transport.c",
            $cfg.Tu,
            "toobloader/core/utils/boot_crc32.c"
        ) `
        -Profiles @(
            @{
                ReplaceCalls = (Merge-Hashtable $StdCoreContracts @{ "stream_write_skip_erased" = "cbmc_write_skip_erased_contract" })
                Runs = @(
                    @{ Label = "stream_writer";   Function = "prove_swap_stream_writer";   Unwind = 4 }
                )
            },
            @{
                ReplaceCalls = $StdCoreContracts
                Runs = @(
                    @{ Label = "erase_and_solve"; Function = "prove_swap_erase_and_solve"; Unwind = 4; UnwindSet = "effect_write_skip_erased.0:${effInner},effect_write_skip_erased.1:${effInner},effect_write_skip_erased.2:${effInner}" }
                )
            },
            @{
                ReplaceCalls = (Merge-Hashtable (Merge-Hashtable $StdCoreContracts $SectorCopyContracts) @{ "boot_random_safe" = "cbmc_swap_random_safe" })
                Runs         = $tpRuns
            }
        )
}

# 8. proof_libtoob_ota.c across CHIP_FLASH_WRITE_ALIGNMENT={1,4,8,32} x SWAPSCRATCH + POINTER
$OtaConfigs = @(
    @{ Mode = "SWAPSCRATCH"; Macro = "TOOB_TRANSPORT_SWAPSCRATCH"; Align = 1 },
    @{ Mode = "SWAPSCRATCH"; Macro = "TOOB_TRANSPORT_SWAPSCRATCH"; Align = 4 },
    @{ Mode = "SWAPSCRATCH"; Macro = "TOOB_TRANSPORT_SWAPSCRATCH"; Align = 8 },
    @{ Mode = "SWAPSCRATCH"; Macro = "TOOB_TRANSPORT_SWAPSCRATCH"; Align = 32 },
    @{ Mode = "POINTER";     Macro = "TOOB_TRANSPORT_POINTER";     Align = 8 },
    @{ Mode = "POINTER";     Macro = "TOOB_TRANSPORT_POINTER";     Align = 32 }
)
$OtaStreamUnwind = "toob_ota_process_chunk.0:3,_ensure_sectors_erased.0:3,mailbox_put.0:3"
foreach ($oc in $OtaConfigs) {
    Invoke-ProofBundle `
        -BundleName "W5A_08_libtoob_ota_$($oc.Mode)_align$($oc.Align)" `
        -Defines @(
            "-DTOOB_TRANSPORT_PROVIDER=$($oc.Macro)",
            "-DCHIP_FLASH_WRITE_ALIGNMENT=$($oc.Align)U",
            "-DCHIP_FLASH_MAX_SECTOR_SIZE=512U"
        ) `
        -Sources @(
            "test/formal/cbmc/proof_libtoob_ota.c",
            "sdk/libtoob/toob_ota.c",
            "sdk/libtoob/toob_handoff.c",
            "sdk/libtoob/toob_mailbox.c",
            "sdk/libtoob/toob_update.c"
        ) `
        -Profiles @(
            @{
                ReplaceCalls = @{
                    "toob_secure_zeroize"        = "cbmc_ota_zeroize_fast"
                    "toob_ct_memcmp_glitch_safe" = "cbmc_toob_ct_memcmp_contract"
                    "_volatile_snapshot_handoff" = "cbmc_snapshot_handoff"
                    "_volatile_snapshot_resume"  = "cbmc_snapshot_resume"
                    "_ctx_reset"                 = "cbmc_ota_ctx_reset"
                    "memcpy"                     = "cbmc_memcpy_stream"
                    "memset"                     = "cbmc_memset_stream"
                }
                Runs = @(
                    @{ Label = "stream_and_trailer";       Function = "prove_ota_stream_and_trailer";       Unwind = 5; NoSatPrep = $true; UnwindSet = $OtaStreamUnwind },
                    @{ Label = "trim_and_unaligned_carry"; Function = "prove_ota_trim_and_carry";           Unwind = 5; NoSatPrep = $true; UnwindSet = $OtaStreamUnwind }
                )
            },
            @{
                ReplaceCalls = @{
                    "toob_secure_zeroize"        = "cbmc_toob_secure_zeroize_safe"
                    "toob_ct_memcmp_glitch_safe" = "cbmc_toob_ct_memcmp_contract"
                    "_volatile_snapshot_handoff" = "cbmc_snapshot_handoff"
                    "_volatile_snapshot_resume"  = "cbmc_snapshot_resume"
                    "_ctx_reset"                 = "cbmc_ota_ctx_reset"
                }
                Runs = @(
                    @{ Label = "resume_and_update_guards"; Function = "prove_ota_resume_and_update_guards"; Unwind = 5; NoArrayFieldSens = $true; NoSatPrep = $true; UnwindSet = "toob_ota_resume_assigned.0:258,toob_ota_resume_assigned.1:3" }
                )
            }
        )
}

# ===========================================================================
# PART 2: GAP-AUDIT WAVE 5B HARNESSES (FV-01 .. FV-09)
# ===========================================================================

# 9. FV-01: proof_stage0_boot.c
$Stage0BaseContracts = @{
    "dead_halt"           = "cbmc_stage0_halt"
    "toob_ecc_trap"       = "cbmc_stage0_halt"
    "boot_panic"          = "cbmc_stage0_panic_halt"
    "boot_terminal_halt"  = "cbmc_stage0_terminal_halt"
    "jump_to_payload"     = "cbmc_stage0_jump_to_payload"
    "dbg_puts"            = "cbmc_stage0_dbg_puts"
    "dbg_hex"             = "cbmc_stage0_dbg_hex"
    "boot_random_safe"    = "cbmc_stage0_random_safe"
    "stage0_seq_is_newer" = "cbmc_stage0_seq_is_newer_mod32"
    "cfi_derive"          = "cbmc_cfi_derive_mod32"
    "boot_proof_mix"      = "cbmc_boot_proof_mix_mod32"
    "boot_crc32_update"   = "cbmc_boot_crc32_update_contract"
    "compute_boot_crc32"  = "cbmc_compute_boot_crc32_contract"
}
$Stage0MainContracts = Merge-Hashtable $Stage0BaseContracts @{
    "stage0_get_active_otp_key_index"  = "cbmc_stage0_otp_contract"
    "constant_time_memcmp_glitch_safe" = "cbmc_ct_memcmp_contract"
    "verify_not_all_zeros_glitch_safe" = "cbmc_verify_not_all_zeros_contract"
}

Invoke-ProofBundle `
    -BundleName "FV01_stage0_boot" `
    -Defines @(
        "-DCBMC_STAGE0_SRAM_DECL=1",
        "-DCBMC_SKIP_HARNESS_MAIN=1",
        "-Dmain=stage0_entry_main",
        "-D__ARM_ARCH_PROFILE=77",
        "-DCHIP_HAS_VTOR=1",
        "-DBOOT_STAGE1_SVN=2U"
    ) `
    -Sources @(
        "test/formal/cbmc/proof_stage0_boot.c",
        "toobloader/stage0/stage0_main.c",
        "toobloader/stage0/stage0_boot_pointer.c",
        "toobloader/stage0/stage0_tentative.c",
        "toobloader/stage0/stage0_verify.c",
        "toobloader/stage0/stage0_otp.c",
        "toobloader/stage0/stage0_hash.c",
        "toobloader/core/boot_platform_bringup.c",
        "toobloader/core/utils/boot_crc32.c"
    ) `
    -Profiles @(
        @{
            ReplaceCalls = $Stage0BaseContracts
            Runs = @(
                @{ Label = "otp_scan";                 Function = "prove_stage0_otp_scan";                 Unwind = 6;  UnwindSet = 'verify_not_all_zeros_glitch_safe.0:34,verify_not_all_zeros_glitch_safe$link1.0:34,verify_not_all_zeros_glitch_safe$link2.0:34' },
                @{ Label = "wal_quorum_and_tentative"; Function = "prove_stage0_wal_quorum_and_tentative"; Unwind = 6;  UnwindSet = "constant_time_memcmp_glitch_safe.0:120,stage0_evaluate_tentative.0:130" },
                @{ Label = "hash_and_verify";          Function = "prove_stage0_hash_and_verify";          Unwind = 6;  UnwindSet = "constant_time_memcmp_glitch_safe.0:36,prove_stage0_hash_and_verify.0:34,prove_stage0_hash_and_verify.1:34" }
            )
        },
        @{
            ReplaceCalls = $Stage0MainContracts
            Runs = @(
                @{ Label = "stage0_main_boot";         Function = "prove_stage0_main_boot";                Unwind = 8;  UnwindSet = "stage0_evaluate_tentative.0:130,cbmc_stage0_jump_to_payload.0:18" }
            )
        }
    )

# 10. FV-02: proof_boot_merkle_and_verify.c across TOOB_PQC_ENABLED={0,1}
foreach ($pqc in @(0, 1)) {
    Invoke-ProofBundle `
        -BundleName "FV02_merkle_verify_pqc$pqc" `
        -Defines @(
            "-DTOOB_PQC_ENABLED=$pqc",
            "-DTOOB_DOUBLE_VERIFY=1"
        ) `
        -Sources @(
            "test/formal/cbmc/proof_boot_merkle_and_verify.c",
            "toobloader/core/utils/boot_merkle.c",
            "toobloader/core/boot_verify.c",
            "toobloader/core/utils/boot_crc32.c"
        ) `
        -Profiles @(
            @{
                ReplaceCalls = @{
                    "cfi_derive"                       = "cbmc_cfi_derive_mod32"
                    "boot_proof_mix"                   = "cbmc_boot_proof_mix_mod32"
                    "constant_time_memcmp_glitch_safe" = "cbmc_ct_memcmp_contract"
                    "boot_random_safe"                 = "cbmc_boot_random_safe_contract"
                    "boot_crc32_update"                = "cbmc_boot_crc32_update_contract"
                    "compute_boot_crc32"               = "cbmc_compute_boot_crc32_contract"
                }
                Runs = @(
                    @{ Label = "merkle_stream";     Function = "prove_merkle_stream_bounds_and_coverage"; Unwind = 5 },
                    @{ Label = "manifest_envelope"; Function = "prove_verify_manifest_envelope";          Unwind = 6; UnwindSet = "verify_not_all_zeros_glitch_safe.0:260,fv02_verify_ed25519.0:34" }
                )
            }
        )
}

# 11. FV-03: proof_os_network_and_diag_wire.c
$Fv03BaseContracts = @{
    "toob_secure_zeroize"        = "cbmc_toob_secure_zeroize_safe"
    "_client_zeroize"            = "cbmc_toob_secure_zeroize_safe"
    "toob_ct_memcmp_glitch_safe" = "cbmc_toob_ct_memcmp_contract"
    "_volatile_snapshot_handoff" = "cbmc_snapshot_handoff"
    "_volatile_snapshot_diag"    = "cbmc_snapshot_diag"
    "printf"                     = "cbmc_printf_noop"
    "snprintf"                   = "cbmc_snprintf_contract"
}
$Fv03ParserContracts = Merge-Hashtable $Fv03BaseContracts @{
    "_is_all_byte"          = "cbmc_is_all_byte_contract"
    "_ct_memeq_glitch_safe" = "cbmc_ct_memeq_contract"
    "_hmac_sha256_3part"    = "cbmc_hmac_sha256_3part_contract"
}
$Fv03CycleContracts = Merge-Hashtable $Fv03ParserContracts @{
    "_client_zeroize"             = "cbmc_fv03_client_zeroize"
    "memcpy"                      = "cbmc_fv03_cycle_memcpy"
    "toob_tci1_parse"             = "cbmc_tci1_parse_contract"
    "toob_get_boot_diag"          = "cbmc_get_boot_diag_contract"
    "toob_get_boot_diag_wire_seq" = "cbmc_diag_wire_seq_contract"
    "_hex_encode"                 = "cbmc_hex_encode_contract"
}
$Fv03FastUnwindSet = "_validate_blob_path_dfa.0:12,toob_tci1_parse.0:12,toob_tci1_parse.1:34,toob_tci1_parse.2:18,toob_tci1_parse.3:34"
$Fv03MaxUnwindSet  = "_validate_blob_path_dfa.0:122,toob_tci1_parse.0:122,toob_tci1_parse.1:34,toob_tci1_parse.2:18,toob_tci1_parse.3:34"
Invoke-ProofBundle `
    -BundleName "FV03_os_network_and_diag_wire" `
    -Sources @(
        "test/formal/cbmc/proof_os_network_and_diag_wire.c",
        "sdk/os_client/src/toob_network_client.c",
        "sdk/libtoob/toob_diag.c",
        "sdk/libtoob/toob_handoff.c"
    ) `
    -Profiles @(
        @{
            ReplaceCalls = $Fv03BaseContracts
            Runs = @(
                @{ Label = "tci1_crypto_helpers";      Function = "prove_tci1_crypto_helpers";      Unwind = 34 },
                @{ Label = "tdr1_diag_wire_bijection"; Function = "prove_tdr1_diag_wire_bijection"; Unwind = 6; UnwindSet = "prove_tdr1_diag_wire_bijection.0:34,prove_tdr1_diag_wire_bijection.1:10,prove_tdr1_diag_wire_bijection.2:34" }
            )
        },
        @{
            ReplaceCalls = $Fv03ParserContracts
            Runs = @(
                @{ Label = "tci1_parse_symbolic_512";   Function = "prove_tci1_parse_symbolic_512";   Unwind = 6; UnwindSet = $Fv03FastUnwindSet },
                @{ Label = "tci1_blob_path_120";        Function = "prove_tci1_blob_path_120";        Unwind = 6; UnwindSet = $Fv03MaxUnwindSet }
            )
        },
        @{
            ReplaceCalls = $Fv03CycleContracts
            Runs = @(
                @{ Label = "network_trigger_ota_cycle"; Function = "prove_network_trigger_ota_cycle"; Unwind = 6; UnwindSet = "_hex_encode.0:34" }
            )
        }
    )

# 12. FV-04: proof_boot_cobs_prov_rescue.c
$Fv04RescueContracts = Merge-Hashtable $StdCoreContracts @{
    "enter_sos_loop"            = "cbmc_sos_halt"
    "boot_cobs_send_frame"      = "cbmc_cobs_send_contract"
    "boot_cobs_recv_frame"      = "cbmc_cobs_recv_contract"
    "boot_cobs_decode_in_place" = "cbmc_cobs_decode_contract"
    "memcpy"                    = "cbmc_memcpy_safe"
    "memset"                    = "cbmc_fv04_memset"
}

Invoke-ProofBundle `
    -BundleName "FV04_cobs_prov_rescue" `
    -Defines @("-DCHIP_FLASH_WRITE_ALIGNMENT=4U") `
    -Sources @(
        "test/formal/cbmc/proof_boot_cobs_prov_rescue.c",
        "toobloader/core/utils/boot_cobs.c",
        "toobloader/core/boot_provisioning.c",
        "toobloader/core/boot_panic.c",
        "toobloader/core/utils/boot_crc32.c"
    ) `
    -Profiles @(
        @{
            ReplaceCalls = $StdCoreContracts
            Runs = @(
                @{ Label = "cobs_decode_and_roundtrip"; Function = "prove_cobs_decode_and_roundtrip"; Unwind = 12 },
                @{ Label = "cobs_recv_frame";           Function = "prove_cobs_recv_frame";           Unwind = 18 }
            )
        },
        @{
            ReplaceCalls = $Fv04RescueContracts
            Runs = @(
                @{ Label = "provisioning_firewall";           Function = "prove_provisioning_firewall";           Unwind = 4; UnwindSet = "boot_terminal_halt.0:6" },
                @{ Label = "serial_rescue_2fa_and_unlock";    Function = "prove_serial_rescue_2fa_and_unlock";    Unwind = 2; NoSatPrep = $true; UnwindSet = "boot_terminal_halt.0:6,boot_panic.5:3,boot_panic.7:6,boot_panic.8:3,boot_panic.10:3,boot_panic.11:3,boot_panic.15:3,boot_panic.18:3,boot_panic.19:3,boot_panic.20:3,boot_panic.21:3,boot_panic.22:3,boot_panic.26:3,boot_panic.27:3,boot_panic.28:3,boot_read_monotonic_counter_safe.0:5" },
                @{ Label = "serial_rescue_cobs_flash_stream"; Function = "prove_serial_rescue_cobs_flash_stream"; Unwind = 2; NoSatPrep = $true; UnwindSet = "memcmp.0:4,boot_terminal_halt.0:6,boot_panic.12:5,boot_panic.25:3,boot_panic.27:3,boot_panic.28:3,boot_read_monotonic_counter_safe.0:5" }
            )
        }
    )

# 13. FV-05: proof_recovery_xmodem.c across SWAPSCRATCH & POINTER
$Fv05BaseContracts = Merge-Hashtable $StdCoreContracts @{
    "toob_secure_zeroize"        = "cbmc_fv05_zeroize_fast"
    "toob_ct_memcmp_glitch_safe" = "cbmc_toob_ct_memcmp_contract"
    "_volatile_snapshot_handoff" = "cbmc_snapshot_handoff_rec"
    "_volatile_snapshot_resume"  = "cbmc_snapshot_resume_rec"
    "_ctx_reset"                 = "cbmc_ota_ctx_reset_rec"
    "recovery_serial_print"      = "cbmc_recovery_print_noop"
    "recovery_system_reboot"     = "cbmc_recovery_reboot_halt"
    "read_bytes"                 = "cbmc_xmodem_read_bytes_contract"
    "_flush_buffer"              = "cbmc_fv05_flush_buffer_contract"
    "toob_ota_process_chunk"     = "cbmc_fv05_ota_process_chunk_contract"
    "memset"                     = "cbmc_fv05_memset"
}
$Fv05StreamContracts = Merge-Hashtable $Fv05BaseContracts @{
    "crc16_ccitt"             = "cbmc_crc16_ccitt_contract"
    "recovery_serial_getchar" = "cbmc_fv05_stream_getchar_contract"
}
$Fv05TrailerContracts = Merge-Hashtable $Fv05StreamContracts @{
    "toob_get_handoff"        = "cbmc_fv05_get_handoff_contract"
    "mailbox_put"             = "cbmc_fv05_mailbox_put_contract"
}

foreach ($recMode in @(
    @{ Name = "SWAPSCRATCH"; Macro = "TOOB_TRANSPORT_SWAPSCRATCH"; SyncLp = 4; PktLp = 5; ScanLp = 6 },
    @{ Name = "POINTER";     Macro = "TOOB_TRANSPORT_POINTER";     SyncLp = 5; PktLp = 6; ScanLp = 7 }
)) {
    $sLp  = $recMode.SyncLp
    $pLp  = $recMode.PktLp
    $scLp = $recMode.ScanLp
    Invoke-ProofBundle `
        -BundleName "FV05_recovery_xmodem_$($recMode.Name)" `
        -Defines @(
            "-DTOOB_TRANSPORT_PROVIDER=$($recMode.Macro)",
            "-DCBMC_TRAP_DECL=1",
            "-D__builtin_trap=cbmc_hardware_trap_halt",
            "-DCHIP_STAGING_SLOT_SIZE=0x2000U",
            "-DCHIP_APP_SLOT_SIZE=0x2000U"
        ) `
        -Sources @(
            "test/formal/cbmc/proof_recovery_xmodem.c",
            "recovery/main.c",
            "recovery/recovery_port.c",
            "sdk/libtoob/toob_ota.c",
            "sdk/libtoob/toob_handoff.c",
            "sdk/libtoob/toob_mailbox.c",
            "sdk/libtoob/toob_update.c",
            "sdk/libtoob/toob_confirm.c",
            "toobloader/core/utils/boot_crc32.c"
        ) `
        -Profiles @(
            @{
                ReplaceCalls = $Fv05BaseContracts
                Runs = @(
                    @{ Label = "crc16_and_port_erase"; Function = "prove_xmodem_crc16_and_port_erase"; Unwind = 4; NoArrayFieldSens = $true; UnwindSet = "recovery_main.${sLp}:3,recovery_main.${pLp}:2,crc16_ccitt.1:130,crc16_ccitt.0:10,recovery_serial_getchar.0:5,toob_os_flash_erase.0:3" }
                )
            },
            @{
                ReplaceCalls = $Fv05StreamContracts
                Runs = @(
                    @{ Label = "short_and_nak_stream"; Function = "prove_xmodem_short_and_nak_stream"; Unwind = 5; NoArrayFieldSens = $true; NoSatPrep = $true; UnwindSet = "recovery_main.${sLp}:4,recovery_main.${pLp}:4,recovery_main.${scLp}:2,compute_head_tbm1_size.0:6,toob_os_flash_erase.0:2" },
                    @{ Label = "head_tbm1_stream";     Function = "prove_xmodem_head_tbm1_stream";     Unwind = 5; NoArrayFieldSens = $true; NoSatPrep = $true; UnwindSet = "recovery_main.${sLp}:2,recovery_main.${pLp}:8,recovery_main.${scLp}:2,compute_head_tbm1_size.0:6,toob_os_flash_erase.0:2" }
                )
            },
            @{
                ReplaceCalls = $Fv05TrailerContracts
                Runs = @(
                    @{ Label = "split_trailer_stream";     Function = "prove_xmodem_split_trailer_stream";     Unwind = 5; NoArrayFieldSens = $true; NoSatPrep = $true; UnwindSet = "recovery_main.${sLp}:2,recovery_main.${pLp}:8,recovery_main.${scLp}:245,compute_head_tbm1_size.0:6,toob_os_flash_erase.0:2" },
                    @{ Label = "unaligned_trailer_stream"; Function = "prove_xmodem_unaligned_trailer_stream"; Unwind = 5; NoArrayFieldSens = $true; NoSatPrep = $true; UnwindSet = "recovery_main.${sLp}:2,recovery_main.${pLp}:8,recovery_main.${scLp}:245,compute_head_tbm1_size.0:6,toob_os_flash_erase.0:2" }
                )
            }
        )
}

# 14. FV-06: proof_boot_transport_pointer_rdelta_multiimage.c
foreach ($asym in @(0, 1)) {
    Invoke-ProofBundle `
        -BundleName "FV06_pointer_rollback_multiimage_asym$asym" `
        -Defines @(
            "-DTOOB_TRANSPORT_PROVIDER=TOOB_TRANSPORT_POINTER",
            "-DTOOB_FEATURE_MULTIIMAGE=1",
            "-DCBMC_ASYMMETRIC_SECTORS=$asym"
        ) `
        -Sources @(
            "test/formal/cbmc/proof_boot_transport_pointer_rdelta_multiimage.c",
            "toobloader/core/boot_transport_pointer.c",
            "toobloader/core/boot_transport.c",
            "toobloader/core/boot_rollback.c",
            "toobloader/core/boot_multiimage.c",
            "toobloader/core/boot_swap.c",
            "toobloader/core/boot_effect.c",
            "toobloader/core/utils/boot_crc32.c"
        ) `
        -Profiles @(
            @{
                ReplaceCalls = (Merge-Hashtable $StdCoreContracts $SectorCopyContracts)
                Runs = @(
                    @{ Label = "pointer_apply_rollback_reassert"; Function = "prove_pointer_apply_rollback_reassert"; Unwind = 4; NoSatPrep = $true; UnwindSet = "boot_swap_copy_region_resumable.0:2" },
                    @{ Label = "rollback_svn_and_revert";         Function = "prove_rollback_svn_and_revert";         Unwind = 4; NoSatPrep = $true; UnwindSet = "boot_rollback_trigger_revert.8:2,boot_rollback_trigger_revert.7:4" },
                    @{ Label = "rollback_revert_loop_bounded";    Function = "prove_rollback_revert_loop_bounded";    Unwind = 4; NoSatPrep = $true },
                    @{ Label = "multiimage_apply_bounds";         Function = "prove_multiimage_apply_bounds";         Unwind = 4; NoSatPrep = $true; UnwindSet = "prove_multiimage_apply_bounds.0:9,boot_multiimage_apply.9:3,boot_multiimage_apply.7:2,boot_multiimage_apply.10:2" }
                )
            }
        )
}

Invoke-ProofBundle `
    -BundleName "FV06_oneway_rdelta" `
    -Defines @(
        "-DTOOB_TRANSPORT_PROVIDER=TOOB_TRANSPORT_ONEWAY",
        "-DTOOB_ONEWAY_BACKUP_MODE=TOOB_ONEWAY_BACKUP_REVERSE_DELTA",
        "-DTOOB_FEATURE_DELTA=1"
    ) `
    -Sources @(
        "test/formal/cbmc/proof_boot_transport_pointer_rdelta_multiimage.c",
        "toobloader/core/boot_transport_oneway.c",
        "toobloader/core/boot_transport.c",
        "toobloader/core/boot_tbm1.c",
        "toobloader/core/boot_swap.c",
        "toobloader/core/boot_effect.c",
        "toobloader/core/utils/boot_crc32.c"
    ) `
    -Profiles @(
        @{
            ReplaceCalls = (Merge-Hashtable $StdCoreContracts $SectorCopyContracts)
            Runs = @(
                @{ Label = "oneway_rdelta_apply_and_rollback"; Function = "prove_oneway_rdelta_apply_and_rollback"; Unwind = 5; NoSatPrep = $true; UnwindSet = 'tbm1_find_region.0:10,tbm1_find_region$link1.0:10,tbm1_validate_regions.0:10,tbm1_validate_images.0:6' }
            )
        }
    )

# 15. FV-07: proof_boot_state_parse_route_and_main.c (PRODUCTION boot_state.c WITHOUT TOOB_MOCK_TEST)
$Fv07UnwindSet = 'tbm1_find_region.0:10,tbm1_find_region$link1.0:10,tbm1_validate_regions.0:10,tbm1_validate_images.0:6,evaluate_transition.0:20,handle_update_result.0:16,run_pipeline.0:10,run_pipeline.1:10,run_pipeline.2:10,run_pipeline.3:2,run_pipeline.4:2,stage_route.0:6,stage_route.1:6'
$Fv07StateContracts = Merge-Hashtable $StdCoreContracts @{
    "memcpy"  = "cbmc_memcpy_safe"
    "memmove" = "cbmc_memmove_safe"
}
$Fv07MainContracts = Merge-Hashtable $StdCoreContracts @{
    "boot_state_run" = "cbmc_fv07_boot_state_contract"
}
foreach ($stMode in @(
    @{ Name = "SWAPSCRATCH"; Macro = "TOOB_TRANSPORT_SWAPSCRATCH" },
    @{ Name = "POINTER";     Macro = "TOOB_TRANSPORT_POINTER" }
)) {
    Invoke-ProofBundle `
        -BundleName "FV07_boot_state_and_main_$($stMode.Name)" `
        -Defines @(
            "-DTOOB_TRANSPORT_PROVIDER=$($stMode.Macro)",
            "-D__ARM_ARCH_PROFILE=77",
            "-DCHIP_HAS_VTOR=1",
            "-DTOOB_FEATURE_DECOMP=1",
            "-DTOOB_FEATURE_DELTA=1",
            "-DTOOB_FEATURE_MULTIIMAGE=1"
        ) `
        -Sources @(
            "test/formal/cbmc/proof_boot_state_parse_route_and_main.c",
            "toobloader/core/boot_state.c",
            "toobloader/core/boot_main.c",
            "toobloader/core/boot_tbm1.c",
            "toobloader/core/utils/boot_diag.c",
            "toobloader/core/utils/boot_identity.c",
            "toobloader/core/boot_platform_bringup.c",
            "toobloader/core/boot_transport.c",
            "toobloader/core/utils/boot_crc32.c"
        ) `
        -Profiles @(
            @{
                ReplaceCalls = $Fv07StateContracts
                Runs = @(
                    @{ Label = "update_pipeline";             Function = "prove_boot_state_update_pipeline";            Unwind = 5; NoSatPrep = $true; UnwindSet = $Fv07UnwindSet },
                    @{ Label = "confirm_rollback_and_cloud";  Function = "prove_boot_state_confirm_rollback_and_cloud"; Unwind = 5; NoSatPrep = $true; UnwindSet = $Fv07UnwindSet }
                )
            },
            @{
                ReplaceCalls = $Fv07MainContracts
                Runs = @(
                    @{ Label = "boot_main_lifecycle_handoff"; Function = "prove_boot_main_lifecycle_and_handoff";       Unwind = 12; NoSatPrep = $true; UnwindSet = "boot_main.11:34" }
                )
            }
        )
}

# 16. FV-08: proof_libtoob_confirm_cloud_cred.c across CHIP_FLASH_WRITE_ALIGNMENT={1,4,8,32}
foreach ($align in @(1, 4, 8, 32)) {
    Invoke-ProofBundle `
        -BundleName "FV08_libtoob_confirm_cloud_cred_align$align" `
        -Defines @(
            "-DCHIP_FLASH_WRITE_ALIGNMENT=${align}U",
            "-DCBMC_FORCE_BAREMETAL_RTC=1",
            "-DADDR_CONFIRM_RTC_RAM=((uintptr_t)&g_mock_rtc_ram)"
        ) `
        -Sources @(
            "test/formal/cbmc/proof_libtoob_confirm_cloud_cred.c",
            "sdk/libtoob/toob_confirm.c",
            "sdk/libtoob/toob_cloud_submit.c",
            "sdk/libtoob/toob_handoff.c",
            "sdk/libtoob/toob_mailbox.c",
            "sdk/os_client/src/toob_device_cred.c"
        ) `
        -Profiles @(
            @{
                ReplaceCalls = @{
                    "toob_secure_zeroize"        = "cbmc_toob_secure_zeroize_safe"
                    "_cred_secure_zeroize"       = "cbmc_toob_secure_zeroize_safe"
                    "toob_ct_memcmp_glitch_safe" = "cbmc_toob_ct_memcmp_contract"
                    "toob_lib_crc32"             = "cbmc_toob_lib_crc32_contract"
                }
                Runs = @(
                    @{ Label = "confirm_and_recovery_resolved"; Function = "prove_confirm_and_recovery_resolved"; Unwind = 5;  UnwindSet = "_volatile_snapshot_handoff.0:130" },
                    @{ Label = "submit_cloud_command";          Function = "prove_submit_cloud_command";          Unwind = 5;  UnwindSet = "_volatile_snapshot_handoff.0:130" },
                    @{ Label = "device_cred_store";             Function = "prove_device_cred_store";             Unwind = 36; UnwindSet = "_volatile_snapshot_handoff.0:130" }
                )
            }
        )
}

# 17. FV-09: proof_boot_utils_quorum_energy_crc.c (Standalone Primitives — ZERO replacement on CRC-32 or ct_utils)
Invoke-ProofBundle `
    -BundleName "FV09_utils_quorum_energy_crc" `
    -Sources @(
        "test/formal/cbmc/proof_boot_utils_quorum_energy_crc.c",
        "toobloader/core/utils/boot_crc32.c",
        "sdk/libtoob/toob_crc32.c",
        "toobloader/core/boot_rstore.c",
        "toobloader/core/utils/boot_energy.c",
        "toobloader/core/utils/boot_delay.c",
        "toobloader/core/boot_effect.c"
    ) `
    -Profiles @(
        @{
            ReplaceCalls = @{
                "cfi_derive"     = "cbmc_cfi_derive_mod32"
                "boot_proof_mix" = "cbmc_boot_proof_mix_mod32"
            }
            Runs = @(
                @{ Label = "crc32_sarwate_equivalence_and_stream"; Function = "prove_crc32_sarwate_equivalence_and_stream"; Unwind = 9;  UnwindSet = "boot_crc32_flash_stream.0:4" },
                @{ Label = "ct_utils_standalone";                  Function = "prove_ct_utils_standalone";                  Unwind = 10; UnwindSet = "boot_flash_is_erased.2:2,boot_flash_is_erased.0:3,boot_flash_is_erased.1:4,boot_random_safe.0:5" },
                @{ Label = "energy_median_and_hysteresis";         Function = "prove_energy_median_and_hysteresis";         Unwind = 6 },
                @{ Label = "delay_time_warp_and_termination";      Function = "prove_delay_time_warp_and_termination";      Unwind = 6;  UnwindSet = "boot_delay_with_wdt.3:30,boot_delay_with_wdt.0:30" },
                @{ Label = "effect_admit_or_defer_and_supply";     Function = "prove_effect_admit_or_defer_and_supply";     Unwind = 6;  UnwindSet = "boot_effect_admit_or_defer.1:8,boot_effect_admit_or_defer.2:66" }
            )
        },
        @{
            ReplaceCalls = (Merge-Hashtable $StdCoreContracts @{
                "boot_crc32_update"  = "cbmc_rstore_det_crc32_update"
                "compute_boot_crc32" = "cbmc_rstore_det_compute_crc32"
            })
            Runs = @(
                @{ Label = "rstore_brownout_quorum";               Function = "prove_rstore_brownout_quorum";               Unwind = 9;  NoSatPrep = $true; UnwindSet = "cbmc_rstore_det_crc32_update.0:26,rstore_flash_read.0:66,rstore_flash_write.0:30" }
            )
        }
    )

$script:SuiteTimer.Stop()
$cFreeGb = [Math]::Round(((Get-PSDrive C).Free / 1GB), 2)

Write-Host ""
Write-Host "==========================================================================="
Write-Host ("CBMC Proof Suite Summary: {0} PASSED, {1} FAILED in {2:N1}s (C: free = {3} GB)" -f `
    $script:TotalPassed, $script:TotalFailed, $script:SuiteTimer.Elapsed.TotalSeconds, $cFreeGb)
Write-Host "==========================================================================="

if ($script:TotalFailed -gt 0) {
    Write-Host "Failed proofs:" -ForegroundColor Red
    foreach ($r in ($script:Results | Where-Object { $_.Status -ne "PASS" })) {
        Write-Host ("  - {0} -> {1}" -f $r.Proof, $r.Log) -ForegroundColor Red
    }
    exit 1
}
if ($script:TotalPassed -eq 0) {
    throw "No proofs matched filter '$Filter'"
}
exit 0
