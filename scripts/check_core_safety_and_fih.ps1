#Requires -Version 5.1
<#
.SYNOPSIS
  Runs Toob-Loader's Core & Stage-0 MISRA C:2023 / CERT C static analysis
  (clang-tidy) and custom Glitch/FIH & Flash-Firewall rules (TOOB-FIH-01..05).
#>
param(
    [switch]$CheckFormat
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$tmpDir   = 'D:\ToobStorage\tmp_build\misra_fih_lint'
if (-not (Test-Path 'D:\ToobStorage')) {
    $tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) 'toob_misra_fih_lint'
}
New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null
$env:TEMP = $tmpDir
$env:TMP  = $tmpDir

$clangTidy   = 'C:\Program Files\LLVM\bin\clang-tidy.exe'
$clangFormat = 'C:\Program Files\LLVM\bin\clang-format.exe'
if (-not (Test-Path $clangTidy)) {
    $cmd = Get-Command clang-tidy -ErrorAction SilentlyContinue
    if ($cmd) { $clangTidy = $cmd.Source } else { throw 'clang-tidy not found.' }
}
if (-not (Test-Path $clangFormat)) {
    $cmd = Get-Command clang-format -ErrorAction SilentlyContinue
    if ($cmd) { $clangFormat = $cmd.Source } else { throw 'clang-format not found.' }
}

$coreStage0Dirs = @(
    (Join-Path $repoRoot 'toobloader/stage0'),
    (Join-Path $repoRoot 'toobloader/core')
)
$fihScanDirs = @(
    (Join-Path $repoRoot 'toobloader/stage0'),
    (Join-Path $repoRoot 'toobloader/core'),
    (Join-Path $repoRoot 'recovery'),
    (Join-Path $repoRoot 'sdk/libtoob'),
    (Join-Path $repoRoot 'sdk/os_client')
)
$fihCAndH = @(foreach ($d in $fihScanDirs) {
    if (Test-Path $d) {
        Get-ChildItem -Path $d -Recurse -File -Include *.c, *.h
    }
})
$coreCAndH = @(foreach ($d in $coreStage0Dirs) {
    Get-ChildItem -Path $d -Recurse -File -Include *.c, *.h
})
$allCFiles = @($coreCAndH | Where-Object { $_.Extension -eq '.c' })

$failures = New-Object System.Collections.Generic.List[string]

Write-Host '================================================================================'
Write-Host '  TOOB-LOADER CORE, STAGE-0, RECOVERY & SDK SAFETY / MISRA C:2023 / FIH GATE'
Write-Host '================================================================================'

# ---------------------------------------------------------------------------
# Gate 1: Custom Toob Glitch-Hardening (FIH) & Firewall Rules (TOOB-FIH-01..05)
# ---------------------------------------------------------------------------
Write-Host '[1/4] Checking custom Glitch/FIH & Flash-Firewall invariants (TOOB-FIH-01..05)...'

$zeroMemsetRegex  = '\bmemset\s*\(\s*([^,]+?)\s*,\s*(?:0[uUlL]*|0x0+[uUlL]*|''\\0'')\s*,'
$rawMemcmpRegex   = '\bmemcmp\s*\('
$voidSecGateRegex = '\(\s*void\s*\)\s*([A-Za-z0-9_>-]*\b(?:verify_signature|stage0_verify_signature|boot_verify_manifest_envelope|boot_merkle_verify_stream|boot_rollback_verify_svn|boot_proof_verify|read_dslc|boot_random_safe|advance_monotonic_counter|boot_read_monotonic_counter_safe|set_otfdec_mode|lockdown_before_handoff))\s*\('
$rawFlashMutRegex = '->\s*(write|erase_sector)\s*\('
$mmioCastRegex    = '\(\s*(?:volatile\s+)?(?:const\s+)?(?:uint(?:8|16|32|64)_t|uintptr_t)\s*\*\s*\)\s*(?:\(\s*uintptr_t\s*\)\s*)?0x[0-9a-fA-F]+'

function Test-AllowedZeroMemset {
    param([string]$RelPath, [string]$DstExpr)
    $dst = $DstExpr.Trim()
    if ($dst -match '(?:->|\.)_padding\w*\s*$') { return $true }
    if ($RelPath -eq 'toobloader/core/boot_delta.c' -and $dst -eq 'w->write_buf + w->write_pos') { return $true }
    if ($RelPath -eq 'sdk/libtoob/toob_ota.c' -and $dst -eq 'zero_sha') { return $true }
    if ($RelPath -eq 'sdk/libtoob/toob_diag.c' -and $dst -eq 'out_buf') { return $true }
    return $false
}

function Test-InfiniteLoopHasExit {
    param([string]$Body)
    $scopeStack = New-Object System.Collections.Generic.Stack[string]
    $scopeStack.Push('outer')
    $parenDepth = 0
    $pendingInnerCtrl = $null
    $skipNextWhileCtrl = $false

    $tokens = [regex]::Matches($Body, '[A-Za-z_][A-Za-z0-9_]*|[{}();]')
    foreach ($t in $tokens) {
        $v = $t.Value
        switch ($v) {
            '(' {
                $parenDepth++
            }
            ')' {
                if ($parenDepth -gt 0) { $parenDepth-- }
            }
            '{' {
                $tag = if ($null -ne $pendingInnerCtrl) { $pendingInnerCtrl } else { 'block' }
                $pendingInnerCtrl = $null
                $skipNextWhileCtrl = $false
                $scopeStack.Push($tag)
            }
            '}' {
                $closed = if ($scopeStack.Count -gt 1) { $scopeStack.Pop() } else { 'outer' }
                $skipNextWhileCtrl = ($closed -eq 'do')
                $pendingInnerCtrl = $null
            }
            ';' {
                if ($parenDepth -eq 0) {
                    $pendingInnerCtrl = $null
                    $skipNextWhileCtrl = $false
                }
            }
            'do' {
                $pendingInnerCtrl = 'do'
                $skipNextWhileCtrl = $false
            }
            'for' {
                $pendingInnerCtrl = 'inner'
                $skipNextWhileCtrl = $false
            }
            'switch' {
                $pendingInnerCtrl = 'inner'
                $skipNextWhileCtrl = $false
            }
            'while' {
                if ($skipNextWhileCtrl) {
                    $skipNextWhileCtrl = $false
                } else {
                    $pendingInnerCtrl = 'inner'
                }
            }
            'return' {
                return $true
            }
            'goto' {
                return $true
            }
            'break' {
                foreach ($s in $scopeStack.ToArray()) {
                    if ($s -eq 'inner' -or $s -eq 'do') {
                        break
                    }
                    if ($s -eq 'outer') {
                        return $true
                    }
                }
            }
        }
    }
    return $false
}

foreach ($file in $fihCAndH) {
    $rel = $file.FullName.Substring($repoRoot.Length + 1).Replace('\', '/')
    $raw = [System.IO.File]::ReadAllText($file.FullName)

    # Strip C block comments and line comments preserving newlines for exact line numbers
    $stripped = [regex]::Replace($raw, '/\*[\s\S]*?\*/', {
        param($m)
        return ($m.Value -replace '[^\r\n]', ' ')
    })
    $stripped = [regex]::Replace($stripped, '//[^\r\n]*', '')
    $lines = $stripped -split "\r?\n"

    for ($idx = 0; $idx -lt $lines.Count; $idx++) {
        $ln = $idx + 1
        $line = $lines[$idx]

        # TOOB-FIH-01: Ban standard short-circuiting memcmp()
        if ($line -match $rawMemcmpRegex) {
            $failures.Add("[TOOB-FIH-01] ${rel}:${ln}: Forbidden raw memcmp() (use constant-time memcmp): $($line.Trim())")
        }

        # TOOB-FW-05a: Direct flash->write / flash->erase_sector outside flash guard implementation
        if ($rel -ne 'toobloader/core/include/boot_flash_guard.h' -and
            $rel -ne 'toobloader/core/utils/boot_crc32.c' -and
            $rel -ne 'toobloader/core/utils/include/boot_ct_utils.h' -and
            $line -match $rawFlashMutRegex) {
            $failures.Add("[TOOB-FW-05] ${rel}:${ln}: Direct flash->write/erase_sector bypasses Stage-0 firewall (use boot_flash_*_guarded): $($line.Trim())")
        }

        # TOOB-FW-05b: Direct MMIO pointer address cast (except documented SCB->AIRCR SYSRESETREQ in recovery_port.c)
        if ($line -match $mmioCastRegex) {
            if (-not ($rel -eq 'recovery/recovery_port.c' -and $line -match '0xE000ED0CU?')) {
                $failures.Add("[TOOB-FW-05] ${rel}:${ln}: Direct MMIO address cast: $($line.Trim())")
            }
        }
    }

    # TOOB-FIH-02: Ban optimizable memset(..., 0, ...) except explicitly allowlisted non-secret fills
    foreach ($zm in [regex]::Matches($stripped, $zeroMemsetRegex)) {
        $dstExpr = $zm.Groups[1].Value
        if (-not (Test-AllowedZeroMemset -RelPath $rel -DstExpr $dstExpr)) {
            $prefix = $stripped.Substring(0, $zm.Index)
            $ln = ($prefix -split "\r?\n").Count
            $failures.Add("[TOOB-FIH-02] ${rel}:${ln}: Forbidden memset(...,0,...) ($($dstExpr.Trim())) -- use boot_secure_zeroize/toob_secure_zeroize")
        }
    }

    # TOOB-FIH-04: Never discard critical security verifier / HAL safety return values via (void)
    foreach ($vm in [regex]::Matches($stripped, $voidSecGateRegex)) {
        $prefix = $stripped.Substring(0, $vm.Index)
        $ln = ($prefix -split "\r?\n").Count
        $failures.Add("[TOOB-FIH-04] ${rel}:${ln}: Security/HAL gate return value discarded via (void): $($vm.Value)")
    }

    # TOOB-FIH-03: Infinite trap loops while(1)/while(true)/for(;;) must contain a glitch barrier or halt call
    $loopSrc = [regex]::Replace($stripped, '"(?:\\.|[^"\\])*"|''(?:\\.|[^''\\])*''', {
        param($m)
        return ($m.Value -replace '[^\r\n]', ' ')
    })
    $loopHeaders = [regex]::Matches($loopSrc, '(?<![A-Za-z0-9_])(?:while\s*\(\s*(?:1|1U|1u|true)\s*\)|for\s*\(\s*;\s*;\s*\))\s*\{')
    foreach ($lh in $loopHeaders) {
        $bodyStart = $lh.Index + $lh.Length
        $braceDepth = 1
        $pos = $bodyStart
        while ($pos -lt $loopSrc.Length -and $braceDepth -gt 0) {
            $ch = $loopSrc[$pos]
            if ($ch -eq '{') { $braceDepth++ }
            elseif ($ch -eq '}') { $braceDepth-- }
            $pos++
        }
        if ($braceDepth -ne 0) {
            $prefix = $loopSrc.Substring(0, $lh.Index)
            $ln = ($prefix -split "\r?\n").Count
            $failures.Add("[TOOB-FIH-03] ${rel}:${ln}: Unbalanced braces inside infinite loop")
            continue
        }
        $body = $loopSrc.Substring($bodyStart, ($pos - 1) - $bodyStart)
        if (Test-InfiniteLoopHasExit -Body $body) {
            continue
        }
        $haltPattern = 'BOOT_GLITCH_DELAY|dead_halt|boot_terminal_halt|boot_panic|toob_ecc_trap|enter_sos_loop'
        if ($rel -like 'recovery/*') {
            $haltPattern += '|TOOB_TRAP|recovery_system_reboot'
        } elseif ($rel -like 'sdk/libtoob/*') {
            $haltPattern += '|TOOB_TRAP'
        } elseif ($rel -like 'sdk/os_client/*') {
            $haltPattern += '|TOOB_TRAP|k_sleep|vTaskDelay|\bSleep\b|\bsleep\b'
        }
        if ($body -notmatch $haltPattern) {
            $prefix = $loopSrc.Substring(0, $lh.Index)
            $ln = ($prefix -split "\r?\n").Count
            $failures.Add("[TOOB-FIH-03] ${rel}:${ln}: Infinite halt loop lacks BOOT_GLITCH_DELAY() barrier")
        }
    }
}

# ---------------------------------------------------------------------------
# Gate 2: UTF-8 No-BOM & English-Only Comments Sanity Check
# ---------------------------------------------------------------------------
Write-Host '[2/4] Checking UTF-8 (no BOM) encoding across Stage-0, Core, Recovery & SDK...'
foreach ($file in $fihCAndH) {
    $bytes = [System.IO.File]::ReadAllBytes($file.FullName)
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        $rel = $file.FullName.Substring($repoRoot.Length + 1).Replace('\', '/')
        $failures.Add("[ENCODING] ${rel}: UTF-8 BOM detected")
    }
}

# ---------------------------------------------------------------------------
# Gate 3: Optional clang-format Verification (-CheckFormat)
# ---------------------------------------------------------------------------
if ($CheckFormat) {
    Write-Host '[3/4] Verifying .clang-format compliance...'
    foreach ($file in $coreCAndH) {
        $prevEap = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        $fmtOut = & $clangFormat --dry-run --Werror $file.FullName 2>&1
        $fmtRc  = $LASTEXITCODE
        $ErrorActionPreference = $prevEap
        if ($fmtRc -ne 0) {
            $rel = $file.FullName.Substring($repoRoot.Length + 1).Replace('\', '/')
            $failures.Add("[FORMAT] ${rel}: clang-format mismatch")
        }
    }
} else {
    Write-Host '[3/4] Skipping clang-format check (pass -CheckFormat to enforce).'
}

# ---------------------------------------------------------------------------
# Gate 4: clang-tidy MISRA C:2023 + CERT C Analysis (32-bit Freestanding C17)
# ---------------------------------------------------------------------------
Write-Host "[4/4] Running clang-tidy MISRA C:2023 + CERT C across $($allCFiles.Count) translation units..."

$compileFlags = @(
    '-std=c17',
    '--target=armv7m-none-eabi',
    '-Os',
    '-Wall',
    '-Wextra',
    '-Wconversion',
    '-Wshadow',
    '-Wstrict-prototypes',
    '-Wmissing-prototypes',
    '-Wcast-qual',
    '-Wvla',
    '-DTOOB_PQC_ENABLED=1',
    "-I$repoRoot/test/formal/cbmc/include",
    "-I$repoRoot/common/include",
    "-I$repoRoot/toobloader/include",
    "-I$repoRoot/toobloader/core/include",
    "-I$repoRoot/toobloader/core/utils/include",
    "-I$repoRoot/toobloader/stage0/include",
    "-I$repoRoot/sdk/libtoob/include",
    "-I$repoRoot/common/lib/heatshrink",
    '-ffreestanding',
    '-isystem', 'D:/ToobStorage/toolchains/arm-none-eabi/15.2.1-1.1/xpack-arm-none-eabi-gcc-15.2.1-1.1/lib/gcc/arm-none-eabi/15.2.1/include',
    '-isystem', 'D:/ToobStorage/toolchains/arm-none-eabi/15.2.1-1.1/xpack-arm-none-eabi-gcc-15.2.1-1.1/arm-none-eabi/include'
)

foreach ($cFile in $allCFiles) {
    $rel = $cFile.FullName.Substring($repoRoot.Length + 1).Replace('\', '/')
    $extra = @()
    if ($rel -like 'toobloader/stage0/*') {
        $extra += '-DTOOB_STAGE0_BUILD=1'
    }
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $tidyOut = & $clangTidy --quiet "--config-file=$repoRoot/.clang-tidy" $cFile.FullName '--' @compileFlags @extra 2>&1
    $tidyRc  = $LASTEXITCODE
    $ErrorActionPreference = $prevEap

    if ($tidyRc -ne 0) {
        $diagText = ($tidyOut | ForEach-Object { "$_" }) -join "`n"
        $failures.Add("[CLANG-TIDY] ${rel}:`n$diagText")
    }
}

if ($failures.Count -gt 0) {
    Write-Host ''
    Write-Host "FAIL: $($failures.Count) violation(s) found:" -ForegroundColor Red
    foreach ($f in $failures) {
        Write-Host $f
    }
    exit 1
}

Write-Host ''
Write-Host "PASS: All $($fihCAndH.Count) Stage-0, Core, Recovery & SDK files satisfy FIH/Safety rules ($($coreCAndH.Count) Stage-0/Core files checked for MISRA/CERT)!" -ForegroundColor Green
exit 0
