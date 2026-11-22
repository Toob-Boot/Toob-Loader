#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$rocqDir  = Join-Path $repoRoot 'test/formal/rocq'
$buildDir = 'D:\ToobStorage\tmp_build\f2_rocq'
$rocqBin  = 'D:\ToobStorage\tools\rocq\bin'

$env:TEMP        = $buildDir
$env:TMP         = $buildDir
$env:GOCACHE     = Join-Path $buildDir 'gocache'
$env:GOTMPDIR    = $buildDir
$env:ROCQLIB     = 'D:\ToobStorage\tools\rocq\lib\coq'
$env:COQLIB      = 'D:\ToobStorage\tools\rocq\lib\coq'
$env:ROCQCORELIB = 'D:\ToobStorage\tools\rocq\lib\rocq-runtime'
$env:OCAMLRUNPARAM = 'o=60,s=2M,i=2M'

New-Item -ItemType Directory -Force -Path $buildDir | Out-Null

$coqcExe   = Join-Path $rocqBin 'coqc.exe'
$coqchkExe = Join-Path $rocqBin 'coqchk.exe'
if (-not (Test-Path $coqcExe))   { throw "Missing coqc.exe at $coqcExe" }
if (-not (Test-Path $coqchkExe)) { throw "Missing coqchk.exe at $coqchkExe" }

$gccCandidates = @(
    'C:\msys64\ucrt64\bin\gcc.exe',
    'C:\msys64\mingw64\bin\gcc.exe'
)
$gcc = $null
foreach ($cand in $gccCandidates) {
    if (Test-Path $cand) {
        $gcc = $cand
        break
    }
}
if (-not $gcc) {
    $cmd = Get-Command gcc -ErrorAction SilentlyContinue
    if ($cmd) {
        $gcc = $cmd.Source
    } else {
        throw 'GCC compiler not found (checked C:\msys64\ucrt64\bin\gcc.exe and PATH).'
    }
}

function Invoke-NativeCaptured {
    param(
        [Parameter(Mandatory = $true)][string]$Exe,
        [string[]]$ArgList = @()
    )
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $lines = & $Exe @ArgList 2>&1 | ForEach-Object { "$_" }
        $code  = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $prevEap
    }
    return [PSCustomObject]@{
        ExitCode = $code
        Lines    = @($lines)
        Text     = (($lines) -join "`n")
    }
}

function Strip-RocqComments {
    param([string]$Text)
    $sb = [System.Text.StringBuilder]::new($Text.Length)
    $depth = 0
    $i = 0
    $n = $Text.Length
    while ($i -lt $n) {
        if (($i + 1 -lt $n) -and $Text[$i] -eq '(' -and $Text[$i + 1] -eq '*') {
            $depth++
            $i += 2
            continue
        }
        if (($depth -gt 0) -and ($i + 1 -lt $n) -and $Text[$i] -eq '*' -and $Text[$i + 1] -eq ')') {
            $depth--
            $i += 2
            continue
        }
        if ($depth -eq 0) {
            [void]$sb.Append($Text[$i])
        } elseif ($Text[$i] -eq "`n") {
            [void]$sb.Append("`n")
        }
        $i++
    }
    return $sb.ToString()
}

$sw = [System.Diagnostics.Stopwatch]::StartNew()

Write-Host '================================================================================'
Write-Host '  Toob-Loader Wave 5B Rocq Formal Proof & 1:1 Host-SIL Oracle Verification'
Write-Host '================================================================================'

# ------------------------------------------------------------------------------
# Step 1: Static Soundness & Encoding Gate (0 Admitted / admit / Axiom / BOM)
# ------------------------------------------------------------------------------
Write-Host '[1/5] Auditing Rocq sources for forbidden proof escapes and UTF-8 BOM...'
$rocqFiles = @(
    'BootModel.v',
    'BootTransitions.v',
    'BootTheorems.v',
    'Stage0Chain.v',
    'StreamingVerify.v',
    'KeyQuorumPointer.v',
    'RescueAndFaults.v',
    'BootOracleGen.v'
)

$bomCheckPaths = @(
    (Join-Path $rocqDir '_CoqProject'),
    (Join-Path $repoRoot 'test/host/test_rocq_oracle.c'),
    $MyInvocation.MyCommand.Path
) + ($rocqFiles | ForEach-Object { Join-Path $rocqDir $_ })

foreach ($p in $bomCheckPaths) {
    if (Test-Path $p) {
        $bytes = [System.IO.File]::ReadAllBytes($p)
        if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
            throw "UTF-8 BOM detected in $p"
        }
    }
}

$forbiddenPattern = '\b(Admitted|admit|Axiom|Axioms|Parameter|Parameters|Variable|Variables|Hypothesis|Hypotheses|Conjecture|Unsafe)\b'
foreach ($vf in $rocqFiles) {
    $vPath = Join-Path $rocqDir $vf
    $rawText = [System.IO.File]::ReadAllText($vPath)
    $codeOnly = Strip-RocqComments -Text $rawText
    $m = [regex]::Match($codeOnly, $forbiddenPattern)
    if ($m.Success) {
        throw "Forbidden unproven construct '$($m.Value)' found in $vPath"
    }
}
Write-Host '      PASS: Zero Admitted/admit/Axiom/Parameter tokens and zero UTF-8 BOMs.'

# ------------------------------------------------------------------------------
# Step 2: Constructive Rocq Proof Compilation & VM Oracle Evaluation
# ------------------------------------------------------------------------------
Write-Host '[2/5] Compiling constructive Rocq proofs (coqc)...'
$rocqWorkDir = Join-Path $buildDir 'rocq_work'
if (Test-Path $rocqWorkDir) {
    Remove-Item -Recurse -Force $rocqWorkDir
}
New-Item -ItemType Directory -Force -Path $rocqWorkDir | Out-Null
foreach ($vf in $rocqFiles) {
    Copy-Item -Force (Join-Path $rocqDir $vf) (Join-Path $rocqWorkDir $vf)
}

$flatOutPath = Join-Path $buildDir 'rocq_oracle_flat.out'
if (Test-Path $flatOutPath) {
    Remove-Item -Force $flatOutPath
}

foreach ($vf in $rocqFiles) {
    $stepSw = [System.Diagnostics.Stopwatch]::StartNew()
    Push-Location $rocqWorkDir
    try {
        $res = Invoke-NativeCaptured -Exe $coqcExe -ArgList @('-Q', '.', 'ToobBoot', $vf)
    }
    finally {
        Pop-Location
    }
    $stepSw.Stop()
    if ($res.ExitCode -ne 0) {
        throw "coqc failed on test/formal/rocq/$vf (exit $($res.ExitCode)):`n$($res.Text)"
    }
    Write-Host ("      Compiled {0,-20} ({1:N2}s)" -f $vf, $stepSw.Elapsed.TotalSeconds)
}

# ------------------------------------------------------------------------------
# Step 3: Independent Kernel Proof Verification (coqchk)
# ------------------------------------------------------------------------------
Write-Host '[3/5] Running independent kernel checker (coqchk)...'
Push-Location $rocqWorkDir
try {
    $chkRes = Invoke-NativeCaptured -Exe $coqchkExe -ArgList @(
        '-o', '-Q', '.', 'ToobBoot',
        'ToobBoot.BootModel', 'ToobBoot.BootTransitions',
        'ToobBoot.BootTheorems', 'ToobBoot.Stage0Chain',
        'ToobBoot.StreamingVerify', 'ToobBoot.KeyQuorumPointer',
        'ToobBoot.RescueAndFaults', 'ToobBoot.BootOracleGen'
    )
}
finally {
    Pop-Location
}
if ($chkRes.ExitCode -ne 0) {
    throw "coqchk failed (exit $($chkRes.ExitCode)):`n$($chkRes.Text)"
}
if ($chkRes.Text -notmatch 'Axioms:\s*<none>') {
    throw "coqchk did not confirm 'Axioms: <none>':`n$($chkRes.Text)"
}
Write-Host '      PASS: coqchk verified all modules with Context Summary: Axioms: <none>.'

# ------------------------------------------------------------------------------
# Step 4: Emit Deterministic C17 Header from Rocq VM Oracle Output
# ------------------------------------------------------------------------------
Write-Host '[4/5] Generating C17 oracle vector header from Rocq VM output...'
if (-not (Test-Path $flatOutPath)) {
    throw "Expected Rocq Redirect output not found at $flatOutPath"
}
$rawFlat = [System.IO.File]::ReadAllText($flatOutPath)
$colonIdx = $rawFlat.LastIndexOf(':')
if ($colonIdx -gt 0) {
    $rawFlat = $rawFlat.Substring(0, $colonIdx)
}

$expectedVectors = 13834
$expectedCols    = 23
$rowMatches = [regex]::Matches($rawFlat, '\[([^\[\]]+)\]')
if ($rowMatches.Count -ne $expectedVectors) {
    throw "Expected $expectedVectors oracle vectors from BootOracleGen.v, parsed $($rowMatches.Count)"
}

$hdrPath = Join-Path $buildDir 'rocq_oracle_vectors.h'
$hdrSb = [System.Text.StringBuilder]::new(1048576)
[void]$hdrSb.AppendLine('#ifndef ROCQ_ORACLE_VECTORS_H')
[void]$hdrSb.AppendLine('#define ROCQ_ORACLE_VECTORS_H')
[void]$hdrSb.AppendLine('#include <stdint.h>')
[void]$hdrSb.AppendLine("#define ROCQ_ORACLE_VECTOR_COUNT $($expectedVectors)U")
[void]$hdrSb.AppendLine("#define ROCQ_ORACLE_ROW_FIELDS   $($expectedCols)U")
[void]$hdrSb.AppendLine('static const uint16_t k_rocq_oracle_vectors[ROCQ_ORACLE_VECTOR_COUNT][ROCQ_ORACLE_ROW_FIELDS] = {')

for ($r = 0; $r -lt $rowMatches.Count; $r++) {
    $inner = $rowMatches[$r].Groups[1].Value
    $parts = $inner -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
    if ($parts.Count -ne $expectedCols) {
        throw "Row $r has $($parts.Count) columns instead of $expectedCols"
    }
    foreach ($tok in $parts) {
        if ($tok -notmatch '^\d+$') {
            throw "Non-integer token '$tok' in oracle row $r"
        }
    }
    [void]$hdrSb.Append('  { ')
    [void]$hdrSb.Append(($parts -join 'U, '))
    [void]$hdrSb.AppendLine('U },')
}
[void]$hdrSb.AppendLine('};')
[void]$hdrSb.AppendLine('#endif /* ROCQ_ORACLE_VECTORS_H */')

$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
[System.IO.File]::WriteAllText($hdrPath, $hdrSb.ToString(), $utf8NoBom)
[System.IO.File]::WriteAllText(
    (Join-Path $buildDir 'generated_boot_config.h'),
    "#ifndef GENERATED_BOOT_CONFIG_H`n#define GENERATED_BOOT_CONFIG_H`n#endif`n",
    $utf8NoBom
)
Write-Host "      Generated $expectedVectors verified $expectedCols-column vectors -> $hdrPath"

# ------------------------------------------------------------------------------
# Step 5: Compile & Run Host-SIL 1:1 C17 Equivalence Oracle
# ------------------------------------------------------------------------------
Write-Host '[5/5] Compiling and executing test/host/test_rocq_oracle.c against production Core...'
$incFlags = @(
    "-I$buildDir",
    "-I$repoRoot/common/include",
    "-I$repoRoot/toobloader/core/include",
    "-I$repoRoot/toobloader/core/utils/include",
    "-I$repoRoot/sdk/libtoob/include",
    "-I$repoRoot/common/lib/heatshrink",
    "-I$repoRoot/toob-infra/registry/packages/crypto/backend/monocypher",
    "-I$repoRoot/toob-infra/registry/packages/crypto/hash/sha256_sw"
)

$hsFlags = @(
    '-DHEATSHRINK_DYNAMIC_ALLOC=0',
    '-DHEATSHRINK_STATIC_INPUT_BUFFER_SIZE=128',
    '-DHEATSHRINK_STATIC_WINDOW_BITS=8',
    '-DHEATSHRINK_STATIC_LOOKAHEAD_BITS=4'
)

$baseCFlags = @('-std=c17', '-Wall', '-Wextra', '-Werror', '-O2') + $incFlags + $hsFlags

$sharedSources = @(
    @{ Name = 'hs_dec';        Src = "$repoRoot/common/lib/heatshrink/heatshrink_decoder.c"; Extra = @() },
    @{ Name = 'hs_enc';        Src = "$repoRoot/common/lib/heatshrink/heatshrink_encoder.c"; Extra = @('-Wno-implicit-fallthrough') },
    @{ Name = 'monocypher';    Src = "$repoRoot/toob-infra/registry/packages/crypto/backend/monocypher/monocypher.c"; Extra = @() },
    @{ Name = 'monocypher_ed'; Src = "$repoRoot/toob-infra/registry/packages/crypto/backend/monocypher/monocypher-ed25519.c"; Extra = @() },
    @{ Name = 'crypto_mono';   Src = "$repoRoot/toob-infra/registry/packages/crypto/backend/monocypher/crypto_monocypher.c"; Extra = @() },
    @{ Name = 'sha256';        Src = "$repoRoot/toob-infra/registry/packages/crypto/hash/sha256_sw/sha256.c"; Extra = @() },
    @{ Name = 'crypto_sha256'; Src = "$repoRoot/toob-infra/registry/packages/crypto/hash/sha256_sw/crypto_sha256.c"; Extra = @() }
)

$objFiles = @()
foreach ($item in $sharedSources) {
    $obj = Join-Path $buildDir ($item.Name + '.o')
    $flags = $baseCFlags + $item.Extra + @('-c', $item.Src, '-o', $obj)
    $compRes = Invoke-NativeCaptured -Exe $gcc -ArgList $flags
    if ($compRes.ExitCode -ne 0) {
        throw "Failed compiling $($item.Src):`n$($compRes.Text)"
    }
    $objFiles += $obj
}

$oracleSrc = Join-Path $repoRoot 'test/host/test_rocq_oracle.c'
$oracleExe = Join-Path $buildDir 'test_rocq_oracle.exe'
$linkArgs  = $baseCFlags + @($oracleSrc) + $objFiles + @('-o', $oracleExe)
$linkRes   = Invoke-NativeCaptured -Exe $gcc -ArgList $linkArgs
if ($linkRes.ExitCode -ne 0) {
    throw "Failed compiling ${oracleSrc}:`n$($linkRes.Text)"
}

$runRes = Invoke-NativeCaptured -Exe $oracleExe -ArgList @()
foreach ($line in $runRes.Lines) {
    Write-Host "      $line"
}
if ($runRes.ExitCode -ne 0 -or $runRes.Text -notmatch 'ROCQ_ORACLE_SUMMARY\s+vectors=13834\s+mismatches=0\s+status=PASS') {
    throw "Host-SIL 1:1 Rocq Oracle failed (exit $($runRes.ExitCode))"
}

$sw.Stop()
Write-Host '================================================================================'
Write-Host ("  ALL ROCQ PROOFS & {0:N0} HOST-SIL ORACLE VECTORS PASSED (0 mismatches) in {1:N2}s" -f $expectedVectors, $sw.Elapsed.TotalSeconds)
Write-Host '================================================================================'
exit 0
