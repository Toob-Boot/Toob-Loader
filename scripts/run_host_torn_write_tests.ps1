#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$buildDir = 'D:\ToobStorage\host_torn_write_build'

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

$sw = [System.Diagnostics.Stopwatch]::StartNew()

if (Test-Path $buildDir) {
    Remove-Item -Recurse -Force $buildDir
}
New-Item -ItemType Directory -Force -Path $buildDir | Out-Null

try {
    Set-Content -Path (Join-Path $buildDir 'generated_boot_config.h') -Value "#ifndef GENERATED_BOOT_CONFIG_H`n#define GENERATED_BOOT_CONFIG_H`n#endif`n" -Encoding Ascii

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

    $maxThreads = [Math]::Min(8, [Math]::Max(2, [Environment]::ProcessorCount))
    $pool = [RunspaceFactory]::CreateRunspacePool(1, $maxThreads)
    $pool.Open()

    try {
        $objFiles = @()
        $sharedTasks = @()
        foreach ($item in $sharedSources) {
            $obj = Join-Path $buildDir ($item.Name + '.o')
            $itemFlags = $baseCFlags + $item.Extra
            $ps = [PowerShell]::Create()
            $ps.RunspacePool = $pool
            [void]$ps.AddScript({
                param($gccExe, $flags, $srcFile, $objFile)
                $out = & $gccExe @flags -c $srcFile -o $objFile 2>&1
                [PSCustomObject]@{ ExitCode = $LASTEXITCODE; Output = ($out -join "`n"); Src = $srcFile }
            }).AddArgument($gcc).AddArgument($itemFlags).AddArgument($item.Src).AddArgument($obj)
            $sharedTasks += @{ PS = $ps; Handle = $ps.BeginInvoke() }
            $objFiles += $obj
        }
        foreach ($t in $sharedTasks) {
            $res = $t.PS.EndInvoke($t.Handle)[0]
            $t.PS.Dispose()
            if ($res.ExitCode -ne 0) {
                throw "Failed compiling shared dependency $($res.Src):`n$($res.Output)"
            }
        }

        $testSrc = Join-Path $repoRoot 'test/host/test_torn_write_injector.c'
        $totalCuts = [uint64]0
        $totalEccChecks = [uint64]0

        Write-Host '================================================================================'
        Write-Host '  Toob-Loader Wave 5C Host-SIL Torn-Write, Power-Cut & ECC Verification Runner'
        Write-Host '================================================================================'

        $profileTasks = @()
        for ($profile = 1; $profile -le 6; $profile++) {
            $exe = Join-Path $buildDir "test_torn_write_p$profile.exe"
            $ps = [PowerShell]::Create()
            $ps.RunspacePool = $pool
            [void]$ps.AddScript({
                param($gccExe, $flags, $prof, $srcFile, $objs, $exeFile)
                $compOut = & $gccExe @flags "-DTOOB_INJ_PROFILE=$prof" $srcFile @objs -o $exeFile 2>&1
                if ($LASTEXITCODE -ne 0) {
                    return [PSCustomObject]@{
                        Profile = $prof; Stage = 'compile'; ExitCode = $LASTEXITCODE
                        Lines = @($compOut | ForEach-Object { "$_" })
                    }
                }
                $runOut = & $exeFile 2>&1
                return [PSCustomObject]@{
                    Profile = $prof; Stage = 'run'; ExitCode = $LASTEXITCODE
                    Lines = @($runOut | ForEach-Object { "$_" })
                }
            }).AddArgument($gcc).AddArgument($baseCFlags).AddArgument($profile).AddArgument($testSrc).AddArgument($objFiles).AddArgument($exe)
            $profileTasks += @{ Profile = $profile; PS = $ps; Handle = $ps.BeginInvoke() }
        }

        foreach ($t in $profileTasks) {
            $res = $t.PS.EndInvoke($t.Handle)[0]
            $t.PS.Dispose()
            foreach ($line in $res.Lines) {
                Write-Host $line
                if ($line -match '^TORN_WRITE_SUMMARY\s+profile=(\d+)\s+cuts=(\d+)\s+ecc_checks=(\d+)\s+status=PASS$') {
                    $totalCuts += [uint64]$Matches[2]
                    $totalEccChecks += [uint64]$Matches[3]
                }
            }
            if ($res.ExitCode -ne 0) {
                throw "$($res.Stage) failed for TOOB_INJ_PROFILE=$($res.Profile) (exit code $($res.ExitCode))"
            }
            Write-Host ''
        }
    }
    finally {
        $pool.Close()
        $pool.Dispose()
    }

    $sw.Stop()
    $elapsedSec = [Math]::Round($sw.Elapsed.TotalSeconds, 2)
    Write-Host '================================================================================'
    Write-Host ("  ALL 6 PROFILES PASSED | Total Power-Cuts={0} | ECC Word Checks={1} | Time={2}s" -f $totalCuts, $totalEccChecks, $elapsedSec)
    Write-Host '================================================================================'
}
finally {
    if (Test-Path $buildDir) {
        Remove-Item -Recurse -Force $buildDir
    }
}
