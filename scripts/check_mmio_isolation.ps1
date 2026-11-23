#Requires -Version 5.1
# check_mmio_isolation.ps1
# Verifies that Stage-0, Core, Recovery, and SDK do not bypass the HAL with direct MMIO casts or
# unauthorized hardware register inline assembly.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$ScanPaths = @("toobloader/core", "toobloader/stage0", "recovery", "sdk")
$RawHexPtrCastPattern = '\(\s*(?:volatile\s+)?(?:const\s+)?(?:uint(?:8|16|32|64)_t|uintptr_t)\s*\*\s*\)\s*(?:\(\s*uintptr_t\s*\)\s*)?0x[0-9a-fA-F]+'
$InlineAsmHeaderPattern = '(?<![A-Za-z0-9_])(?:__asm__|__asm|asm)\b(?:\s+volatile)?\s*\('
$PureBarrierAsmSet = @(
    '"" : : "g"(ptr) : "memory"',
    '"" ::: "memory"',
    '"nop; nop; nop;" ::: "memory"'
)
$Violations = New-Object System.Collections.Generic.List[PSCustomObject]

foreach ($Path in $ScanPaths) {
    $AbsPath = Join-Path $RepoRoot $Path
    if (Test-Path $AbsPath) {
        $Files = Get-ChildItem -Path $AbsPath -Recurse -File -Include *.c, *.h
        foreach ($File in $Files) {
            $Rel = $File.FullName.Substring($RepoRoot.Length + 1).Replace('\', '/')
            $Raw = [System.IO.File]::ReadAllText($File.FullName)
            $Stripped = [regex]::Replace($Raw, '/\*[\s\S]*?\*/', {
                param($m)
                return ($m.Value -replace '[^\r\n]', ' ')
            })
            $Stripped = [regex]::Replace($Stripped, '//[^\r\n]*', '')

            $Lines = $Stripped -split "\r?\n"
            for ($i = 0; $i -lt $Lines.Length; $i++) {
                $LineText = $Lines[$i]
                if ($LineText -match $RawHexPtrCastPattern) {
                    if ($Rel -eq 'recovery/recovery_port.c' -and $LineText -match '0xE000ED0CU?') {
                        continue
                    }
                    $Violations.Add([PSCustomObject]@{
                        File = $Rel
                        Line = $i + 1
                        Kind = 'RAW_HEX_PTR_CAST'
                        Text = $LineText.Trim()
                    })
                }
            }

            foreach ($am in [regex]::Matches($Stripped, $InlineAsmHeaderPattern)) {
                $pStart = $am.Index + $am.Length
                $pDepth = 1
                $pPos = $pStart
                while ($pPos -lt $Stripped.Length -and $pDepth -gt 0) {
                    $ch = $Stripped[$pPos]
                    if ($ch -eq '(') { $pDepth++ }
                    elseif ($ch -eq ')') { $pDepth-- }
                    $pPos++
                }
                if ($pDepth -ne 0) { continue }
                $AsmRawInner = $Stripped.Substring($pStart, ($pPos - 1) - $pStart)
                $AsmInner = ($AsmRawInner -replace '\\\r?\n', ' ' -replace '\s+', ' ').Trim()
                if ($PureBarrierAsmSet -contains $AsmInner) {
                    continue
                }
                if ($Rel -eq 'toobloader/stage0/stage0_main.c') {
                    # Stage-0 boot entry trampoline, interrupt mask, cache sync, and VTOR jump
                    continue
                }
                if ($Rel -eq 'recovery/recovery_port.c' -and $AsmInner -match '^"dsb sy"\s*:::\s*"memory"$') {
                    continue
                }
                $Prefix = $Stripped.Substring(0, $am.Index)
                $Ln = ($Prefix -split "\r?\n").Count
                $Violations.Add([PSCustomObject]@{
                    File = $Rel
                    Line = $Ln
                    Kind = 'HARDWARE_INLINE_ASM'
                    Text = $AsmInner
                })
            }
        }
    }
}

if ($Violations.Count -gt 0) {
    Write-Host "FAIL: Direct MMIO / unauthorized hardware register access detected!" -ForegroundColor Red
    foreach ($V in $Violations) {
        Write-Host "  [$($V.Kind)] $($V.File):$($V.Line) -> $($V.Text)" -ForegroundColor Red
    }
    Exit 1
} else {
    Write-Host "PASS: Zero unauthorized direct MMIO casts or hardware inline asm across Stage-0, Core, Recovery & SDK." -ForegroundColor Green
    Exit 0
}
