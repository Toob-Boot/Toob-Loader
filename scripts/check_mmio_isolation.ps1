# check_mmio_isolation.ps1
# E0-T2: Verifiziert, dass der Core Hardware ausschließlich über das boot_platform_t HAL Interface anspricht.
# Sucht nach Mustern wie (volatile uint32_t *)0x... im Core/Stage0.

$CorePaths = @("toobloader/core", "toobloader/stage0")
$ViolationPattern = '\(\s*volatile\s+(const\s+)?uint(8|16|32|64)_t\s*\*\s*\)\s*0x'
$Violations = @()

foreach ($Path in $CorePaths) {
    if (Test-Path $Path) {
        $Files = Get-ChildItem -Path $Path -Recurse -Include *.c, *.h
        foreach ($File in $Files) {
            $Content = Get-Content -Path $File.FullName
            for ($i = 0; $i -lt $Content.Length; $i++) {
                if ($Content[$i] -match $ViolationPattern) {
                    $Violations += [PSCustomObject]@{
                        File = $File.FullName
                        Line = $i + 1
                        Text = $Content[$i].Trim()
                    }
                }
            }
        }
    }
}

if ($Violations.Count -gt 0) {
    Write-Error "FAIL: Direct MMIO register access detected in Core/Stage0 codebase!"
    foreach ($V in $Violations) {
        Write-Host "  $($V.File):$($V.Line) -> $($V.Text)" -ForegroundColor Red
    }
    Exit 1
} else {
    Write-Host "PASS: Zero direct MMIO accesses found in Core/Stage0. Hardware boundary is strictly isolated." -ForegroundColor Green
    Exit 0
}
