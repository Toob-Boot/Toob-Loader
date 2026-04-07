param (
    [string]$OutFile = "libtoob_review_export.txt"
)

$TargetDir = "libtoob"

if (-not (Test-Path $TargetDir)) {
    Write-Host "Error: Directory '$TargetDir' not found!" -ForegroundColor Red
    exit 1
}

$Files = Get-ChildItem -Path $TargetDir -Recurse -File -Include *.c,*.h

# Create or clear the output file
New-Item -Path $OutFile -ItemType File -Force | Out-Null

foreach ($File in $Files) {
    # Generate relative path, e.g. "include/libtoob.h"
    $RelativePath = $File.FullName.Substring((Resolve-Path $TargetDir).ProviderPath.Length + 1).Replace('\', '/')
    
    $Header = "`n======================================================================`n"
    $Header += "FILE: libtoob/$RelativePath`n"
    $Header += "======================================================================`n"
    
    Add-Content -Path $OutFile -Value $Header
    
    # Read file content safely and append
    $Content = Get-Content -Path $File.FullName -Raw
    if ($Content) {
        Add-Content -Path $OutFile -Value $Content
    }
}

Write-Host "Done! All libtoob files have been exported into: $OutFile" -ForegroundColor Green
