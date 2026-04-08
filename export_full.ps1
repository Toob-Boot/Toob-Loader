param (
    [string]$OutFile = "full_review_export.txt"
)

$ExportItems = @(
    "libtoob",
    "core"
)

# Create or clear the output file
New-Item -Path $OutFile -ItemType File -Force | Out-Null

foreach ($Item in $ExportItems) {
    if (-not (Test-Path $Item)) {
        Write-Host "Warning: '$Item' not found, skipping." -ForegroundColor Yellow
        continue
    }

    if ((Get-Item $Item) -is [System.IO.DirectoryInfo]) {
        $Files = Get-ChildItem -Path $Item -Recurse -File -Include *.c,*.h
        foreach ($File in $Files) {
            $RelativePath = $File.FullName.Substring((Resolve-Path ".").ProviderPath.Length + 1).Replace('\', '/')
            $Header = "`n======================================================================`n"
            $Header += "FILE: $RelativePath`n"
            $Header += "======================================================================`n"
            Add-Content -Path $OutFile -Value $Header
            $Content = Get-Content -Path $File.FullName -Raw
            if ($Content) { Add-Content -Path $OutFile -Value $Content }
        }
    } else {
        $File = Get-Item $Item
        $RelativePath = $File.FullName.Substring((Resolve-Path ".").ProviderPath.Length + 1).Replace('\', '/')
        $Header = "`n======================================================================`n"
        $Header += "FILE: $RelativePath`n"
        $Header += "======================================================================`n"
        Add-Content -Path $OutFile -Value $Header
        $Content = Get-Content -Path $File.FullName -Raw
        if ($Content) { Add-Content -Path $OutFile -Value $Content }
    }
}

Write-Host "Done! All specified files have been exported into: $OutFile" -ForegroundColor Green
