$p = Resolve-Path "scripts/run.ps1"
$content = Get-Content -Raw -Path $p
[System.IO.File]::WriteAllText($p, $content, (New-Object System.Text.UTF8Encoding $true))
Write-Host 'WROTE BOM'
