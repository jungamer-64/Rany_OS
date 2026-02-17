$bytes = [System.IO.File]::ReadAllBytes('scripts/run.ps1')
$zeroCount = ($bytes | Where-Object { $_ -eq 0 }).Count
Write-Output "Zero bytes: $zeroCount"