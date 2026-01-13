$s = Get-Content -Raw -Path scripts/run.ps1
$dq = ($s -split '"').Count-1
$sq = ($s -split "'").Count-1
Write-Host "DoubleQuotes:$dq SingleQuotes:$sq"