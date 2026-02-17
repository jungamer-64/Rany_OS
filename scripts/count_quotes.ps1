$s = Get-Content -Raw -Path scripts/run.ps1
$dq = ($s -split '"').Count-1
$sq = ($s -split "'").Count-1
Write-Output "DoubleQuotes:$dq SingleQuotes:$sq"