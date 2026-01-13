$s = Get-Content -Raw -Path scripts/run.ps1
$open = ($s -split '\(').Count-1
$close = ($s -split '\)').Count-1
Write-Host "OpenParen:$open CloseParen:$close"