param([int]$lines = 309)
$scriptPath = Join-Path $PSScriptRoot 'run.ps1'
$content = Get-Content -Raw -Encoding UTF8 -Path $scriptPath
$allLines = [regex]::Split($content, '\r?\n')
$prefix = ($allLines[0..($lines-1)] -join "`n")
$tokens = [System.Management.Automation.Language.Token[]]::new(0)
$errors = [System.Collections.ObjectModel.Collection[System.Management.Automation.Language.ParseError]]::new()
[System.Management.Automation.Language.Parser]::ParseInput($prefix, [ref]$tokens, [ref]$errors)
Write-Output "PREFIX Errors: $($errors.Count)"
if ($errors.Count -gt 0) { $errors | ForEach-Object { Write-Output $_.Message } }

$suffix = ($allLines[$lines..($allLines.Length-1)] -join "`n")
$tokens2 = [System.Management.Automation.Language.Token[]]::new(0)
$errors2 = [System.Collections.ObjectModel.Collection[System.Management.Automation.Language.ParseError]]::new()
[System.Management.Automation.Language.Parser]::ParseInput($suffix, [ref]$tokens2, [ref]$errors2)
Write-Output "SUFFIX Errors: $($errors2.Count)"
if ($errors2.Count -gt 0) { $errors2 | ForEach-Object { Write-Output $_.Message } }