$scriptPath = Join-Path $PSScriptRoot 'run.ps1'
$content = Get-Content -Raw -Encoding UTF8 -Path $scriptPath
$tokens = [System.Management.Automation.Language.Token[]]::new(0)
$errors = [System.Collections.ObjectModel.Collection[System.Management.Automation.Language.ParseError]]::new()
[System.Management.Automation.Language.Parser]::ParseInput($content, [ref]$tokens, [ref]$errors)
Write-Host "Errors: $($errors.Count)"
if ($errors.Count -gt 0) {
    $e = $errors[0]
    Write-Host "Error at $($e.Extent.StartLineNumber):$($e.Extent.StartColumnNumber) - $($e.Message)"
    $toks = $tokens | Where-Object { ($_.Extent.StartLineNumber -le $e.Extent.StartLineNumber) -and ($_.Extent.EndLineNumber -ge $e.Extent.StartLineNumber) }
    foreach ($t in $toks) { Write-Host ("Token: {0} ({1}-{2}): '{3}'" -f $t.Type, $t.Extent.StartLineNumber, $t.Extent.EndLineNumber, $t.Text) }
} else {
   Write-Host "No errors, tokens count $($tokens.Count)"
}