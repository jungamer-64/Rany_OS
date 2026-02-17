$scriptPath = Join-Path $PSScriptRoot 'run.ps1'
$tokens = [System.Management.Automation.Language.Token[]]::new(0)
$errors = [System.Collections.ObjectModel.Collection[System.Management.Automation.Language.ParseError]]::new()
[System.Management.Automation.Language.Parser]::ParseInput((Get-Content -Raw -Encoding UTF8 -Path $scriptPath), [ref]$tokens, [ref]$errors)
if ($errors.Count -ne 0) {
    Write-Output "PARSE ERRORS: $($errors.Count)"
    foreach ($e in $errors) {
        Write-Output "Line:$($e.Extent.StartLineNumber) Col:$($e.Extent.StartColumnNumber) - $($e.Message)"
    }
    exit 2
}
else {
    Write-Output "PARSE_OK"
    exit 0
}