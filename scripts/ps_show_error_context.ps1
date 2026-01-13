$scriptPath = Join-Path $PSScriptRoot 'run.ps1'
$content = Get-Content -Raw -Encoding UTF8 -Path $scriptPath
$tokens = [System.Management.Automation.Language.Token[]]::new(0)
$errors = [System.Collections.ObjectModel.Collection[System.Management.Automation.Language.ParseError]]::new()
[System.Management.Automation.Language.Parser]::ParseInput($content, [ref]$tokens, [ref]$errors)
if ($errors.Count -eq 0) { Write-Host 'No parse errors'; exit 0 }
foreach ($e in $errors) {
    $start = [math]::Max(1, $e.Extent.StartLineNumber - 5)
    $end = [math]::Min(($content -split "`n").Count, $e.Extent.EndLineNumber + 5)
    Write-Host "Error: $($e.Message) at $($e.Extent.StartLineNumber):$($e.Extent.StartColumnNumber)"
    $allLines = [regex]::Split($content, '\r?\n')
    $lines = $allLines[$start-1..$end-1]
    for ($i=$start;$i -le $end;$i++) {
        $ln = $lines[$i-$start]
        Write-Host ("{0,4}: {1}" -f $i, $ln)
        if ($i -eq $e.Extent.StartLineNumber) {
            $col = $e.Extent.StartColumnNumber
            $marker = (' ' * ($col+5)) + '^
'
            Write-Host $marker
        }
    }
}
exit 1