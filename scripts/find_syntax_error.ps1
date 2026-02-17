$scriptPath = Join-Path $PSScriptRoot 'run.ps1'
$content = Get-Content -Raw -Encoding UTF8 -Path $scriptPath
$allLines = [regex]::Split($content, '\r?\n')
$start = 309 # 0-indexed in our Python earlier; but here we use 0-based index; we want to start at line index 309 (line numbers start at 1)
$low = $start
$high = $allLines.Length - 1

while ($low -lt $high) {
    $mid = [int](($low + $high) / 2)
    $frag = ($allLines[$start..$mid] -join "`n")
    $tokens = [System.Management.Automation.Language.Token[]]::new(0)
    $errors = [System.Collections.ObjectModel.Collection[System.Management.Automation.Language.ParseError]]::new()
    [System.Management.Automation.Language.Parser]::ParseInput($frag, [ref]$tokens, [ref]$errors)
    if ($errors.Count -eq 0) {
        $low = $mid + 1
    } else {
        $high = $mid
    }
}
Write-Output "Suspected bad line index (0-based): $low"
$contextStart = [math]::Max($start, $low - 5)
$contextEnd = [math]::Min($allLines.Length - 1, $low + 5)
for ($i = $contextStart; $i -le $contextEnd; $i++) {
    $ln = $allLines[$i]
    $num = $i + 1
    Write-Output ("{0,4}: {1}" -f $num, $ln)
}
$frag2 = ($allLines[$start..$low] -join "`n")
$tokens2 = [System.Management.Automation.Language.Token[]]::new(0)
$errors2 = [System.Collections.ObjectModel.Collection[System.Management.Automation.Language.ParseError]]::new()
[System.Management.Automation.Language.Parser]::ParseInput($frag2, [ref]$tokens2, [ref]$errors2)
Write-Output "Errors when parsing up to suspected line: $($errors2.Count)"
if ($errors2.Count -gt 0) { $errors2 | ForEach-Object { Write-Output $_.Message } }

