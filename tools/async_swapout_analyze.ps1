$csv = Import-Csv async_swapout_sweep_agg.csv
$filtered = $csv | Where-Object { [double]$_.avg_success -eq 528 } | Sort-Object {[double]$_.avg_time_ms}
Write-Host "Top combos (success=528, sorted by avg_time_ms):"
$filtered | Select-Object -First 10 | Format-Table -AutoSize

Write-Host ""
Write-Host "Top 10 combos by success_rate (avg_success / (avg_success + avg_failures)) :"
$sc = $csv | ForEach-Object { $_ | Add-Member -NotePropertyName success_rate -NotePropertyValue ([double]$($_.avg_success) / ([double]$($_.avg_success) + [double]$($_.avg_failures))) -PassThru }
$sc | Sort-Object {[double]$_.success_rate} -Descending | Select-Object -First 10 | Format-Table -AutoSize
