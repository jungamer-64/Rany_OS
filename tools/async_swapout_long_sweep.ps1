# async_swapout_long_sweep.ps1
# Two-phase sweep: exploration (wide grid, single repeat) -> validation (top-N combos, many repeats)
# Produces CSVs: async_swapout_long_explore.csv, async_swapout_long_validation.csv, async_swapout_long_agg.csv

param(
    [int]$ChannelSize = 512,
    [int]$BatchSize = 16,
    [int]$Threads = 8,
    [int]$Iters = 400,
    [int]$TopN = 8,
    [int]$ValidationRepeats = 10
)

$token_caps = @(32, 64, 128, 256, 512)
$reserved_slots = @(16, 32, 64, 128)
$refills = @(4, 8, 16)
$proc_delays = @(1, 2, 5)

$explore_out = "async_swapout_long_explore.csv"
$valid_out = "async_swapout_long_validation.csv"
$agg_out = "async_swapout_long_agg.csv"

"token_cap,reserved_slots,refill,proc_delay,repeat,success,failures,processed,tokens_left,max_queue_len,time_ms,elapsed_ms,exit_code,logfile" | Out-File $explore_out -Encoding UTF8
"token_cap,reserved_slots,refill,proc_delay,repeat,success,failures,processed,tokens_left,max_queue_len,time_ms,elapsed_ms,exit_code,logfile" | Out-File $valid_out -Encoding UTF8

function Run-One($cap, $reserve, $ref, $proc, $rep, $outcsv) {
    Write-Host "Running cap=$cap reserve=$reserve refill=$ref proc=$proc (rep $rep) ..."
    $env:ASYNC_SWAPOUT_CHANNEL_SIZE = "$ChannelSize"
    $env:ASYNC_SWAPOUT_BATCH_SIZE = "$BatchSize"
    $env:ASYNC_SWAPOUT_THREADS = "$Threads"
    $env:ASYNC_SWAPOUT_ITERS = "$Iters"
    $env:ASYNC_SWAPOUT_TOKEN_CAPACITY = "$cap"
    $env:ASYNC_SWAPOUT_RESERVED_FILE_SLOTS = "$reserve"
    $env:ASYNC_SWAPOUT_TOKEN_REFILL = "$ref"
    $env:ASYNC_SWAPOUT_PROCESSING_DELAY_MS = "$proc"

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $output = & cargo test -p rany_kernel --lib -- --nocapture async_swapout_sim_short_baseline --test-threads=1 2>&1
    $sw.Stop()
    $elapsed_ms = [math]::Round($sw.Elapsed.TotalMilliseconds,3)
    $exit = $LASTEXITCODE

    $sline = $output | Select-String "enq_success=" -SimpleMatch | Select-Object -First 1
    if ($sline) {
        $s = $sline.Line
        if ($s -match "enq_success=(\d+), enq_failures=(\d+), processed=(\d+), tokens_left=(\d+), max_queue_len=(\d+)") {
            $success = $Matches[1]
            $failures = $Matches[2]
            $processed = $Matches[3]
            $tokens_left = $Matches[4]
            $max_q = $Matches[5]
        } else {
            $success = 0; $failures = 0; $processed = 0; $tokens_left = 0; $max_q = 0
        }
    } else {
        $success = 0; $failures = 0; $processed = 0; $tokens_left = 0; $max_q = 0
    }

    $logfile = ""
    if ($exit -ne 0) {
        $logfile = "explore_fail_cap_${cap}_res_${reserve}_ref_${ref}_proc_${proc}_rep_${rep}.log" -f
        $output | Out-File $logfile -Encoding UTF8
    }

    $time_ms = $elapsed_ms
    "$cap,$reserve,$ref,$proc,$rep,$success,$failures,$processed,$tokens_left,$max_q,$time_ms,$elapsed_ms,$exit,$logfile" | Out-File $outcsv -Append -Encoding UTF8
}

# Phase 1: Exploration (single repeat)
Write-Host "== Exploration Phase =="
foreach ($cap in $token_caps) {
    foreach ($reserve in $reserved_slots) {
        foreach ($ref in $refills) {
            foreach ($proc in $proc_delays) {
                Run-One $cap $reserve $ref $proc 1 $explore_out
                Start-Sleep -Milliseconds 100
            }
        }
    }
}

# Aggregate exploratory results and pick top-N combos
$rows = Import-Csv $explore_out
$groups = $rows | Group-Object -Property token_cap,reserved_slots,refill,proc_delay
$summary = @()
foreach ($g in $groups) {
    $cap = $g.Group[0].token_cap
    $reserve = $g.Group[0].reserved_slots
    $ref = $g.Group[0].refill
    $proc = $g.Group[0].proc_delay

    $avgSuccess = [math]::Round(($g.Group | Measure-Object -Property success -Average).Average,2)
    $avgFailures = [math]::Round(($g.Group | Measure-Object -Property failures -Average).Average,2)
    $avgProcessed = [math]::Round(($g.Group | Measure-Object -Property processed -Average).Average,2)
    $avgTokensLeft = [math]::Round(($g.Group | Measure-Object -Property tokens_left -Average).Average,2)
    $avgMaxQ = [math]::Round(($g.Group | Measure-Object -Property max_queue_len -Average).Average,2)
    $avgTimeMs = [math]::Round(($g.Group | Measure-Object -Property time_ms -Average).Average,2)

    $summary += ,@($cap,$reserve,$ref,$proc,$avgSuccess,$avgFailures,$avgProcessed,$avgTokensLeft,$avgMaxQ,$avgTimeMs)
}

# Convert summary to object array for sorting
$objs = $summary | ForEach-Object {
    [PSCustomObject]@{
        token_cap = $_[0]
        reserved_slots = $_[1]
        refill = $_[2]
        proc_delay = $_[3]
        avg_success = $_[4]
        avg_failures = $_[5]
        avg_processed = $_[6]
        avg_tokens_left = $_[7]
        avg_max_q = $_[8]
        avg_time_ms = $_[9]
    }
}

$ranked = $objs | Sort-Object @{Expression={[double]$_.avg_success};Descending=$true}, @{Expression={[double]$_.avg_time_ms};Descending=$false}
Write-Host "Top candidate combos from exploration (Top $TopN):"
$ranked | Select-Object -First $TopN | Format-Table -AutoSize

# Phase 2: Validation on top-N combos
$top = $ranked | Select-Object -First $TopN
Write-Host "== Validation Phase (Top $TopN combos, $ValidationRepeats repeats each) =="
foreach ($r in $top) {
    $cap = $r.token_cap
    $reserve = $r.reserved_slots
    $ref = $r.refill
    $proc = $r.proc_delay
    for ($rep = 1; $rep -le $ValidationRepeats; $rep++) {
        Run-One $cap $reserve $ref $proc $rep $valid_out
        Start-Sleep -Milliseconds 150
    }
}

# Aggregate validation results and pick recommendation
$rows2 = Import-Csv $valid_out
$groups2 = $rows2 | Group-Object -Property token_cap,reserved_slots,refill,proc_delay
$summary2 = @()
foreach ($g in $groups2) {
    $cap = $g.Group[0].token_cap
    $reserve = $g.Group[0].reserved_slots
    $ref = $g.Group[0].refill
    $proc = $g.Group[0].proc_delay

    $avgSuccess = [math]::Round(($g.Group | Measure-Object -Property success -Average).Average,2)
    $avgFailures = [math]::Round(($g.Group | Measure-Object -Property failures -Average).Average,2)
    $avgProcessed = [math]::Round(($g.Group | Measure-Object -Property processed -Average).Average,2)
    $avgTokensLeft = [math]::Round(($g.Group | Measure-Object -Property tokens_left -Average).Average,2)
    $avgMaxQ = [math]::Round(($g.Group | Measure-Object -Property max_queue_len -Average).Average,2)
    $avgTimeMs = [math]::Round(($g.Group | Measure-Object -Property time_ms -Average).Average,2)

    $summary2 += ,@($cap,$reserve,$ref,$proc,$avgSuccess,$avgFailures,$avgProcessed,$avgTokensLeft,$avgMaxQ,$avgTimeMs)
}

$objs2 = $summary2 | ForEach-Object {
    [PSCustomObject]@{
        token_cap = $_[0]
        reserved_slots = $_[1]
        refill = $_[2]
        proc_delay = $_[3]
        avg_success = $_[4]
        avg_failures = $_[5]
        avg_processed = $_[6]
        avg_tokens_left = $_[7]
        avg_max_q = $_[8]
        avg_time_ms = $_[9]
    }
}

$ranked2 = $objs2 | Sort-Object @{Expression={[double]$_.avg_success};Descending=$true}, @{Expression={[double]$_.avg_time_ms};Descending=$false}
Write-Host "Top validation results (sorted):"
$ranked2 | Select-Object -First 10 | Format-Table -AutoSize

# Write aggregated CSV
"token_cap,reserved_slots,refill,proc_delay,avg_success,avg_failures,avg_processed,avg_tokens_left,avg_max_q,avg_time_ms" | Out-File $agg_out -Encoding UTF8
foreach ($r in $ranked2) {
    "$($r.token_cap),$($r.reserved_slots),$($r.refill),$($r.proc_delay),$($r.avg_success),$($r.avg_failures),$($r.avg_processed),$($r.avg_tokens_left),$($r.avg_max_q),$($r.avg_time_ms)" | Out-File $agg_out -Append -Encoding UTF8
}

# Recommendation: pick top row
$best = $ranked2 | Select-Object -First 1
Write-Host "\nRecommended defaults (from validation):"
Write-Host "TOKEN_BUCKET_CAPACITY = $($best.token_cap), RESERVED_FILE_SLOTS = $($best.reserved_slots), TOKEN_REFILL_PER_BATCH = $($best.refill), proc_delay=$($best.proc_delay)"

# Save recommendation
$recfile = "async_swapout_recommendation.txt"
"Recommended defaults: TOKEN_BUCKET_CAPACITY = $($best.token_cap), RESERVED_FILE_SLOTS = $($best.reserved_slots), TOKEN_REFILL_PER_BATCH = $($best.refill), proc_delay=$($best.proc_delay)" | Out-File $recfile -Encoding UTF8

Write-Host "Sweep complete. Files: $explore_out, $valid_out, $agg_out, $recfile"