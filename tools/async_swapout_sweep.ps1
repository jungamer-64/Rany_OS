# async_swapout_sweep.ps1 - Extended sweep with repeats and aggregation
# Run expanded parameter sweep for the async_swapout simulation test and aggregate results

# Base test parameters
$channel_size = 512
$batch_size = 16
$threads = 8
$iters = 400

# Parameter ranges to sweep (adjust as needed)
$token_caps = @(64, 128, 256)
$reserved_slots = @(32, 64, 128)
$refills = @(4, 8, 16)
$proc_delays = @(1, 2, 5)
$repeats = 2

$outfile = "async_swapout_sweep_results.csv"
$aggfile = "async_swapout_sweep_agg.csv"

# Per-run CSV (one line per run)
"token_cap,reserved_slots,refill,proc_delay,repeat,success,failures,processed,tokens_left,max_queue_len,time_ms,elapsed_ms" | Out-File $outfile -Encoding UTF8
# Aggregated CSV (averages)
"token_cap,reserved_slots,refill,proc_delay,avg_success,avg_failures,avg_processed,avg_tokens_left,avg_max_q,avg_time_ms,avg_elapsed_ms" | Out-File $aggfile -Encoding UTF8

foreach ($cap in $token_caps) {
    foreach ($reserve in $reserved_slots) {
        foreach ($ref in $refills) {
            foreach ($proc in $proc_delays) {
                for ($rep = 1; $rep -le $repeats; $rep++) {
                    Write-Host "Running cap=$cap reserve=$reserve refill=$ref proc=$proc (rep $rep/$repeats)..."

                    $env:ASYNC_SWAPOUT_CHANNEL_SIZE = "$channel_size"
                    $env:ASYNC_SWAPOUT_BATCH_SIZE = "$batch_size"
                    $env:ASYNC_SWAPOUT_THREADS = "$threads"
                    $env:ASYNC_SWAPOUT_ITERS = "$iters"
                    $env:ASYNC_SWAPOUT_TOKEN_CAPACITY = "$cap"
                    $env:ASYNC_SWAPOUT_RESERVED_FILE_SLOTS = "$reserve"
                    $env:ASYNC_SWAPOUT_TOKEN_REFILL = "$ref"
                    $env:ASYNC_SWAPOUT_PROCESSING_DELAY_MS = "$proc"

                    $sw = [System.Diagnostics.Stopwatch]::StartNew()
                    $output = & cargo test -p rany_kernel --lib -- --nocapture async_swapout_sim_short_baseline --test-threads=1 2>&1
                    $sw.Stop()
                    $elapsed_ms = [math]::Round($sw.Elapsed.TotalMilliseconds,3)

                    $line = $output | Select-String "enq_success=" -SimpleMatch | Select-Object -First 1
                    if ($line) {
                        $sline = $line.Line
                        if ($sline -match "enq_success=(\d+), enq_failures=(\d+), processed=(\d+), tokens_left=(\d+), max_queue_len=(\d+)") {
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

                    $time_ms = $elapsed_ms
                    "$cap,$reserve,$ref,$proc,$rep,$success,$failures,$processed,$tokens_left,$max_q,$time_ms,$elapsed_ms" | Out-File $outfile -Append -Encoding UTF8

                    Start-Sleep -Milliseconds 300
                }
            }
        }
    }
}

# Aggregate results by (token_cap, reserved_slots, refill, proc_delay)
$rows = Import-Csv $outfile
$groups = $rows | Group-Object -Property token_cap,reserved_slots,refill,proc_delay
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
    $avgElapsedMs = [math]::Round(($g.Group | Measure-Object -Property elapsed_ms -Average).Average,2)

    "$cap,$reserve,$ref,$proc,$avgSuccess,$avgFailures,$avgProcessed,$avgTokensLeft,$avgMaxQ,$avgTimeMs,$avgElapsedMs" | Out-File $aggfile -Append -Encoding UTF8
}

Write-Host "Sweep complete. Results: $outfile and $aggfile"