# async_swapout_validate_default.ps1
# Runs the simulation with recommended defaults multiple times to validate stability
param(
    [int]$Runs = 10,
    [int]$ChannelSize = 512,
    [int]$BatchSize = 16,
    [int]$Threads = 8,
    [int]$Iters = 400,
    [int]$TokenCapacity = 32,
    [int]$ReservedSlots = 128,
    [int]$Refill = 4,
    [int]$ProcDelay = 1
)

$out = "async_swapout_validate_default.csv"
"run,success,failures,processed,tokens_left,max_queue_len,time_ms,elapsed_ms,exit_code" | Out-File $out -Encoding UTF8

for ($i = 1; $i -le $Runs; $i++) {
    Write-Host "Run #$i ..."
    $env:ASYNC_SWAPOUT_CHANNEL_SIZE = "$ChannelSize"
    $env:ASYNC_SWAPOUT_BATCH_SIZE = "$BatchSize"
    $env:ASYNC_SWAPOUT_THREADS = "$Threads"
    $env:ASYNC_SWAPOUT_ITERS = "$Iters"
    $env:ASYNC_SWAPOUT_TOKEN_CAPACITY = "$TokenCapacity"
    $env:ASYNC_SWAPOUT_RESERVED_FILE_SLOTS = "$ReservedSlots"
    $env:ASYNC_SWAPOUT_TOKEN_REFILL = "$Refill"
    $env:ASYNC_SWAPOUT_PROCESSING_DELAY_MS = "$ProcDelay"

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $output = & cargo test -p rany_kernel --lib -- --nocapture async_swapout_sim_short_baseline --test-threads=1 2>&1
    $sw.Stop()
    $elapsed = [math]::Round($sw.Elapsed.TotalMilliseconds,3)
    $exit = $LASTEXITCODE

    $line = $output | Select-String "enq_success=" -SimpleMatch | Select-Object -First 1
    if ($line) {
        $s = $line.Line
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

    "$i,$success,$failures,$processed,$tokens_left,$max_q,$success,$elapsed,$exit" | Out-File $out -Append -Encoding UTF8
    Start-Sleep -Milliseconds 200
}

# Aggregate
$csv = Import-Csv $out
$avgSuccess = [math]::Round(($csv | Measure-Object -Property success -Average).Average,2)
$avgProcessed = [math]::Round(($csv | Measure-Object -Property processed -Average).Average,2)
$avgTime = [math]::Round(($csv | Measure-Object -Property elapsed_ms -Average).Average,2)
Write-Host "Validation results over $Runs runs: avg_success=$avgSuccess avg_processed=$avgProcessed avg_time_ms=$avgTime"
Write-Host "CSV: $out"