# async_swapout_sweep.ps1
# Run a parameter sweep for the async_swapout simulation test and collect results

$channel_size = 512
$batch_size = 16
$threads = 8
$iters = 400

$token_caps = @(64, 128, 256)
$reserved_slots = @(32, 64, 128)
$refills = @(4, 8, 16)

$outfile = "async_swapout_sweep_results.csv"
"token_cap,reserved_slots,refill,success,failures,processed,tokens_left,max_queue_len,time_ms" | Out-File $outfile -Encoding UTF8

foreach ($cap in $token_caps) {
    foreach ($reserve in $reserved_slots) {
        foreach ($refill in $refills) {
            Write-Host "Running cap=$cap reserve=$reserve refill=$refill..."
            $env:ASYNC_SWAPOUT_CHANNEL_SIZE = "$channel_size"
            $env:ASYNC_SWAPOUT_BATCH_SIZE = "$batch_size"
            $env:ASYNC_SWAPOUT_THREADS = "$threads"
            $env:ASYNC_SWAPOUT_ITERS = "$iters"
            $env:ASYNC_SWAPOUT_TOKEN_CAPACITY = "$cap"
            $env:ASYNC_SWAPOUT_RESERVED_FILE_SLOTS = "$reserve"
            $env:ASYNC_SWAPOUT_TOKEN_REFILL = "$refill"

            $output = & cargo test -p rany_kernel --lib -- --nocapture async_swapout_sim_short_baseline --test-threads=1 2>&1

            # Extract the two lines we need
            $line1 = ($output | Select-String "async_swapout_sim_short_baseline: threads=.*time=(.*)").Line
            $line2 = ($output | Select-String "enq_success=.*").Line

            if ($line1 -and $line2) {
                # parse values
                if ($line1 -match "time=(.*)s") {
                    $time_ms = ([double]$Matches[1]) * 1000.0
                } elseif ($line1 -match "time=(.*)ms") {
                    $time_ms = [double]$Matches[1]
                } else {
                    $time_ms = 0
                }

                if ($line2 -match "enq_success=(\d+), enq_failures=(\d+), processed=(\d+), tokens_left=(\d+), max_queue_len=(\d+)") {
                    $success = $Matches[1]
                    $failures = $Matches[2]
                    $processed = $Matches[3]
                    $tokens_left = $Matches[4]
                    $max_q = $Matches[5]
                } else {
                    $success = 0; $failures = 0; $processed = 0; $tokens_left = 0; $max_q = 0
                }

                "$cap,$reserve,$refill,$success,$failures,$processed,$tokens_left,$max_q,$time_ms" | Out-File $outfile -Append -Encoding UTF8
                Write-Host "Result: success=$success failures=$failures processed=$processed tokens_left=$tokens_left max_q=$max_q time_ms=$time_ms"
            } else {
                Write-Host "Failed to parse output for cap=$cap reserve=$reserve refill=$refill"
                $output | Out-File ("async_swapout_sweep_$cap`_$reserve`_$refill.log") -Encoding UTF8
            }

            Start-Sleep -Milliseconds 200
        }
    }
}

Write-Host "Sweep complete. Results in $outfile"