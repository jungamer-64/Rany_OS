Param(
    [int[]]$ChunkSizes = @(512, 1024, 2048),
    [int[]]$StreamThresholds = @(1024, 2048),
    [int]$Runs = 3,
    [int]$TargetPixelsPerIter = 1000000
)

$results = @()
$features = "bench,std"

foreach ($chunk in $ChunkSizes) {
    foreach ($stream in $StreamThresholds) {
        Write-Output "Running benches: CHUNK_24=$chunk STREAM_THRESHOLD=$stream";
        $env:RANY_CHUNK_24_PIXELS = $chunk.ToString()
        $env:RANY_STREAM_THRESHOLD_PIXELS = $stream.ToString()
        $env:RANY_BENCH_TARGET_PIXELS_PER_ITER = $TargetPixelsPerIter.ToString()

        # Run bench multiple times to reduce noise and take median-of-medians
        $medians = @()
        for ($run = 0; $run -lt $Runs; $run++) {
            Write-Output "  Run $($run + 1)/$Runs"
            $output = cargo bench --manifest-path kernel/Cargo.toml --bench framebuffer_bench --features $features -- draw_image_bgr24 2>&1
            $outStr = $output -join "`n"

            $match = [regex]::Match($outStr, "draw_image_bgr24\s+time:\s+\[(.*?)\]")
            if ($match.Success) {
                $bracket = $match.Groups[1].Value
                $numbers = [regex]::Matches($bracket, '([0-9]+(?:\.[0-9]+)?)')
                if ($numbers.Count -ge 1) {
                    # Choose center value if 3 values are present, otherwise use the middle index
                    $centerIndex = [int][math]::Floor($numbers.Count / 2)
                    $median_val = [double]$numbers[$centerIndex].Groups[1].Value

                    if ($bracket -match 'ms') {
                        $median_us = $median_val * 1000.0
                    }
                    elseif ($bracket -match 'ns') {
                        $median_us = $median_val / 1000.0
                    }
                    elseif ($bracket -match '\bs\b') {
                        $median_us = $median_val * 1000000.0
                    }
                    else {
                        $median_us = $median_val
                    }
                    $medians += $median_us
                }
                else {
                    $medians += 0
                }
            }
            else {
                $medians += 0
            }
        }

        # Compute median-of-medians
        if ($medians.Count -ge 1) {
            $sorted = $medians | Sort-Object
            $mid = [int][math]::Floor($sorted.Count / 2)
            $median_us = $sorted[$mid]
            $median = "{0:N2}" -f $median_us
        }
        else {
            $median = "N/A"
            $median_us = 0
        }

        $results += [PSCustomObject]@{
            Chunk           = $chunk
            StreamThreshold = $stream
            Bgr24Median_us  = $median
        }
    }
}

$results | Format-Table -AutoSize
$results | ConvertTo-Csv -NoTypeInformation | Out-File tune_results.csv
Write-Output "Results written to tune_results.csv"