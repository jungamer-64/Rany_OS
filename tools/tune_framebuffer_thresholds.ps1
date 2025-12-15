Param(
    [int[]]$ChunkSizes = @(512,1024,2048),
    [int[]]$StreamThresholds = @(1024,2048)
)

$results = @()

foreach ($chunk in $ChunkSizes) {
    foreach ($stream in $StreamThresholds) {
        Write-Host "Running benches: CHUNK_24=$chunk STREAM_THRESHOLD=$stream"
        $env:RANY_CHUNK_24_PIXELS = $chunk.ToString()
        $env:RANY_STREAM_THRESHOLD_PIXELS = $stream.ToString()

        # Run bench. This will recompile as needed; may take a while.
        $output = cargo bench --manifest-path kernel/Cargo.toml --bench framebuffer_bench --features bench 2>&1

        # Extract draw_image_bgr24_mmio median (middle number in bracket)
        $match = $output | Select-String -Pattern "draw_image_bgr24_mmio\s+time:\s+\[(.*?)\]" -AllMatches
        if ($match) {
            $bracket = $match.Matches[0].Groups[1].Value
            # bracket example: '453.72 µs 458.04 µs 463.56 µs' -> take middle number
            $parts = $bracket -split '\s+' | Where-Object {$_ -match '^[0-9]+\.[0-9]+'}
            $median = if ($parts.Count -ge 2) { $parts[1] } else { $parts[0] }
        } else {
            $median = "N/A"
        }

        $results += [PSCustomObject]@{
            Chunk = $chunk
            StreamThreshold = $stream
            Bgr24Median = $median
        }
    }
}

$results | Format-Table -AutoSize
$results | ConvertTo-Csv -NoTypeInformation | Out-File tune_results.csv
Write-Host "Results written to tune_results.csv"