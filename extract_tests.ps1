$src = "kernel/src/graphics/framebuffer.rs"
$dst = "kernel/src/graphics/framebuffer/tests.rs"
$lines = Get-Content $src
# Lines 127 to 1587 (1-based) correspond to indices 126 to 1586.
$test_lines = $lines[126..1586]
$dedented = $test_lines | ForEach-Object {
    if ($_.StartsWith("    ")) { $_.Substring(4) } else { $_ }
}
$dedented | Set-Content $dst -Encoding UTF8
Write-Host "Extracted $($dedented.Count) lines to $dst"
