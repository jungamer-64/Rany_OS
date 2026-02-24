# Build kernel (with integration test feature) and run QEMU for the storage E2E
# Usage: .\run_e2e_qemu.ps1

param(
    [string]$KernelPath = "target/x86_64-exorust/debug/RanyOS",
    [string]$DiskImage = "test_disk.img",
    [int]$TimeoutSeconds = 60
)

Write-Output "Building kernel with integration tests feature..."
# Use the same target as CI. Adjust if your environment differs.
cargo build --target x86_64-exorust.json --features run-integration-tests
if ($LASTEXITCODE -ne 0) {
    Write-Error "Kernel build failed"
    exit $LASTEXITCODE
}

if (-not (Test-Path $DiskImage)) {
    Write-Output "Disk image $DiskImage not found. Creating..."
    & "$PSScriptRoot\create_test_disk.ps1"
}

Write-Output "Launching QEMU..."
$KERNEL = $KernelPath
$qemuArgs = @(
    "-machine", "q35,accel=tcg",
    "-cpu", "qemu64",
    "-smp", "2",
    "-m", "512M",
    "-nic", "none",
    "-kernel", $KERNEL,
    "-serial", "stdio",
    "-display", "none",
    "-device", "virtio-blk-pci,drive=drive0",
    "-drive", "id=drive0,if=none,format=raw,file=$DiskImage",
    "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
    "-no-reboot"
)

# Run QEMU and wait (timeout)
$proc = Start-Process -FilePath qemu-system-x86_64 -ArgumentList $qemuArgs -NoNewWindow -PassThru -Wait -ErrorAction SilentlyContinue
if ($proc -eq $null) {
    Write-Error "qemu-system-x86_64 not found in PATH"
    exit 1
}

Write-Output "QEMU exited with code $($proc.ExitCode)"
if ($proc.ExitCode -eq 0) {
    Write-Output "QEMU exited normally"
} else {
    Write-Output "Check storage_test.log or serial output for failures"
}
