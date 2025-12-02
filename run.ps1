# ExoRust QEMU Runner Script
# PowerShell script for launching ExoRust kernel in QEMU

param(
    [switch]$Debug,
    [switch]$GDB,
    [switch]$NoGraphics,
    [switch]$Network,
    [switch]$Serial,
    [int]$Memory = 512,
    [int]$Cpus = 2,
    [string]$Disk = "",
    [switch]$Help
)

$ErrorActionPreference = "Stop"

# Configuration
$KERNEL_NAME = "RanyOS"
$KERNEL_PATH = "target/x86_64-rany_os/debug/$KERNEL_NAME"
$QEMU_BIN = "qemu-system-x86_64"

# Display help
if ($Help) {
    Write-Host @"
ExoRust QEMU Runner Script

Usage: .\run.ps1 [options]

Options:
  -Debug       Enable QEMU debug output
  -GDB         Start GDB server on port 1234 (pauses at start)
  -NoGraphics  Run without graphical display (serial only)
  -Network     Enable network with user-mode networking
  -Serial      Enable serial output to terminal
  -Memory N    Set memory size in MB (default: 512)
  -Cpus N      Set number of CPUs (default: 2)
  -Disk PATH   Attach a disk image
  -Help        Show this help message

Examples:
  .\run.ps1                    # Basic run
  .\run.ps1 -Debug -Serial     # Run with debug output
  .\run.ps1 -GDB               # Run with GDB server
  .\run.ps1 -Network -Memory 1024  # Run with network, 1GB RAM
"@
    exit 0
}

# Check for QEMU
Write-Host "[*] Checking for QEMU..." -ForegroundColor Cyan
$qemuPath = Get-Command $QEMU_BIN -ErrorAction SilentlyContinue

if (-not $qemuPath) {
    # Try common installation paths
    $commonPaths = @(
        "C:\Program Files\qemu\$QEMU_BIN.exe",
        "C:\Program Files (x86)\qemu\$QEMU_BIN.exe",
        "$env:LOCALAPPDATA\Programs\qemu\$QEMU_BIN.exe"
    )
    
    foreach ($path in $commonPaths) {
        if (Test-Path $path) {
            $QEMU_BIN = $path
            break
        }
    }
}

# Build the kernel first
Write-Host "[*] Building kernel..." -ForegroundColor Cyan
cargo build --target x86_64-rany_os.json

if ($LASTEXITCODE -ne 0) {
    Write-Host "[!] Build failed!" -ForegroundColor Red
    exit 1
}

Write-Host "[+] Build successful" -ForegroundColor Green

# Check if kernel binary exists
if (-not (Test-Path $KERNEL_PATH)) {
    Write-Host "[!] Kernel binary not found at: $KERNEL_PATH" -ForegroundColor Red
    exit 1
}

# Build QEMU command line
$qemuArgs = @(
    "-machine", "q35,accel=tcg",
    "-cpu", "qemu64,+rdtscp,+invtsc",
    "-m", "${Memory}M",
    "-smp", "$Cpus"
)

# Add kernel
$qemuArgs += "-kernel", $KERNEL_PATH

# Serial output
if ($Serial -or $NoGraphics) {
    $qemuArgs += "-serial", "stdio"
}

# No graphics mode
if ($NoGraphics) {
    $qemuArgs += "-nographic"
} else {
    # Enable VGA
    $qemuArgs += "-vga", "std"
}

# GDB support
if ($GDB) {
    $qemuArgs += "-s", "-S"
    Write-Host "[*] GDB server enabled on port 1234" -ForegroundColor Yellow
    Write-Host "    Connect with: gdb -ex 'target remote localhost:1234'" -ForegroundColor Yellow
}

# Network configuration
if ($Network) {
    $qemuArgs += "-netdev", "user,id=net0,hostfwd=tcp::8080-:80,hostfwd=tcp::2222-:22"
    $qemuArgs += "-device", "virtio-net-pci,netdev=net0"
    Write-Host "[*] Network enabled with port forwarding:" -ForegroundColor Yellow
    Write-Host "    Host 8080 -> Guest 80 (HTTP)" -ForegroundColor Yellow
    Write-Host "    Host 2222 -> Guest 22 (SSH)" -ForegroundColor Yellow
}

# Disk configuration
if ($Disk -and (Test-Path $Disk)) {
    $qemuArgs += "-drive", "file=$Disk,format=raw,if=virtio"
    Write-Host "[*] Disk attached: $Disk" -ForegroundColor Yellow
}

# Debug output
if ($Debug) {
    $qemuArgs += "-d", "int,cpu_reset", "-D", "qemu.log"
    Write-Host "[*] Debug output enabled (see qemu.log)" -ForegroundColor Yellow
}

# Add common devices
$qemuArgs += @(
    # RTC
    "-rtc", "base=utc",
    # Disable default devices we don't need
    "-no-reboot",
    "-no-shutdown"
)

# Display configuration
Write-Host ""
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "                        ExoRust QEMU Configuration" -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "  Kernel:  $KERNEL_PATH"
Write-Host "  Memory:  ${Memory}MB"
Write-Host "  CPUs:    $Cpus"
Write-Host "  Network: $(if ($Network) { 'Enabled' } else { 'Disabled' })"
Write-Host "  GDB:     $(if ($GDB) { 'Enabled (port 1234)' } else { 'Disabled' })"
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host ""

# Run QEMU
Write-Host "[*] Starting QEMU..." -ForegroundColor Green
Write-Host "    Command: $QEMU_BIN $($qemuArgs -join ' ')" -ForegroundColor DarkGray
Write-Host ""

& $QEMU_BIN @qemuArgs

$exitCode = $LASTEXITCODE
Write-Host ""
Write-Host "[*] QEMU exited with code: $exitCode" -ForegroundColor Cyan
