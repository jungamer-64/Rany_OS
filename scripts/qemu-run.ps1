#!/usr/bin/env pwsh
<#
.SYNOPSIS
    ExoRust (RanyOS) QEMU Launch Script for Windows PowerShell
.DESCRIPTION
    Builds and runs the ExoRust kernel in QEMU with configurable options.
.PARAMETER BuildOnly
    Only build the kernel, do not start QEMU.
.PARAMETER Debug
    Enable QEMU GDB debugging on port 1234.
.PARAMETER NoKVM
    Disable KVM/WHPX hardware acceleration.
.PARAMETER Memory
    Amount of RAM in MB (default: 512).
.PARAMETER Cpus
    Number of CPU cores (default: 4).
.PARAMETER Network
    Enable network with virtio-net.
.PARAMETER Storage
    Path to a disk image for storage testing.
.PARAMETER Benchmark
    Enable benchmark mode with performance counters.
.PARAMETER Timeout
    Timeout in seconds for automated tests (default: 60).
.PARAMETER TestMode
    Run in test mode (exit after boot tests complete).
#>

[CmdletBinding()]
param(
    [switch]$BuildOnly,
    [switch]$Debug,
    [switch]$NoKVM,
    [int]$Memory = 512,
    [int]$Cpus = 4,
    [switch]$Network,
    [string]$Storage,
    [switch]$Benchmark,
    [int]$Timeout = 60,
    [switch]$TestMode
)

$ErrorActionPreference = "Stop"

# Configuration
$KERNEL_NAME = "RanyOS"
$TARGET = "x86_64-rany_os"
$BUILD_DIR = "target/$TARGET/debug"

# Colors for output
function Write-ColorOutput($ForegroundColor) {
    $fc = $host.UI.RawUI.ForegroundColor
    $host.UI.RawUI.ForegroundColor = $ForegroundColor
    if ($args) {
        Write-Output $args
    }
    $host.UI.RawUI.ForegroundColor = $fc
}

function Write-Info($message) {
    Write-ColorOutput Cyan "[INFO] $message"
}

function Write-Success($message) {
    Write-ColorOutput Green "[SUCCESS] $message"
}

function Write-Error($message) {
    Write-ColorOutput Red "[ERROR] $message"
}

function Write-Warning($message) {
    Write-ColorOutput Yellow "[WARNING] $message"
}

# Check prerequisites
function Test-Prerequisites {
    Write-Info "Checking prerequisites..."
    
    # Check Rust
    if (-not (Get-Command "cargo" -ErrorAction SilentlyContinue)) {
        Write-Error "Cargo not found. Please install Rust."
        exit 1
    }
    
    # Check QEMU
    $qemu = Get-Command "qemu-system-x86_64" -ErrorAction SilentlyContinue
    if (-not $qemu) {
        # Try common Windows paths
        $commonPaths = @(
            "C:\Program Files\qemu\qemu-system-x86_64.exe",
            "C:\qemu\qemu-system-x86_64.exe",
            "$env:LOCALAPPDATA\Programs\qemu\qemu-system-x86_64.exe"
        )
        foreach ($path in $commonPaths) {
            if (Test-Path $path) {
                $env:PATH += ";$(Split-Path $path)"
                break
            }
        }
    }
    
    if (-not (Get-Command "qemu-system-x86_64" -ErrorAction SilentlyContinue)) {
        Write-Warning "QEMU not found in PATH. QEMU execution will fail."
        Write-Warning "Please install QEMU and add it to PATH."
    }
    
    Write-Success "Prerequisites check completed."
}

# Build the kernel
function Build-Kernel {
    Write-Info "Building ExoRust kernel..."
    
    $buildArgs = @("build", "--target", "$TARGET.json")
    
    if ($Benchmark) {
        $buildArgs += "--features"
        $buildArgs += "benchmark"
    }
    
    $result = & cargo @buildArgs 2>&1
    
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Build failed!"
        Write-Output $result
        exit 1
    }
    
    $kernelPath = "$BUILD_DIR/$KERNEL_NAME"
    if (-not (Test-Path $kernelPath)) {
        Write-Error "Kernel binary not found at: $kernelPath"
        exit 1
    }
    
    Write-Success "Kernel built successfully: $kernelPath"
    return $kernelPath
}

# Create bootable image
function New-BootImage($kernelPath) {
    Write-Info "Creating bootable image..."
    
    # The bootloader crate should handle this, but we verify the output
    $imagePath = "$BUILD_DIR/boot-bios-$KERNEL_NAME.img"
    
    if (-not (Test-Path $imagePath)) {
        # Try to create using bootimage if available
        if (Get-Command "bootimage" -ErrorAction SilentlyContinue) {
            & bootimage build --target "$TARGET.json"
        } else {
            Write-Warning "bootimage tool not found. Using kernel binary directly."
            return $kernelPath
        }
    }
    
    if (Test-Path $imagePath) {
        Write-Success "Boot image created: $imagePath"
        return $imagePath
    }
    
    return $kernelPath
}

# Run QEMU
function Start-Qemu($imagePath) {
    Write-Info "Starting QEMU..."
    
    $qemuArgs = @(
        "-machine", "q35"
        "-cpu", "qemu64,+rdtscp,+x2apic,+pdpe1gb"
        "-smp", "$Cpus"
        "-m", "${Memory}M"
        "-serial", "stdio"
        "-display", "none"
    )
    
    # Hardware acceleration
    if (-not $NoKVM) {
        # Check for Windows Hypervisor Platform (WHPX)
        $whpxAvailable = $false
        try {
            $hypervisor = Get-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform -ErrorAction SilentlyContinue
            if ($hypervisor -and $hypervisor.State -eq "Enabled") {
                $qemuArgs += @("-accel", "whpx,kernel-irqchip=off")
                $whpxAvailable = $true
                Write-Info "Using WHPX acceleration"
            }
        } catch {
            # Not on Windows or no admin rights
        }
        
        if (-not $whpxAvailable) {
            # Try tcg with multi-threading
            $qemuArgs += @("-accel", "tcg,thread=multi")
            Write-Info "Using TCG acceleration (software)"
        }
    } else {
        $qemuArgs += @("-accel", "tcg,thread=multi")
    }
    
    # Boot configuration
    if ($imagePath -match "\.img$") {
        $qemuArgs += @("-drive", "format=raw,file=$imagePath")
    } else {
        $qemuArgs += @("-kernel", $imagePath)
    }
    
    # Network
    if ($Network) {
        $qemuArgs += @(
            "-device", "virtio-net-pci,netdev=net0"
            "-netdev", "user,id=net0,hostfwd=tcp::8080-:80"
        )
        Write-Info "Network enabled: port 8080 forwarded to guest port 80"
    }
    
    # Storage
    if ($Storage -and (Test-Path $Storage)) {
        $qemuArgs += @(
            "-device", "virtio-blk-pci,drive=drive0"
            "-drive", "id=drive0,if=none,format=raw,file=$Storage"
        )
        Write-Info "Storage: $Storage"
    }
    
    # Debug
    if ($Debug) {
        $qemuArgs += @("-s", "-S")
        Write-Info "GDB server started on port 1234. Connect with: gdb -ex 'target remote :1234'"
    }
    
    # Benchmark mode
    if ($Benchmark) {
        $qemuArgs += @("-icount", "shift=0,align=on,sleep=on")
    }
    
    # Test mode
    if ($TestMode) {
        $qemuArgs += @(
            "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04"
            "-no-reboot"
        )
        
        Write-Info "Running in test mode with ${Timeout}s timeout..."
        
        $process = Start-Process -FilePath "qemu-system-x86_64" `
            -ArgumentList $qemuArgs `
            -NoNewWindow -PassThru `
            -RedirectStandardOutput "qemu_stdout.log" `
            -RedirectStandardError "qemu_stderr.log"
        
        $exited = $process.WaitForExit($Timeout * 1000)
        
        if (-not $exited) {
            Write-Warning "QEMU timed out after ${Timeout}s"
            $process.Kill()
            return 1
        }
        
        $exitCode = $process.ExitCode
        
        # QEMU exit codes: (code << 1) | 1
        # Success = 0x10 -> (0x10 >> 1) = 8, but we want 0
        # Failure = 0x11 -> (0x11 >> 1) = 8
        
        if ($exitCode -eq 33) {
            Write-Success "Tests passed!"
            return 0
        } else {
            Write-Error "Tests failed with exit code: $exitCode"
            return 1
        }
    } else {
        Write-Info "QEMU command: qemu-system-x86_64 $($qemuArgs -join ' ')"
        & qemu-system-x86_64 @qemuArgs
    }
}

# Main execution
function Main {
    Push-Location $PSScriptRoot\..
    
    try {
        Test-Prerequisites
        
        $kernelPath = Build-Kernel
        
        if ($BuildOnly) {
            Write-Success "Build completed. Kernel at: $kernelPath"
            return 0
        }
        
        $imagePath = New-BootImage $kernelPath
        Start-Qemu $imagePath
        
    } finally {
        Pop-Location
    }
}

# Run
exit (Main)
