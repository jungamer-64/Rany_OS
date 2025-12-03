#!/usr/bin/env pwsh
<#
.SYNOPSIS
    ExoRust (RanyOS) QEMU Launch Script for Windows PowerShell
.DESCRIPTION
    Builds and runs the ExoRust kernel in QEMU with configurable options.
.PARAMETER BuildOnly
    Only build the kernel, do not start QEMU.
.PARAMETER DebugMode
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
    [switch]$DebugMode,
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
$KERNEL_NAME = "exorust_kernel"
$TARGET = "x86_64-rany_os"
$BUILD_DIR = "target/$TARGET/debug"

# Colors for output - using Write-Host to avoid polluting return values
function Write-Info($message) {
    Write-Host "[INFO] $message" -ForegroundColor Cyan
}

function Write-Success($message) {
    Write-Host "[SUCCESS] $message" -ForegroundColor Green
}

function Write-ErrorMsg($message) {
    Write-Host "[ERROR] $message" -ForegroundColor Red
}

function Write-Warn($message) {
    Write-Host "[WARNING] $message" -ForegroundColor Yellow
}

# Check prerequisites
function Test-Prerequisites {
    Write-Info "Checking prerequisites..."
    
    # Check Rust
    if (-not (Get-Command "cargo" -ErrorAction SilentlyContinue)) {
        Write-ErrorMsg "Cargo not found. Please install Rust."
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
        Write-Warn "QEMU not found in PATH. QEMU execution will fail."
        Write-Warn "Please install QEMU and add it to PATH."
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
    
    # Run cargo build (warnings go to stderr but are not errors)
    $prevErrorAction = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    & cargo @buildArgs
    $buildExitCode = $LASTEXITCODE
    $ErrorActionPreference = $prevErrorAction
    
    if ($buildExitCode -ne 0) {
        Write-ErrorMsg "Build failed!"
        exit 1
    }
    
    $kernelPath = "$BUILD_DIR/$KERNEL_NAME"
    if (-not (Test-Path $kernelPath)) {
        Write-ErrorMsg "Kernel binary not found at: $kernelPath"
        exit 1
    }
    
    Write-Success "Kernel built successfully: $kernelPath"
    return $kernelPath
}

# Create bootable image
function New-BootImage($kernelPath) {
    Write-Info "Creating bootable image..."
    
    # Check for existing bootimage output
    $imagePath = "$BUILD_DIR/bootimage-$KERNEL_NAME.bin"
    
    if (-not (Test-Path $imagePath)) {
        # Try to create using cargo bootimage
        if (Get-Command "cargo" -ErrorAction SilentlyContinue) {
            Write-Info "Running cargo bootimage..."
            $prevErrorAction = $ErrorActionPreference
            $ErrorActionPreference = "Continue"
            & cargo bootimage --target "$TARGET.json" | Out-Null
            $ErrorActionPreference = $prevErrorAction
        } else {
            Write-Warn "cargo not found. Cannot create bootimage."
            return $kernelPath
        }
    }
    
    if (Test-Path $imagePath) {
        Write-Success "Boot image found: $imagePath"
        return $imagePath
    }
    
    Write-Warn "Boot image not found, using kernel binary directly."
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
    if ($imagePath -match "\.(img|bin)$") {
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
    if ($DebugMode) {
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
            Write-Warn "QEMU timed out after ${Timeout}s"
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
            Write-ErrorMsg "Tests failed with exit code: $exitCode"
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
