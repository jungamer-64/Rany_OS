#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Build and run RanyOS with ExoLoader bootloader.
.DESCRIPTION
    Automates the build process for Kernel, Bootloader, and Signing.
    Supports QEMU execution with WHPX/KVM acceleration.
.PARAMETER Release
    Build in release mode (optimizations enabled).
.PARAMETER GdbDebug
    Enable GDB stub on port 1234 and freeze CPU at startup.
.PARAMETER Memory
    Memory size in MB (default: 512).
.PARAMETER Smp
    Number of CPU cores (default: 4).
.PARAMETER Clean
    Clean target directory before building.
.PARAMETER NoRun
    Build only, do not launch QEMU.
.PARAMETER Test
    Run in test mode (exit on test completion, commonly used for CI).
.PARAMETER Serial
    Serial output mode: "stdio" (default), "file", "null".
.PARAMETER NvmeDevice
    Add a virtual NVMe device with specified size (e.g., "1G", "512M").
.PARAMETER Features
    List of Cargo features to enable for the kernel (e.g. "debug_print", "vga").
.PARAMETER QemuExtraArgs
    Additional arguments to pass directly to QEMU.
.PARAMETER Lint
    Run cargo fmt and clippy checks before building.
.PARAMETER Iommu
    Enable Intel VT-d IOMMU emulation (default: enabled for ExoRust DMA protection).
.PARAMETER NoIommu
    Disable IOMMU emulation (for compatibility testing without DMA protection).
.PARAMETER Numa
    Enable NUMA topology simulation (default: enabled, 2 nodes).
.PARAMETER NoNuma
    Disable NUMA topology simulation.
.PARAMETER Network
    Enable VirtIO network device with IOMMU support (hostfwd: tcp/udp 5555->80).
.PARAMETER Networks
    Ordered NIC descriptors: "user", "bridge:<bridge>[:<nic>]", "macvtap:<ifname>", "pcie:<bdf>".
.PARAMETER Monitor
    Enable QEMU Monitor on telnet port 4444 for runtime inspection.
.PARAMETER Tcg
    Force TCG (software emulation) instead of WHPX/KVM. Slower but more compatible.
.PARAMETER VerboseOutput
    Show detailed build output.
.PARAMETER ResetVars
    Reset UEFI variables (OVMF_VARS.fd) to original state before launch.
    Useful when UEFI settings become corrupted or cause boot issues.
.PARAMETER Cpu
    QEMU CPU model to use (e.g., "max", "host", "qemu64").
    Default: "host" for KVM/HVF, "max" for WHPX/TCG.
.EXAMPLE
    # Development: Quick iteration with debug build
    .\run.ps1
.EXAMPLE
    # Full ExoRust testing: IOMMU + Network + Monitor
    .\run.ps1 -Release -Numa -Network -Monitor
.EXAMPLE
    # CI/Headless testing: TCG for compatibility, exit on test result
    .\run.ps1 -Test -Tcg -Serial null
.EXAMPLE
    # GDB debugging: Freeze at startup, connect with gdb-multiarch
    .\run.ps1 -GdbDebug -Monitor
.EXAMPLE
    # WHPX compatibility: Disable IOMMU for Windows Hypervisor Platform
    .\run.ps1 -NoIommu -Network
.EXAMPLE
    # Reset UEFI state when boot fails mysteriously
    .\run.ps1 -ResetVars
.EXAMPLE
    # Force specific CPU model for compatibility
    .\run.ps1 -Cpu qemu64 -Tcg
#>

[CmdletBinding()]
param(
    [switch]$Release,
    [switch]$GdbDebug,
    [switch]$Clean,
    [switch]$NoRun,
    [switch]$Test,
    [switch]$Lint,
    [bool]$Iommu = $true,  # ExoRust: IOMMU enabled by default for DMA protection
    [switch]$NoIommu,      # Explicitly disable IOMMU
    [bool]$Numa = $true,   # ExoRust: NUMA enabled by default (2 nodes)
    [switch]$NoNuma,       # Explicitly disable NUMA
    [switch]$Network,
    [string[]]$Networks = @(),
    [switch]$Monitor,
    [switch]$Tcg,          # Force TCG software emulation
    [switch]$VerboseOutput,
    [switch]$ResetVars,    # Reset UEFI variables to original state
    [string]$Cpu,          # CPU model override (default: auto based on accel)
    [int]$Memory = 512,
    [int]$Smp = 4,
    [ValidateSet("stdio", "file", "null")]
    [string]$Serial = "stdio",
    [string]$NvmeDevice,
    [string[]]$Features = @(),
    [string[]]$QemuExtraArgs = @(),

    # Cargo Runner Integration
    [switch]$CargoRunner,
    [string]$CargoKernelPath
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

# Build timing
$script:TotalWatch = [System.Diagnostics.Stopwatch]::StartNew()

# Cross-platform support
$EXE_EXT = if ($IsWindows) { ".exe" } else { "" }

# --- Global Configuration & Paths ---
$ROOT_DIR = Split-Path -Parent $PSScriptRoot  # Project root (parent of scripts/)
Set-Location $ROOT_DIR

# Project Constants
$TARGET_KERNEL_JSON = Join-Path $ROOT_DIR "x86_64-exorust.json"
$TARGET_LOADER = "x86_64-unknown-uefi"
$KERNEL_CRATE = "rany_kernel"
$LOADER_CRATE = "exoloader"
$LOADER_BIN_NAME = "exoloader.efi"

# Resources
$OVMF_DIR = Join-Path $ROOT_DIR "assets/firmware/ovmf-x64"
$KEYS_DIR = Join-Path $ROOT_DIR "keys"
$TOOLS_DIR = Join-Path $ROOT_DIR "tools"

# Build Profile Setup
if ($Release) {
    $PROFILE = "release"
    $CARGO_ARGS_COMMON = @("--release")
}
else {
    $PROFILE = "debug"
    $CARGO_ARGS_COMMON = @()
}

# Output Paths
$TARGET_DIR = Join-Path $ROOT_DIR "target"
$KERNEL_TARGET_DIR = Join-Path $TARGET_DIR "x86_64-exorust/$PROFILE"
$LOADER_TARGET_DIR = Join-Path $TARGET_DIR "$TARGET_LOADER/release" # Loader is always release
if ($CargoRunner -and $CargoKernelPath) {
    $KERNEL_RAW = $CargoKernelPath
} else {
    $KERNEL_RAW = Join-Path $KERNEL_TARGET_DIR "exorust_kernel"
}
$KERNEL_SIGNED = Join-Path $KERNEL_TARGET_DIR "rany_os_signed"
$LOADER_EFI = Join-Path $LOADER_TARGET_DIR $LOADER_BIN_NAME
$SIGNER_TOOL_DIR = Join-Path $TOOLS_DIR "signer"
$SIGNER_TOOL_BIN = Join-Path $SIGNER_TOOL_DIR "target/x86_64-pc-windows-msvc/release/kernel-signer$EXE_EXT"

# --- Helper Functions ---

function Write-Step($icon, $msg) { Write-Output "$icon $msg" }
function Write-Done($msg) { Write-Output "   -> $msg" }
function Write-Warn($msg) { Write-Output "   -> [WARN] $msg" }
function Write-Fail($msg) { Write-Output "   -> [ERROR] $msg" }

# QEMU path/value safety helpers
# QEMU parses -drive value internally with comma as separator, so paths with
# commas, spaces, or quotes need special handling.
function Get-FullPath([string]$p) {
    # Resolve to absolute path, handling relative paths correctly
    if (Test-Path $p) {
        return (Resolve-Path -LiteralPath $p).Path
    }
    return $p
}

function Format-QemuValue([string]$v) {
    # Quote value if it contains QEMU-unsafe characters (comma, space, quote)
    if ($v -match '[,"\s]') {
        $escaped = $v -replace '"', '\"'
        return '"' + $escaped + '"'
    }
    return $v
}

function Get-NewestWriteTime([string]$dir) {
    # Get the most recent file modification time in a directory tree
    if (-not (Test-Path $dir)) { return [datetime]::MinValue }
    $newest = Get-ChildItem $dir -Recurse -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
    if ($newest) { return $newest.LastWriteTime }
    return [datetime]::MinValue
}

function Test-Command($cmd) {
    if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
        throw "Command '$cmd' not found. Please install it or add it to PATH."
    }
}

function Test-RustComponent($component) {
    $list = rustup component list --installed 2>$null
    # Check if component appears in the list (handles versioned names like rust-src-nightly)
    $found = $list | Where-Object { $_ -like "$component*" }
    if (-not $found) {
        Write-Warn "Rust component '$component' is missing."
        Write-Step "踏" "Installing '$component'..."
        rustup component add $component
        if ($LASTEXITCODE -ne 0) { throw "Failed to install $component" }
    }
}

function Test-NightlyToolchain {
    # Check rust-toolchain.toml for pinned version
    $toolchainFile = Join-Path $ROOT_DIR "rust-toolchain.toml"
    if (Test-Path $toolchainFile) {
        $content = Get-Content $toolchainFile -Raw
        if ($content -match 'channel\s*=\s*"([^"]+)"') {
            $requiredVersion = $matches[1]
            Write-Done "Toolchain pinned: $requiredVersion"
        }
    }
    
    $version = rustc --version 2>$null
    if ($version -notmatch "nightly") {
        # -Z build-std requires nightly, so this is a hard requirement
        throw "Nightly toolchain required. Current: $version`nFix: rustup override set nightly"
    }
    Write-Done "Nightly toolchain: OK"
}

function Get-HostTarget {
    $out = rustc -vV
    foreach ($line in $out) {
        if ($line -match '^host:\s*(.+)$') {
            return $matches[1]
        }
    }
    return $null
}

function Check-Dependencies {
    Write-Step "剥" "Checking dependencies..."
    Test-Command "cargo"
    Test-Command "rustup"
    
    # Check toolchain and components
    Test-NightlyToolchain
    Test-RustComponent "rust-src"
    
    # QEMU check (only if we're going to run)
    if (-not $NoRun) {
        Test-Command "qemu-system-x86_64"
    }

    if (-not (Test-Path $OVMF_DIR)) {
        throw "OVMF firmware directory not found at: $OVMF_DIR"
    }
}

function Run-Clean {
    Write-Step "ｧｹ" "Cleaning target directory..."
    if (Test-Path $TARGET_DIR) {
        Remove-Item -Recurse -Force $TARGET_DIR -ErrorAction SilentlyContinue
        Write-Done "Cleaned."
    }
}

# --- Lint & Format ---

function Invoke-Lints {
    Write-Step "ｧｹ" "Running Cargo Fmt & Clippy..."
    
    # Format check (don't modify, just check)
    Write-Done "Checking format..."
    & cargo fmt --all -- --check
    if ($LASTEXITCODE -ne 0) {
        Write-Fail "Format check failed. Run 'cargo fmt' to fix."
        throw "Format check failed"
    }
    
    # Clippy for kernel (with custom target)
    Write-Done "Running Clippy on kernel..."
    $clippyArgs = @(
        "clippy",
        "-p", $KERNEL_CRATE,
        "--target", $TARGET_KERNEL_JSON,
        "-Z", "build-std=core,compiler_builtins,alloc",
        "--", "-D", "warnings"
    )
    & cargo $clippyArgs
    if ($LASTEXITCODE -ne 0) { throw "Clippy failed on kernel" }
    
    # Clippy for loader
    Write-Done "Running Clippy on loader..."
    $clippyArgs = @(
        "clippy",
        "-p", $LOADER_CRATE,
        "--target", $TARGET_LOADER,
        "-Z", "build-std=core,compiler_builtins,alloc",
        "--", "-D", "warnings"
    )
    & cargo $clippyArgs
    if ($LASTEXITCODE -ne 0) { throw "Clippy failed on loader" }
    
    Write-Done "Code is clean."
}

# --- Build Steps ---

function Build-Signer {
    # Build if missing, or if ANY source file is newer than the binary
    $needsBuild = $false
    
    if (-not (Test-Path $SIGNER_TOOL_BIN)) {
        $needsBuild = $true
    }
    else {
        # Check if any file in the signer directory is newer than the binary
        $binTime = (Get-Item $SIGNER_TOOL_BIN).LastWriteTime
        $srcTime = Get-NewestWriteTime $SIGNER_TOOL_DIR
        if ($srcTime -gt $binTime) {
            Write-Done "Signer tool outdated (source newer: $($srcTime.ToString('HH:mm:ss'))), rebuilding..."
            $needsBuild = $true
        }
    }
    
    if ($needsBuild) {
        Write-Step "屏・・ "Building Kernel Signer Tool..."
        Push-Location $SIGNER_TOOL_DIR
        try {
            $hostTarget = Get-HostTarget
            # Disable build-std for host tools (override parent .cargo/config.toml)
            $buildArgs = @("build", "--release", "-Z", "build-std=")
            if ($hostTarget) {
                $buildArgs += "--target"
                $buildArgs += $hostTarget
            }
            if (-not $VerboseOutput) { $buildArgs += "--quiet" }
            & cargo $buildArgs
            if ($LASTEXITCODE -ne 0) { throw "Signer build failed" }
        }
        finally {
            Pop-Location
        }
        Write-Done "Signer tool built."
    }
}

function Setup-Keys {
    if (-not (Test-Path "$KEYS_DIR/kernel_pub.key")) {
        Write-Step "泊" "Generating Secure Boot Keys..."
        if (-not (Test-Path $KEYS_DIR)) { New-Item -ItemType Directory -Path $KEYS_DIR | Out-Null }
        
        # Direct invocation is more reliable cross-platform than Start-Process -NoNewWindow
        & $SIGNER_TOOL_BIN keygen --output-dir $KEYS_DIR
        if ($LASTEXITCODE -ne 0) { throw "Key generation failed" }
        
        Write-Done "Keys generated in $KEYS_DIR"
        Write-Warn "Keep private keys secret!"
    }
}

function Build-Loader {
    Write-Step "噫" "Building ExoLoader (UEFI)..."
    $buildArgs = @(
        "build",
        "-p", $LOADER_CRATE,
        "--target", $TARGET_LOADER,
        "--release",
        "-Z", "build-std=core,compiler_builtins,alloc",
        "-Z", "build-std-features=compiler-builtins-mem"
    )
    
    if (-not $VerboseOutput) { $buildArgs += "--quiet" }

    & cargo $buildArgs
    if ($LASTEXITCODE -ne 0) { throw "ExoLoader build failed" }
    Write-Done "ExoLoader built."
}

function Build-Kernel {
    Write-Step "ｦ" "Building Kernel ($PROFILE)..."
    
    $buildArgs = @(
        "build",
        "-p", $KERNEL_CRATE,
        "--target", $TARGET_KERNEL_JSON
    ) + $CARGO_ARGS_COMMON
    
    # Feature flags handling
    if ($Features.Count -gt 0) {
        $buildArgs += "--features"
        $buildArgs += ($Features -join ",")
        Write-Done "Enabled features: $($Features -join ', ')"
    }

    $buildArgs += @(
        "-Z", "build-std=core,compiler_builtins,alloc",
        "-Z", "build-std-features=compiler-builtins-mem"
    )
    
    if (-not $VerboseOutput) { $buildArgs += "--quiet" }

    & cargo $buildArgs
    if ($LASTEXITCODE -ne 0) { throw "Kernel build failed" }
    Write-Done "Kernel compiled."
}

function Sign-Kernel-Binary {
    Write-Step "笨搾ｸ・ "Signing Kernel..."
    
    if (-not (Test-Path $KERNEL_RAW)) { throw "Kernel binary not found at $KERNEL_RAW" }

    $signArgs = @(
        "sign",
        "--kernel", $KERNEL_RAW,
        "--secret-key", "$KEYS_DIR/kernel.key",
        "--output", $KERNEL_SIGNED
    )
    
    & $SIGNER_TOOL_BIN $signArgs
    if ($LASTEXITCODE -ne 0) { throw "Signing failed" }
    Write-Done "Kernel signed."
}

# --- Image Creation ---

function Create-Disk-Image {
    Write-Step "沈" "Preparing Boot Image..."
    
    $fatRoot = Join-Path $KERNEL_TARGET_DIR "fat_root"
    if (Test-Path $fatRoot) { Remove-Item $fatRoot -Recurse -Force }
    New-Item -ItemType Directory -Force -Path "$fatRoot/EFI/BOOT" | Out-Null
    
    # Check artifacts
    if (-not (Test-Path $LOADER_EFI)) { throw "Loader binary missing: $LOADER_EFI" }
    if (-not (Test-Path $KERNEL_SIGNED)) { throw "Signed kernel missing: $KERNEL_SIGNED" }

    # Copy artifacts
    Copy-Item $LOADER_EFI "$fatRoot/EFI/BOOT/BOOTX64.EFI"
    Copy-Item $KERNEL_SIGNED "$fatRoot/rany_os"

    $bootArtifactsDir = Join-Path $KERNEL_TARGET_DIR "boot_artifacts"
    $driversDir = Join-Path $bootArtifactsDir "drivers"
    if (Test-Path $driversDir) {
        $bootDriversDir = "$fatRoot/drivers"
        New-Item -ItemType Directory -Force -Path $bootDriversDir | Out-Null
        Copy-Item "$driversDir/*" $bootDriversDir -Recurse -ErrorAction SilentlyContinue
        $driverCount = (Get-ChildItem $bootDriversDir -File -Recurse | Measure-Object).Count
        if ($driverCount -gt 0) {
            Write-Done "Deployed $driverCount driver artifact(s) to /drivers"
        }
    }

    # [ExoRust] Deploy Cells (Drivers/Apps)
    # Cells are isolated driver/app binaries loaded at runtime
    $cellsDir = Join-Path $bootArtifactsDir "cells"
    if (-not (Test-Path $cellsDir)) {
        $cellsDir = Join-Path $KERNEL_TARGET_DIR "cells"
    }
    if (Test-Path $cellsDir) {
        $bootCellsDir = "$fatRoot/cells"
        New-Item -ItemType Directory -Force -Path $bootCellsDir | Out-Null
        Copy-Item "$cellsDir/*" $bootCellsDir -Recurse -ErrorAction SilentlyContinue
        $cellCount = (Get-ChildItem $bootCellsDir -File -Recurse | Measure-Object).Count
        if ($cellCount -gt 0) {
            Write-Done "Deployed $cellCount Cell(s) to /cells"
        }
    }

    return $fatRoot
}

# --- Run QEMU ---

function Get-QemuAccelerator {
    # Force TCG if requested
    if ($Tcg) {
        Write-Warn "[ACCEL] TCG (forced via -Tcg flag)"
        return "tcg"
    }
    
    # Query QEMU for available accelerators
    $helpOut = & qemu-system-x86_64 -accel help 2>&1
    
    if ($IsWindows) {
        # Windows: prefer WHPX > HAXM > TCG
        if ($helpOut -match "whpx") {
            Write-Done "[ACCEL] Windows Hypervisor Platform (WHPX)"
            return "whpx"
        }
        elseif ($helpOut -match "hax") {
            Write-Done "[ACCEL] HAXM"
            return "hax"
        }
    }
    else {
        # Linux/macOS: prefer KVM (if available) > HVF (macOS) > TCG
        if ($helpOut -match "kvm") {
            # KVM requires /dev/kvm to be accessible
            if (Test-Path "/dev/kvm") {
                Write-Done "[ACCEL] KVM (Linux hardware virtualization)"
                return "kvm"
            }
            else {
                Write-Warn "[ACCEL] KVM listed but /dev/kvm not accessible (missing permissions or VT-x disabled)"
            }
        }
        if ($helpOut -match "hvf") {
            Write-Done "[ACCEL] Hypervisor.framework (macOS)"
            return "hvf"
        }
    }
    
    Write-Warn "No hardware acceleration detected. Using TCG (Slow)."
    return "tcg"
}

function Start-Qemu {
    param([string]$FatDir)
    
    Write-Step "箕・・ "Launching QEMU..."
    
    # Firmware Setup
    $ovmfCode = Join-Path $OVMF_DIR "OVMF_CODE.fd"
    $ovmfVarsOrig = Join-Path $OVMF_DIR "OVMF_VARS.fd"
    $ovmfVarsLocal = Join-Path $KERNEL_TARGET_DIR "OVMF_VARS.fd"
    
    if (-not (Test-Path $ovmfCode)) { throw "OVMF_CODE.fd missing" }
    
    # Reset UEFI variables if requested (fixes mysterious boot failures)
    if ($ResetVars -and (Test-Path $ovmfVarsLocal)) {
        Remove-Item $ovmfVarsLocal -Force
        Write-Done "[UEFI] OVMF_VARS.fd reset to original state"
    }
    if (-not (Test-Path $ovmfVarsLocal)) { Copy-Item $ovmfVarsOrig $ovmfVarsLocal }

    $accel = Get-QemuAccelerator

    # CPU model selection: use explicit -Cpu if given, otherwise auto-select based on accel
    # - KVM/HVF: "host" for best performance (passthrough)
    # - WHPX/TCG: "max" for feature detection (host passthrough may not work)
    $cpuModel = if ($Cpu) { $Cpu } else {
        switch ($accel) {
            "kvm" { "host" }
            "hvf" { "host" }
            default { "max" }  # whpx/tcg/hax: use max, user can override with -Cpu
        }
    }
    Write-Done "[CPU] $cpuModel"

    # Serial Config
    $serialLogPath = Join-Path $KERNEL_TARGET_DIR "serial.log"
    $serialArg = switch ($Serial) {
        "stdio" { "stdio" }
        "file" { "file:$(Format-QemuValue (Get-FullPath $KERNEL_TARGET_DIR))/serial.log" }
        "null" { "null" }
    }

    # Base Arguments
    # [ExoRust] IOMMU: Separate "requested" vs "active" states
    # - iommuRequested: User wants IOMMU (via -Iommu flag, not -NoIommu)
    # - iommuActive: IOMMU is actually enabled (WHPX doesn't support it)
    # This prevents VirtIO-net from using iommu_platform=on when IOMMU is not active
    $iommuRequested = $Iommu -and (-not $NoIommu)
    $iommuActive = $iommuRequested -and ($accel -ne "whpx")
    
    # NOTE: WHPX doesn't support kernel-irqchip=split, only use it when IOMMU is active
    if ($iommuActive) {
        $machineSpec = "q35,kernel-irqchip=split"
    } else {
        $machineSpec = "q35"
    }
    
    # Safe path handling for QEMU -drive arguments
    # QEMU parses these internally with comma as separator
    $ovmfCodePath = Format-QemuValue (Get-FullPath $ovmfCode)
    $ovmfVarsPath = Format-QemuValue (Get-FullPath $ovmfVarsLocal)
    $fatDirPath = Format-QemuValue (Get-FullPath $FatDir)
    
    $qemuArgs = @(
        "-machine", $machineSpec,
        "-cpu", $cpuModel,
        "-smp", "$Smp",
        "-m", "${Memory}M",
        "-nic", "none",
        "-serial", $serialArg,
        "-no-reboot",
        "-no-shutdown",
        "-drive", "if=pflash,format=raw,readonly=on,file=$ovmfCodePath",
        "-drive", "if=pflash,format=raw,file=$ovmfVarsPath",
        "-drive", "file=fat:rw:$fatDirPath,format=raw,media=disk",
        "-accel", $accel
    )
    
    # [ExoRust] IOMMU (Intel VT-d) Support
    # Required for DMA protection (Design Doc 5.4.1)
    # Enabled by default for ExoRust; use -NoIommu to disable
    if ($iommuRequested -and -not $iommuActive) {
        Write-Warn "[IOMMU] Skipped (WHPX does not support intel-iommu device)"
    } elseif ($iommuActive) {
        $qemuArgs += @("-device", "intel-iommu,intremap=on,caching-mode=on")
        Write-Done "[IOMMU] Intel VT-d enabled (intremap=on) [DEFAULT]"
    }
    
    # [ExoRust] NUMA Topology Simulation
    # Required for Share-Nothing architecture testing (Design Doc 5.3)
    # Memory split: ensure mem0 + mem1 = Memory (remainder goes to node1)
    $numaRequested = $Numa -and (-not $NoNuma)
    if ($numaRequested -and $Smp -ge 2) {
        $coresNode0 = [math]::Floor($Smp / 2)
        $memNode0 = [math]::Floor($Memory / 2)
        $memNode1 = $Memory - $memNode0  # Remainder to node1 to ensure exact match with -m
        $qemuArgs += @(
            "-object", "memory-backend-ram,id=mem0,size=${memNode0}M",
            "-object", "memory-backend-ram,id=mem1,size=${memNode1}M",
            "-numa", "node,nodeid=0,cpus=0-$($coresNode0-1),memdev=mem0",
            "-numa", "node,nodeid=1,cpus=$($coresNode0)-$($Smp-1),memdev=mem1"
        )
        Write-Done "[NUMA] 2-node topology: node0 $coresNode0 cores ${memNode0}MB, node1 $($Smp - $coresNode0) cores ${memNode1}MB"
    }
    
    # [ExoRust] VirtIO Network with IOMMU Support
    # Required for zero-copy network testing (Design Doc 6.2)
    # NOTE: iommu_platform only when IOMMU is *active* (not just requested)
    if ($Networks.Count -gt 0) {
        for ($i = 0; $i -lt $Networks.Count; $i++) {
            $descriptor = $Networks[$i]
            if ([string]::IsNullOrWhiteSpace($descriptor)) { continue }
            $netId = "net$i"
            if ($descriptor -eq "user") {
                $netdevArgs = "user,id=$netId"
                if ($i -eq 0) {
                    $netdevArgs += ",hostfwd=tcp::5555-:80,hostfwd=udp::5556-:80"
                }
                $deviceArgs = "virtio-net-pci,netdev=$netId,mq=on,vectors=10"
                if ($iommuActive) {
                    $deviceArgs += ",iommu_platform=on,disable-legacy=on"
                }
                $qemuArgs += @("-netdev", $netdevArgs, "-device", $deviceArgs)
                Write-Done "[NET] Added descriptor $descriptor as $netId"
            }
            elseif ($descriptor.StartsWith("bridge:")) {
                $bridgeSpec = $descriptor.Substring(7)
                $bridgeName = $bridgeSpec.Split(":", 2)[0]
                $tapName = "tap$($PID)-$i"
                $netdevArgs = "tap,id=$netId,ifname=$tapName,script=no,downscript=no"
                $deviceArgs = "virtio-net-pci,netdev=$netId,mq=on,vectors=10"
                if ($iommuActive) {
                    $deviceArgs += ",iommu_platform=on,disable-legacy=on"
                }
                $qemuArgs += @("-netdev", $netdevArgs, "-device", $deviceArgs)
                Write-Done "[NET] Added descriptor $descriptor as $netId (bridge=$bridgeName, host tap setup required)"
            }
            elseif ($descriptor.StartsWith("macvtap:")) {
                $ifName = $descriptor.Substring(8)
                $tapPath = "/sys/class/net/$ifName/ifindex"
                $ifIndex = if (Test-Path $tapPath) { (Get-Content $tapPath -ErrorAction SilentlyContinue | Select-Object -First 1) } else { "0" }
                $fd = 3 + $i
                $qemuArgs += @("$fd<>/dev/tap$ifIndex")
                $netdevArgs = "tap,id=$netId,fd=$fd"
                $deviceArgs = "virtio-net-pci,netdev=$netId,mq=on,vectors=10"
                if ($iommuActive) {
                    $deviceArgs += ",iommu_platform=on,disable-legacy=on"
                }
                $qemuArgs += @("-netdev", $netdevArgs, "-device", $deviceArgs)
                Write-Done "[NET] Added descriptor $descriptor as $netId"
            }
            elseif ($descriptor.StartsWith("pcie:")) {
                $bdf = $descriptor.Substring(5)
                $qemuArgs += @("-device", "vfio-pci,host=$bdf")
                Write-Done "[NET][VFIO] Added PCIe descriptor $bdf"
            }
            else {
                throw "Unsupported network descriptor: $descriptor"
            }
        }
    }
    elseif ($Network) {
        $netdevArgs = "user,id=net0,hostfwd=tcp::5555-:80,hostfwd=udp::5555-:80"
        $deviceArgs = "virtio-net-pci,netdev=net0,mq=on,vectors=10"
        if ($iommuActive) {
            $deviceArgs += ",iommu_platform=on,disable-legacy=on"
        }
        $qemuArgs += @("-netdev", $netdevArgs, "-device", $deviceArgs)
        Write-Done "[NET] VirtIO-net enabled (hostfwd: 5555->80)"
    }

    # NVMe Device
    if ($NvmeDevice) {
        Test-Command "qemu-img"  # Ensure qemu-img is available
        $nvmePath = Join-Path $KERNEL_TARGET_DIR "nvme.img"
        if (-not (Test-Path $nvmePath)) {
            Write-Done "Creating NVMe disk image ($NvmeDevice)..."
            & qemu-img create -f qcow2 $nvmePath $NvmeDevice *>$null
            if ($LASTEXITCODE -ne 0) { throw "Failed to create NVMe image" }
        }
        $qemuArgs += @("-drive", "file=$nvmePath,if=none,id=nvm", "-device", "nvme,serial=deadbeef,drive=nvm")
        Write-Done "NVMe device attached ($NvmeDevice)"
    }

    # Debug / Test Flags
    if ($GdbDebug) {
        $qemuArgs += @("-s", "-S")
        Write-Warn "GDB Stub: localhost:1234 (CPU Frozen)"
    }
    
    # [ExoRust] QEMU Monitor for runtime inspection
    if ($Monitor -or $GdbDebug) {
        $qemuArgs += @("-monitor", "telnet:127.0.0.1:4444,server,nowait")
        Write-Done "[MONITOR] telnet localhost 4444 (info tlb, info mem, etc.)"
    }

    if ($Test) {
        $qemuArgs += @("-device", "isa-debug-exit,iobase=0xf4,iosize=0x04", "-display", "none")
        Write-Done "Test mode: Headless execution"
    }

    # Inject Extra Arguments (Passthrough)
    if ($QemuExtraArgs.Count -gt 0) {
        $qemuArgs += $QemuExtraArgs
        Write-Done "Injected extra args: $($QemuExtraArgs -join ' ')"
    }

    if ($Serial -eq "file") {
        Write-Done "Log: $KERNEL_TARGET_DIR/serial.log"
    }

    # Run QEMU
    & qemu-system-x86_64 @qemuArgs
    
    $exitCode = $LASTEXITCODE

    # QEMU isa-debug-exit normalization
    if ($Test) {
        # 0x10 (Success) -> 33, 0x11 (Fail) -> 35
        if ($exitCode -eq 33) {
            Write-Done "TEST RESULT: PASSED"
            return 0
        }
        else {
            Write-Fail "TEST RESULT: FAILED (Code: $exitCode)"
            return 1
        }
    }

    return $exitCode
}

# --- Main Pipeline ---

try {
    Check-Dependencies
    if ($Clean) { Run-Clean }
    
    # 0. Lint (optional)
    if ($Lint) { Invoke-Lints }
    
    # 1. Tools
    Build-Signer
    Setup-Keys
    
    # 2. Compilation
    Build-Loader
    if (-not $CargoRunner) {
        Build-Kernel
    }
    
    # 3. Packaging
    Sign-Kernel-Binary
    
    # Performance Report
    $script:TotalWatch.Stop()
    $elapsed = $script:TotalWatch.Elapsed.TotalSeconds.ToString('F2')
    Write-Step "笨・ "Build success in ${elapsed}s"
    
    # 4. Execution
    if (-not $NoRun) {
        $bootSource = Create-Disk-Image
        $qemuExit = Start-Qemu -FatDir $bootSource
        exit $qemuExit
    }
}
catch {
    Write-Fail $_
    exit 1
}
