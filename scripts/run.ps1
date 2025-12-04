#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Build and run RanyOS with Limine bootloader (UEFI/BIOS)
.DESCRIPTION
    Creates a bootable ISO image with Limine bootloader and runs it in QEMU.
    Supports both UEFI and legacy BIOS boot modes.
.PARAMETER Release
    Build in release mode
.PARAMETER Uefi
    Force UEFI boot mode (default if OVMF available)
.PARAMETER Bios
    Force legacy BIOS mode
.PARAMETER Debug
    Enable GDB debugging on port 1234
.PARAMETER Memory
    Memory size in MB (default: 512)
#>

[CmdletBinding()]
param(
    [switch]$Release,
    [switch]$Uefi,
    [switch]$Bios,
    [switch]$GdbDebug,
    [int]$Memory = 512
)

$ErrorActionPreference = "Stop"

# Configuration
$TARGET = "x86_64-unknown-none"
$KERNEL_NAME = "exorust_kernel"
$LIMINE_VERSION = "8.x"  # Use latest 8.x series
$LIMINE_DIR = "assets/limine"
$OVMF_DIR = "assets/firmware/ovmf-x64"

if ($Release) {
    $PROFILE = "release"
    $BUILD_FLAGS = "--release"
} else {
    $PROFILE = "debug"
    $BUILD_FLAGS = ""
}

$KERNEL_PATH = "target/$TARGET/$PROFILE/$KERNEL_NAME"
$ISO_PATH = "target/$TARGET/$PROFILE/ranyos.iso"

function Write-Info($msg) { Write-Host "[INFO] $msg" -ForegroundColor Cyan }
function Write-Success($msg) { Write-Host "[OK] $msg" -ForegroundColor Green }
function Write-ErrorMsg($msg) { Write-Host "[ERROR] $msg" -ForegroundColor Red }
function Write-Warn($msg) { Write-Host "[WARN] $msg" -ForegroundColor Yellow }

# Download Limine if not present
function Get-Limine {
    if (-not (Test-Path "$LIMINE_DIR/limine-bios.sys")) {
        Write-Info "Downloading Limine bootloader v$LIMINE_VERSION..."
        
        New-Item -ItemType Directory -Force -Path $LIMINE_DIR | Out-Null
        
        # Download from the v8.x-binary branch (contains pre-built binaries)
        $baseUrl = "https://github.com/limine-bootloader/limine/raw/v$LIMINE_VERSION-binary"
        
        $files = @(
            "limine-bios.sys",
            "limine-bios-cd.bin", 
            "limine-uefi-cd.bin",
            "BOOTX64.EFI",
            "BOOTIA32.EFI"
        )
        
        try {
            foreach ($file in $files) {
                $url = "$baseUrl/$file"
                $dest = "$LIMINE_DIR/$file"
                Write-Host "  Downloading $file..." -ForegroundColor DarkGray
                Invoke-WebRequest -Uri $url -OutFile $dest -UseBasicParsing -ErrorAction Stop
            }
            Write-Success "Limine downloaded successfully"
        } catch {
            Write-ErrorMsg "Failed to download Limine: $_"
            Write-Info "Please download manually from: https://github.com/limine-bootloader/limine/releases"
            Write-Info "Or clone the v8.x-binary branch"
            exit 1
        }
    } else {
        Write-Info "Limine bootloader found"
    }
}

# Build kernel
function Build-Kernel {
    Write-Info "Building kernel..."
    $buildCmd = "cargo build --target $TARGET $BUILD_FLAGS".Trim()
    
    Invoke-Expression $buildCmd
    if ($LASTEXITCODE -ne 0) {
        Write-ErrorMsg "Build failed!"
        exit 1
    }
    
    if (-not (Test-Path $KERNEL_PATH)) {
        Write-ErrorMsg "Kernel not found: $KERNEL_PATH"
        exit 1
    }
    
    Write-Success "Kernel built: $KERNEL_PATH"
}

# Create FAT32 disk image for UEFI boot
function New-BootableDisk {
    Write-Info "Creating FAT32 disk image for UEFI boot..."
    
    $diskImage = "target/$TARGET/$PROFILE/ranyos.img"
    $diskSizeMB = 64  # 64MB should be enough
    
    # Create empty disk image
    $diskSizeBytes = $diskSizeMB * 1024 * 1024
    $buffer = [byte[]]::new(512)  # One sector
    
    # Create or truncate file
    $stream = [System.IO.File]::Create($diskImage)
    try {
        $stream.SetLength($diskSizeBytes)
    } finally {
        $stream.Close()
    }
    
    Write-Info "Created $diskSizeMB MB disk image"
    
    # Use mtools if available for FAT32 creation
    $mformat = Get-Command "mformat" -ErrorAction SilentlyContinue
    
    if ($mformat) {
        Write-Info "Using mtools for FAT32 formatting..."
        
        # Create mtools config
        $mtoolsrc = "target/$TARGET/$PROFILE/mtoolsrc"
        "drive x: file=`"$diskImage`" offset=0" | Out-File -FilePath $mtoolsrc -Encoding ascii
        
        $env:MTOOLSRC = $mtoolsrc
        
        & mformat -i $diskImage -F ::
        & mmd -i $diskImage ::/EFI
        & mmd -i $diskImage ::/EFI/BOOT
        & mmd -i $diskImage ::/boot
        
        & mcopy -i $diskImage $KERNEL_PATH ::/boot/exorust_kernel
        & mcopy -i $diskImage "limine.conf" ::/boot/limine.conf
        & mcopy -i $diskImage "$LIMINE_DIR/limine-bios.sys" ::/boot/limine-bios.sys
        & mcopy -i $diskImage "$LIMINE_DIR/BOOTX64.EFI" ::/EFI/BOOT/BOOTX64.EFI
        
        Write-Success "Disk image created with mtools: $diskImage"
        return $diskImage
    }
    
    # Fallback: Create raw structure manually (simpler approach)
    Write-Warn "mtools not found - creating minimal FAT image manually..."
    
    # Create a directory structure for use with QEMU's vvfat
    $vfatDir = "target/$TARGET/$PROFILE/fat_root"
    if (Test-Path $vfatDir) {
        Remove-Item $vfatDir -Recurse -Force
    }
    New-Item -ItemType Directory -Force -Path "$vfatDir/EFI/BOOT" | Out-Null
    New-Item -ItemType Directory -Force -Path "$vfatDir/boot/limine" | Out-Null
    
    # Copy files - kernel
    Copy-Item $KERNEL_PATH "$vfatDir/boot/exorust_kernel"
    
    # Copy Limine config to multiple locations for compatibility
    Copy-Item "limine.conf" "$vfatDir/limine.conf"
    Copy-Item "limine.conf" "$vfatDir/boot/limine.conf"
    Copy-Item "limine.conf" "$vfatDir/boot/limine/limine.conf"
    Copy-Item "limine.conf" "$vfatDir/EFI/BOOT/limine.conf"
    
    # Copy UEFI bootloader
    Copy-Item "$LIMINE_DIR/BOOTX64.EFI" "$vfatDir/EFI/BOOT/"
    if (Test-Path "$LIMINE_DIR/BOOTIA32.EFI") {
        Copy-Item "$LIMINE_DIR/BOOTIA32.EFI" "$vfatDir/EFI/BOOT/"
    }
    
    # Copy BIOS files
    Copy-Item "$LIMINE_DIR/limine-bios.sys" "$vfatDir/boot/limine/"
    
    Write-Success "FAT root directory created: $vfatDir"
    return $vfatDir
}

# Create ISO (if xorriso available via WSL or native)
function New-BootableIso {
    Write-Info "Checking for ISO creation tools..."
    
    $xorrisoNative = Get-Command "xorriso" -ErrorAction SilentlyContinue
    $wslAvailable = $false
    
    # Check for WSL xorriso
    try {
        $wslCheck = wsl -e bash -c "which xorriso" 2>$null
        if ($wslCheck) {
            $wslAvailable = $true
            Write-Info "Found xorriso in WSL"
        }
    } catch {}
    
    if (-not $xorrisoNative -and -not $wslAvailable) {
        Write-Info "xorriso not found - using FAT image instead"
        return $null
    }
    
    Write-Info "Creating bootable ISO..."
    
    $isoRoot = "target/$TARGET/$PROFILE/iso_root"
    
    # Clean and create ISO root
    if (Test-Path $isoRoot) {
        Remove-Item $isoRoot -Recurse -Force
    }
    New-Item -ItemType Directory -Force -Path "$isoRoot/boot/limine" | Out-Null
    New-Item -ItemType Directory -Force -Path "$isoRoot/EFI/BOOT" | Out-Null
    
    # Copy kernel
    Copy-Item $KERNEL_PATH "$isoRoot/boot/$KERNEL_NAME"
    
    # Copy Limine config
    Copy-Item "limine.conf" "$isoRoot/limine.conf"
    Copy-Item "limine.conf" "$isoRoot/boot/limine/limine.conf"
    
    # Copy Limine files
    Copy-Item "$LIMINE_DIR/limine-bios.sys" "$isoRoot/boot/limine/"
    Copy-Item "$LIMINE_DIR/limine-bios-cd.bin" "$isoRoot/boot/limine/"
    Copy-Item "$LIMINE_DIR/limine-uefi-cd.bin" "$isoRoot/boot/limine/"
    Copy-Item "$LIMINE_DIR/BOOTX64.EFI" "$isoRoot/EFI/BOOT/"
    if (Test-Path "$LIMINE_DIR/BOOTIA32.EFI") {
        Copy-Item "$LIMINE_DIR/BOOTIA32.EFI" "$isoRoot/EFI/BOOT/"
    }
    
    # Convert Windows path to WSL path
    function Convert-ToWslPath {
        param([string]$WindowsPath)
        $absPath = (Resolve-Path $WindowsPath -ErrorAction SilentlyContinue)
        if (-not $absPath) {
            $absPath = $WindowsPath
        } else {
            $absPath = $absPath.Path
        }
        $wslPath = $absPath -replace '\\', '/'
        if ($wslPath -match '^([A-Z]):') {
            $drive = $matches[1].ToLower()
            $wslPath = $wslPath -replace '^[A-Z]:', "/mnt/$drive"
        }
        return $wslPath
    }
    
    $isoRootWsl = Convert-ToWslPath $isoRoot
    
    # For output path, ensure parent exists
    $isoDir = Split-Path $ISO_PATH -Parent
    if (-not (Test-Path $isoDir)) {
        New-Item -ItemType Directory -Force -Path $isoDir | Out-Null
    }
    $isoPathWsl = Convert-ToWslPath (Join-Path (Get-Location).Path $ISO_PATH)
    
    Write-Info "ISO root (WSL): $isoRootWsl"
    Write-Info "ISO output (WSL): $isoPathWsl"
    
    $xorrisoCmd = "xorriso -as mkisofs -b boot/limine/limine-bios-cd.bin -no-emul-boot -boot-load-size 4 -boot-info-table --efi-boot boot/limine/limine-uefi-cd.bin -efi-boot-part --efi-boot-image --protective-msdos-label '$isoRootWsl' -o '$isoPathWsl'"
    
    if ($wslAvailable) {
        Write-Info "Running xorriso via WSL..."
        wsl -e bash -c $xorrisoCmd
        
        if ($LASTEXITCODE -ne 0) {
            Write-ErrorMsg "xorriso failed!"
            return $null
        }
    } else {
        Write-Info "Running native xorriso..."
        & xorriso -as mkisofs `
            -b boot/limine/limine-bios-cd.bin `
            -no-emul-boot -boot-load-size 4 -boot-info-table `
            --efi-boot boot/limine/limine-uefi-cd.bin `
            -efi-boot-part --efi-boot-image --protective-msdos-label `
            $isoRoot -o $ISO_PATH
    }
    
    if (Test-Path $ISO_PATH) {
        Write-Success "ISO created: $ISO_PATH"
        return $ISO_PATH
    } else {
        Write-ErrorMsg "ISO creation failed!"
        return $null
    }
}

# Run QEMU
function Start-Qemu {
    param([string]$BootSource)
    
    Write-Info "Starting QEMU..."
    
    $qemuArgs = @(
        "-machine", "q35"
        "-cpu", "qemu64,+rdtscp,+x2apic"
        "-m", "${Memory}M"
        "-serial", "mon:stdio"
        "-no-reboot"
        "-no-shutdown"
    )
    
    # Determine boot mode
    $ovmfCode = "$OVMF_DIR/OVMF_CODE.fd"
    $ovmfVars = "$OVMF_DIR/OVMF_VARS.fd"
    $useUefi = $Uefi -or ((Test-Path $ovmfCode) -and -not $Bios)
    
    if ($useUefi -and (Test-Path $ovmfCode)) {
        Write-Info "Boot mode: UEFI"
        
        # Make a copy of OVMF_VARS if needed (it gets modified)
        $ovmfVarsCopy = "target/$TARGET/$PROFILE/OVMF_VARS.fd"
        if (-not (Test-Path $ovmfVarsCopy) -or ((Get-Item $ovmfVars).LastWriteTime -gt (Get-Item $ovmfVarsCopy).LastWriteTime)) {
            Copy-Item $ovmfVars $ovmfVarsCopy -Force
        }
        
        $qemuArgs += @(
            "-drive", "if=pflash,format=raw,readonly=on,file=$ovmfCode"
            "-drive", "if=pflash,format=raw,file=$ovmfVarsCopy"
        )
        
        # Add boot menu for debugging
        $qemuArgs += @("-boot", "menu=on,splash-time=3000")
    } else {
        Write-Info "Boot mode: Legacy BIOS"
    }
    
    # Boot source
    if ($BootSource -and (Test-Path $BootSource)) {
        if ($BootSource -match "\.iso$") {
            # ISO image
            $qemuArgs += @("-cdrom", $BootSource)
        } elseif (Test-Path $BootSource -PathType Container) {
            # Directory - use vvfat with AHCI for better UEFI compatibility
            Write-Info "Using QEMU vvfat for FAT directory"
            $absolutePath = (Resolve-Path $BootSource).Path
            # Use AHCI controller (id=ahci) for UEFI compatibility
            $qemuArgs += @(
                "-device", "ahci,id=ahci"
                "-drive", "file=fat:rw:$absolutePath,format=raw,if=none,id=fatdisk"
                "-device", "ide-hd,drive=fatdisk,bus=ahci.0"
            )
        } else {
            # Raw disk image
            $qemuArgs += @(
                "-drive", "file=$BootSource,format=raw,if=virtio"
            )
        }
    } else {
        Write-ErrorMsg "No bootable media found!"
        exit 1
    }
    
    # Acceleration
    try {
        $hypervisor = Get-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform -ErrorAction SilentlyContinue
        if ($hypervisor -and $hypervisor.State -eq "Enabled") {
            $qemuArgs += @("-accel", "whpx,kernel-irqchip=off")
            Write-Info "Using WHPX acceleration"
        } else {
            $qemuArgs += @("-accel", "tcg,thread=multi")
        }
    } catch {
        $qemuArgs += @("-accel", "tcg,thread=multi")
    }
    
    # Debug mode
    if ($GdbDebug) {
        $qemuArgs += @("-s", "-S")
        Write-Info "GDB: localhost:1234 (waiting)"
    }
    
    Write-Host "QEMU: qemu-system-x86_64 $($qemuArgs -join ' ')" -ForegroundColor DarkGray
    & qemu-system-x86_64 @qemuArgs
}

# Main
Write-Info "RanyOS Limine Boot Builder"
Write-Info "=========================="

Get-Limine
Build-Kernel

# Try ISO first, fall back to FAT directory
$bootSource = New-BootableIso
if (-not $bootSource) {
    $bootSource = New-BootableDisk
}

Start-Qemu -BootSource $bootSource
