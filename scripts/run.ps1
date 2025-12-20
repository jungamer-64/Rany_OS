#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Build and run RanyOS with ExoLoader or Limine bootloader
.DESCRIPTION
    Creates a bootable disk image and runs it in QEMU.
    Supports ExoLoader (UEFI) and Limine (UEFI/BIOS).
.PARAMETER Release
    Build in release mode
.PARAMETER Bootloader
    "ExoLoader" (default) or "Limine"
.PARAMETER GdbDebug
    Enable GDB debugging on port 1234
.PARAMETER Memory
    Memory size in MB (default: 512)
#>

[CmdletBinding()]
param(
    [switch]$Release,
    [ValidateSet("ExoLoader", "Limine")]
    [string]$Bootloader = "ExoLoader",
    [switch]$GdbDebug,
    [int]$Memory = 512
)

$ErrorActionPreference = "Stop"

# Configuration
$TARGET_KERNEL = "x86_64-kernel.json"
$TARGET_LOADER = "x86_64-unknown-uefi"
$KERNEL_NAME = "exorust_kernel"
$LOADER_NAME = "exoloader.efi"
$LIMINE_VERSION = "8.x"
$LIMINE_DIR = "assets/limine"
$OVMF_DIR = "assets/firmware/ovmf-x64"

if ($Release) {
    $PROFILE = "release"
    $BUILD_FLAGS = "--release"
}
else {
    $PROFILE = "debug"
    $BUILD_FLAGS = ""
}

# Note: Cargo uses target name without .json extension for output directory
$KERNEL_TARGET_DIR = "x86_64-kernel"
$KERNEL_PATH = "target/$KERNEL_TARGET_DIR/$PROFILE/$KERNEL_NAME"
$KERNEL_SIGNED_PATH = "target/$KERNEL_TARGET_DIR/$PROFILE/rany_os_signed"
$LOADER_PATH = "target/$TARGET_LOADER/release/exoloader.efi"
$DISK_IMG = "target/$KERNEL_TARGET_DIR/$PROFILE/ranyos.img"
$SIGNER_PATH = "tools/signer/target/release/kernel-signer.exe"
$KEYS_DIR = "keys"

function Write-Info($msg) { Write-Host "[INFO] $msg" -ForegroundColor Cyan }
function Write-Success($msg) { Write-Host "[OK] $msg" -ForegroundColor Green }
function Write-ErrorMsg($msg) { Write-Host "[ERROR] $msg" -ForegroundColor Red }
function Write-Warn($msg) { Write-Host "[WARN] $msg" -ForegroundColor Yellow }

# --- Limine Functions ---
function Get-Limine {
    if (-not (Test-Path "$LIMINE_DIR/limine-bios.sys")) {
        Write-Info "Downloading Limine bootloader v$LIMINE_VERSION..."
        New-Item -ItemType Directory -Force -Path $LIMINE_DIR | Out-Null
        $baseUrl = "https://github.com/limine-bootloader/limine/raw/v$LIMINE_VERSION-binary"
        $files = @("limine-bios.sys", "limine-bios-cd.bin", "limine-uefi-cd.bin", "BOOTX64.EFI", "BOOTIA32.EFI")
        try {
            foreach ($file in $files) {
                Invoke-WebRequest -Uri "$baseUrl/$file" -OutFile "$LIMINE_DIR/$file" -UseBasicParsing -ErrorAction Stop
            }
        }
        catch {
            Write-ErrorMsg "Failed to download Limine: $_"
            exit 1
        }
    }
}

# --- Build Functions ---
function Build-Kernel {
    $ErrorActionPreference = "Continue" # Don't stop on cargo warnings
    Write-Info "Building kernel..."
    # Config for Limine/ExoLoader (static relocation)
    # $env:CARGO_TARGET_X86_64_UNKNOWN_NONE_RUSTFLAGS = ... (Moved to .cargo/config.toml)
    $buildCmd = "cargo build -p rany_kernel --target $TARGET_KERNEL $BUILD_FLAGS -Z 'build-std=core,compiler_builtins,alloc' -Z 'build-std-features=compiler-builtins-mem' 2>&1"
    Invoke-Expression $buildCmd
    if ($LASTEXITCODE -ne 0) { 
        $ErrorActionPreference = "Stop"
        throw "Kernel build failed" 
    }
    $ErrorActionPreference = "Stop"
    Write-Success "Kernel built"
}

function Build-ExoLoader {
    $ErrorActionPreference = "Continue" 
    Write-Info "Building ExoLoader..."
    # Fix: Quote arguments
    $buildCmd = "cargo build -p exoloader --target $TARGET_LOADER --release -Z 'build-std=core,compiler_builtins,alloc' -Z 'build-std-features=compiler-builtins-mem' 2>&1"
    Invoke-Expression $buildCmd
    if ($LASTEXITCODE -ne 0) { 
        $ErrorActionPreference = "Stop"
        throw "ExoLoader build failed" 
    }
    $ErrorActionPreference = "Stop"
    Write-Success "ExoLoader built"
}

# --- Secure Boot Functions ---
function Build-Signer {
    if (-not (Test-Path $SIGNER_PATH)) {
        Write-Info "Building kernel signer tool..."
        $buildCmd = "cargo build --release --manifest-path tools/signer/Cargo.toml 2>&1"
        Invoke-Expression $buildCmd
        if ($LASTEXITCODE -ne 0) { throw "Signer build failed" }
        Write-Success "Signer built"
    }
}

function Ensure-Keypair {
    if (-not (Test-Path "$KEYS_DIR/kernel_pub.key")) {
        Write-Info "Generating Ed25519 keypair for secure boot..."
        & $SIGNER_PATH keygen --output-dir $KEYS_DIR
        if ($LASTEXITCODE -ne 0) { throw "Keypair generation failed" }
        Write-Success "Keypair generated"
        Write-Warn "Keep keys/kernel.key SECRET! It is excluded from git."
    }
}

function Sign-Kernel {
    Write-Info "Signing kernel with Ed25519..."
    & $SIGNER_PATH sign --kernel $KERNEL_PATH --secret-key "$KEYS_DIR/kernel.key" --output $KERNEL_SIGNED_PATH
    if ($LASTEXITCODE -ne 0) { throw "Kernel signing failed" }
    Write-Success "Kernel signed"
}

# --- Image Creation ---
function New-BootableDisk {
    Write-Info "Creating FAT32 disk image for $Bootloader..."
    
    # Ensure dir exists
    $diskDir = Split-Path $DISK_IMG -Parent
    if (-not (Test-Path $diskDir)) { New-Item -ItemType Directory -Force -Path $diskDir | Out-Null }

    # Setup Directory Structure (Generic for both tools)
    $fatRoot = "target/$TARGET_KERNEL/$PROFILE/fat_root"
    if (Test-Path $fatRoot) { Remove-Item $fatRoot -Recurse -Force }
    New-Item -ItemType Directory -Force -Path "$fatRoot/EFI/BOOT" | Out-Null
    
    if ($Bootloader -eq "ExoLoader") {
        # Deploy ExoLoader
        Copy-Item $LOADER_PATH "$fatRoot/EFI/BOOT/BOOTX64.EFI"
        # ExoLoader expects signed kernel at root named "rany_os"
        Copy-Item $KERNEL_SIGNED_PATH "$fatRoot/rany_os"
    }
    else {
        # Deploy Limine
        Get-Limine
        New-Item -ItemType Directory -Force -Path "$fatRoot/boot/limine" | Out-Null
        Copy-Item $KERNEL_PATH "$fatRoot/boot/exorust_kernel"
        Copy-Item "limine.conf" "$fatRoot/boot/limine/"
        Copy-Item "limine.conf" "$fatRoot/EFI/BOOT/"
        Copy-Item "$LIMINE_DIR/BOOTX64.EFI" "$fatRoot/EFI/BOOT/"
        Copy-Item "$LIMINE_DIR/limine-bios.sys" "$fatRoot/boot/limine/"
    }

    # Checks for mtools
    $mformat = Get-Command "mformat" -ErrorAction SilentlyContinue
    if ($mformat) {
        Write-Info "Using mtools to create disk image..."
        # Create blank file
        $sizeBytes = 64 * 1024 * 1024
        $f = [System.IO.File]::Create($DISK_IMG)
        $f.SetLength($sizeBytes); $f.Close()
        
        $mtoolsrc = "target/mtoolsrc"
        "drive x: file=`"$DISK_IMG`" offset=0" | Out-File $mtoolsrc -Encoding ascii
        $env:MTOOLSRC = $mtoolsrc
        
        & mformat -i $DISK_IMG -F ::
        
        # Recursive copy function for mtools
        function MCopy-Recurse($srcPath, $dstPath) {
            Get-ChildItem $srcPath | ForEach-Object {
                if ($_.PSIsContainer) {
                    & mmd -i $DISK_IMG "$dstPath/$($_.Name)"
                    MCopy-Recurse $_.FullName "$dstPath/$($_.Name)"
                }
                else {
                    & mcopy -i $DISK_IMG $_.FullName "$dstPath/$($_.Name)"
                }
            }
        }
        
        # Init root dirs
        & mmd -i $DISK_IMG ::/EFI
        & mmd -i $DISK_IMG ::/EFI/BOOT
        if ($Bootloader -eq "Limine") { & mmd -i $DISK_IMG ::/boot; & mmd -i $DISK_IMG ::/boot/limine }
        
        # Copy content
        MCopy-Recurse $fatRoot "::"
        
        return $DISK_IMG
    }
    
    Write-Info "Returning FAT root directory for QEMU vvfat"
    return $fatRoot
}

# --- Run QEMU ---
function Start-Qemu {
    param([string]$BootSource)
    
    $qemuArgs = @("-machine", "q35", "-cpu", "max", "-m", "${Memory}M", "-serial", "file:qemu_log_final.txt", "-no-reboot", "-no-shutdown")
    
    # UEFI Config
    $ovmfCode = "$OVMF_DIR/OVMF_CODE.fd"
    $ovmfVars = "$OVMF_DIR/OVMF_VARS.fd"
    
    if (-not (Test-Path $ovmfCode)) {
        if ($Bootloader -eq "ExoLoader") {
            Write-ErrorMsg "ExoLoader requires UEFI (OVMF). Please ensure assets/firmware/ovmf-x64/OVMF_CODE.fd exists."
            exit 1
        }
        Write-Info "UEFI not found, using legacy BIOS"
    }
    else {
        Write-Info "Booting UEFI..."
        $ovmfVarsLocal = "target/$TARGET_KERNEL/$PROFILE/OVMF_VARS.fd"
        if (-not (Test-Path $ovmfVarsLocal)) { Copy-Item $ovmfVars $ovmfVarsLocal }
        $qemuArgs += @("-drive", "if=pflash,format=raw,readonly=on,file=$ovmfCode", "-drive", "if=pflash,format=raw,file=$ovmfVarsLocal")
    }

    # Drive Config
    if (Test-Path $BootSource -PathType Container) {
        # vvfat
        $absPath = (Resolve-Path $BootSource).Path
        $qemuArgs += @("-device", "ahci,id=ahci", "-drive", "file=fat:rw:$absPath,format=raw,if=none,id=fatdisk", "-device", "ide-hd,drive=fatdisk,bus=ahci.0")
    }
    else {
        $qemuArgs += @("-drive", "file=$BootSource,format=raw,if=virtio")
    }

    # Debug
    if ($GdbDebug) { $qemuArgs += @("-s", "-S"); Write-Info "GDB enabled" }

    # Accel
    try {
        $hypervisor = Get-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform -ErrorAction SilentlyContinue
        if ($hypervisor -and $hypervisor.State -eq "Enabled") {
            $qemuArgs += @("-accel", "tcg,thread=multi") 
        }
        else {
            $qemuArgs += @("-accel", "tcg,thread=multi") 
        }
    }
    catch {
        $qemuArgs += @("-accel", "tcg,thread=multi") 
    }
    
    Write-Host "Running: qemu-system-x86_64 $($qemuArgs -join ' ')" -ForegroundColor DarkGray
    & qemu-system-x86_64 @qemuArgs
}

# --- Main Execution ---
try {
    # Secure boot: build signer and ensure keys exist BEFORE bootloader
    # (bootloader uses include_bytes! which needs the public key at compile time)
    if ($Bootloader -eq "ExoLoader") {
        Build-Signer
        Ensure-Keypair
        Build-ExoLoader
    }
    Build-Kernel
    if ($Bootloader -eq "ExoLoader") {
        Sign-Kernel
    }
    $media = New-BootableDisk
    Start-Qemu -BootSource $media
}
catch {
    Write-ErrorMsg "Script failed: $_"
    exit 1
}
