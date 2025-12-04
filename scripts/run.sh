#!/bin/bash
# ExoRust (RanyOS) Limine Boot Runner Script
# Usage: ./scripts/run.sh [options]

set -e

# Configuration
TARGET="x86_64-unknown-none"
KERNEL_NAME="exorust_kernel"
LIMINE_VERSION="8.x"
LIMINE_DIR="assets/limine"
OVMF_DIR="assets/firmware/ovmf-x64"

# Defaults
PROFILE="debug"
BUILD_FLAGS=""
MEMORY="512"
USE_UEFI=true
GDB_DEBUG=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --release)
            PROFILE="release"
            BUILD_FLAGS="--release"
            shift
            ;;
        --bios)
            USE_UEFI=false
            shift
            ;;
        --debug)
            GDB_DEBUG=true
            shift
            ;;
        --memory)
            MEMORY="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [options]"
            echo "Options:"
            echo "  --release    Build in release mode"
            echo "  --bios       Use legacy BIOS boot (default: UEFI)"
            echo "  --debug      Enable GDB debugging on port 1234"
            echo "  --memory N   Set memory size in MB (default: 512)"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

KERNEL_PATH="target/$TARGET/$PROFILE/$KERNEL_NAME"
ISO_PATH="target/$TARGET/$PROFILE/ranyos.iso"

echo "[INFO] RanyOS Limine Boot Builder"
echo "[INFO] =========================="

# Download Limine if needed
download_limine() {
    if [[ ! -f "$LIMINE_DIR/limine-bios.sys" ]]; then
        echo "[INFO] Downloading Limine bootloader..."
        mkdir -p "$LIMINE_DIR"
        
        BASE_URL="https://github.com/limine-bootloader/limine/raw/v$LIMINE_VERSION-binary"
        
        for file in limine-bios.sys limine-bios-cd.bin limine-uefi-cd.bin BOOTX64.EFI BOOTIA32.EFI; do
            echo "  Downloading $file..."
            curl -sL "$BASE_URL/$file" -o "$LIMINE_DIR/$file"
        done
        
        echo "[OK] Limine downloaded"
    else
        echo "[INFO] Limine bootloader found"
    fi
}

# Build kernel
build_kernel() {
    echo "[INFO] Building kernel..."
    cargo build --target "$TARGET" $BUILD_FLAGS
    
    if [[ ! -f "$KERNEL_PATH" ]]; then
        echo "[ERROR] Kernel not found: $KERNEL_PATH"
        exit 1
    fi
    
    echo "[OK] Kernel built: $KERNEL_PATH"
}

# Create ISO
create_iso() {
    echo "[INFO] Creating bootable ISO..."
    
    ISO_ROOT="target/$TARGET/$PROFILE/iso_root"
    
    rm -rf "$ISO_ROOT"
    mkdir -p "$ISO_ROOT/boot/limine"
    mkdir -p "$ISO_ROOT/EFI/BOOT"
    
    # Copy kernel
    cp "$KERNEL_PATH" "$ISO_ROOT/boot/$KERNEL_NAME"
    
    # Copy Limine config
    cp "limine.conf" "$ISO_ROOT/limine.conf"
    cp "limine.conf" "$ISO_ROOT/boot/limine/limine.conf"
    
    # Copy Limine files
    cp "$LIMINE_DIR/limine-bios.sys" "$ISO_ROOT/boot/limine/"
    cp "$LIMINE_DIR/limine-bios-cd.bin" "$ISO_ROOT/boot/limine/"
    cp "$LIMINE_DIR/limine-uefi-cd.bin" "$ISO_ROOT/boot/limine/"
    cp "$LIMINE_DIR/BOOTX64.EFI" "$ISO_ROOT/EFI/BOOT/"
    [[ -f "$LIMINE_DIR/BOOTIA32.EFI" ]] && cp "$LIMINE_DIR/BOOTIA32.EFI" "$ISO_ROOT/EFI/BOOT/"
    
    # Create ISO with xorriso
    xorriso -as mkisofs \
        -b boot/limine/limine-bios-cd.bin \
        -no-emul-boot -boot-load-size 4 -boot-info-table \
        --efi-boot boot/limine/limine-uefi-cd.bin \
        -efi-boot-part --efi-boot-image --protective-msdos-label \
        "$ISO_ROOT" -o "$ISO_PATH"
    
    echo "[OK] ISO created: $ISO_PATH"
}

# Run QEMU
run_qemu() {
    echo "[INFO] Starting QEMU..."
    
    QEMU_ARGS=(
        -machine q35
        -cpu qemu64,+rdtscp,+x2apic
        -m "${MEMORY}M"
        -serial mon:stdio
        -no-reboot
        -no-shutdown
        -cdrom "$ISO_PATH"
    )
    
    if $USE_UEFI && [[ -f "$OVMF_DIR/OVMF_CODE.fd" ]]; then
        echo "[INFO] Boot mode: UEFI"
        
        # Create fresh OVMF_VARS copy
        OVMF_VARS_COPY="target/$TARGET/$PROFILE/OVMF_VARS.fd"
        cp "$OVMF_DIR/OVMF_VARS.fd" "$OVMF_VARS_COPY"
        
        QEMU_ARGS+=(
            -drive "if=pflash,format=raw,readonly=on,file=$OVMF_DIR/OVMF_CODE.fd"
            -drive "if=pflash,format=raw,file=$OVMF_VARS_COPY"
        )
    else
        echo "[INFO] Boot mode: Legacy BIOS"
    fi
    
    # Check for KVM
    if [[ -w /dev/kvm ]]; then
        QEMU_ARGS+=(-accel kvm)
        echo "[INFO] Using KVM acceleration"
    else
        QEMU_ARGS+=(-accel tcg,thread=multi)
    fi
    
    if $GDB_DEBUG; then
        QEMU_ARGS+=(-s -S)
        echo "[INFO] GDB: localhost:1234 (waiting)"
    fi
    
    qemu-system-x86_64 "${QEMU_ARGS[@]}"
}

# Main
download_limine
build_kernel
create_iso
run_qemu
