#!/bin/bash
#
# ExoRust (RanyOS) QEMU Launch Script for Linux/macOS
#
# Usage: ./qemu-run.sh [options]
#
# Options:
#   --build-only     Only build, don't run QEMU
#   --debug          Enable GDB debugging on port 1234
#   --no-kvm         Disable KVM acceleration
#   --memory SIZE    RAM in MB (default: 512)
#   --cpus N         Number of CPU cores (default: 4)
#   --network        Enable virtio-net
#   --storage FILE   Add storage device
#   --benchmark      Enable benchmark mode
#   --test           Run in test mode with timeout
#   --timeout SECS   Test timeout (default: 60)
#   --help           Show this help

set -e

# Configuration
KERNEL_NAME="RanyOS"
TARGET="x86_64-rany_os"
BUILD_DIR="target/${TARGET}/debug"

# Default options
BUILD_ONLY=false
DEBUG=false
NO_KVM=false
MEMORY=512
CPUS=4
NETWORK=false
STORAGE=""
BENCHMARK=false
TEST_MODE=false
TIMEOUT=60

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

info() {
    echo -e "${CYAN}[INFO]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

show_help() {
    head -30 "$0" | tail -20
    exit 0
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --build-only) BUILD_ONLY=true ;;
        --debug) DEBUG=true ;;
        --no-kvm) NO_KVM=true ;;
        --memory) MEMORY="$2"; shift ;;
        --cpus) CPUS="$2"; shift ;;
        --network) NETWORK=true ;;
        --storage) STORAGE="$2"; shift ;;
        --benchmark) BENCHMARK=true ;;
        --test) TEST_MODE=true ;;
        --timeout) TIMEOUT="$2"; shift ;;
        --help|-h) show_help ;;
        *) error "Unknown option: $1"; exit 1 ;;
    esac
    shift
done

# Check prerequisites
check_prerequisites() {
    info "Checking prerequisites..."
    
    if ! command -v cargo &> /dev/null; then
        error "Cargo not found. Please install Rust."
        exit 1
    fi
    
    if ! command -v qemu-system-x86_64 &> /dev/null; then
        warn "QEMU not found. Installation instructions:"
        echo "  Ubuntu/Debian: sudo apt install qemu-system-x86"
        echo "  Fedora: sudo dnf install qemu-system-x86"
        echo "  macOS: brew install qemu"
        if $BUILD_ONLY; then
            warn "Continuing with build only..."
        else
            exit 1
        fi
    fi
    
    success "Prerequisites check completed."
}

# Build kernel
build_kernel() {
    info "Building ExoRust kernel..."
    
    BUILD_ARGS="--target ${TARGET}.json"
    
    if $BENCHMARK; then
        BUILD_ARGS="$BUILD_ARGS --features benchmark"
    fi
    
    if ! cargo build $BUILD_ARGS; then
        error "Build failed!"
        exit 1
    fi
    
    KERNEL_PATH="${BUILD_DIR}/${KERNEL_NAME}"
    
    if [[ ! -f "$KERNEL_PATH" ]]; then
        error "Kernel binary not found at: $KERNEL_PATH"
        exit 1
    fi
    
    success "Kernel built successfully: $KERNEL_PATH"
}

# Run QEMU
run_qemu() {
    info "Starting QEMU..."
    
    QEMU_ARGS=(
        -machine q35
        -cpu qemu64,+rdtscp,+x2apic,+pdpe1gb
        -smp "$CPUS"
        -m "${MEMORY}M"
        -serial stdio
        -display none
    )
    
    # Hardware acceleration
    if ! $NO_KVM; then
        if [[ -e /dev/kvm ]]; then
            QEMU_ARGS+=(-enable-kvm)
            info "Using KVM acceleration"
        elif [[ "$(uname)" == "Darwin" ]]; then
            # macOS Hypervisor.framework
            QEMU_ARGS+=(-accel hvf)
            info "Using HVF acceleration (macOS)"
        else
            QEMU_ARGS+=(-accel tcg,thread=multi)
            info "Using TCG acceleration (software)"
        fi
    else
        QEMU_ARGS+=(-accel tcg,thread=multi)
    fi
    
    # Kernel
    QEMU_ARGS+=(-kernel "$KERNEL_PATH")
    
    # Network
    if $NETWORK; then
        QEMU_ARGS+=(
            -device virtio-net-pci,netdev=net0
            -netdev user,id=net0,hostfwd=tcp::8080-:80
        )
        info "Network enabled: port 8080 forwarded to guest port 80"
    fi
    
    # Storage
    if [[ -n "$STORAGE" && -f "$STORAGE" ]]; then
        QEMU_ARGS+=(
            -device virtio-blk-pci,drive=drive0
            -drive id=drive0,if=none,format=raw,file="$STORAGE"
        )
        info "Storage: $STORAGE"
    fi
    
    # Debug
    if $DEBUG; then
        QEMU_ARGS+=(-s -S)
        info "GDB server started on port 1234"
        info "Connect with: gdb -ex 'target remote :1234'"
    fi
    
    # Test mode
    if $TEST_MODE; then
        QEMU_ARGS+=(
            -device isa-debug-exit,iobase=0xf4,iosize=0x04
            -no-reboot
        )
        
        info "Running in test mode with ${TIMEOUT}s timeout..."
        
        timeout "$TIMEOUT" qemu-system-x86_64 "${QEMU_ARGS[@]}" || EXIT_CODE=$?
        
        case $EXIT_CODE in
            0)
                success "QEMU exited normally"
                ;;
            33)
                success "Tests passed! (exit code 33)"
                exit 0
                ;;
            124)
                error "QEMU timed out after ${TIMEOUT}s"
                exit 1
                ;;
            *)
                error "Tests failed with exit code: $EXIT_CODE"
                exit 1
                ;;
        esac
    else
        info "QEMU command: qemu-system-x86_64 ${QEMU_ARGS[*]}"
        qemu-system-x86_64 "${QEMU_ARGS[@]}"
    fi
}

# Main
main() {
    cd "$(dirname "$0")/.."
    
    check_prerequisites
    build_kernel
    
    if $BUILD_ONLY; then
        success "Build completed. Kernel at: $KERNEL_PATH"
        exit 0
    fi
    
    run_qemu
}

main
