#!/bin/bash
# ExoRust QEMU Runner Script
# Bash script for launching ExoRust kernel in QEMU

set -e

# Configuration
KERNEL_NAME="RanyOS"
KERNEL_PATH="target/x86_64-rany_os/debug/$KERNEL_NAME"
QEMU_BIN="qemu-system-x86_64"

# Default options
MEMORY=512
CPUS=2
DEBUG=0
GDB=0
NO_GRAPHICS=0
NETWORK=0
SERIAL=0
DISK=""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Help message
show_help() {
    cat << EOF
ExoRust QEMU Runner Script

Usage: ./run.sh [options]

Options:
  -d, --debug       Enable QEMU debug output
  -g, --gdb         Start GDB server on port 1234 (pauses at start)
  -n, --no-graphics Run without graphical display (serial only)
  --network         Enable network with user-mode networking
  -s, --serial      Enable serial output to terminal
  -m, --memory N    Set memory size in MB (default: 512)
  -c, --cpus N      Set number of CPUs (default: 2)
  --disk PATH       Attach a disk image
  -h, --help        Show this help message

Examples:
  ./run.sh                    # Basic run
  ./run.sh -d -s              # Run with debug output
  ./run.sh -g                 # Run with GDB server
  ./run.sh --network -m 1024  # Run with network, 1GB RAM
EOF
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -d|--debug)
            DEBUG=1
            shift
            ;;
        -g|--gdb)
            GDB=1
            shift
            ;;
        -n|--no-graphics)
            NO_GRAPHICS=1
            shift
            ;;
        --network)
            NETWORK=1
            shift
            ;;
        -s|--serial)
            SERIAL=1
            shift
            ;;
        -m|--memory)
            MEMORY="$2"
            shift 2
            ;;
        -c|--cpus)
            CPUS="$2"
            shift 2
            ;;
        --disk)
            DISK="$2"
            shift 2
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            show_help
            exit 1
            ;;
    esac
done

# Check for QEMU
echo -e "${CYAN}[*] Checking for QEMU...${NC}"
if ! command -v $QEMU_BIN &> /dev/null; then
    echo -e "${RED}[!] QEMU not found. Please install qemu-system-x86_64${NC}"
    exit 1
fi

# Build the kernel
echo -e "${CYAN}[*] Building kernel...${NC}"
cargo build --target x86_64-rany_os.json

if [ $? -ne 0 ]; then
    echo -e "${RED}[!] Build failed!${NC}"
    exit 1
fi

echo -e "${GREEN}[+] Build successful${NC}"

# Check if kernel binary exists
if [ ! -f "$KERNEL_PATH" ]; then
    echo -e "${RED}[!] Kernel binary not found at: $KERNEL_PATH${NC}"
    exit 1
fi

# Build QEMU command line
QEMU_ARGS=(
    -machine q35,accel=tcg
    -cpu qemu64,+rdtscp,+invtsc
    -m ${MEMORY}M
    -smp $CPUS
    -kernel "$KERNEL_PATH"
)

# Serial output
if [ $SERIAL -eq 1 ] || [ $NO_GRAPHICS -eq 1 ]; then
    QEMU_ARGS+=(-serial stdio)
fi

# No graphics mode
if [ $NO_GRAPHICS -eq 1 ]; then
    QEMU_ARGS+=(-nographic)
else
    QEMU_ARGS+=(-vga std)
fi

# GDB support
if [ $GDB -eq 1 ]; then
    QEMU_ARGS+=(-s -S)
    echo -e "${YELLOW}[*] GDB server enabled on port 1234${NC}"
    echo -e "${YELLOW}    Connect with: gdb -ex 'target remote localhost:1234'${NC}"
fi

# Network configuration
if [ $NETWORK -eq 1 ]; then
    QEMU_ARGS+=(
        -netdev user,id=net0,hostfwd=tcp::8080-:80,hostfwd=tcp::2222-:22
        -device virtio-net-pci,netdev=net0
    )
    echo -e "${YELLOW}[*] Network enabled with port forwarding:${NC}"
    echo -e "${YELLOW}    Host 8080 -> Guest 80 (HTTP)${NC}"
    echo -e "${YELLOW}    Host 2222 -> Guest 22 (SSH)${NC}"
fi

# Disk configuration
if [ -n "$DISK" ] && [ -f "$DISK" ]; then
    QEMU_ARGS+=(-drive file=$DISK,format=raw,if=virtio)
    echo -e "${YELLOW}[*] Disk attached: $DISK${NC}"
fi

# Debug output
if [ $DEBUG -eq 1 ]; then
    QEMU_ARGS+=(-d int,cpu_reset -D qemu.log)
    echo -e "${YELLOW}[*] Debug output enabled (see qemu.log)${NC}"
fi

# Add common devices
QEMU_ARGS+=(
    -rtc base=utc
    -no-reboot
    -no-shutdown
)

# Display configuration
echo ""
echo -e "${CYAN}================================================================================${NC}"
echo -e "${CYAN}                        ExoRust QEMU Configuration${NC}"
echo -e "${CYAN}================================================================================${NC}"
echo "  Kernel:  $KERNEL_PATH"
echo "  Memory:  ${MEMORY}MB"
echo "  CPUs:    $CPUS"
echo "  Network: $([ $NETWORK -eq 1 ] && echo 'Enabled' || echo 'Disabled')"
echo "  GDB:     $([ $GDB -eq 1 ] && echo 'Enabled (port 1234)' || echo 'Disabled')"
echo -e "${CYAN}================================================================================${NC}"
echo ""

# Run QEMU
echo -e "${GREEN}[*] Starting QEMU...${NC}"
echo -e "\033[0;90m    Command: $QEMU_BIN ${QEMU_ARGS[*]}\033[0m"
echo ""

exec $QEMU_BIN "${QEMU_ARGS[@]}"
