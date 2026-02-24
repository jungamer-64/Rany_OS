#!/bin/bash
# =============================================================================
# ExoRust (RanyOS) Build & Run Script
# Bash equivalent of run.ps1 — ExoLoader (UEFI) bootloader pipeline.
# =============================================================================
# Usage: ./scripts/run.sh [options]
#
# Examples:
#   ./scripts/run.sh                          # Dev: quick debug build + QEMU
#   ./scripts/run.sh --release --numa --network --monitor   # Full ExoRust testing
#   ./scripts/run.sh --test --tcg --serial null             # CI/Headless
#   ./scripts/run.sh --gdb --monitor                        # GDB debugging
#   ./scripts/run.sh --no-iommu --network                   # Compatibility test
#   ./scripts/run.sh --reset-vars                           # Reset UEFI state
#   ./scripts/run.sh --cpu qemu64 --tcg                     # Force CPU model

set -e

# --- Global Configuration & Paths ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"

# Project Constants
TARGET_KERNEL_JSON="$ROOT_DIR/x86_64-exorust.json"
TARGET_LOADER="x86_64-unknown-uefi"
KERNEL_CRATE="rany_kernel"
LOADER_CRATE="exoloader"
LOADER_BIN_NAME="exoloader.efi"

# Resources
OVMF_DIR="$ROOT_DIR/assets/firmware/ovmf-x64"
KEYS_DIR="$ROOT_DIR/keys"
TOOLS_DIR="$ROOT_DIR/tools"
SIGNER_TOOL_DIR="$TOOLS_DIR/signer"

# --- Defaults ---
PROFILE="debug"
CARGO_ARGS_COMMON=()
MEMORY=1024
SMP=4
SERIAL="stdio"
GDB_DEBUG=false
CLEAN=false
NO_RUN=false
TEST_MODE=false
LINT=false
IOMMU=true
NO_IOMMU=false
NUMA=true
NO_NUMA=false
NETWORK=true          # network enabled by default
NO_NETWORK=false
MONITOR=false
TCG=false
VERBOSE=false
RESET_VARS=false
CPU_MODEL=""
NVME_DEVICE=""
FEATURES=()
QEMU_EXTRA_ARGS=()
CARGO_RUNNER=false
CARGO_KERNEL_PATH=""
KERNEL_CMDLINE=""

# --- Argument Parsing ---
while [[ $# -gt 0 ]]; do
    case $1 in
        --release)
            PROFILE="release"
            CARGO_ARGS_COMMON=("--release")
            shift ;;
        --gdb|--gdb-debug)
            GDB_DEBUG=true
            shift ;;
        --clean)
            CLEAN=true
            shift ;;
        --no-run)
            NO_RUN=true
            shift ;;
        --test)
            TEST_MODE=true
            shift ;;
        --lint)
            LINT=true
            shift ;;
        --iommu)
            IOMMU=true
            shift ;;
        --no-iommu)
            NO_IOMMU=true
            shift ;;
        --numa)
            NUMA=true
            shift ;;
        --no-numa)
            NO_NUMA=true
            shift ;;
        --network)
            NETWORK=true
            shift ;;
        --no-network)
            NO_NETWORK=true
            shift ;;
        --monitor)
            MONITOR=true
            shift ;;
        --tcg)
            TCG=true
            shift ;;
        --verbose)
            VERBOSE=true
            shift ;;
        --reset-vars)
            RESET_VARS=true
            shift ;;
        --cpu)
            CPU_MODEL="$2"
            shift 2 ;;
        --memory)
            MEMORY="$2"
            shift 2 ;;
        --smp)
            SMP="$2"
            shift 2 ;;
        --serial)
            SERIAL="$2"
            shift 2 ;;
        --nvme)
            NVME_DEVICE="$2"
            shift 2 ;;
        --features)
            IFS=',' read -ra FEATURES <<< "$2"
            shift 2 ;;
        --qemu-extra)
            QEMU_EXTRA_ARGS+=("$2")
            shift 2 ;;
        --cmdline)
            KERNEL_CMDLINE="$2"
            shift 2 ;;
        --cargo-runner)
            CARGO_RUNNER=true
            CARGO_KERNEL_PATH="$2"
            shift 2 ;;
        --help)
            cat <<'HELPEOF'
Usage: ./scripts/run.sh [options]

Build & Execution:
  --release         Build in release mode (optimizations enabled)
  --clean           Clean target directory before building
  --no-run          Build only, do not launch QEMU
  --lint            Run cargo fmt and clippy checks before building
  --verbose         Show detailed build output

QEMU Options:
  --memory N        Memory size in MB (default: 512)
  --smp N           Number of CPU cores (default: 4)
  --serial MODE     Serial output: stdio (default), file, null
  --cpu MODEL       QEMU CPU model (default: auto based on accel)
  --gdb             Enable GDB stub on port 1234, freeze CPU at startup
  --test            Run in test mode (headless, exit on test completion)
  --tcg             Force TCG software emulation (slower but compatible)
  --reset-vars      Reset UEFI variables (OVMF_VARS.fd) to original state
  --monitor         Enable QEMU Monitor on telnet port 4444
  --cmdline ARGS    Write ARGS to exoloader.cmdline for kernel cmdline injection

Hardware Emulation:
  --iommu           Enable Intel VT-d IOMMU emulation (default: enabled)
  --no-iommu        Disable IOMMU emulation
  --numa            Enable NUMA topology simulation (default: enabled, 2 nodes)
  --no-numa         Disable NUMA topology simulation
  --network         Enable VirtIO network device (hostfwd: tcp 5555->80, udp 5556->80) [default]
  --no-network      Disable VirtIO network device
  --nvme SIZE       Add virtual NVMe device (e.g., "1G", "512M")

Advanced:
  --features F1,F2  Cargo features for kernel (comma-separated)
  --qemu-extra ARG  Additional QEMU argument (can be repeated)
  --cargo-runner P  Cargo runner integration with kernel path P

Examples:
  ./scripts/run.sh                                          # Dev build
  ./scripts/run.sh --release --numa --network --monitor     # Full test
  ./scripts/run.sh --test --tcg --serial null               # CI/Headless
  ./scripts/run.sh --gdb --monitor                          # Debug
HELPEOF
            exit 0 ;;
        *)
            echo "[ERROR] Unknown option: $1"
            exit 1 ;;
    esac
done

# --- Derived Paths ---
TARGET_DIR="$ROOT_DIR/target"
KERNEL_TARGET_DIR="$TARGET_DIR/x86_64-exorust/$PROFILE"
LOADER_TARGET_DIR="$TARGET_DIR/$TARGET_LOADER/release"  # Loader is always release
# FAT_ROOT is derived from the kernel output directory and used by both
# create_disk_image and start_qemu.  Calculating it here avoids accidental
# usage before it is set (e.g. if pipelines are reordered later).
FAT_ROOT="$KERNEL_TARGET_DIR/fat_root"

if [[ "$CARGO_RUNNER" = true ]] && [[ -n "$CARGO_KERNEL_PATH" ]]; then
    KERNEL_RAW="$CARGO_KERNEL_PATH"
else
    KERNEL_RAW="$KERNEL_TARGET_DIR/exorust_kernel"
fi
KERNEL_SIGNED="$KERNEL_TARGET_DIR/rany_os_signed"
LOADER_EFI="$LOADER_TARGET_DIR/$LOADER_BIN_NAME"

# Signer tool: find host-native binary
get_host_target() {
    rustc -vV 2>/dev/null | sed -n 's/^host: //p'
}

HOST_TARGET="$(get_host_target)"
SIGNER_TOOL_BIN="$SIGNER_TOOL_DIR/target/$HOST_TARGET/release/kernel-signer"

# --- Helper Functions ---

step()  { printf '\033[36m%s\033[0m\n' "$1" >&2; }
done_() { printf '   -> \033[32m%s\033[0m\n' "$1" >&2; }
warn_() { printf '   -> \033[33m[WARN] %s\033[0m\n' "$1" >&2; }
fail_() { printf '   -> \033[31m[ERROR] %s\033[0m\n' "$1" >&2; }

# --- Dependency Checks ---

check_dependencies() {
    step "Checking dependencies..."

    for cmd in cargo rustup; do
        if ! command -v "$cmd" &>/dev/null; then
            fail_ "Command '$cmd' not found. Please install it or add it to PATH."
            exit 1
        fi
    done

    # Nightly toolchain check
    local version
    version="$(rustc --version 2>/dev/null)"
    if [[ "$version" != *nightly* ]]; then
        fail_ "Nightly toolchain required. Current: $version"
        fail_ "Fix: rustup override set nightly"
        exit 1
    fi
    done_ "Nightly toolchain: OK"

    # rust-src component
    if ! rustup component list --installed 2>/dev/null | grep -q "^rust-src"; then
        warn_ "Rust component 'rust-src' is missing. Installing..."
        rustup component add rust-src
    fi

    # If we plan to lint, ensure the formatter and clippy are installed too.
    if [[ "$LINT" = true ]]; then
        for comp in rustfmt clippy; do
            if ! rustup component list --installed 2>/dev/null | grep -q "^${comp}"; then
                warn_ "Rust component '$comp' is missing. Installing..."
                rustup component add "$comp"
            fi
        done
    fi

    # QEMU check (only if we're going to run)
    if [[ "$NO_RUN" != true ]]; then
        if ! command -v qemu-system-x86_64 &>/dev/null; then
            fail_ "qemu-system-x86_64 not found."
            exit 1
        fi
    fi

    # OVMF firmware
    if [[ ! -d "$OVMF_DIR" ]]; then
        fail_ "OVMF firmware directory not found at: $OVMF_DIR"
        exit 1
    fi
}

# --- Clean ---

run_clean() {
    step "Cleaning target directory..."
    if [[ -d "$TARGET_DIR" ]]; then
        rm -rf "$TARGET_DIR"
        done_ "Cleaned."
    fi
}

# --- Lint & Format ---

invoke_lints() {
    step "Running Cargo Fmt & Clippy..."

    done_ "Checking format..."
    if ! cargo fmt --all -- --check; then
        fail_ "Format check failed. Run 'cargo fmt' to fix."
        exit 1
    fi

    done_ "Running Clippy on kernel..."
    if ! cargo clippy -p "$KERNEL_CRATE" \
        --target "$TARGET_KERNEL_JSON" \
        -Z json-target-spec \
        -Z build-std=core,compiler_builtins,alloc \
        -- -D warnings; then
        exit 1
    fi

    done_ "Running Clippy on loader..."
    if ! cargo clippy -p "$LOADER_CRATE" \
        --target "$TARGET_LOADER" \
        -Z build-std=core,compiler_builtins,alloc \
        -- -D warnings; then
        exit 1
    fi

    done_ "Code is clean."
}

# --- Build Steps ---

build_signer() {
    local needs_build=false

    if [[ ! -f "$SIGNER_TOOL_BIN" ]]; then
        needs_build=true
    else
        # Check if source is newer than binary
        local src_newest
        src_newest="$(find "$SIGNER_TOOL_DIR/src" -type f -newer "$SIGNER_TOOL_BIN" 2>/dev/null | head -1)"
        if [[ -n "$src_newest" ]]; then
            needs_build=true
        fi
    fi

    if [[ "$needs_build" = true ]]; then
        step "Building Kernel Signer Tool..."
        local build_args=("build" "--release" "-Z" "build-std=")
        if [[ -n "$HOST_TARGET" ]]; then
            build_args+=("--target" "$HOST_TARGET")
        fi
        if [[ "$VERBOSE" != true ]]; then build_args+=("--quiet"); fi

        (cd "$SIGNER_TOOL_DIR" && cargo "${build_args[@]}")
        done_ "Signer tool built."
    fi
}

setup_keys() {
    # ensure both public and private key exist; regenerating when either is
    # missing avoids situations where a leftover pub key but missing secret
    # would later make sign_kernel fail with a confusing error.
    if [[ ! -f "$KEYS_DIR/kernel_pub.key" ]] || [[ ! -f "$KEYS_DIR/kernel.key" ]]; then
        step "Generating Secure Boot Keys..."
        mkdir -p "$KEYS_DIR"
        "$SIGNER_TOOL_BIN" keygen --output-dir "$KEYS_DIR"
        done_ "Keys generated in $KEYS_DIR"
        warn_ "Keep private keys secret!"
    fi
}

build_loader() {
    step "Building ExoLoader (UEFI)..."
    local build_args=(
        build
        -p "$LOADER_CRATE"
        --target "$TARGET_LOADER"
        --release
        -Z build-std=core,compiler_builtins,alloc
        -Z build-std-features=compiler-builtins-mem
    )
    if [[ "$VERBOSE" != true ]]; then build_args+=("--quiet"); fi

    cargo "${build_args[@]}"
    done_ "ExoLoader built."
}

build_kernel() {
    step "Building Kernel ($PROFILE)..."
    local build_args=(
        build
        -p "$KERNEL_CRATE"
        --target "$TARGET_KERNEL_JSON"
        "${CARGO_ARGS_COMMON[@]}"
    )

    # Feature flags
    if [[ ${#FEATURES[@]} -gt 0 ]]; then
        local joined
        # nosemgrep: bash.lang.security.ifs-tampering.ifs-tampering
        joined="$(IFS=','; echo "${FEATURES[*]}")"
        build_args+=("--features" "$joined")
        done_ "Enabled features: $joined"
    fi

    build_args+=(
        -Z json-target-spec
        -Z build-std=core,compiler_builtins,alloc
        -Z build-std-features=compiler-builtins-mem
    )
    if [[ "$VERBOSE" != true ]]; then build_args+=("--quiet"); fi

    cargo "${build_args[@]}"
    done_ "Kernel compiled."
}

sign_kernel() {
    step "Signing Kernel..."
    if [[ ! -f "$KERNEL_RAW" ]]; then
        fail_ "Kernel binary not found at $KERNEL_RAW"
        exit 1
    fi
    # Ensure output directory exists (cargorunner skips kernel build which may
    # leave $KERNEL_TARGET_DIR missing).  Without this qemu pipeline will blow
    # up inside the signer tool.
    mkdir -p "$(dirname "$KERNEL_SIGNED")"
    "$SIGNER_TOOL_BIN" sign \
        --kernel "$KERNEL_RAW" \
        --secret-key "$KEYS_DIR/kernel.key" \
        --output "$KERNEL_SIGNED"
    done_ "Kernel signed."
}

# --- Image Creation ---

create_disk_image() {
    step "Preparing Boot Image..."

    rm -rf "$FAT_ROOT"
    mkdir -p "$FAT_ROOT/EFI/BOOT"

    # Check artifacts
    if [[ ! -f "$LOADER_EFI" ]]; then
        fail_ "Loader binary missing: $LOADER_EFI"
        exit 1
    fi
    if [[ ! -f "$KERNEL_SIGNED" ]]; then
        fail_ "Signed kernel missing: $KERNEL_SIGNED"
        exit 1
    fi

    # Copy artifacts
    cp "$LOADER_EFI" "$FAT_ROOT/EFI/BOOT/BOOTX64.EFI"
    cp "$KERNEL_SIGNED" "$FAT_ROOT/rany_os"

    # Optional kernel cmdline injection (bootloader reads exoloader.cmdline)
    if [[ -n "$KERNEL_CMDLINE" ]]; then
        printf '%s\n' "$KERNEL_CMDLINE" > "$FAT_ROOT/exoloader.cmdline"
        done_ "Injected exoloader.cmdline"
    fi

    # Optional initramfs
    if [[ -f "$TARGET_DIR/initramfs.tar" ]]; then
        cp "$TARGET_DIR/initramfs.tar" "$FAT_ROOT/initramfs.tar"
        done_ "Included initramfs.tar"
    fi

    # [ExoRust] Deploy Cells (Drivers/Apps)
    local cells_dir="$KERNEL_TARGET_DIR/cells"
    if [[ -d "$cells_dir" ]]; then
        mkdir -p "$FAT_ROOT/cells"
        cp -r "$cells_dir/"* "$FAT_ROOT/cells/" 2>/dev/null || true
        local cell_count
        cell_count="$(find "$FAT_ROOT/cells" -type f 2>/dev/null | wc -l)"
        if [[ "$cell_count" -gt 0 ]]; then
            done_ "Deployed $cell_count Cell(s) to /cells"
        fi
    fi
}

# --- QEMU Accelerator Detection ---

get_qemu_accelerator() {
    # Force TCG if requested
    if [[ "$TCG" = true ]]; then
        warn_ "[ACCEL] TCG (forced via --tcg flag)"
        echo "tcg"
        return
    fi

    local help_out
    help_out="$(qemu-system-x86_64 -accel help 2>&1)"

    # Linux: prefer KVM > TCG
    if echo "$help_out" | grep -q "kvm"; then
        if [[ -w /dev/kvm ]]; then
            done_ "[ACCEL] KVM (Linux hardware virtualization)"
            echo "kvm"
            return
        else
            warn_ "[ACCEL] KVM listed but /dev/kvm not accessible"
        fi
    fi

    # macOS: HVF
    if echo "$help_out" | grep -q "hvf"; then
        done_ "[ACCEL] Hypervisor.framework (macOS)"
        echo "hvf"
        return
    fi

    warn_ "No hardware acceleration detected. Using TCG (Slow)."
    echo "tcg"
}

# --- Start QEMU ---

start_qemu() {
    step "Launching QEMU..."

    # Firmware setup
    local ovmf_code="$OVMF_DIR/OVMF_CODE.fd"
    local ovmf_vars_orig="$OVMF_DIR/OVMF_VARS.fd"
    local ovmf_vars_local="$KERNEL_TARGET_DIR/OVMF_VARS.fd"

    if [[ ! -f "$ovmf_code" ]]; then
        fail_ "OVMF_CODE.fd missing at $ovmf_code"
        exit 1
    fi

    # Reset UEFI variables if requested
    if [[ "$RESET_VARS" = true ]] && [[ -f "$ovmf_vars_local" ]]; then
        rm -f "$ovmf_vars_local"
        done_ "[UEFI] OVMF_VARS.fd reset to original state"
    fi
    if [[ ! -f "$ovmf_vars_local" ]]; then
        cp "$ovmf_vars_orig" "$ovmf_vars_local"
    fi

    local accel
    accel="$(get_qemu_accelerator)"

    # CPU model selection
    local cpu_model
    if [[ -n "$CPU_MODEL" ]]; then
        cpu_model="$CPU_MODEL"
    else
        case "$accel" in
            kvm|hvf) cpu_model="host" ;;
            *)       cpu_model="max" ;;
        esac
    fi
    done_ "[CPU] $cpu_model"

    # Serial config
    local serial_arg
    case "$SERIAL" in
        stdio) serial_arg="stdio" ;;
        file)  serial_arg="file:$KERNEL_TARGET_DIR/serial.log" ;;
        null)  serial_arg="null" ;;
        *)     serial_arg="stdio" ;;
    esac

    # [ExoRust] IOMMU: separate "requested" vs "active" states
    local iommu_requested=false
    local iommu_active=false
    if [[ "$IOMMU" = true ]] && [[ "$NO_IOMMU" != true ]]; then
        iommu_requested=true
        iommu_active=true
    fi

    # Machine spec: kernel-irqchip=split only when IOMMU is active
    local machine_spec
    if [[ "$iommu_active" = true ]]; then
        machine_spec="q35,kernel-irqchip=split"
    else
        machine_spec="q35"
    fi

    local qemu_args=(
        -machine "$machine_spec"
        -cpu "$cpu_model"
        -smp "$SMP"
        -m "${MEMORY}M"
        -nic none
        -serial "$serial_arg"
        -no-reboot
        -no-shutdown
        -drive "if=pflash,format=raw,readonly=on,file=$ovmf_code"
        -drive "if=pflash,format=raw,file=$ovmf_vars_local"
        -drive "file=fat:rw:$FAT_ROOT,format=raw,media=disk"
        -accel "$accel"
    )

    # [ExoRust] IOMMU (Intel VT-d) Support
    if [[ "$iommu_active" = true ]]; then
        qemu_args+=(-device "intel-iommu,intremap=on,caching-mode=on")
        done_ "[IOMMU] Intel VT-d enabled (intremap=on) [DEFAULT]"
    fi

    # [ExoRust] NUMA Topology Simulation
    local numa_requested=false
    if [[ "$NUMA" = true ]] && [[ "$NO_NUMA" != true ]]; then
        numa_requested=true
    fi
    if [[ "$numa_requested" = true ]] && [[ "$SMP" -ge 2 ]]; then
        local cores_node0=$(( SMP / 2 ))
        local mem_node0=$(( MEMORY / 2 ))
        local mem_node1=$(( MEMORY - mem_node0 ))
        qemu_args+=(
            -object "memory-backend-ram,id=mem0,size=${mem_node0}M"
            -object "memory-backend-ram,id=mem1,size=${mem_node1}M"
            -numa "node,nodeid=0,cpus=0-$(( cores_node0 - 1 )),memdev=mem0"
            -numa "node,nodeid=1,cpus=${cores_node0}-$(( SMP - 1 )),memdev=mem1"
        )
        done_ "[NUMA] 2-node topology: node0 ${cores_node0} cores ${mem_node0}MB, node1 $(( SMP - cores_node0 )) cores ${mem_node1}MB"
    fi

    # [ExoRust] VirtIO Network with IOMMU Support
    if [[ "$NETWORK" = true ]] && [[ "$NO_NETWORK" != true ]]; then
        # Keep TCP/UDP hostfwd ports distinct: some QEMU builds reject reuse.
        local netdev_args="user,id=net0,hostfwd=tcp::5555-:80,hostfwd=udp::5556-:80"
        local device_args="virtio-net-pci,netdev=net0,mq=on,vectors=10"
        if [[ "$iommu_active" = true ]]; then
            device_args+=",iommu_platform=on,disable-legacy=on"
        fi
        qemu_args+=(-netdev "$netdev_args" -device "$device_args")
        done_ "[NET] VirtIO-net enabled (hostfwd: tcp 5555->80, udp 5556->80)"
    fi

    # NVMe Device
    if [[ -n "$NVME_DEVICE" ]]; then
        if ! command -v qemu-img &>/dev/null; then
            fail_ "qemu-img not found."
            exit 1
        fi
        local nvme_path="$KERNEL_TARGET_DIR/nvme.img"
        if [[ ! -f "$nvme_path" ]]; then
            done_ "Creating NVMe disk image ($NVME_DEVICE)..."
            qemu-img create -f qcow2 "$nvme_path" "$NVME_DEVICE" &>/dev/null
        fi
        qemu_args+=(-drive "file=$nvme_path,if=none,id=nvm" -device "nvme,serial=deadbeef,drive=nvm")
        done_ "NVMe device attached ($NVME_DEVICE)"
    fi

    # Debug / Test Flags
    if [[ "$GDB_DEBUG" = true ]]; then
        qemu_args+=(-s -S)
        warn_ "GDB Stub: localhost:1234 (CPU Frozen)"
    fi

    # [ExoRust] QEMU Monitor for runtime inspection
    if [[ "$MONITOR" = true ]] || [[ "$GDB_DEBUG" = true ]]; then
        # check port to help users diagnose silent failures
        if command -v lsof &>/dev/null && lsof -iTCP:4444 -sTCP:LISTEN &>/dev/null; then
            warn_ "Port 4444 is already in use; QEMU monitor may fail to bind"
        fi
        qemu_args+=(-monitor "telnet:127.0.0.1:4444,server,nowait")
        done_ "[MONITOR] telnet localhost 4444 (info tlb, info mem, etc.)"
    fi

    if [[ "$TEST_MODE" = true ]]; then
        qemu_args+=(-device "isa-debug-exit,iobase=0xf4,iosize=0x04" -display none)
        done_ "Test mode: Headless execution"
    fi

    # Extra QEMU arguments
    if [[ ${#QEMU_EXTRA_ARGS[@]} -gt 0 ]]; then
        qemu_args+=("${QEMU_EXTRA_ARGS[@]}")
        done_ "Injected extra args: ${QEMU_EXTRA_ARGS[*]}"
    fi

    if [[ "$SERIAL" == "file" ]]; then
        done_ "Log: $KERNEL_TARGET_DIR/serial.log"
    fi

    # Run QEMU
    set +e
    qemu-system-x86_64 "${qemu_args[@]}"
    local exit_code=$?
    set -e

    # QEMU isa-debug-exit normalization
    if [[ "$TEST_MODE" = true ]]; then
        if [[ $exit_code -eq 33 ]]; then
            done_ "TEST RESULT: PASSED"
            return 0
        else
            fail_ "TEST RESULT: FAILED (Code: $exit_code)"
            return 1
        fi
    fi

    return "$exit_code"
}

# ===========================================================================
# Main Pipeline
# ===========================================================================

TOTAL_START="$(date +%s%N 2>/dev/null || date +%s)"

check_dependencies
if [[ "$CLEAN" = true ]]; then run_clean; fi

# 0. Lint (optional)
if [[ "$LINT" = true ]]; then invoke_lints; fi

# 1. Tools
build_signer
setup_keys

# 2. Compilation
build_loader
if [[ "$CARGO_RUNNER" != true ]]; then
    build_kernel
fi

# 3. Packaging
sign_kernel

# Performance Report
TOTAL_END="$(date +%s%N 2>/dev/null || date +%s)"
if [[ ${#TOTAL_START} -gt 10 ]]; then
    ELAPSED_MS=$(( (TOTAL_END - TOTAL_START) / 1000000 ))
    ELAPSED_S=$(( ELAPSED_MS / 1000 ))
    ELAPSED_FRAC=$(( ELAPSED_MS % 1000 ))
    step "Build success in ${ELAPSED_S}.$(printf '%03d' "$ELAPSED_FRAC")s"
else
    ELAPSED=$(( TOTAL_END - TOTAL_START ))
    step "Build success in ${ELAPSED}s"
fi

# 4. Execution
if [[ "$NO_RUN" != true ]]; then
    create_disk_image
    start_qemu
    exit $?
fi
