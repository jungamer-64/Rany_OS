#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Build standalone driver wrapper cells and staged PCI driver packs.

Usage:
  scripts/build_standalone_driver_packs.sh [--profile debug|release]

Outputs:
  target/x86_64-exorust/<profile>/standalone_drivers/*.raw.cell
  target/x86_64-exorust/<profile>/standalone_drivers/*.cell
EOF
}

PROFILE="debug"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --profile)
            [[ $# -ge 2 ]] || { echo "missing value for --profile" >&2; exit 1; }
            PROFILE="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "unknown argument: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

if [[ "$PROFILE" != "debug" && "$PROFILE" != "release" ]]; then
    echo "invalid profile: $PROFILE (expected debug or release)" >&2
    exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CELL_TARGET_SPEC="$ROOT_DIR/x86_64-exorust-cell.json"
CELL_TARGET_DIR_NAME="x86_64-exorust-cell"
DEPLOY_DIR="$ROOT_DIR/target/x86_64-exorust/$PROFILE/standalone_drivers"
WRAPPER_MANIFEST="$ROOT_DIR/tools/standalone_driver_wrapper/Cargo.toml"
DRIVER_PACK_BUILDER_MANIFEST="$ROOT_DIR/tools/driver_pack_builder/Cargo.toml"
STANDALONE_BUILD_TARGET_DIR="$ROOT_DIR/target/standalone_driver_build"
BUILD_PROFILE_DIR="$STANDALONE_BUILD_TARGET_DIR/$CELL_TARGET_DIR_NAME/$PROFILE"

source "$ROOT_DIR/scripts/lib_host_toolchain.sh"
configure_host_linker_env

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "required command not found: $1" >&2
        exit 1
    }
}

require_cmd cargo

for required in "$CELL_TARGET_SPEC" "$WRAPPER_MANIFEST" "$DRIVER_PACK_BUILDER_MANIFEST"; do
    [[ -f "$required" ]] || {
        echo "missing required file: $required" >&2
        exit 1
    }
done

mkdir -p "$DEPLOY_DIR"

find_cdylib() {
    local dir="$1"
    local base="$dir/libstandalone_driver_wrapper"
    local cand
    for cand in "$base.so" "$base.dylib" "$base.dll"; do
        if [[ -f "$cand" ]]; then
            printf '%s\n' "$cand"
            return 0
        fi
    done
    cand="$(
        find "$dir" "$dir/deps" -maxdepth 2 -type f -name 'libstandalone_driver_wrapper.*' 2>/dev/null \
            | head -n 1 || true
    )"
    [[ -n "$cand" ]] || return 1
    printf '%s\n' "$cand"
}

build_wrapper_cell() {
    local driver_feature="$1"
    local raw_output="$2"

    local cargo_args=(
        build
        -Zbuild-std=core,alloc
        -Zbuild-std-features=compiler-builtins-mem
        --manifest-path "$WRAPPER_MANIFEST"
        # Keep host proc-macro/build-script artifacts isolated from other builds so
        # stale linker outputs do not poison standalone cell packaging.
        --target-dir "$STANDALONE_BUILD_TARGET_DIR"
        -Zjson-target-spec
        --target "$CELL_TARGET_SPEC"
        --no-default-features
        --features "standalone,${driver_feature}"
    )

    if [[ "$PROFILE" == "release" ]]; then
        cargo_args+=("--release")
    fi

    echo "[standalone_driver_packs] building ${driver_feature} (${PROFILE})"
    (cd "$ROOT_DIR" && cargo "${cargo_args[@]}")

    local artifact
    artifact="$(find_cdylib "$BUILD_PROFILE_DIR")"
    cp "$artifact" "$DEPLOY_DIR/$raw_output"
    echo "[standalone_driver_packs] wrote $DEPLOY_DIR/$raw_output"
}

build_driver_pack() {
    local name="$1"
    local input="$2"
    local output="$3"
    shift 3

    echo "[standalone_driver_packs] packing ${name}"
    (cd "$ROOT_DIR" && cargo run --quiet --manifest-path "$DRIVER_PACK_BUILDER_MANIFEST" -- \
        --name "$name" \
        --input "$DEPLOY_DIR/$input" \
        --output "$DEPLOY_DIR/$output" \
        --driver-abi-version 2 \
        --kernel-api-min-version 4 \
        "$@")
    echo "[standalone_driver_packs] wrote $DEPLOY_DIR/$output"
}

MLX5_VENDOR_ID="0x15b3"
MLX5_DEVICE_IDS=(
    "0x1011"
    "0x1012"
    "0x1013"
    "0x1014"
    "0x1015"
    "0x1016"
    "0x1017"
    "0x1018"
    "0x1019"
    "0x101a"
    "0x101b"
    "0x101c"
    "0x101d"
    "0x101e"
    "0x101f"
    "0x1020"
    "0x1021"
    "0x1022"
)
VIRTIO_VENDOR_ID="0x1af4"
VIRTIO_DEVICE_IDS=(
    "0x1000"
    "0x1041"
    "0x1001"
    "0x1042"
    "0x1003"
    "0x1043"
    "0x1005"
    "0x1045"
    "0x1050"
    "0x1052"
)

build_wrapper_cell "driver-ahci" "ahci_driver.raw.cell"
build_driver_pack \
    "ahci_driver" \
    "ahci_driver.raw.cell" \
    "ahci_driver.cell" \
    --pci-class 0x01 \
    --pci-subclass 0x06 \
    --pci-prog-if 0x01

build_wrapper_cell "driver-nvme" "nvme_driver.raw.cell"
build_driver_pack \
    "nvme_driver" \
    "nvme_driver.raw.cell" \
    "nvme_driver.cell" \
    --pci-class 0x01 \
    --pci-subclass 0x08 \
    --pci-prog-if 0x02

build_wrapper_cell "driver-usb" "usb_xhci_driver.raw.cell"
build_driver_pack \
    "usb_xhci_driver" \
    "usb_xhci_driver.raw.cell" \
    "usb_xhci_driver.cell" \
    --pci-class 0x0c \
    --pci-subclass 0x03 \
    --pci-prog-if 0x30

build_wrapper_cell "driver-mlx5" "mlx5_driver.raw.cell"
for device_id in "${MLX5_DEVICE_IDS[@]}"; do
    normalized_id="${device_id#0x}"
    build_driver_pack \
        "mlx5_driver_${normalized_id}" \
        "mlx5_driver.raw.cell" \
        "mlx5_driver_${normalized_id}.cell" \
        --pci-vendor-id "$MLX5_VENDOR_ID" \
        --pci-device-id "$device_id"
done

build_wrapper_cell "driver-virtio" "virtio_driver.raw.cell"
for device_id in "${VIRTIO_DEVICE_IDS[@]}"; do
    normalized_id="${device_id#0x}"
    build_driver_pack \
        "virtio_driver_${normalized_id}" \
        "virtio_driver.raw.cell" \
        "virtio_driver_${normalized_id}.cell" \
        --pci-vendor-id "$VIRTIO_VENDOR_ID" \
        --pci-device-id "$device_id"
done

echo "[standalone_driver_packs] generated packs in $DEPLOY_DIR"
