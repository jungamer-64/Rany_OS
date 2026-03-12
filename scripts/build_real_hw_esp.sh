#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Build an Intel-first real-hardware UEFI ESP payload.

Usage:
  scripts/build_real_hw_esp.sh [--profile debug|release] [--image [path]] [--usb-mount <path>]

Outputs:
  target/x86_64-exorust/<profile>/real_hw/esp_root/
  target/x86_64-exorust/<profile>/real_hw/exorust-esp.img   (when --image is used)

Notes:
  - The default kernel cmdline is fixed to: loglevel=info shell=console
  - If runtime boot artifacts are available they are copied into /drivers and /cells
  - If --usb-mount is supplied, the prepared ESP tree is mirrored to that mount point
EOF
}

require_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "missing required command: $1" >&2
        exit 1
    fi
}

copy_tree_contents() {
    local src="$1"
    local dst="$2"
    if command -v rsync >/dev/null 2>&1; then
        rsync -a --delete "$src"/ "$dst"/
    else
        rm -rf "$dst"
        mkdir -p "$dst"
        cp -a "$src"/. "$dst"/
    fi
}

PROFILE="debug"
MAKE_PROFILE="debug"
IMAGE_MODE=0
IMAGE_PATH=""
USB_MOUNT=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --profile)
            [[ $# -ge 2 ]] || { echo "missing value for --profile" >&2; exit 1; }
            PROFILE="$2"
            MAKE_PROFILE="$2"
            shift 2
            ;;
        --image)
            IMAGE_MODE=1
            if [[ $# -ge 2 && "${2:-}" != --* ]]; then
                IMAGE_PATH="$2"
                shift 2
            else
                shift
            fi
            ;;
        --usb-mount)
            [[ $# -ge 2 ]] || { echo "missing value for --usb-mount" >&2; exit 1; }
            USB_MOUNT="$2"
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
BUILD_DIR="$ROOT_DIR/target/x86_64-exorust/$PROFILE"
REAL_HW_DIR="$BUILD_DIR/real_hw"
ESP_ROOT="$REAL_HW_DIR/esp_root"
DEFAULT_IMAGE="$REAL_HW_DIR/exorust-esp.img"
IMAGE_PATH="${IMAGE_PATH:-$DEFAULT_IMAGE}"

require_cmd make

mkdir -p "$REAL_HW_DIR"

if [[ -x "$ROOT_DIR/scripts/build_runtime_boot_artifacts.sh" ]]; then
    (cd "$ROOT_DIR" && bash scripts/build_runtime_boot_artifacts.sh --profile "$PROFILE")
fi

(cd "$ROOT_DIR" && make image PROFILE="$MAKE_PROFILE" CMDLINE="loglevel=info shell=console")

FAT_ROOT="$BUILD_DIR/fat_root"
LOADER_CFG_SRC="$ROOT_DIR/assets/exoloader.cfg.example"
CMDLINE_FILE="$ESP_ROOT/exoloader.cmdline"
LOADER_CFG_FILE="$ESP_ROOT/exoloader.cfg"

rm -rf "$ESP_ROOT"
mkdir -p "$ESP_ROOT"
copy_tree_contents "$FAT_ROOT" "$ESP_ROOT"

cp "$LOADER_CFG_SRC" "$LOADER_CFG_FILE"
printf '%s\n' 'loglevel=info shell=console' > "$CMDLINE_FILE"

echo "[real-hw-esp] wrote $ESP_ROOT"

if [[ "$IMAGE_MODE" -eq 1 ]]; then
    require_cmd dd
    require_cmd mkfs.vfat
    if command -v mcopy >/dev/null 2>&1; then
        rm -f "$IMAGE_PATH"
        dd if=/dev/zero of="$IMAGE_PATH" bs=1M count=64 status=none
        mkfs.vfat -F 32 "$IMAGE_PATH" >/dev/null
        mmd -i "$IMAGE_PATH" ::/EFI ::/EFI/BOOT >/dev/null 2>&1 || true
        mcopy -i "$IMAGE_PATH" -spmn "$ESP_ROOT"/* ::/
        echo "[real-hw-esp] wrote FAT image $IMAGE_PATH"
    else
        echo "mcopy not found; skipping FAT image creation for $IMAGE_PATH" >&2
    fi
fi

if [[ -n "$USB_MOUNT" ]]; then
    mkdir -p "$USB_MOUNT"
    copy_tree_contents "$ESP_ROOT" "$USB_MOUNT"
    sync
    echo "[real-hw-esp] mirrored ESP contents to $USB_MOUNT"
fi
