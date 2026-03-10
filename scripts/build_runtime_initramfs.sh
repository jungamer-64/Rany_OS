#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Build the merged runtime initramfs used by standalone PCI driver profiles.

Usage:
  scripts/build_runtime_initramfs.sh [--profile debug|release]

Outputs:
  target/initramfs.tar
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
INITRAMFS_PATH="$ROOT_DIR/target/initramfs.tar"
PROBE_CELLS_DIR="$ROOT_DIR/target/x86_64-exorust/$PROFILE/cells"
STANDALONE_DIR="$ROOT_DIR/target/x86_64-exorust/$PROFILE/standalone_drivers"

command -v bash >/dev/null 2>&1 || {
    echo "required command not found: bash" >&2
    exit 1
}
command -v tar >/dev/null 2>&1 || {
    echo "required command not found: tar" >&2
    exit 1
}

(cd "$ROOT_DIR" && bash scripts/build_driver_cell_probe_fixtures.sh --profile "$PROFILE")
(cd "$ROOT_DIR" && bash scripts/build_standalone_driver_packs.sh --profile "$PROFILE")

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
mkdir -p "$tmp_dir/drivers" "$tmp_dir/cells"

cp "$PROBE_CELLS_DIR/driver_cell_probe_v1.cell" "$tmp_dir/drivers/driver_cell_probe.cell"
cp "$PROBE_CELLS_DIR/driver_cell_probe_pci.cell" "$tmp_dir/drivers/driver_cell_probe_pci.cell"
cp "$PROBE_CELLS_DIR/driver_cell_probe_v1.cell" "$tmp_dir/cells/driver_cell_probe_v1.cell"
cp "$PROBE_CELLS_DIR/driver_cell_probe_v2.cell" "$tmp_dir/cells/driver_cell_probe_v2.cell"

find "$STANDALONE_DIR" -maxdepth 1 -type f -name '*.cell' ! -name '*.raw.cell' -print0 | \
    while IFS= read -r -d '' pack; do
        cp "$pack" "$tmp_dir/drivers/$(basename "$pack")"
    done

rm -f "$INITRAMFS_PATH"
(cd "$tmp_dir" && tar -cf "$INITRAMFS_PATH" drivers cells)

echo "[runtime_initramfs] wrote $INITRAMFS_PATH"
