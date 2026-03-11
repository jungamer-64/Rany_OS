#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Build the runtime boot-artifact directory used by standalone PCI driver profiles.

Usage:
  scripts/build_runtime_boot_artifacts.sh [--profile debug|release]

Outputs:
  target/x86_64-exorust/<profile>/boot_artifacts/drivers/*.cell
  target/x86_64-exorust/<profile>/boot_artifacts/cells/*.cell
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
PROBE_CELLS_DIR="$ROOT_DIR/target/x86_64-exorust/$PROFILE/cells"
STANDALONE_DIR="$ROOT_DIR/target/x86_64-exorust/$PROFILE/standalone_drivers"
BOOT_ARTIFACTS_DIR="$ROOT_DIR/target/x86_64-exorust/$PROFILE/boot_artifacts"

(cd "$ROOT_DIR" && bash scripts/build_driver_cell_probe_fixtures.sh --profile "$PROFILE")
(cd "$ROOT_DIR" && bash scripts/build_standalone_driver_packs.sh --profile "$PROFILE")

rm -rf "$BOOT_ARTIFACTS_DIR"
mkdir -p "$BOOT_ARTIFACTS_DIR/drivers" "$BOOT_ARTIFACTS_DIR/cells"

cp "$PROBE_CELLS_DIR/driver_cell_probe_v1.cell" \
    "$BOOT_ARTIFACTS_DIR/drivers/driver_cell_probe.cell"
cp "$PROBE_CELLS_DIR/driver_cell_probe_pci.cell" \
    "$BOOT_ARTIFACTS_DIR/drivers/driver_cell_probe_pci.cell"
cp "$PROBE_CELLS_DIR/driver_cell_probe_v1.cell" \
    "$BOOT_ARTIFACTS_DIR/cells/driver_cell_probe_v1.cell"
cp "$PROBE_CELLS_DIR/driver_cell_probe_v2.cell" \
    "$BOOT_ARTIFACTS_DIR/cells/driver_cell_probe_v2.cell"

find "$STANDALONE_DIR" -maxdepth 1 -type f -name '*.cell' ! -name '*.raw.cell' -print0 | \
    while IFS= read -r -d '' pack; do
        cp "$pack" "$BOOT_ARTIFACTS_DIR/drivers/$(basename "$pack")"
    done

echo "[runtime_boot_artifacts] wrote $BOOT_ARTIFACTS_DIR"
