#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Build DriverCell probe fixture cells (v1/v2), deploy them to /cells staging, and generate target/initramfs.tar.

Usage:
  scripts/build_driver_cell_probe_fixtures.sh [--profile debug|release]

Outputs:
  target/initramfs.tar
  target/x86_64-exorust/<profile>/cells/driver_cell_probe_v1.cell
  target/x86_64-exorust/<profile>/cells/driver_cell_probe_v2.cell
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
BUILD_PROFILE_DIR="$ROOT_DIR/target/$CELL_TARGET_DIR_NAME/$PROFILE"
DEPLOY_DIR="$ROOT_DIR/target/x86_64-exorust/$PROFILE/cells"
INITRAMFS_PATH="$ROOT_DIR/target/initramfs.tar"

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "required command not found: $1" >&2
        exit 1
    }
}

require_cmd cargo
require_cmd tar

if [[ ! -f "$CELL_TARGET_SPEC" ]]; then
    echo "missing target spec: $CELL_TARGET_SPEC" >&2
    exit 1
fi

find_cdylib() {
    local dir="$1"
    local base="$dir/libdriver_cell_probe"
    local cand
    for cand in "$base.so" "$base.dylib" "$base.dll"; do
        if [[ -f "$cand" ]]; then
            printf '%s\n' "$cand"
            return 0
        fi
    done
    cand="$(
        find "$dir" "$dir/deps" -maxdepth 2 -type f -name 'libdriver_cell_probe.*' 2>/dev/null \
            | head -n 1 || true
    )"
    [[ -n "$cand" ]] || return 1
    printf '%s\n' "$cand"
}

build_variant() {
    local variant="$1"    # variant_v1 / variant_v2
    local out_name="$2"   # driver_cell_probe_v1.cell / driver_cell_probe_v2.cell

    local cargo_args=(
        rustc
        -Zbuild-std=core,alloc
        -Zbuild-std-features=compiler-builtins-mem
        -Zjson-target-spec
        -p driver_cell_probe
        --target "$CELL_TARGET_SPEC"
        --features "standalone,${variant}"
        --
        --crate-type cdylib
    )
    if [[ "$PROFILE" == "release" ]]; then
        cargo_args=(
            rustc
            -Zbuild-std=core,alloc
            -Zbuild-std-features=compiler-builtins-mem
            -Zjson-target-spec
            -p driver_cell_probe
            --target "$CELL_TARGET_SPEC"
            --release
            --features "standalone,${variant}"
            --
            --crate-type cdylib
        )
    fi

    echo "[driver_cell_probe_fixtures] building ${variant} (${PROFILE})"
    (cd "$ROOT_DIR" && cargo "${cargo_args[@]}")

    mkdir -p "$DEPLOY_DIR"
    local artifact
    artifact="$(find_cdylib "$BUILD_PROFILE_DIR")"
    cp "$artifact" "$DEPLOY_DIR/$out_name"
    echo "[driver_cell_probe_fixtures] wrote $DEPLOY_DIR/$out_name"
}

build_variant "variant_v1" "driver_cell_probe_v1.cell"
build_variant "variant_v2" "driver_cell_probe_v2.cell"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

mkdir -p "$tmp_dir/drivers"
mkdir -p "$tmp_dir/cells"
cp "$DEPLOY_DIR/driver_cell_probe_v1.cell" "$tmp_dir/drivers/driver_cell_probe.cell"
cp "$DEPLOY_DIR/driver_cell_probe_v1.cell" "$tmp_dir/cells/driver_cell_probe_v1.cell"
cp "$DEPLOY_DIR/driver_cell_probe_v2.cell" "$tmp_dir/cells/driver_cell_probe_v2.cell"
rm -f "$INITRAMFS_PATH"
(cd "$tmp_dir" && tar -cf "$INITRAMFS_PATH" \
    drivers/driver_cell_probe.cell \
    cells/driver_cell_probe_v1.cell \
    cells/driver_cell_probe_v2.cell)

echo "[driver_cell_probe_fixtures] wrote $INITRAMFS_PATH"
echo "[driver_cell_probe_fixtures] run.sh will auto-deploy:"
echo "  - $INITRAMFS_PATH -> /initramfs.tar"
echo "  - $DEPLOY_DIR/* -> /cells/*"
echo "[driver_cell_probe_fixtures] build target spec: $CELL_TARGET_SPEC"
