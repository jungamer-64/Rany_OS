#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Build DriverCell probe fixture cells (v1/v2) and deploy them to /cells staging.

Usage:
  scripts/build_driver_cell_probe_fixtures.sh [--profile debug|release]

Outputs:
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
CELL_PROBE_MANIFEST="$ROOT_DIR/tools/driver_cell_probe/Cargo.toml"
DRIVER_PACK_BUILDER_MANIFEST="$ROOT_DIR/tools/driver_pack_builder/Cargo.toml"

source "$ROOT_DIR/scripts/lib_host_toolchain.sh"
configure_host_linker_env

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "required command not found: $1" >&2
        exit 1
    }
}

require_cmd cargo

if [[ ! -f "$CELL_TARGET_SPEC" ]]; then
    echo "missing target spec: $CELL_TARGET_SPEC" >&2
    exit 1
fi

if [[ ! -f "$CELL_PROBE_MANIFEST" ]]; then
    echo "missing driver_cell_probe manifest: $CELL_PROBE_MANIFEST" >&2
    exit 1
fi

if [[ ! -f "$DRIVER_PACK_BUILDER_MANIFEST" ]]; then
    echo "missing driver_pack_builder manifest: $DRIVER_PACK_BUILDER_MANIFEST" >&2
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
        build
        -Zbuild-std=core,alloc
        -Zbuild-std-features=compiler-builtins-mem
        --manifest-path "$CELL_PROBE_MANIFEST"
        --target-dir "$ROOT_DIR/target"
        -Zjson-target-spec
        --target "$CELL_TARGET_SPEC"
        --features "standalone,${variant}"
    )
    if [[ "$PROFILE" == "release" ]]; then
        cargo_args=(
            build
            -Zbuild-std=core,alloc
            -Zbuild-std-features=compiler-builtins-mem
            --manifest-path "$CELL_PROBE_MANIFEST"
            --target-dir "$ROOT_DIR/target"
            -Zjson-target-spec
            --target "$CELL_TARGET_SPEC"
            --release
            --features "standalone,${variant}"
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

echo "[driver_cell_probe_fixtures] building staged PCI probe pack"
(cd "$ROOT_DIR" && cargo run --quiet --manifest-path "$DRIVER_PACK_BUILDER_MANIFEST" -- \
    --name driver_cell_probe_pci \
    --input "$DEPLOY_DIR/driver_cell_probe_v1.cell" \
    --output "$DEPLOY_DIR/driver_cell_probe_pci.cell" \
    --driver-abi-version 2 \
    --kernel-api-min-version 3 \
    --pci-class 0x04 \
    --pci-subclass 0x03 \
    --pci-prog-if 0x00)
echo "[driver_cell_probe_fixtures] wrote $DEPLOY_DIR/driver_cell_probe_pci.cell"
echo "[driver_cell_probe_fixtures] run.sh will auto-deploy:"
echo "  - $DEPLOY_DIR/* -> /cells/*"
echo "[driver_cell_probe_fixtures] build target spec: $CELL_TARGET_SPEC"
