#!/usr/bin/env bash
set -euo pipefail

SYSROOT="$(rustc --print sysroot)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
HOST_LIB_DIR="/usr/lib/x86_64-linux-gnu"
HOST_RUNTIME_LIB_DIR="/lib/x86_64-linux-gnu"
HOST_LINK_LIB_DIR="${EXORUST_HOST_LINK_LIB_DIR:-$REPO_ROOT/target/host_linker_shims/lib}"
RUST_LLD="${EXORUST_HOST_RUST_LLD:-$SYSROOT/lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld}"

if [[ ! -d "$HOST_LINK_LIB_DIR" ]]; then
    echo "ERROR: host_linker_wrapper.sh requires the shim directory: $HOST_LINK_LIB_DIR" >&2
    exit 1
fi

BASE_ARGS=(-flavor gnu)
ARGS=()
COMMON_LIB_ARGS=(
    "-L$HOST_LIB_DIR"
    "-L$HOST_RUNTIME_LIB_DIR"
    "-L$HOST_LINK_LIB_DIR"
)

next_is_output=0
is_shared_link=0
for arg in "$@"; do
    if [[ "$next_is_output" == 1 ]]; then
        ARGS+=("$arg")
        next_is_output=0
        continue
    fi

    case "$arg" in
        -o)
            ARGS+=("$arg")
            next_is_output=1
            ;;
        -shared)
            is_shared_link=1
            ARGS+=("$arg")
            ;;
        -m64|-nodefaultlibs|-fuse-ld=*)
            ;;
        -B*)
            # rustc adds a self-contained linker search path here; raw lld does not understand it.
            ;;
        -Wl,*)
            IFS=',' read -r -a wl_parts <<< "$arg"
            for ((i = 1; i < ${#wl_parts[@]}; i++)); do
                [[ -n "${wl_parts[i]}" ]] && ARGS+=("${wl_parts[i]}")
            done
            ;;
        *)
            ARGS+=("$arg")
            ;;
    esac
done

PREFIX_ARGS=("${COMMON_LIB_ARGS[@]}")
SUFFIX_ARGS=()

if [[ "$is_shared_link" == 0 ]]; then
    PREFIX_ARGS=(
        "$HOST_LIB_DIR/Scrt1.o"
        "$HOST_LIB_DIR/crti.o"
        "${PREFIX_ARGS[@]}"
        --dynamic-linker=/lib64/ld-linux-x86-64.so.2
    )
    SUFFIX_ARGS+=("$HOST_LIB_DIR/crtn.o")
fi

exec "$RUST_LLD" "${BASE_ARGS[@]}" "${PREFIX_ARGS[@]}" "${ARGS[@]}" "${SUFFIX_ARGS[@]}"
