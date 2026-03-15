#!/usr/bin/env bash

host_target_triple() {
    rustc -vV | sed -n 's/^host: //p'
}

target_env_key() {
    local value="$1"
    value="${value^^}"
    value="${value//-/_}"
    value="${value//./_}"
    printf '%s' "$value"
}

select_host_cc_or_die() {
    if [[ -n "${EXORUST_HOST_CC:-}" ]]; then
        if command -v "$EXORUST_HOST_CC" >/dev/null 2>&1; then
            printf '%s' "$EXORUST_HOST_CC"
            return 0
        fi
        echo "ERROR: EXORUST_HOST_CC points to an unavailable compiler: $EXORUST_HOST_CC" >&2
        return 1
    fi

    if command -v cc >/dev/null 2>&1; then
        printf '%s' "cc"
        return 0
    fi

    if command -v clang >/dev/null 2>&1; then
        printf '%s' "clang"
        return 0
    fi

    if configure_host_linker_wrapper; then
        printf '%s' "$EXORUST_HOST_LINKER"
        return 0
    fi

    echo "ERROR: missing host C toolchain. Install 'cc' or 'clang' to build runtime boot artifacts." >&2
    return 1
}

configure_host_linker_wrapper() {
    local root_dir
    local wrapper
    local shim_dir
    local link_dir
    local libgcc_src

    root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    wrapper="$root_dir/scripts/host_linker_wrapper.sh"
    shim_dir="$root_dir/target/host_linker_shims"
    link_dir="$shim_dir/lib"

    [[ -x "$wrapper" ]] || return 1
    [[ -f /usr/lib/x86_64-linux-gnu/Scrt1.o ]] || return 1
    [[ -f /usr/lib/x86_64-linux-gnu/crti.o ]] || return 1
    [[ -f /usr/lib/x86_64-linux-gnu/crtn.o ]] || return 1
    [[ -f /usr/lib/x86_64-linux-gnu/libc.so ]] || return 1

    libgcc_src=""
    if [[ -f /usr/lib/x86_64-linux-gnu/libgcc_s.so.1 ]]; then
        libgcc_src="/usr/lib/x86_64-linux-gnu/libgcc_s.so.1"
    elif [[ -f /lib/x86_64-linux-gnu/libgcc_s.so.1 ]]; then
        libgcc_src="/lib/x86_64-linux-gnu/libgcc_s.so.1"
    fi
    [[ -n "$libgcc_src" ]] || return 1

    mkdir -p "$link_dir"
    ln -sf "$libgcc_src" "$link_dir/libgcc_s.so"

    export EXORUST_HOST_LINK_LIB_DIR="$link_dir"
    export EXORUST_HOST_RUST_LLD="$(rustc --print sysroot)/lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld"
    export EXORUST_HOST_LINKER="$wrapper"
    return 0
}

configure_host_linker_env() {
    local host_linker="${1:-}"
    local host_target
    local linker_var

    if [[ -z "$host_linker" ]]; then
        host_linker="$(select_host_cc_or_die)" || return 1
    fi

    host_target="$(host_target_triple)"
    if [[ -z "$host_target" ]]; then
        echo "ERROR: unable to determine the Rust host target via 'rustc -vV'." >&2
        return 1
    fi

    export EXORUST_HOST_LINKER="$host_linker"
    if [[ "$host_linker" == "cc" || "$host_linker" == "clang" || "$host_linker" == "gcc" ]]; then
        export EXORUST_HOST_CC="$host_linker"
        export CC="$host_linker"
    fi

    linker_var="CARGO_TARGET_$(target_env_key "$host_target")_LINKER"
    printf -v "$linker_var" '%s' "$host_linker"
    export "$linker_var"

    if [[ "${EXORUST_HOST_TOOLCHAIN_ANNOUNCED:-0}" != "1" ]]; then
        echo "[host-toolchain] using host linker '$host_linker' for $host_target"
        export EXORUST_HOST_TOOLCHAIN_ANNOUNCED=1
    fi
}
