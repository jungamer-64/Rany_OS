#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_DIR="$ROOT_DIR/target/qemu-logs"

mkdir -p "$LOG_DIR"

run_and_check() {
  local name="$1"
  shift

  local log_path="$LOG_DIR/warning-check-${name}.log"

  echo "[verify_qemu_official_warning_free] run ${name}: $*"
  if ! (
    cd "$ROOT_DIR"
    "$@" 2>&1 | tee "$log_path"
  ); then
    echo "[verify_qemu_official_warning_free] command failed for '${name}'" >&2
    echo "[verify_qemu_official_warning_free] log: ${log_path}" >&2
    exit 1
  fi

  if rg -n "^warning:" "$log_path" >/dev/null; then
    echo "[verify_qemu_official_warning_free] compiler warnings detected for '${name}'" >&2
    rg -n "^warning:" "$log_path" >&2
    echo "[verify_qemu_official_warning_free] log: ${log_path}" >&2
    exit 1
  fi
}

run_and_check "suite-kernel" cargo test -p qemu-tests -- --nocapture suite_kernel
run_and_check "suite-drivers" cargo test -p qemu-tests -- --nocapture suite_drivers
run_and_check "cargo-test" cargo test

echo "[verify_qemu_official_warning_free] PASS"
