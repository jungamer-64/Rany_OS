#!/usr/bin/env bash
set -euo pipefail

# Validates that Wave7 MM deterministic exports stay wired into suite_kernel.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ASYNC_EXPORT_FILE="$ROOT_DIR/kernel/src/mm/async_swapout/qemu_tests.rs"
RECLAIM_EXPORT_FILE="$ROOT_DIR/kernel/src/mm/page_reclaim/qemu_tests.rs"
KERNEL_WRAPPER_FILE="$ROOT_DIR/kernel/src/qemu_tests.rs"
KERNEL_SUITE_FILE="$ROOT_DIR/qemu-suites/kernel/src/main.rs"
PENDING_FILE="$ROOT_DIR/scripts/qemu_pending_cases.lst"

for required_file in \
  "$ASYNC_EXPORT_FILE" \
  "$RECLAIM_EXPORT_FILE" \
  "$KERNEL_WRAPPER_FILE" \
  "$KERNEL_SUITE_FILE" \
  "$PENDING_FILE"
do
  if [[ ! -f "$required_file" ]]; then
    echo "[verify_mm_wave7_required] missing file: $required_file" >&2
    exit 1
  fi
done

async_cases=(
  "buffer_pool_4k_basic"
  "buffer_pool_2m_basic"
)

reclaim_cases=(
  "watermarks_calculation"
  "pressure_level"
  "mglru_list_add"
  "blocked_unsafe_requeues_victim"
  "blocked_unsafe_requeues_anonymous_dirty_victim"
  "file_backed_clean_reclaims_with_unsafe_disabled"
  "async_success_clears_pending_and_accounts_success"
  "async_failure_requeues_and_clears_pending"
)

violations=0

if ! rg -q "mm_wave7_async_swapout_exports" "$KERNEL_SUITE_FILE"; then
  echo "[verify_mm_wave7_required] missing mm_wave7_async_swapout_exports in ${KERNEL_SUITE_FILE#$ROOT_DIR/}"
  violations=$((violations + 1))
fi

if ! rg -q "mm_wave7_page_reclaim_exports" "$KERNEL_SUITE_FILE"; then
  echo "[verify_mm_wave7_required] missing mm_wave7_page_reclaim_exports in ${KERNEL_SUITE_FILE#$ROOT_DIR/}"
  violations=$((violations + 1))
fi

for case_name in "${async_cases[@]}"; do
  export_fn="wave7_${case_name}_smoke"
  wrapper_fn="mm_wave7_${case_name}_smoke"

  if ! rg -q "pub fn ${export_fn}\\(" "$ASYNC_EXPORT_FILE"; then
    echo "[verify_mm_wave7_required] missing async export '${export_fn}' in ${ASYNC_EXPORT_FILE#$ROOT_DIR/}"
    violations=$((violations + 1))
  fi

  if ! rg -q "pub fn ${wrapper_fn}\\(" "$KERNEL_WRAPPER_FILE"; then
    echo "[verify_mm_wave7_required] missing wrapper '${wrapper_fn}' in ${KERNEL_WRAPPER_FILE#$ROOT_DIR/}"
    violations=$((violations + 1))
  fi

  if ! rg -q "${wrapper_fn}" "$KERNEL_SUITE_FILE"; then
    echo "[verify_mm_wave7_required] missing suite wiring '${wrapper_fn}' in ${KERNEL_SUITE_FILE#$ROOT_DIR/}"
    violations=$((violations + 1))
  fi

  if rg -q "${case_name}" "$PENDING_FILE"; then
    echo "[verify_mm_wave7_required] promoted case '${case_name}' still listed in ${PENDING_FILE#$ROOT_DIR/}"
    violations=$((violations + 1))
  fi
done

for case_name in "${reclaim_cases[@]}"; do
  export_fn="wave7_${case_name}_smoke"
  wrapper_fn="mm_wave7_${case_name}_smoke"

  if ! rg -q "pub fn ${export_fn}\\(" "$RECLAIM_EXPORT_FILE"; then
    echo "[verify_mm_wave7_required] missing reclaim export '${export_fn}' in ${RECLAIM_EXPORT_FILE#$ROOT_DIR/}"
    violations=$((violations + 1))
  fi

  if ! rg -q "pub fn ${wrapper_fn}\\(" "$KERNEL_WRAPPER_FILE"; then
    echo "[verify_mm_wave7_required] missing wrapper '${wrapper_fn}' in ${KERNEL_WRAPPER_FILE#$ROOT_DIR/}"
    violations=$((violations + 1))
  fi

  if ! rg -q "${wrapper_fn}" "$KERNEL_SUITE_FILE"; then
    echo "[verify_mm_wave7_required] missing suite wiring '${wrapper_fn}' in ${KERNEL_SUITE_FILE#$ROOT_DIR/}"
    violations=$((violations + 1))
  fi

  if rg -q "${case_name}" "$PENDING_FILE"; then
    echo "[verify_mm_wave7_required] promoted case '${case_name}' still listed in ${PENDING_FILE#$ROOT_DIR/}"
    violations=$((violations + 1))
  fi
done

if ! rg -q "MM Wave7 Phase A deterministic set is promoted to required suite_kernel" "$PENDING_FILE"; then
  echo "[verify_mm_wave7_required] missing Wave7 marker in ${PENDING_FILE#$ROOT_DIR/}"
  violations=$((violations + 1))
fi

if [[ "$violations" -gt 0 ]]; then
  echo "[verify_mm_wave7_required] FAIL: found $violations issues"
  exit 1
fi

echo "[verify_mm_wave7_required] PASS"
