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

reclaim_phase_b_cases=(
  "file_backed_dirty_reclaims_on_writeback_success_with_unsafe_disabled"
  "file_backed_dirty_requeues_on_writeback_failure_with_unsafe_disabled"
  "file_backed_dirty_without_backing_requeues_with_unsafe_disabled"
  "notsupported_anonymous_dirty_requeues_without_writeback_skipped"
  "notsupported_file_dirty_falls_back_without_writeback_skipped_on_success"
  "notsupported_file_dirty_requeues_and_counts_writeback_skipped_on_failure"
)

reclaim_phase_c_cases=(
  "already_pending_does_not_count_writeback_skipped"
  "already_pending_without_registered_pending_requeues"
  "already_pending_without_registered_pending_requeues_once_in_direct_reclaim"
  "queuefull_does_not_count_writeback_skipped"
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

if ! rg -q "mm_wave7_page_reclaim_phase_b_exports" "$KERNEL_SUITE_FILE"; then
  echo "[verify_mm_wave7_required] missing mm_wave7_page_reclaim_phase_b_exports in ${KERNEL_SUITE_FILE#$ROOT_DIR/}"
  violations=$((violations + 1))
fi

if ! rg -q "mm_wave7_page_reclaim_phase_c_exports" "$KERNEL_SUITE_FILE"; then
  echo "[verify_mm_wave7_required] missing mm_wave7_page_reclaim_phase_c_exports in ${KERNEL_SUITE_FILE#$ROOT_DIR/}"
  violations=$((violations + 1))
fi

if ! rg -q "pub fn qemu_test_set_enqueue_override\\(" "$ROOT_DIR/kernel/src/mm/async_swapout.rs"; then
  echo "[verify_mm_wave7_required] missing qemu enqueue hook in kernel/src/mm/async_swapout.rs"
  violations=$((violations + 1))
fi

if ! rg -q "pub fn qemu_test_clear_enqueue_override\\(" "$ROOT_DIR/kernel/src/mm/async_swapout.rs"; then
  echo "[verify_mm_wave7_required] missing qemu enqueue clear hook in kernel/src/mm/async_swapout.rs"
  violations=$((violations + 1))
fi

if ! rg -q "pub fn qemu_test_set_sync_page_writeback_override\\(" "$ROOT_DIR/kernel/src/mm/page_reclaim.rs"; then
  echo "[verify_mm_wave7_required] missing qemu page writeback hook in kernel/src/mm/page_reclaim.rs"
  violations=$((violations + 1))
fi

if ! rg -q "pub fn qemu_test_set_sync_all_writeback_override\\(" "$ROOT_DIR/kernel/src/mm/page_reclaim.rs"; then
  echo "[verify_mm_wave7_required] missing qemu all-writeback hook in kernel/src/mm/page_reclaim.rs"
  violations=$((violations + 1))
fi

if ! rg -q "pub fn qemu_test_clear_writeback_overrides\\(" "$ROOT_DIR/kernel/src/mm/page_reclaim.rs"; then
  echo "[verify_mm_wave7_required] missing qemu writeback clear hook in kernel/src/mm/page_reclaim.rs"
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

for case_name in "${reclaim_phase_c_cases[@]}"; do
  export_fn="wave7_${case_name}_smoke"
  wrapper_fn="mm_wave7_${case_name}_smoke"

  if ! rg -q "pub fn ${export_fn}\\(" "$RECLAIM_EXPORT_FILE"; then
    echo "[verify_mm_wave7_required] missing reclaim phase-c export '${export_fn}' in ${RECLAIM_EXPORT_FILE#$ROOT_DIR/}"
    violations=$((violations + 1))
  fi

  if ! rg -q "pub fn ${wrapper_fn}\\(" "$KERNEL_WRAPPER_FILE"; then
    echo "[verify_mm_wave7_required] missing phase-c wrapper '${wrapper_fn}' in ${KERNEL_WRAPPER_FILE#$ROOT_DIR/}"
    violations=$((violations + 1))
  fi

  if ! rg -q "${wrapper_fn}" "$KERNEL_SUITE_FILE"; then
    echo "[verify_mm_wave7_required] missing phase-c suite wiring '${wrapper_fn}' in ${KERNEL_SUITE_FILE#$ROOT_DIR/}"
    violations=$((violations + 1))
  fi

  if rg -q "${case_name}" "$PENDING_FILE"; then
    echo "[verify_mm_wave7_required] promoted phase-c case '${case_name}' still listed in ${PENDING_FILE#$ROOT_DIR/}"
    violations=$((violations + 1))
  fi
done

for case_name in "${reclaim_phase_b_cases[@]}"; do
  export_fn="wave7_${case_name}_smoke"
  wrapper_fn="mm_wave7_${case_name}_smoke"

  if ! rg -q "pub fn ${export_fn}\\(" "$RECLAIM_EXPORT_FILE"; then
    echo "[verify_mm_wave7_required] missing reclaim phase-b export '${export_fn}' in ${RECLAIM_EXPORT_FILE#$ROOT_DIR/}"
    violations=$((violations + 1))
  fi

  if ! rg -q "pub fn ${wrapper_fn}\\(" "$KERNEL_WRAPPER_FILE"; then
    echo "[verify_mm_wave7_required] missing phase-b wrapper '${wrapper_fn}' in ${KERNEL_WRAPPER_FILE#$ROOT_DIR/}"
    violations=$((violations + 1))
  fi

  if ! rg -q "${wrapper_fn}" "$KERNEL_SUITE_FILE"; then
    echo "[verify_mm_wave7_required] missing phase-b suite wiring '${wrapper_fn}' in ${KERNEL_SUITE_FILE#$ROOT_DIR/}"
    violations=$((violations + 1))
  fi

  if rg -q "${case_name}" "$PENDING_FILE"; then
    echo "[verify_mm_wave7_required] promoted phase-b case '${case_name}' still listed in ${PENDING_FILE#$ROOT_DIR/}"
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

if ! rg -q "MM Wave7 Phase B deterministic set is promoted to required suite_kernel" "$PENDING_FILE"; then
  echo "[verify_mm_wave7_required] missing Wave7 phase-b marker in ${PENDING_FILE#$ROOT_DIR/}"
  violations=$((violations + 1))
fi

if ! rg -q "MM Wave7 Phase C deterministic set is promoted to required suite_kernel" "$PENDING_FILE"; then
  echo "[verify_mm_wave7_required] missing Wave7 phase-c marker in ${PENDING_FILE#$ROOT_DIR/}"
  violations=$((violations + 1))
fi

if [[ "$violations" -gt 0 ]]; then
  echo "[verify_mm_wave7_required] FAIL: found $violations issues"
  exit 1
fi

echo "[verify_mm_wave7_required] PASS"
