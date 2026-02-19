#!/usr/bin/env bash
set -euo pipefail

# Validates that Wave7 MM deterministic exports stay wired into suite_kernel.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ASYNC_EXPORT_ROOT="$ROOT_DIR/kernel/src/mm/reclaim/async_swapout"
ASYNC_EXPORT_FILE="$ROOT_DIR/kernel/src/mm/reclaim/async_swapout/qemu_tests.rs"
ASYNC_WORKER_ROOT="$ROOT_DIR/kernel/src/mm/reclaim/async_swapout/worker"
RECLAIM_EXPORT_ROOT="$ROOT_DIR/kernel/src/mm/reclaim/page_reclaim"
RECLAIM_EXPORT_FILE="$ROOT_DIR/kernel/src/mm/reclaim/page_reclaim/qemu_tests.rs"
KERNEL_WRAPPER_FILE="$ROOT_DIR/kernel/src/qemu_tests.rs"
KERNEL_SUITE_ROOT="$ROOT_DIR/qemu-suites/kernel/src"
PENDING_FILE="$ROOT_DIR/scripts/qemu_pending_cases.lst"

for required_file in \
  "$ASYNC_EXPORT_ROOT" \
  "$ASYNC_EXPORT_FILE" \
  "$ASYNC_WORKER_ROOT" \
  "$RECLAIM_EXPORT_ROOT" \
  "$RECLAIM_EXPORT_FILE" \
  "$KERNEL_WRAPPER_FILE" \
  "$KERNEL_SUITE_ROOT" \
  "$PENDING_FILE"
do
  if [[ ! -e "$required_file" ]]; then
    echo "[verify_mm_wave7_required] missing file: $required_file" >&2
    exit 1
  fi
done

async_cases=(
  "buffer_pool_4k_basic"
  "buffer_pool_2m_basic"
)

async_phase_d_cases=(
  "enqueue_override_forces_error"
  "token_exhaustion_rolls_back_pending"
  "token_bucket_clamp"
  "runtime_tunable_roundtrip"
)

async_phase_e_cases=(
  "memcg_concurrent_swapout_canonical"
  "async_swapout_concurrent_dedup_canonical"
)

async_phase_f_cases=(
  "async_swapout_stress_concurrency_canonical"
  "async_swapout_heavy_stress_canonical"
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

for suite_group in \
  "mm_wave7_async_swapout_exports" \
  "mm_wave7_async_swapout_phase_d_exports" \
  "mm_wave7_async_swapout_phase_e_exports" \
  "mm_wave7_async_swapout_phase_f_exports" \
  "mm_wave7_page_reclaim_exports" \
  "mm_wave7_page_reclaim_phase_b_exports" \
  "mm_wave7_page_reclaim_phase_c_exports"
do
  if ! rg -q "${suite_group}" "$KERNEL_SUITE_ROOT"; then
    echo "[verify_mm_wave7_required] missing ${suite_group} under ${KERNEL_SUITE_ROOT#"$ROOT_DIR"/}"
    violations=$((violations + 1))
  fi
done

if ! rg -q "pub fn qemu_test_set_enqueue_override\\(" "$ASYNC_EXPORT_ROOT"; then
  echo "[verify_mm_wave7_required] missing qemu enqueue hook under ${ASYNC_EXPORT_ROOT#"$ROOT_DIR"/}"
  violations=$((violations + 1))
fi

if ! rg -q "pub fn qemu_test_clear_enqueue_override\\(" "$ASYNC_EXPORT_ROOT"; then
  echo "[verify_mm_wave7_required] missing qemu enqueue clear hook under ${ASYNC_EXPORT_ROOT#"$ROOT_DIR"/}"
  violations=$((violations + 1))
fi

if ! rg -q "pub fn qemu_test_drain_until_idle\\(" "$ASYNC_EXPORT_ROOT" "$ASYNC_WORKER_ROOT"; then
  echo "[verify_mm_wave7_required] missing qemu drain hook under ${ASYNC_EXPORT_ROOT#"$ROOT_DIR"/}"
  violations=$((violations + 1))
fi

if ! rg -q "pub fn qemu_test_reset_worker_runtime_state\\(" "$ASYNC_EXPORT_ROOT" "$ASYNC_WORKER_ROOT"; then
  echo "[verify_mm_wave7_required] missing qemu reset hook under ${ASYNC_EXPORT_ROOT#"$ROOT_DIR"/}"
  violations=$((violations + 1))
fi

if ! rg -q "pub fn qemu_test_set_sync_page_writeback_override\\(" "$RECLAIM_EXPORT_ROOT"; then
  echo "[verify_mm_wave7_required] missing qemu page writeback hook under ${RECLAIM_EXPORT_ROOT#"$ROOT_DIR"/}"
  violations=$((violations + 1))
fi

if ! rg -q "pub fn qemu_test_set_sync_all_writeback_override\\(" "$RECLAIM_EXPORT_ROOT"; then
  echo "[verify_mm_wave7_required] missing qemu all-writeback hook under ${RECLAIM_EXPORT_ROOT#"$ROOT_DIR"/}"
  violations=$((violations + 1))
fi

if ! rg -q "pub fn qemu_test_clear_writeback_overrides\\(" "$RECLAIM_EXPORT_ROOT"; then
  echo "[verify_mm_wave7_required] missing qemu writeback clear hook under ${RECLAIM_EXPORT_ROOT#"$ROOT_DIR"/}"
  violations=$((violations + 1))
fi

for case_name in "${async_phase_f_cases[@]}"; do
  export_fn="wave7_${case_name}_smoke"
  wrapper_fn="mm_wave7_${case_name}_smoke"

  if ! rg -q "pub fn ${export_fn}\\(" "$ASYNC_EXPORT_FILE" "$ASYNC_EXPORT_ROOT"; then
    echo "[verify_mm_wave7_required] missing async phase-f export '${export_fn}' under ${ASYNC_EXPORT_ROOT#"$ROOT_DIR"/}"
    violations=$((violations + 1))
  fi

  if ! rg -q "pub fn ${wrapper_fn}\\(" "$KERNEL_WRAPPER_FILE"; then
    echo "[verify_mm_wave7_required] missing async phase-f wrapper '${wrapper_fn}' in ${KERNEL_WRAPPER_FILE#"$ROOT_DIR"/}"
    violations=$((violations + 1))
  fi

  if ! rg -q "${wrapper_fn}" "$KERNEL_SUITE_ROOT"; then
    echo "[verify_mm_wave7_required] missing async phase-f suite wiring '${wrapper_fn}' under ${KERNEL_SUITE_ROOT#"$ROOT_DIR"/}"
    violations=$((violations + 1))
  fi

  if rg -q "${case_name}" "$PENDING_FILE"; then
    echo "[verify_mm_wave7_required] promoted async phase-f case '${case_name}' still listed in ${PENDING_FILE#"$ROOT_DIR"/}"
    violations=$((violations + 1))
  fi
done

for case_name in "${async_phase_e_cases[@]}"; do
  export_fn="wave7_${case_name}_smoke"
  wrapper_fn="mm_wave7_${case_name}_smoke"

  if ! rg -q "pub fn ${export_fn}\\(" "$ASYNC_EXPORT_FILE" "$ASYNC_EXPORT_ROOT"; then
    echo "[verify_mm_wave7_required] missing async phase-e export '${export_fn}' under ${ASYNC_EXPORT_ROOT#"$ROOT_DIR"/}"
    violations=$((violations + 1))
  fi

  if ! rg -q "pub fn ${wrapper_fn}\\(" "$KERNEL_WRAPPER_FILE"; then
    echo "[verify_mm_wave7_required] missing async phase-e wrapper '${wrapper_fn}' in ${KERNEL_WRAPPER_FILE#"$ROOT_DIR"/}"
    violations=$((violations + 1))
  fi

  if ! rg -q "${wrapper_fn}" "$KERNEL_SUITE_ROOT"; then
    echo "[verify_mm_wave7_required] missing async phase-e suite wiring '${wrapper_fn}' under ${KERNEL_SUITE_ROOT#"$ROOT_DIR"/}"
    violations=$((violations + 1))
  fi

  if rg -q "${case_name}" "$PENDING_FILE"; then
    echo "[verify_mm_wave7_required] promoted async phase-e case '${case_name}' still listed in ${PENDING_FILE#"$ROOT_DIR"/}"
    violations=$((violations + 1))
  fi
done

for case_name in "${async_phase_d_cases[@]}"; do
  export_fn="wave7_${case_name}_smoke"
  wrapper_fn="mm_wave7_${case_name}_smoke"

  if ! rg -q "pub fn ${export_fn}\\(" "$ASYNC_EXPORT_FILE" "$ASYNC_EXPORT_ROOT"; then
    echo "[verify_mm_wave7_required] missing async phase-d export '${export_fn}' under ${ASYNC_EXPORT_ROOT#"$ROOT_DIR"/}"
    violations=$((violations + 1))
  fi

  if ! rg -q "pub fn ${wrapper_fn}\\(" "$KERNEL_WRAPPER_FILE"; then
    echo "[verify_mm_wave7_required] missing async phase-d wrapper '${wrapper_fn}' in ${KERNEL_WRAPPER_FILE#"$ROOT_DIR"/}"
    violations=$((violations + 1))
  fi

  if ! rg -q "${wrapper_fn}" "$KERNEL_SUITE_ROOT"; then
    echo "[verify_mm_wave7_required] missing async phase-d suite wiring '${wrapper_fn}' under ${KERNEL_SUITE_ROOT#"$ROOT_DIR"/}"
    violations=$((violations + 1))
  fi

  if rg -q "${case_name}" "$PENDING_FILE"; then
    echo "[verify_mm_wave7_required] promoted async phase-d case '${case_name}' still listed in ${PENDING_FILE#"$ROOT_DIR"/}"
    violations=$((violations + 1))
  fi
done

for case_name in "${async_cases[@]}"; do
  export_fn="wave7_${case_name}_smoke"
  wrapper_fn="mm_wave7_${case_name}_smoke"

  if ! rg -q "pub fn ${export_fn}\\(" "$ASYNC_EXPORT_FILE" "$ASYNC_EXPORT_ROOT"; then
    echo "[verify_mm_wave7_required] missing async export '${export_fn}' under ${ASYNC_EXPORT_ROOT#"$ROOT_DIR"/}"
    violations=$((violations + 1))
  fi

  if ! rg -q "pub fn ${wrapper_fn}\\(" "$KERNEL_WRAPPER_FILE"; then
    echo "[verify_mm_wave7_required] missing wrapper '${wrapper_fn}' in ${KERNEL_WRAPPER_FILE#"$ROOT_DIR"/}"
    violations=$((violations + 1))
  fi

  if ! rg -q "${wrapper_fn}" "$KERNEL_SUITE_ROOT"; then
    echo "[verify_mm_wave7_required] missing suite wiring '${wrapper_fn}' under ${KERNEL_SUITE_ROOT#"$ROOT_DIR"/}"
    violations=$((violations + 1))
  fi

  if rg -q "${case_name}" "$PENDING_FILE"; then
    echo "[verify_mm_wave7_required] promoted case '${case_name}' still listed in ${PENDING_FILE#"$ROOT_DIR"/}"
    violations=$((violations + 1))
  fi
done

for case_name in "${reclaim_phase_c_cases[@]}"; do
  export_fn="wave7_${case_name}_smoke"
  wrapper_fn="mm_wave7_${case_name}_smoke"

  if ! rg -q "pub fn ${export_fn}\\(" "$RECLAIM_EXPORT_FILE" "$RECLAIM_EXPORT_ROOT"; then
    echo "[verify_mm_wave7_required] missing reclaim phase-c export '${export_fn}' under ${RECLAIM_EXPORT_ROOT#"$ROOT_DIR"/}"
    violations=$((violations + 1))
  fi

  if ! rg -q "pub fn ${wrapper_fn}\\(" "$KERNEL_WRAPPER_FILE"; then
    echo "[verify_mm_wave7_required] missing phase-c wrapper '${wrapper_fn}' in ${KERNEL_WRAPPER_FILE#"$ROOT_DIR"/}"
    violations=$((violations + 1))
  fi

  if ! rg -q "${wrapper_fn}" "$KERNEL_SUITE_ROOT"; then
    echo "[verify_mm_wave7_required] missing phase-c suite wiring '${wrapper_fn}' under ${KERNEL_SUITE_ROOT#"$ROOT_DIR"/}"
    violations=$((violations + 1))
  fi

  if rg -q "${case_name}" "$PENDING_FILE"; then
    echo "[verify_mm_wave7_required] promoted phase-c case '${case_name}' still listed in ${PENDING_FILE#"$ROOT_DIR"/}"
    violations=$((violations + 1))
  fi
done

for case_name in "${reclaim_phase_b_cases[@]}"; do
  export_fn="wave7_${case_name}_smoke"
  wrapper_fn="mm_wave7_${case_name}_smoke"

  if ! rg -q "pub fn ${export_fn}\\(" "$RECLAIM_EXPORT_FILE" "$RECLAIM_EXPORT_ROOT"; then
    echo "[verify_mm_wave7_required] missing reclaim phase-b export '${export_fn}' under ${RECLAIM_EXPORT_ROOT#"$ROOT_DIR"/}"
    violations=$((violations + 1))
  fi

  if ! rg -q "pub fn ${wrapper_fn}\\(" "$KERNEL_WRAPPER_FILE"; then
    echo "[verify_mm_wave7_required] missing phase-b wrapper '${wrapper_fn}' in ${KERNEL_WRAPPER_FILE#"$ROOT_DIR"/}"
    violations=$((violations + 1))
  fi

  if ! rg -q "${wrapper_fn}" "$KERNEL_SUITE_ROOT"; then
    echo "[verify_mm_wave7_required] missing phase-b suite wiring '${wrapper_fn}' under ${KERNEL_SUITE_ROOT#"$ROOT_DIR"/}"
    violations=$((violations + 1))
  fi

  if rg -q "${case_name}" "$PENDING_FILE"; then
    echo "[verify_mm_wave7_required] promoted phase-b case '${case_name}' still listed in ${PENDING_FILE#"$ROOT_DIR"/}"
    violations=$((violations + 1))
  fi
done

for case_name in "${reclaim_cases[@]}"; do
  export_fn="wave7_${case_name}_smoke"
  wrapper_fn="mm_wave7_${case_name}_smoke"

  if ! rg -q "pub fn ${export_fn}\\(" "$RECLAIM_EXPORT_FILE" "$RECLAIM_EXPORT_ROOT"; then
    echo "[verify_mm_wave7_required] missing reclaim export '${export_fn}' under ${RECLAIM_EXPORT_ROOT#"$ROOT_DIR"/}"
    violations=$((violations + 1))
  fi

  if ! rg -q "pub fn ${wrapper_fn}\\(" "$KERNEL_WRAPPER_FILE"; then
    echo "[verify_mm_wave7_required] missing wrapper '${wrapper_fn}' in ${KERNEL_WRAPPER_FILE#"$ROOT_DIR"/}"
    violations=$((violations + 1))
  fi

  if ! rg -q "${wrapper_fn}" "$KERNEL_SUITE_ROOT"; then
    echo "[verify_mm_wave7_required] missing suite wiring '${wrapper_fn}' under ${KERNEL_SUITE_ROOT#"$ROOT_DIR"/}"
    violations=$((violations + 1))
  fi

  if rg -q "${case_name}" "$PENDING_FILE"; then
    echo "[verify_mm_wave7_required] promoted case '${case_name}' still listed in ${PENDING_FILE#"$ROOT_DIR"/}"
    violations=$((violations + 1))
  fi
done

for marker in \
  "MM Wave7 Phase A deterministic set is promoted to required suite_kernel" \
  "MM Wave7 Phase B deterministic set is promoted to required suite_kernel" \
  "MM Wave7 Phase C deterministic set is promoted to required suite_kernel" \
  "MM Wave7 Phase D deterministic set is promoted to required suite_kernel" \
  "MM Wave7 Phase E deterministic set is promoted to required suite_kernel" \
  "MM Wave7 Phase F deterministic set is promoted to required suite_kernel"
do
  if ! rg -q "${marker}" "$PENDING_FILE"; then
    echo "[verify_mm_wave7_required] missing marker '${marker}' in ${PENDING_FILE#"$ROOT_DIR"/}"
    violations=$((violations + 1))
  fi
done

if [[ "$violations" -gt 0 ]]; then
  echo "[verify_mm_wave7_required] FAIL: found $violations issues"
  exit 1
fi

echo "[verify_mm_wave7_required] PASS"
