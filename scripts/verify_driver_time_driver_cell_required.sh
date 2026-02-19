#!/usr/bin/env bash
set -euo pipefail

# Validates required wiring for migrated legacy #[test] sets:
# - drivers/time (6 cases) -> suite_drivers
# - kernel driver_cell (20 cases) -> suite_kernel

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

TIME_LIB_FILE="$ROOT_DIR/drivers/time/src/lib.rs"
TIME_EXPORT_FILE="$ROOT_DIR/drivers/time/src/qemu_tests.rs"
DRIVERS_SUITE_FILE="$ROOT_DIR/qemu-suites/drivers/src/main.rs"
DRIVERS_SUITE_CARGO="$ROOT_DIR/qemu-suites/drivers/Cargo.toml"

DRIVER_CELL_MOD_FILE="$ROOT_DIR/kernel/src/driver_cell/mod.rs"
DRIVER_CELL_EXPORT_FILE="$ROOT_DIR/kernel/src/driver_cell/tests.rs"
KERNEL_WRAPPER_FILE="$ROOT_DIR/kernel/src/qemu_tests.rs"
KERNEL_SUITE_ROOT="$ROOT_DIR/qemu-suites/kernel/src"
KERNEL_SUITE_MAIN_FILE="$ROOT_DIR/qemu-suites/kernel/src/main.rs"

for required_file in \
  "$TIME_LIB_FILE" \
  "$TIME_EXPORT_FILE" \
  "$DRIVERS_SUITE_FILE" \
  "$DRIVERS_SUITE_CARGO" \
  "$DRIVER_CELL_MOD_FILE" \
  "$DRIVER_CELL_EXPORT_FILE" \
  "$KERNEL_WRAPPER_FILE" \
  "$KERNEL_SUITE_ROOT" \
  "$KERNEL_SUITE_MAIN_FILE"
do
  if [[ ! -e "$required_file" ]]; then
    echo "[verify_driver_time_driver_cell_required] missing file: $required_file" >&2
    exit 1
  fi
done

violations=0

if ! rg -q '^qemu-test-export = \[\]$' "$ROOT_DIR/drivers/time/Cargo.toml"; then
  echo "[verify_driver_time_driver_cell_required] missing drivers/time qemu-test-export feature"
  violations=$((violations + 1))
fi

if ! rg -q '^time_driver = .*qemu-test-export' "$DRIVERS_SUITE_CARGO"; then
  echo "[verify_driver_time_driver_cell_required] missing qemu-suites/drivers dependency on time_driver with qemu-test-export"
  violations=$((violations + 1))
fi

if ! rg -q '^\s*pub mod qemu_tests;' "$TIME_LIB_FILE"; then
  echo "[verify_driver_time_driver_cell_required] missing pub mod qemu_tests in ${TIME_LIB_FILE#"$ROOT_DIR"/}"
  violations=$((violations + 1))
fi

if rg -q '^\s*#\[test\]' "$TIME_LIB_FILE"; then
  echo "[verify_driver_time_driver_cell_required] stale #[test] found in ${TIME_LIB_FILE#"$ROOT_DIR"/}"
  violations=$((violations + 1))
fi

if ! rg -q 'test_time_driver_exports' "$DRIVERS_SUITE_FILE"; then
  echo "[verify_driver_time_driver_cell_required] missing test_time_driver_exports wiring in ${DRIVERS_SUITE_FILE#"$ROOT_DIR"/}"
  violations=$((violations + 1))
fi

time_cases=(
  "tick_increment"
  "timer_registration"
  "cpu_tracker"
  "shard_index"
  "uptime_ns"
  "wall_clock_adjustment"
)

for case_name in "${time_cases[@]}"; do
  fn_name="${case_name}_smoke"
  if ! rg -q "pub fn ${fn_name}\\(" "$TIME_EXPORT_FILE"; then
    echo "[verify_driver_time_driver_cell_required] missing time export '${fn_name}' in ${TIME_EXPORT_FILE#"$ROOT_DIR"/}"
    violations=$((violations + 1))
  fi

  if ! rg -q "time_driver::qemu_tests::${fn_name}" "$DRIVERS_SUITE_FILE"; then
    echo "[verify_driver_time_driver_cell_required] missing suite_drivers wiring for '${fn_name}'"
    violations=$((violations + 1))
  fi
done

if ! rg -q '^\s*pub mod qemu_tests;' "$DRIVER_CELL_MOD_FILE"; then
  echo "[verify_driver_time_driver_cell_required] missing pub mod qemu_tests in ${DRIVER_CELL_MOD_FILE#"$ROOT_DIR"/}"
  violations=$((violations + 1))
fi

if rg -q '^\s*mod tests;' "$DRIVER_CELL_MOD_FILE"; then
  echo "[verify_driver_time_driver_cell_required] stale mod tests found in ${DRIVER_CELL_MOD_FILE#"$ROOT_DIR"/}"
  violations=$((violations + 1))
fi

if rg -q '^\s*#\[test\]' "$DRIVER_CELL_EXPORT_FILE"; then
  echo "[verify_driver_time_driver_cell_required] stale #[test] found in ${DRIVER_CELL_EXPORT_FILE#"$ROOT_DIR"/}"
  violations=$((violations + 1))
fi

if ! rg -q 'kernel_driver_cell_exports' "$KERNEL_SUITE_MAIN_FILE"; then
  echo "[verify_driver_time_driver_cell_required] missing kernel_driver_cell_exports run_check in ${KERNEL_SUITE_MAIN_FILE#"$ROOT_DIR"/}"
  violations=$((violations + 1))
fi

if ! rg -q 'fn test_kernel_driver_cell_exports\(' "$KERNEL_SUITE_ROOT"; then
  echo "[verify_driver_time_driver_cell_required] missing test_kernel_driver_cell_exports definition under ${KERNEL_SUITE_ROOT#"$ROOT_DIR"/}"
  violations=$((violations + 1))
fi

driver_cell_cases=(
  "driver_cell_state_default_is_created"
  "driver_cell_state_transitions_are_valid"
  "driver_cell_state_faulted"
  "driver_cell_id_equality"
  "driver_cell_id_ordering"
  "driver_cell_restart_policy_never"
  "driver_cell_restart_policy_on_panic_defaults"
  "driver_cell_restart_policy_always"
  "driver_cell_fault_kind_variants"
  "driver_cell_stats_initial_values"
  "driver_cell_stats_default"
  "driver_cell_stats_record_start"
  "driver_cell_stats_record_stop"
  "driver_cell_stats_record_fault"
  "driver_cell_stats_record_restart"
  "driver_cell_stats_record_hot_swap"
  "driver_cell_error_not_found"
  "driver_cell_error_invalid_state"
  "driver_cell_global_stats_new"
  "driver_cell_global_stats_tracking"
)

for case_name in "${driver_cell_cases[@]}"; do
  fn_name="${case_name}_smoke"

  if ! rg -q "pub fn ${fn_name}\\(" "$DRIVER_CELL_EXPORT_FILE"; then
    echo "[verify_driver_time_driver_cell_required] missing driver_cell export '${fn_name}' in ${DRIVER_CELL_EXPORT_FILE#"$ROOT_DIR"/}"
    violations=$((violations + 1))
  fi

  if ! rg -q "pub fn ${fn_name}\\(" "$KERNEL_WRAPPER_FILE"; then
    echo "[verify_driver_time_driver_cell_required] missing kernel wrapper '${fn_name}' in ${KERNEL_WRAPPER_FILE#"$ROOT_DIR"/}"
    violations=$((violations + 1))
  fi

  if ! rg -q "${fn_name}" "$KERNEL_SUITE_ROOT"; then
    echo "[verify_driver_time_driver_cell_required] missing suite_kernel wiring for '${fn_name}'"
    violations=$((violations + 1))
  fi
done

if [[ "$violations" -gt 0 ]]; then
  echo "[verify_driver_time_driver_cell_required] FAIL: found $violations issues"
  exit 1
fi

echo "[verify_driver_time_driver_cell_required] PASS"
