#!/usr/bin/env bash
set -euo pipefail

# Validates IOMMU Wave5 canonical required wiring and residual-none boundaries.
# Scope: required wiring + canonical pending/parity responsibility split.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IOMMU_QEMU_TESTS_FILE="$ROOT_DIR/kernel/src/io/iommu/qemu_tests.rs"
IOMMU_SECURITY_FILE="$ROOT_DIR/kernel/src/io/iommu/security.rs"
KERNEL_WRAPPER_FILE="$ROOT_DIR/kernel/src/qemu_tests.rs"
KERNEL_WRAPPER_DIR="$ROOT_DIR/kernel/src/qemu_tests"
KERNEL_SUITE_FILE="$ROOT_DIR/qemu-suites/kernel/src/main.rs"
KERNEL_SUITE_DIR="$ROOT_DIR/qemu-suites/kernel/src"
PENDING_FILE="$ROOT_DIR/scripts/qemu_pending_cases.lst"
PARITY_FILE="$ROOT_DIR/scripts/qemu_iommu_residual_parity.lst"

for required_file in \
  "$IOMMU_QEMU_TESTS_FILE" \
  "$IOMMU_SECURITY_FILE" \
  "$KERNEL_WRAPPER_FILE" \
  "$KERNEL_WRAPPER_DIR" \
  "$KERNEL_SUITE_FILE" \
  "$KERNEL_SUITE_DIR" \
  "$PENDING_FILE" \
  "$PARITY_FILE"
do
  if [[ ! -e "$required_file" ]]; then
    echo "[verify_iommu_wave5_residual_canonical_required] missing file: $required_file" >&2
    exit 1
  fi
done

canonical_cases=(
  "cmdqueue_map_unmap_with_domain_canonical"
  "map_for_device_async_and_unmap_canonical"
  "map_for_device_respects_dma_mask_canonical"
  "api_security_notifier_registration_canonical"
  "qi_metrics_pressure_canonical"
)

compat_wave2_exports=(
  "wave2_cmdqueue_map_unmap_with_domain_smoke"
  "wave2_cmdqueue_map_device_nonblocking_smoke"
  "wave2_dma_mask_respects_32bit_limit_smoke"
  "wave2_controller_security_notifier_dispatch_smoke"
  "wave2_qi_metrics_pressure_smoke"
)

compat_wave2_wrappers=(
  "iommu_wave2_cmdqueue_map_unmap_with_domain_smoke"
  "iommu_wave2_cmdqueue_map_device_nonblocking_smoke"
  "iommu_wave2_dma_mask_respects_32bit_limit_smoke"
  "iommu_wave2_controller_security_notifier_dispatch_smoke"
  "iommu_wave2_qi_metrics_pressure_smoke"
)

promoted_original_cases=(
  "test_cmdqueue_map_unmap_with_domain"
  "test_map_for_device_async_and_unmap"
  "test_map_for_device_respects_dma_mask"
  "test_api_security_notifier_registration"
  "test_qi_metrics_pressure"
)

residual_wrapper_cases=(
  "iommu_wave5_cmdqueue_map_unmap_with_domain_residual_smoke"
  "iommu_wave5_map_for_device_async_and_unmap_residual_smoke"
)

violations=0

if ! rg -q "fn test_iommu_wave5_canonical_exports\\(" "$KERNEL_SUITE_FILE" "$KERNEL_SUITE_DIR"; then
  echo "[verify_iommu_wave5_residual_canonical_required] missing test_iommu_wave5_canonical_exports in ${KERNEL_SUITE_FILE#$ROOT_DIR/}"
  violations=$((violations + 1))
fi

if rg -q "fn test_iommu_wave5_residual_exports\\(" "$KERNEL_SUITE_FILE" "$KERNEL_SUITE_DIR"; then
  echo "[verify_iommu_wave5_residual_canonical_required] stale test_iommu_wave5_residual_exports in ${KERNEL_SUITE_FILE#$ROOT_DIR/}"
  violations=$((violations + 1))
fi

if rg -q "iommu_wave5_residual_exports" "$KERNEL_SUITE_FILE" "$KERNEL_SUITE_DIR"; then
  echo "[verify_iommu_wave5_residual_canonical_required] stale iommu_wave5_residual_exports run_check in ${KERNEL_SUITE_FILE#$ROOT_DIR/}"
  violations=$((violations + 1))
fi

if rg -q "fn test_iommu_wave2_residual_exports\\(" "$KERNEL_SUITE_FILE" "$KERNEL_SUITE_DIR"; then
  echo "[verify_iommu_wave5_residual_canonical_required] stale test_iommu_wave2_residual_exports in ${KERNEL_SUITE_FILE#$ROOT_DIR/}"
  violations=$((violations + 1))
fi

if ! rg -q "pub fn qemu_test_clear_security_notifier\\(" "$IOMMU_SECURITY_FILE"; then
  echo "[verify_iommu_wave5_residual_canonical_required] missing qemu_test_clear_security_notifier in ${IOMMU_SECURITY_FILE#$ROOT_DIR/}"
  violations=$((violations + 1))
fi

for case_name in "${canonical_cases[@]}"; do
  export_case="wave5_${case_name}_smoke"
  wrapper_case="iommu_wave5_${case_name}_smoke"

  if ! rg -q "pub fn ${export_case}\\(" "$IOMMU_QEMU_TESTS_FILE"; then
    echo "[verify_iommu_wave5_residual_canonical_required] missing export '${export_case}' in ${IOMMU_QEMU_TESTS_FILE#$ROOT_DIR/}"
    violations=$((violations + 1))
  fi

  if ! rg -q "pub fn ${wrapper_case}\\(" "$KERNEL_WRAPPER_FILE" "$KERNEL_WRAPPER_DIR"; then
    echo "[verify_iommu_wave5_residual_canonical_required] missing wrapper '${wrapper_case}' in ${KERNEL_WRAPPER_FILE#$ROOT_DIR/}"
    violations=$((violations + 1))
  fi

  if ! rg -q "${wrapper_case}" "$KERNEL_SUITE_FILE" "$KERNEL_SUITE_DIR"; then
    echo "[verify_iommu_wave5_residual_canonical_required] missing suite wiring '${wrapper_case}' in ${KERNEL_SUITE_FILE#$ROOT_DIR/}"
    violations=$((violations + 1))
  fi
done

for wrapper_case in "${residual_wrapper_cases[@]}"; do
  if ! rg -q "pub fn ${wrapper_case}\\(" "$KERNEL_WRAPPER_FILE" "$KERNEL_WRAPPER_DIR"; then
    echo "[verify_iommu_wave5_residual_canonical_required] missing compat residual wrapper '${wrapper_case}' in ${KERNEL_WRAPPER_FILE#$ROOT_DIR/}"
    violations=$((violations + 1))
  fi

  if rg -q "${wrapper_case}" "$KERNEL_SUITE_FILE" "$KERNEL_SUITE_DIR"; then
    echo "[verify_iommu_wave5_residual_canonical_required] stale required suite wiring for residual wrapper '${wrapper_case}' in ${KERNEL_SUITE_FILE#$ROOT_DIR/}"
    violations=$((violations + 1))
  fi
done

for export_case in "${compat_wave2_exports[@]}"; do
  if ! rg -q "pub fn ${export_case}\\(" "$IOMMU_QEMU_TESTS_FILE"; then
    echo "[verify_iommu_wave5_residual_canonical_required] missing compat export '${export_case}' in ${IOMMU_QEMU_TESTS_FILE#$ROOT_DIR/}"
    violations=$((violations + 1))
  fi
done

for wrapper_case in "${compat_wave2_wrappers[@]}"; do
  if ! rg -q "pub fn ${wrapper_case}\\(" "$KERNEL_WRAPPER_FILE" "$KERNEL_WRAPPER_DIR"; then
    echo "[verify_iommu_wave5_residual_canonical_required] missing compat wrapper '${wrapper_case}' in ${KERNEL_WRAPPER_FILE#$ROOT_DIR/}"
    violations=$((violations + 1))
  fi

  if rg -q "${wrapper_case}" "$KERNEL_SUITE_FILE" "$KERNEL_SUITE_DIR"; then
    echo "[verify_iommu_wave5_residual_canonical_required] stale required suite wiring for compat wrapper '${wrapper_case}' in ${KERNEL_SUITE_FILE#$ROOT_DIR/}"
    violations=$((violations + 1))
  fi
done

for original_case in "${promoted_original_cases[@]}"; do
  if rg -q "IOMMU residual canonical: ${original_case}" "$PENDING_FILE"; then
    echo "[verify_iommu_wave5_residual_canonical_required] promoted canonical case still pending: '${original_case}' in ${PENDING_FILE#$ROOT_DIR/}"
    violations=$((violations + 1))
  fi

  if rg -q "^${original_case}\\|" "$PARITY_FILE"; then
    echo "[verify_iommu_wave5_residual_canonical_required] promoted canonical case still in parity map: '${original_case}' in ${PARITY_FILE#$ROOT_DIR/}"
    violations=$((violations + 1))
  fi
done

if ! rg -q "IOMMU residual canonical pending: none" "$PENDING_FILE"; then
  echo "[verify_iommu_wave5_residual_canonical_required] missing residual none marker in ${PENDING_FILE#$ROOT_DIR/}"
  violations=$((violations + 1))
fi

if ! rg -q "^# none$" "$PARITY_FILE"; then
  echo "[verify_iommu_wave5_residual_canonical_required] missing '# none' marker in ${PARITY_FILE#$ROOT_DIR/}"
  violations=$((violations + 1))
fi

if ! rg -q "IOMMU Wave5 canonical deterministic set is promoted to required suite_kernel" "$PENDING_FILE"; then
  echo "[verify_iommu_wave5_residual_canonical_required] missing Wave5 promotion marker in ${PENDING_FILE#$ROOT_DIR/}"
  violations=$((violations + 1))
fi

if [[ "$violations" -gt 0 ]]; then
  echo "[verify_iommu_wave5_residual_canonical_required] FAIL: found $violations issues"
  exit 1
fi

echo "[verify_iommu_wave5_residual_canonical_required] PASS"
