#!/usr/bin/env bash
set -euo pipefail

# Validates IOMMU Wave5 required wiring and residual tracking boundaries.
# Scope: Wave5 canonical/residual required chain + pending/parity consistency.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IOMMU_QEMU_TESTS_FILE="$ROOT_DIR/kernel/src/io/iommu/qemu_tests.rs"
KERNEL_WRAPPER_FILE="$ROOT_DIR/kernel/src/qemu_tests.rs"
KERNEL_SUITE_FILE="$ROOT_DIR/qemu-suites/kernel/src/main.rs"
SECURITY_FILE="$ROOT_DIR/kernel/src/io/iommu/security.rs"
PENDING_FILE="$ROOT_DIR/scripts/qemu_pending_cases.lst"
PARITY_FILE="$ROOT_DIR/scripts/qemu_iommu_residual_parity.lst"

for required_file in \
  "$IOMMU_QEMU_TESTS_FILE" \
  "$KERNEL_WRAPPER_FILE" \
  "$KERNEL_SUITE_FILE" \
  "$SECURITY_FILE" \
  "$PENDING_FILE" \
  "$PARITY_FILE"
do
  if [[ ! -f "$required_file" ]]; then
    echo "[verify_iommu_wave5_residual_canonical_required] missing file: $required_file" >&2
    exit 1
  fi
done

canonical_cases=(
  "cmdqueue_map_unmap_with_domain_canonical"
  "map_for_device_respects_dma_mask_canonical"
  "api_security_notifier_registration_canonical"
  "qi_metrics_pressure_canonical"
)

residual_cases=(
  "map_for_device_async_and_unmap_residual"
)

legacy_wave2_compat=(
  "wave2_cmdqueue_map_unmap_with_domain_smoke"
  "wave2_cmdqueue_map_device_nonblocking_smoke"
  "wave2_dma_mask_respects_32bit_limit_smoke"
  "wave2_controller_security_notifier_dispatch_smoke"
  "wave2_qi_metrics_pressure_smoke"
)

promoted_canonical_originals=(
  "test_cmdqueue_map_unmap_with_domain"
  "test_map_for_device_respects_dma_mask"
  "test_api_security_notifier_registration"
  "test_qi_metrics_pressure"
)

residual_originals=(
  "test_map_for_device_async_and_unmap"
)

violations=0

if ! rg -q "pub fn qemu_test_clear_security_notifier\\(" "$SECURITY_FILE"; then
  echo "[verify_iommu_wave5_residual_canonical_required] missing qemu_test_clear_security_notifier hook in ${SECURITY_FILE#$ROOT_DIR/}"
  violations=$((violations + 1))
fi

if ! rg -q "fn test_iommu_wave5_canonical_exports\\(" "$KERNEL_SUITE_FILE"; then
  echo "[verify_iommu_wave5_residual_canonical_required] missing test_iommu_wave5_canonical_exports in ${KERNEL_SUITE_FILE#$ROOT_DIR/}"
  violations=$((violations + 1))
fi

if ! rg -q "fn test_iommu_wave5_residual_exports\\(" "$KERNEL_SUITE_FILE"; then
  echo "[verify_iommu_wave5_residual_canonical_required] missing test_iommu_wave5_residual_exports in ${KERNEL_SUITE_FILE#$ROOT_DIR/}"
  violations=$((violations + 1))
fi

if rg -q "iommu_wave2_residual_exports" "$KERNEL_SUITE_FILE"; then
  echo "[verify_iommu_wave5_residual_canonical_required] stale iommu_wave2_residual_exports reference in ${KERNEL_SUITE_FILE#$ROOT_DIR/}"
  violations=$((violations + 1))
fi

for legacy in "${legacy_wave2_compat[@]}"; do
  if ! rg -q "pub fn ${legacy}\\(" "$IOMMU_QEMU_TESTS_FILE"; then
    echo "[verify_iommu_wave5_residual_canonical_required] missing compat alias '${legacy}' in ${IOMMU_QEMU_TESTS_FILE#$ROOT_DIR/}"
    violations=$((violations + 1))
  fi

  wrapper="iommu_${legacy}"
  if ! rg -q "pub fn ${wrapper}\\(" "$KERNEL_WRAPPER_FILE"; then
    echo "[verify_iommu_wave5_residual_canonical_required] missing compat wrapper '${wrapper}' in ${KERNEL_WRAPPER_FILE#$ROOT_DIR/}"
    violations=$((violations + 1))
  fi
done

for case_name in "${canonical_cases[@]}"; do
  export_fn="wave5_${case_name}_smoke"
  wrapper_fn="iommu_wave5_${case_name}_smoke"

  if ! rg -q "pub fn ${export_fn}\\(" "$IOMMU_QEMU_TESTS_FILE"; then
    echo "[verify_iommu_wave5_residual_canonical_required] missing canonical export '${export_fn}' in ${IOMMU_QEMU_TESTS_FILE#$ROOT_DIR/}"
    violations=$((violations + 1))
  fi

  if ! rg -q "pub fn ${wrapper_fn}\\(" "$KERNEL_WRAPPER_FILE"; then
    echo "[verify_iommu_wave5_residual_canonical_required] missing canonical wrapper '${wrapper_fn}' in ${KERNEL_WRAPPER_FILE#$ROOT_DIR/}"
    violations=$((violations + 1))
  fi

  if ! rg -q "${wrapper_fn}" "$KERNEL_SUITE_FILE"; then
    echo "[verify_iommu_wave5_residual_canonical_required] missing canonical suite wiring '${wrapper_fn}' in ${KERNEL_SUITE_FILE#$ROOT_DIR/}"
    violations=$((violations + 1))
  fi
done

for case_name in "${residual_cases[@]}"; do
  export_fn="wave5_${case_name}_smoke"
  wrapper_fn="iommu_wave5_${case_name}_smoke"

  if ! rg -q "pub fn ${export_fn}\\(" "$IOMMU_QEMU_TESTS_FILE"; then
    echo "[verify_iommu_wave5_residual_canonical_required] missing residual export '${export_fn}' in ${IOMMU_QEMU_TESTS_FILE#$ROOT_DIR/}"
    violations=$((violations + 1))
  fi

  if ! rg -q "pub fn ${wrapper_fn}\\(" "$KERNEL_WRAPPER_FILE"; then
    echo "[verify_iommu_wave5_residual_canonical_required] missing residual wrapper '${wrapper_fn}' in ${KERNEL_WRAPPER_FILE#$ROOT_DIR/}"
    violations=$((violations + 1))
  fi

  if ! rg -q "${wrapper_fn}" "$KERNEL_SUITE_FILE"; then
    echo "[verify_iommu_wave5_residual_canonical_required] missing residual suite wiring '${wrapper_fn}' in ${KERNEL_SUITE_FILE#$ROOT_DIR/}"
    violations=$((violations + 1))
  fi
done

for original in "${promoted_canonical_originals[@]}"; do
  if rg -q "^IOMMU residual canonical: ${original}$" "$PENDING_FILE"; then
    echo "[verify_iommu_wave5_residual_canonical_required] promoted canonical '${original}' still present as residual canonical entry in ${PENDING_FILE#$ROOT_DIR/}"
    violations=$((violations + 1))
  fi

  if rg -q "^${original}\\|" "$PARITY_FILE"; then
    echo "[verify_iommu_wave5_residual_canonical_required] promoted canonical '${original}' still present in ${PARITY_FILE#$ROOT_DIR/}"
    violations=$((violations + 1))
  fi
done

for original in "${residual_originals[@]}"; do
  if ! rg -q "^IOMMU residual canonical: ${original}$" "$PENDING_FILE"; then
    echo "[verify_iommu_wave5_residual_canonical_required] residual canonical '${original}' missing in ${PENDING_FILE#$ROOT_DIR/}"
    violations=$((violations + 1))
  fi

  if ! rg -q "^${original}\\|" "$PARITY_FILE"; then
    echo "[verify_iommu_wave5_residual_canonical_required] residual canonical '${original}' missing in ${PARITY_FILE#$ROOT_DIR/}"
    violations=$((violations + 1))
  fi
done

if [[ "$violations" -gt 0 ]]; then
  echo "[verify_iommu_wave5_residual_canonical_required] FAIL: found $violations issues"
  exit 1
fi

echo "[verify_iommu_wave5_residual_canonical_required] PASS"
