#!/usr/bin/env bash
set -euo pipefail

# Validates that AMD Wave5 required smoke exports stay wired into suite_kernel.
# Scope: required wiring guard (separate from #[test] allowlist and residual parity).

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AMD_EXPORT_FILE="$ROOT_DIR/kernel/src/io/iommu/amd/qemu_tests.rs"
IOMMU_WRAPPER_ROOT="$ROOT_DIR/kernel/src/io/iommu/qemu_tests"
KERNEL_WRAPPER_ROOT="$ROOT_DIR/kernel/src/qemu_tests"
KERNEL_WRAPPER_FILE="$ROOT_DIR/kernel/src/qemu_tests.rs"
KERNEL_SUITE_ROOT="$ROOT_DIR/qemu-suites/kernel/src"
PENDING_FILE="$ROOT_DIR/scripts/qemu_pending_cases.lst"

for required_file in \
  "$AMD_EXPORT_FILE" \
  "$IOMMU_WRAPPER_ROOT" \
  "$KERNEL_WRAPPER_ROOT" \
  "$KERNEL_WRAPPER_FILE" \
  "$KERNEL_SUITE_ROOT" \
  "$PENDING_FILE"
do
  if [[ ! -e "$required_file" ]]; then
    echo "[verify_iommu_amd_wave5_required] missing file: $required_file" >&2
    exit 1
  fi
done

wave1_cases=(
  "cmdqueue_map_unmap_with_domain"
  "map_device_nonblocking"
  "dma_mask_respects_32bit_limit"
  "security_notifier_dispatch"
  "cmdqueue_pressure"
)

wave5_cases=(
  "irt_entry_construction"
  "irt_alloc_free"
  "irt_exhaustion"
  "irt_invalidation_cmd_format"
  "map_interrupt_returns_handle"
  "get_remap_msi_message_format"
)

violations=0

if ! rg -q "fn test_iommu_wave5_amd_exports\\(" "$KERNEL_SUITE_ROOT"; then
  echo "[verify_iommu_amd_wave5_required] missing test_iommu_wave5_amd_exports under ${KERNEL_SUITE_ROOT#"$ROOT_DIR"/}"
  violations=$((violations + 1))
fi

for case_name in "${wave1_cases[@]}"; do
  amd_export="wave1_${case_name}_smoke"
  iommu_wrapper="amd_wave1_${case_name}_smoke"
  kernel_wrapper="iommu_amd_wave1_${case_name}_smoke"

  if ! rg -q "pub fn ${amd_export}\\(" "$AMD_EXPORT_FILE"; then
    echo "[verify_iommu_amd_wave5_required] missing AMD export '${amd_export}' in ${AMD_EXPORT_FILE#"$ROOT_DIR"/}"
    violations=$((violations + 1))
  fi

  if ! rg -q "pub fn ${iommu_wrapper}\\(" "$IOMMU_WRAPPER_ROOT"; then
    echo "[verify_iommu_amd_wave5_required] missing IOMMU wrapper '${iommu_wrapper}' under ${IOMMU_WRAPPER_ROOT#"$ROOT_DIR"/}"
    violations=$((violations + 1))
  fi

  if ! rg -q "pub fn ${kernel_wrapper}\\(" "$KERNEL_WRAPPER_FILE" "$KERNEL_WRAPPER_ROOT"; then
    echo "[verify_iommu_amd_wave5_required] missing kernel wrapper '${kernel_wrapper}' under kernel/src/qemu_tests*"
    violations=$((violations + 1))
  fi

  if ! rg -q "${kernel_wrapper}" "$KERNEL_SUITE_ROOT"; then
    echo "[verify_iommu_amd_wave5_required] missing required suite wiring '${kernel_wrapper}' under ${KERNEL_SUITE_ROOT#"$ROOT_DIR"/}"
    violations=$((violations + 1))
  fi
done

for case_name in "${wave5_cases[@]}"; do
  amd_export="wave5_${case_name}_smoke"
  iommu_wrapper="amd_wave5_${case_name}_smoke"
  kernel_wrapper="iommu_amd_wave5_${case_name}_smoke"

  if ! rg -q "pub fn ${amd_export}\\(" "$AMD_EXPORT_FILE"; then
    echo "[verify_iommu_amd_wave5_required] missing AMD export '${amd_export}' in ${AMD_EXPORT_FILE#"$ROOT_DIR"/}"
    violations=$((violations + 1))
  fi

  if ! rg -q "pub fn ${iommu_wrapper}\\(" "$IOMMU_WRAPPER_ROOT"; then
    echo "[verify_iommu_amd_wave5_required] missing IOMMU wrapper '${iommu_wrapper}' under ${IOMMU_WRAPPER_ROOT#"$ROOT_DIR"/}"
    violations=$((violations + 1))
  fi

  if ! rg -q "pub fn ${kernel_wrapper}\\(" "$KERNEL_WRAPPER_FILE" "$KERNEL_WRAPPER_ROOT"; then
    echo "[verify_iommu_amd_wave5_required] missing kernel wrapper '${kernel_wrapper}' under kernel/src/qemu_tests*"
    violations=$((violations + 1))
  fi

  if ! rg -q "${kernel_wrapper}" "$KERNEL_SUITE_ROOT"; then
    echo "[verify_iommu_amd_wave5_required] missing required suite wiring '${kernel_wrapper}' under ${KERNEL_SUITE_ROOT#"$ROOT_DIR"/}"
    violations=$((violations + 1))
  fi
done

if rg -q "amd_wave1_|amd_wave5_" "$PENDING_FILE"; then
  echo "[verify_iommu_amd_wave5_required] stale AMD pending markers detected in ${PENDING_FILE#"$ROOT_DIR"/}"
  violations=$((violations + 1))
fi

if ! rg -q "iommu-wave5\\(" "$PENDING_FILE"; then
  echo "[verify_iommu_amd_wave5_required] missing wave5 marker in ${PENDING_FILE#"$ROOT_DIR"/}"
  violations=$((violations + 1))
fi

if [[ "$violations" -gt 0 ]]; then
  echo "[verify_iommu_amd_wave5_required] FAIL: found $violations issues"
  exit 1
fi

echo "[verify_iommu_amd_wave5_required] PASS"
