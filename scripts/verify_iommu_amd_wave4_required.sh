#!/usr/bin/env bash
set -euo pipefail

# Validates that AMD Wave0 smoke exports stay wired into required suite_kernel.
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
    echo "[verify_iommu_amd_wave4_required] missing file: $required_file" >&2
    exit 1
  fi
done

cases=(
  "alias_devids_for_device_dedup"
  "alias_devids_for_device_no_match"
  "ivhd_flags_for_device_combined"
  "ivhd_flags_for_device_acpi_hid"
  "map_ivmd_ranges_exclusion_splits"
  "map_for_device_rejects_exclusion_range"
)

violations=0

if ! rg -q "fn test_iommu_wave4_amd_exports\\(" "$KERNEL_SUITE_ROOT"; then
  echo "[verify_iommu_amd_wave4_required] missing test_iommu_wave4_amd_exports under ${KERNEL_SUITE_ROOT#"$ROOT_DIR"/}"
  violations=$((violations + 1))
fi

for case_name in "${cases[@]}"; do
  amd_export="wave0_${case_name}_smoke"
  iommu_wrapper="amd_wave0_${case_name}_smoke"
  kernel_wrapper="iommu_amd_wave0_${case_name}_smoke"

  if ! rg -q "pub fn ${amd_export}\\(" "$AMD_EXPORT_FILE"; then
    echo "[verify_iommu_amd_wave4_required] missing AMD export '${amd_export}' in ${AMD_EXPORT_FILE#"$ROOT_DIR"/}"
    violations=$((violations + 1))
  fi

  if ! rg -q "pub fn ${iommu_wrapper}\\(" "$IOMMU_WRAPPER_ROOT"; then
    echo "[verify_iommu_amd_wave4_required] missing IOMMU wrapper '${iommu_wrapper}' under ${IOMMU_WRAPPER_ROOT#"$ROOT_DIR"/}"
    violations=$((violations + 1))
  fi

  if ! rg -q "pub fn ${kernel_wrapper}\\(" "$KERNEL_WRAPPER_FILE" "$KERNEL_WRAPPER_ROOT"; then
    echo "[verify_iommu_amd_wave4_required] missing kernel wrapper '${kernel_wrapper}' under kernel/src/qemu_tests*"
    violations=$((violations + 1))
  fi

  if ! rg -q "${kernel_wrapper}" "$KERNEL_SUITE_ROOT"; then
    echo "[verify_iommu_amd_wave4_required] missing required suite wiring '${kernel_wrapper}' under ${KERNEL_SUITE_ROOT#"$ROOT_DIR"/}"
    violations=$((violations + 1))
  fi
done

if rg -q "AMD-Vi Wave0 runtime pending" "$PENDING_FILE"; then
  echo "[verify_iommu_amd_wave4_required] stale pending entry detected in ${PENDING_FILE#"$ROOT_DIR"/}: AMD-Vi Wave0 runtime pending"
  violations=$((violations + 1))
fi

if ! rg -q "iommu-wave4\\(amd-wave0\\)" "$PENDING_FILE"; then
  echo "[verify_iommu_amd_wave4_required] missing wave4 marker in ${PENDING_FILE#"$ROOT_DIR"/}"
  violations=$((violations + 1))
fi

if [[ "$violations" -gt 0 ]]; then
  echo "[verify_iommu_amd_wave4_required] FAIL: found $violations issues"
  exit 1
fi

echo "[verify_iommu_amd_wave4_required] PASS"
