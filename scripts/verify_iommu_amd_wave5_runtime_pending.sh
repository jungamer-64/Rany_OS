#!/usr/bin/env bash
set -euo pipefail

# Validates that AMD Wave1+Wave5 smoke exports stay wired into runtime pending
# and execute before runtime preflight blocking.
# Scope: runtime pending guard (separate from required wiring and #[test] allowlist).

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AMD_EXPORT_FILE="$ROOT_DIR/kernel/src/io/iommu/amd/qemu_tests.rs"
IOMMU_WRAPPER_FILE="$ROOT_DIR/kernel/src/io/iommu/qemu_tests.rs"
KERNEL_WRAPPER_FILE="$ROOT_DIR/kernel/src/qemu_tests.rs"
RUNTIME_SUITE_FILE="$ROOT_DIR/qemu-suites/kernel-runtime-pending/src/main.rs"
PENDING_FILE="$ROOT_DIR/scripts/qemu_pending_cases.lst"

for required_file in \
  "$AMD_EXPORT_FILE" \
  "$IOMMU_WRAPPER_FILE" \
  "$KERNEL_WRAPPER_FILE" \
  "$RUNTIME_SUITE_FILE" \
  "$PENDING_FILE"
do
  if [[ ! -f "$required_file" ]]; then
    echo "[verify_iommu_amd_wave5_runtime_pending] missing file: $required_file" >&2
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

if ! rg -q "const AMD_EXPECTED_CASES: u64 = 11;" "$RUNTIME_SUITE_FILE"; then
  echo "[verify_iommu_amd_wave5_runtime_pending] missing AMD expected count constant (11) in ${RUNTIME_SUITE_FILE#$ROOT_DIR/}"
  violations=$((violations + 1))
fi

if ! rg -q "amd_expected=" "$RUNTIME_SUITE_FILE"; then
  echo "[verify_iommu_amd_wave5_runtime_pending] missing amd_expected logging token in ${RUNTIME_SUITE_FILE#$ROOT_DIR/}"
  violations=$((violations + 1))
fi

for case_name in "${wave1_cases[@]}"; do
  amd_export="wave1_${case_name}_smoke"
  iommu_wrapper="amd_wave1_${case_name}_smoke"
  kernel_wrapper="iommu_amd_wave1_${case_name}_smoke"
  runtime_case="iommu_amd_wave1_${case_name}"
  pending_marker="amd_wave1_${case_name}"

  if ! rg -q "pub fn ${amd_export}\\(" "$AMD_EXPORT_FILE"; then
    echo "[verify_iommu_amd_wave5_runtime_pending] missing AMD export '${amd_export}' in ${AMD_EXPORT_FILE#$ROOT_DIR/}"
    violations=$((violations + 1))
  fi

  if ! rg -q "pub fn ${iommu_wrapper}\\(" "$IOMMU_WRAPPER_FILE"; then
    echo "[verify_iommu_amd_wave5_runtime_pending] missing IOMMU wrapper '${iommu_wrapper}' in ${IOMMU_WRAPPER_FILE#$ROOT_DIR/}"
    violations=$((violations + 1))
  fi

  if ! rg -q "pub fn ${kernel_wrapper}\\(" "$KERNEL_WRAPPER_FILE"; then
    echo "[verify_iommu_amd_wave5_runtime_pending] missing kernel wrapper '${kernel_wrapper}' in ${KERNEL_WRAPPER_FILE#$ROOT_DIR/}"
    violations=$((violations + 1))
  fi

  if ! rg -q "\"${runtime_case}\"" "$RUNTIME_SUITE_FILE"; then
    echo "[verify_iommu_amd_wave5_runtime_pending] missing runtime suite case label '${runtime_case}' in ${RUNTIME_SUITE_FILE#$ROOT_DIR/}"
    violations=$((violations + 1))
  fi

  if ! rg -q "${kernel_wrapper}" "$RUNTIME_SUITE_FILE"; then
    echo "[verify_iommu_amd_wave5_runtime_pending] missing runtime suite wiring '${kernel_wrapper}' in ${RUNTIME_SUITE_FILE#$ROOT_DIR/}"
    violations=$((violations + 1))
  fi

  if ! rg -q "$pending_marker" "$PENDING_FILE"; then
    echo "[verify_iommu_amd_wave5_runtime_pending] missing pending marker '${pending_marker}' in ${PENDING_FILE#$ROOT_DIR/}"
    violations=$((violations + 1))
  fi
done

for case_name in "${wave5_cases[@]}"; do
  amd_export="wave5_${case_name}_smoke"
  iommu_wrapper="amd_wave5_${case_name}_smoke"
  kernel_wrapper="iommu_amd_wave5_${case_name}_smoke"
  runtime_case="iommu_amd_wave5_${case_name}"
  pending_marker="amd_wave5_${case_name}"

  if ! rg -q "pub fn ${amd_export}\\(" "$AMD_EXPORT_FILE"; then
    echo "[verify_iommu_amd_wave5_runtime_pending] missing AMD export '${amd_export}' in ${AMD_EXPORT_FILE#$ROOT_DIR/}"
    violations=$((violations + 1))
  fi

  if ! rg -q "pub fn ${iommu_wrapper}\\(" "$IOMMU_WRAPPER_FILE"; then
    echo "[verify_iommu_amd_wave5_runtime_pending] missing IOMMU wrapper '${iommu_wrapper}' in ${IOMMU_WRAPPER_FILE#$ROOT_DIR/}"
    violations=$((violations + 1))
  fi

  if ! rg -q "pub fn ${kernel_wrapper}\\(" "$KERNEL_WRAPPER_FILE"; then
    echo "[verify_iommu_amd_wave5_runtime_pending] missing kernel wrapper '${kernel_wrapper}' in ${KERNEL_WRAPPER_FILE#$ROOT_DIR/}"
    violations=$((violations + 1))
  fi

  if ! rg -q "\"${runtime_case}\"" "$RUNTIME_SUITE_FILE"; then
    echo "[verify_iommu_amd_wave5_runtime_pending] missing runtime suite case label '${runtime_case}' in ${RUNTIME_SUITE_FILE#$ROOT_DIR/}"
    violations=$((violations + 1))
  fi

  if ! rg -q "${kernel_wrapper}" "$RUNTIME_SUITE_FILE"; then
    echo "[verify_iommu_amd_wave5_runtime_pending] missing runtime suite wiring '${kernel_wrapper}' in ${RUNTIME_SUITE_FILE#$ROOT_DIR/}"
    violations=$((violations + 1))
  fi

  if ! rg -q "$pending_marker" "$PENDING_FILE"; then
    echo "[verify_iommu_amd_wave5_runtime_pending] missing pending marker '${pending_marker}' in ${PENDING_FILE#$ROOT_DIR/}"
    violations=$((violations + 1))
  fi
done

first_amd_line="$(rg -n '"iommu_amd_wave1_cmdqueue_map_unmap_with_domain"' "$RUNTIME_SUITE_FILE" | head -n1 | cut -d: -f1 || true)"
preflight_line="$(rg -n 'if !memory_ready \{' "$RUNTIME_SUITE_FILE" | head -n1 | cut -d: -f1 || true)"

if [[ -z "$first_amd_line" || -z "$preflight_line" ]]; then
  echo "[verify_iommu_amd_wave5_runtime_pending] failed to locate amd wiring or preflight guard lines in ${RUNTIME_SUITE_FILE#$ROOT_DIR/}"
  violations=$((violations + 1))
elif (( first_amd_line >= preflight_line )); then
  echo "[verify_iommu_amd_wave5_runtime_pending] AMD Wave1 wiring appears after preflight guard in ${RUNTIME_SUITE_FILE#$ROOT_DIR/} (amd line ${first_amd_line}, preflight line ${preflight_line})"
  violations=$((violations + 1))
fi

if [[ "$violations" -gt 0 ]]; then
  echo "[verify_iommu_amd_wave5_runtime_pending] FAIL: found $violations issues"
  exit 1
fi

echo "[verify_iommu_amd_wave5_runtime_pending] PASS (wave1=5 + wave5=6 = 11 cases)"
