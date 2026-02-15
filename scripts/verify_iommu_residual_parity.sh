#!/usr/bin/env bash
set -euo pipefail

# Validates canonical residual test names against required no_std smoke mappings.
# Scope: migration parity visibility only (separate from #[test] allowlist guard).

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PARITY_FILE="$ROOT_DIR/scripts/qemu_iommu_residual_parity.lst"
PENDING_FILE="$ROOT_DIR/scripts/qemu_pending_cases.lst"
IOMMU_TESTS_FILE="$ROOT_DIR/kernel/src/io/iommu/tests.rs"
IOMMU_QEMU_TESTS_FILE="$ROOT_DIR/kernel/src/io/iommu/qemu_tests.rs"
KERNEL_WRAPPER_FILE="$ROOT_DIR/kernel/src/qemu_tests.rs"
KERNEL_SUITE_FILE="$ROOT_DIR/qemu-suites/kernel/src/main.rs"

if [[ ! -f "$PARITY_FILE" ]]; then
  echo "[verify_iommu_residual_parity] missing parity file: $PARITY_FILE" >&2
  exit 1
fi

if [[ ! -f "$PENDING_FILE" ]]; then
  echo "[verify_iommu_residual_parity] missing pending file: $PENDING_FILE" >&2
  exit 1
fi

violations=0
line_no=0
declare -A seen_original=()
declare -A seen_smoke=()

while IFS= read -r raw_line || [[ -n "$raw_line" ]]; do
  line_no=$((line_no + 1))
  line="$(echo "$raw_line" | sed -E 's/^[[:space:]]+//;s/[[:space:]]+$//')"

  if [[ -z "$line" || "$line" == \#* ]]; then
    continue
  fi

  IFS='|' read -r original_case required_smoke_case status notes extra <<<"$line"
  original_case="$(echo "${original_case:-}" | sed -E 's/^[[:space:]]+//;s/[[:space:]]+$//')"
  required_smoke_case="$(echo "${required_smoke_case:-}" | sed -E 's/^[[:space:]]+//;s/[[:space:]]+$//')"
  status="$(echo "${status:-}" | sed -E 's/^[[:space:]]+//;s/[[:space:]]+$//')"
  notes="$(echo "${notes:-}" | sed -E 's/^[[:space:]]+//;s/[[:space:]]+$//')"
  extra="$(echo "${extra:-}" | sed -E 's/^[[:space:]]+//;s/[[:space:]]+$//')"

  if [[ -n "$extra" || -z "$original_case" || -z "$required_smoke_case" || -z "$status" || -z "$notes" ]]; then
    echo "[verify_iommu_residual_parity] invalid format at ${PARITY_FILE}:${line_no}: '$line'"
    violations=$((violations + 1))
    continue
  fi

  if [[ -n "${seen_original[$original_case]+x}" ]]; then
    echo "[verify_iommu_residual_parity] duplicate original_case '${original_case}' in ${PARITY_FILE#$ROOT_DIR/}"
    violations=$((violations + 1))
  fi
  seen_original["$original_case"]=1

  if [[ -n "${seen_smoke[$required_smoke_case]+x}" ]]; then
    echo "[verify_iommu_residual_parity] duplicate required_smoke_case '${required_smoke_case}' in ${PARITY_FILE#$ROOT_DIR/}"
    violations=$((violations + 1))
  fi
  seen_smoke["$required_smoke_case"]=1

  if ! rg -q "$original_case" "$PENDING_FILE"; then
    echo "[verify_iommu_residual_parity] missing canonical pending entry for '${original_case}' in ${PENDING_FILE#$ROOT_DIR/}"
    violations=$((violations + 1))
  fi

  if ! rg -q "fn ${original_case}\\(" "$IOMMU_TESTS_FILE"; then
    echo "[verify_iommu_residual_parity] missing original case '${original_case}' in ${IOMMU_TESTS_FILE#$ROOT_DIR/}"
    violations=$((violations + 1))
  fi

  if ! rg -q "pub fn ${required_smoke_case}\\(" "$IOMMU_QEMU_TESTS_FILE"; then
    echo "[verify_iommu_residual_parity] missing required smoke '${required_smoke_case}' in ${IOMMU_QEMU_TESTS_FILE#$ROOT_DIR/}"
    violations=$((violations + 1))
  fi

  wrapper_case="iommu_${required_smoke_case}"
  if ! rg -q "pub fn ${wrapper_case}\\(" "$KERNEL_WRAPPER_FILE"; then
    echo "[verify_iommu_residual_parity] missing wrapper '${wrapper_case}' in ${KERNEL_WRAPPER_FILE#$ROOT_DIR/}"
    violations=$((violations + 1))
  fi

  if ! rg -q "${wrapper_case}" "$KERNEL_SUITE_FILE"; then
    echo "[verify_iommu_residual_parity] missing suite wiring '${wrapper_case}' in ${KERNEL_SUITE_FILE#$ROOT_DIR/}"
    violations=$((violations + 1))
  fi
done < "$PARITY_FILE"

if [[ "$violations" -gt 0 ]]; then
  echo "[verify_iommu_residual_parity] FAIL: found $violations issues"
  exit 1
fi

echo "[verify_iommu_residual_parity] PASS"
