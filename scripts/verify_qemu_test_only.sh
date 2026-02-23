#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# This file is only for legacy #[test] exception control.
# Pending migration tracking is managed separately by scripts/qemu_pending_cases.lst.
# IOMMU residual canonical<->smoke parity is verified by scripts/verify_iommu_residual_parity.sh.
# IOMMU AMD Wave4 required wiring is verified by scripts/verify_iommu_amd_wave4_required.sh.
# IOMMU AMD Wave5 required wiring is verified by scripts/verify_iommu_amd_wave5_required.sh.
# IOMMU Wave5 residual/canonical required wiring is verified by scripts/verify_iommu_wave5_residual_canonical_required.sh.
# Graphics/Framebuffer Wave6 required wiring is verified by scripts/verify_graphics_framebuffer_wave6_required.sh.
# MM Wave7 required wiring (Phase A + Phase E/F) is verified by scripts/verify_mm_wave7_required.sh.
# NET endpoint required wiring (68 cases) is verified by scripts/verify_net_endpoint_required.sh.
# NET core stack required wiring (90 cases) is verified by scripts/verify_net_core_required.sh.
# Official QEMU warning-free gate is verified by scripts/verify_qemu_official_warning_free.sh.
# Duplicate wrapper/helper root-cause cleanup is verified by scripts/verify_qemu_warning_root_cause_cleanup.sh.
ALLOWLIST_FILE="$ROOT_DIR/scripts/qemu_legacy_test_allowlist.lst"

if [[ ! -f "$ALLOWLIST_FILE" ]]; then
  echo "missing allowlist: $ALLOWLIST_FILE" >&2
  exit 1
fi

mapfile -t ALLOWLIST < <(sed -E '/^\s*#/d;/^\s*$/d' "$ALLOWLIST_FILE")

declare -A ALLOWSET
for item in "${ALLOWLIST[@]}"; do
  ALLOWSET["$item"]=1
done

violations=0

while IFS= read -r line; do
  file="${line%%:*}"
  file="${file#./}"

  # Official orchestrator test entrypoint is always allowed.
  if [[ "$file" == "qemu-tests/src/lib.rs" ]]; then
    continue
  fi

  if [[ -n "${ALLOWSET[$file]+x}" ]]; then
    continue
  fi

  echo "[verify_qemu_test_only] unexpected #[test] detected: $line"
  violations=$((violations + 1))
done < <(cd "$ROOT_DIR" && rg -n '^\s*#\[test\]' --glob '**/*.rs' .)

if [[ "$violations" -gt 0 ]]; then
  echo "[verify_qemu_test_only] FAIL: found $violations unexpected #[test] occurrences"
  echo "If intentional during migration, add file to scripts/qemu_legacy_test_allowlist.lst"
  exit 1
fi

echo "[verify_qemu_test_only] PASS"
