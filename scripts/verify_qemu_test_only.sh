#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
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
