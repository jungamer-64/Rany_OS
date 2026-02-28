#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

SEARCH_DIRS=(kernel interfaces)
FN_PATTERN='\bfn[[:space:]]+sys_(log|alloc|dealloc|sleep|panic)\b'
SYM_PATTERN='"sys_(log|alloc|dealloc|sleep|panic)"'
KAPI_PATTERN='__exorust_kernel_api_v1|KERNEL_API_SYMBOL'

if command -v rg >/dev/null 2>&1; then
  fn_hits="$(rg -n -e "$FN_PATTERN" "${SEARCH_DIRS[@]}" || true)"
  sym_hits="$(rg -n -e "$SYM_PATTERN" "${SEARCH_DIRS[@]}" || true)"
  kapi_hits="$(rg -n -e "$KAPI_PATTERN" "${SEARCH_DIRS[@]}" || true)"
else
  fn_hits="$(grep -RInE "$FN_PATTERN" "${SEARCH_DIRS[@]}" || true)"
  sym_hits="$(grep -RInE "$SYM_PATTERN" "${SEARCH_DIRS[@]}" || true)"
  kapi_hits="$(grep -RInE "$KAPI_PATTERN" "${SEARCH_DIRS[@]}" || true)"
fi

failed=0

if [ -n "$fn_hits" ]; then
  echo "ERROR: legacy sys_* function boundary found:"
  echo "$fn_hits"
  failed=1
fi

if [ -n "$sym_hits" ]; then
  echo "ERROR: legacy sys_* symbol string found:"
  echo "$sym_hits"
  failed=1
fi

if [ -z "$kapi_hits" ]; then
  echo "ERROR: Kernel API symbol bridge missing (__exorust_kernel_api_v1|KERNEL_API_SYMBOL)"
  failed=1
fi

if [ "$failed" -ne 0 ]; then
  exit 1
fi

echo "PASS: no legacy sys_* boundary and KernelApi symbol bridge detected."
