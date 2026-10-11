#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if command -v rg >/dev/null 2>&1 && rg --version >/dev/null 2>&1; then
  SEARCH="rg"
else
  SEARCH="grep"
fi

fail=0

search_count() {
  local pattern="$1"
  shift
  if [[ "$SEARCH" == "rg" ]]; then
    { rg -n -- "$pattern" "$@" 2>/dev/null || true; } | wc -l | tr -d ' '
  else
    { grep -R -n -E -- "$pattern" "$@" 2>/dev/null || true; } | wc -l | tr -d ' '
  fi
}

echo "[M05-GUARD] Checking consume_cpu_time wiring..."
scheduler_accounting_hits=$(search_count "consume_cpu_time\(" kernel/src/task/scheduler.rs)
scheduler_admission_hits=$(search_count "is_domain_runnable_now\(" kernel/src/task/scheduler.rs)
if [[ "$scheduler_accounting_hits" -eq 0 || "$scheduler_admission_hits" -eq 0 ]]; then
  echo "[M05-GUARD] FAIL: scheduler quota wiring missing (accounting=$scheduler_accounting_hits admission=$scheduler_admission_hits)"
  fail=1
fi

echo "[M05-GUARD] Checking quota victim selection in heap OOM path..."
quota_path_hits=$(search_count "select_oom_victim" kernel/src/heap/oom.rs)
if [[ "$quota_path_hits" -eq 0 ]]; then
  echo "[M05-GUARD] FAIL: select_oom_victim path missing in heap/oom.rs"
  fail=1
fi

if [[ "$fail" -ne 0 ]]; then
  exit 1
fi

echo "[M05-GUARD] PASS"
