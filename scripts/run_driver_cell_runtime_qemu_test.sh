#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

LOG_PATH="$ROOT_DIR/target/x86_64-exorust/debug/serial.log"
TIMEOUT_SEC="${DRIVER_CELL_RUNTIME_TIMEOUT_SEC:-240}"

echo "[driver-cell-runtime] building probe fixtures"
"$ROOT_DIR/scripts/build_driver_cell_probe_fixtures.sh" --profile debug

rm -f "$LOG_PATH"

echo "[driver-cell-runtime] launching qemu-test-export runtime suite"
run_status=0
if command -v timeout >/dev/null 2>&1; then
    set +e
    timeout --foreground "${TIMEOUT_SEC}s" "$ROOT_DIR/scripts/run.sh" \
        --test \
        --tcg \
        --serial file \
        --features qemu-test-export \
        --cmdline "run_integration=driver_cell"
    run_status=$?
    set -e
else
    set +e
    "$ROOT_DIR/scripts/run.sh" \
        --test \
        --tcg \
        --serial file \
        --features qemu-test-export \
        --cmdline "run_integration=driver_cell"
    run_status=$?
    set -e
fi

if [[ "$run_status" -eq 124 || "$run_status" -eq 137 ]]; then
    echo "[driver-cell-runtime] run.sh timed out" >&2
    pkill -f qemu-system-x86_64 >/dev/null 2>&1 || true
    exit 1
fi

if [[ "$run_status" -ne 0 ]]; then
    echo "[driver-cell-runtime] run.sh failed with status $run_status" >&2
    exit "$run_status"
fi

if [[ ! -f "$LOG_PATH" ]]; then
    echo "[driver-cell-runtime] missing serial log: $LOG_PATH" >&2
    exit 1
fi

summary_line="$(
    grep -E "\\[driver-cell-runtime\\] summary pass=[0-9]+ fail=[0-9]+ blocked=[0-9]+" "$LOG_PATH" \
        | tail -n 1 || true
)"
if [[ -z "$summary_line" ]]; then
    echo "[driver-cell-runtime] summary marker not found in serial log" >&2
    exit 1
fi

pass_count="$(echo "$summary_line" | sed -n 's/.*pass=\([0-9]\+\).*/\1/p')"
fail_count="$(echo "$summary_line" | sed -n 's/.*fail=\([0-9]\+\).*/\1/p')"
blocked_count="$(echo "$summary_line" | sed -n 's/.*blocked=\([0-9]\+\).*/\1/p')"

if grep -Eq "\\[driver-cell-runtime\\] case .* \\.\\.\\. fail" "$LOG_PATH"; then
    echo "[driver-cell-runtime] case failure found in serial log" >&2
    exit 1
fi

if grep -Eq "\\[driver-cell-runtime\\] case .* \\.\\.\\. blocked" "$LOG_PATH"; then
    echo "[driver-cell-runtime] blocked case found in serial log" >&2
    exit 1
fi

case_count="$(grep -Ec "\\[driver-cell-runtime\\] case " "$LOG_PATH" || true)"
if [[ "$case_count" -lt 8 ]]; then
    echo "[driver-cell-runtime] expected at least 8 case lines, found $case_count" >&2
    exit 1
fi

if [[ "${fail_count:-1}" != "0" || "${blocked_count:-1}" != "0" ]]; then
    echo "[driver-cell-runtime] non-zero summary: $summary_line" >&2
    exit 1
fi

echo "[driver-cell-runtime] PASS (pass=$pass_count fail=$fail_count blocked=$blocked_count)"
