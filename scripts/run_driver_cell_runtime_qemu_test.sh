#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

TIMEOUT_SEC="${DRIVER_DOMAIN_RUNTIME_TIMEOUT_SEC:-240}"
CASE_FILTER="${DRIVER_DOMAIN_RUNTIME_CASE:-}"

echo "[driver-domain-runtime] launching full-boot profile=driver_domain"
run_status=0
if command -v timeout >/dev/null 2>&1; then
    set +e
    if [[ -n "$CASE_FILTER" ]]; then
        timeout --foreground "${TIMEOUT_SEC}s" env \
            RUST_TEST_THREADS=1 \
            QEMU_TEST_PROFILE_ONLY=driver_domain \
            QEMU_TEST_CASE_FILTER="$CASE_FILTER" \
            QEMU_TEST_TIMEOUT_SECS="$TIMEOUT_SEC" \
            cargo test -p qemu-tests fullboot_pr_required -- --exact --nocapture
    else
        timeout --foreground "${TIMEOUT_SEC}s" env \
            RUST_TEST_THREADS=1 \
            QEMU_TEST_PROFILE_ONLY=driver_domain \
            QEMU_TEST_TIMEOUT_SECS="$TIMEOUT_SEC" \
            cargo test -p qemu-tests fullboot_pr_required -- --exact --nocapture
    fi
    run_status=$?
    set -e
else
    set +e
    if [[ -n "$CASE_FILTER" ]]; then
        env \
            RUST_TEST_THREADS=1 \
            QEMU_TEST_PROFILE_ONLY=driver_domain \
            QEMU_TEST_CASE_FILTER="$CASE_FILTER" \
            QEMU_TEST_TIMEOUT_SECS="$TIMEOUT_SEC" \
            cargo test -p qemu-tests fullboot_pr_required -- --exact --nocapture
    else
        env \
            RUST_TEST_THREADS=1 \
            QEMU_TEST_PROFILE_ONLY=driver_domain \
            QEMU_TEST_TIMEOUT_SECS="$TIMEOUT_SEC" \
            cargo test -p qemu-tests fullboot_pr_required -- --exact --nocapture
    fi
    run_status=$?
    set -e
fi

if [[ "$run_status" -eq 124 || "$run_status" -eq 137 ]]; then
    echo "[driver-domain-runtime] cargo test timed out" >&2
    pkill -f qemu-system-x86_64 >/dev/null 2>&1 || true
    exit 1
fi

if [[ "$run_status" -ne 0 ]]; then
    echo "[driver-domain-runtime] cargo test failed with status $run_status" >&2
    exit "$run_status"
fi

LOG_PATH="$(
    find "$ROOT_DIR/target/qemu-logs" -maxdepth 1 -type f -name 'fullboot-driver_domain*.log' 2>/dev/null \
        | grep -v 'qemu-stderr' \
        | xargs -r ls -1t \
        | head -n 1 || true
)"
if [[ -z "${LOG_PATH:-}" || ! -f "$LOG_PATH" ]]; then
    echo "[driver-domain-runtime] missing full-boot serial log under target/qemu-logs" >&2
    exit 1
fi

summary_line="$(
    grep -aE "\\[kernel-test\\] summary pass=[0-9]+ fail=[0-9]+ blocked=[0-9]+" "$LOG_PATH" \
        | tail -n 1 || true
)"
if [[ -z "$summary_line" ]]; then
    echo "[driver-domain-runtime] kernel-test summary marker not found in serial log" >&2
    exit 1
fi

pass_count="$(echo "$summary_line" | sed -n 's/.*pass=\([0-9]\+\).*/\1/p')"
fail_count="$(echo "$summary_line" | sed -n 's/.*fail=\([0-9]\+\).*/\1/p')"
blocked_count="$(echo "$summary_line" | sed -n 's/.*blocked=\([0-9]\+\).*/\1/p')"

if grep -aEq "\\[kernel-test\\] case .* fail" "$LOG_PATH"; then
    echo "[driver-domain-runtime] case failure found in serial log: $LOG_PATH" >&2
    exit 1
fi

if grep -aEq "\\[kernel-test\\] case .* blocked" "$LOG_PATH"; then
    echo "[driver-domain-runtime] blocked case found in serial log: $LOG_PATH" >&2
    exit 1
fi

case_count="$(grep -aEc "\\[kernel-test\\] case " "$LOG_PATH" || true)"
if [[ "$case_count" -lt 1 ]]; then
    echo "[driver-domain-runtime] expected at least 1 kernel-test case line, found $case_count" >&2
    exit 1
fi

if [[ "${fail_count:-1}" != "0" || "${blocked_count:-1}" != "0" ]]; then
    echo "[driver-domain-runtime] non-zero summary: $summary_line" >&2
    exit 1
fi

echo "[driver-domain-runtime] PASS (pass=$pass_count fail=$fail_count blocked=$blocked_count log=$LOG_PATH)"
