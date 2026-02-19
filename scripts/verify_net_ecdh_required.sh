#!/usr/bin/env bash
set -euo pipefail

# Validates that NET/ECDH required exports are wired into suite_kernel.
# - net_ecdh_exports: X25519 deterministic set
# - net_ecdh_phase_b_exports: P-256 deterministic set
#
# Also guards that P-256 required routing stays on net_ecdh wrappers only;
# legacy net_tls_wave8_*p256* compatibility wrappers must not be wired into suite_kernel.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ECDH_ENTRY_FILE="$ROOT_DIR/kernel/src/net/ecdh.rs"
ECDH_EXPORT_ROOT="$ROOT_DIR/kernel/src/net/ecdh"
KERNEL_WRAPPER_FILE="$ROOT_DIR/kernel/src/qemu_tests.rs"
KERNEL_SUITE_ROOT="$ROOT_DIR/qemu-suites/kernel/src"
PENDING_FILE="$ROOT_DIR/scripts/qemu_pending_cases.lst"

for required_file in \
  "$ECDH_ENTRY_FILE" \
  "$ECDH_EXPORT_ROOT" \
  "$KERNEL_WRAPPER_FILE" \
  "$KERNEL_SUITE_ROOT" \
  "$PENDING_FILE"
do
  if [[ ! -e "$required_file" ]]; then
    echo "[verify_net_ecdh_required] missing file: $required_file" >&2
    exit 1
  fi
done

x25519_cases=(
  "x25519_key_exchange_symmetry"
  "x25519_public_key_length"
  "x25519_group"
  "group_from_named_group"
  "x25519_reject_invalid_peer_key"
  "x25519_rfc7748_vector"
)

phase_b_p256_cases=(
  "p256_key_exchange_symmetry"
  "p256_public_key_length"
  "p256_reject_invalid_peer_key"
  "group_from_named_group_p256"
  "p256_point_on_curve"
  "p256_scalar_mul_base"
)

violations=0

for suite_group in \
  "net_ecdh_exports" \
  "net_ecdh_phase_b_exports"
do
  if ! rg -q "${suite_group}" "$KERNEL_SUITE_ROOT"; then
    echo "[verify_net_ecdh_required] missing ${suite_group} under ${KERNEL_SUITE_ROOT#"$ROOT_DIR"/}"
    violations=$((violations + 1))
  fi
done

# P-256 required routing must stay on net_ecdh wrappers; TLS-route wrappers are compatibility only.
for forbidden_wrapper in \
  "net_tls_wave8_p256_point_on_curve_smoke" \
  "net_tls_wave8_p256_scalar_mul_base_smoke" \
  "net_tls_wave8_ecdh_p256_key_exchange_symmetry_smoke" \
  "net_tls_wave8_ecdh_p256_public_key_length_smoke" \
  "net_tls_wave8_ecdh_p256_reject_invalid_peer_key_smoke" \
  "net_tls_wave8_ecdh_group_from_named_group_p256_smoke"
do
  if rg -q "${forbidden_wrapper}" "$KERNEL_SUITE_ROOT"; then
    echo "[verify_net_ecdh_required] unexpected TLS-routed P-256 wiring '${forbidden_wrapper}' under ${KERNEL_SUITE_ROOT#"$ROOT_DIR"/}"
    violations=$((violations + 1))
  fi
done

if ! rg -q "pub mod qemu_tests" "$ECDH_EXPORT_ROOT"; then
  echo "[verify_net_ecdh_required] missing qemu_tests module declaration under ${ECDH_EXPORT_ROOT#"$ROOT_DIR"/}"
  violations=$((violations + 1))
fi

verify_case() {
  local case_name="$1"
  local export_fn="$2"
  local wrapper_fn="$3"

  if ! rg -q "pub fn ${export_fn}\\(" "$ECDH_EXPORT_ROOT"; then
    echo "[verify_net_ecdh_required] missing ECDH export '${export_fn}' under ${ECDH_EXPORT_ROOT#"$ROOT_DIR"/}"
    violations=$((violations + 1))
  fi

  if ! rg -q "pub fn ${wrapper_fn}\\(" "$KERNEL_WRAPPER_FILE"; then
    echo "[verify_net_ecdh_required] missing wrapper '${wrapper_fn}' in ${KERNEL_WRAPPER_FILE#"$ROOT_DIR"/}"
    violations=$((violations + 1))
  fi

  if ! rg -q "${wrapper_fn}" "$KERNEL_SUITE_ROOT"; then
    echo "[verify_net_ecdh_required] missing suite wiring '${wrapper_fn}' under ${KERNEL_SUITE_ROOT#"$ROOT_DIR"/}"
    violations=$((violations + 1))
  fi

  if rg -q "${case_name}" "$PENDING_FILE"; then
    echo "[verify_net_ecdh_required] promoted case '${case_name}' still listed in ${PENDING_FILE#"$ROOT_DIR"/}"
    violations=$((violations + 1))
  fi
}

for case_name in "${x25519_cases[@]}"; do
  verify_case "$case_name" "ecdh_${case_name}_smoke" "net_ecdh_${case_name}_smoke"
done

for case_name in "${phase_b_p256_cases[@]}"; do
  verify_case "$case_name" "ecdh_${case_name}_smoke" "net_ecdh_${case_name}_smoke"
done

for marker in \
  "NET ECDH X25519 deterministic set is promoted to required suite_kernel" \
  "NET ECDH Phase B P-256 deterministic set is promoted to required suite_kernel"
do
  if ! rg -q "${marker}" "$PENDING_FILE"; then
    echo "[verify_net_ecdh_required] missing marker '${marker}' in ${PENDING_FILE#"$ROOT_DIR"/}"
    violations=$((violations + 1))
  fi
done

if [[ "$violations" -gt 0 ]]; then
  echo "[verify_net_ecdh_required] FAIL: found $violations issues"
  exit 1
fi

echo "[verify_net_ecdh_required] PASS"
