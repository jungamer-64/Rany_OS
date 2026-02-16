#!/usr/bin/env bash
set -euo pipefail

# Validates that NET/TLS Wave8 Phase A deterministic exports are wired into suite_kernel.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TLS_EXPORT_FILE="$ROOT_DIR/kernel/src/net/tls.rs"
KERNEL_WRAPPER_FILE="$ROOT_DIR/kernel/src/qemu_tests.rs"
KERNEL_SUITE_FILE="$ROOT_DIR/qemu-suites/kernel/src/main.rs"
PENDING_FILE="$ROOT_DIR/scripts/qemu_pending_cases.lst"

for required_file in \
  "$TLS_EXPORT_FILE" \
  "$KERNEL_WRAPPER_FILE" \
  "$KERNEL_SUITE_FILE" \
  "$PENDING_FILE"
do
  if [[ ! -f "$required_file" ]]; then
    echo "[verify_net_tls_wave8_required] missing file: $required_file" >&2
    exit 1
  fi
done

cases=(
  "hmac_sha256_rfc4231_case1"
  "hmac_sha256_rfc4231_case2"
  "hmac_sha256_rfc4231_case3"
  "hkdf_rfc5869_case1_extract"
  "hkdf_rfc5869_case1_expand"
  "chacha20_rfc8439_block"
  "chacha20_rfc8439_encrypt"
  "poly1305_rfc8439"
  "chacha20_poly1305_rfc8439_encrypt"
  "chacha20_poly1305_rfc8439_decrypt"
  "aes_gcm_roundtrip"
  "aes_gcm_auth_failure"
  "aes_ctr_roundtrip"
  "gf128_mul_zero"
  "gf_mul_basic"
)

violations=0

if ! rg -q "net_tls_wave8_phase_a_exports" "$KERNEL_SUITE_FILE"; then
  echo "[verify_net_tls_wave8_required] missing net_tls_wave8_phase_a_exports in ${KERNEL_SUITE_FILE#$ROOT_DIR/}"
  violations=$((violations + 1))
fi

if ! rg -q "pub mod qemu_tests" "$TLS_EXPORT_FILE"; then
  echo "[verify_net_tls_wave8_required] missing qemu_tests module in ${TLS_EXPORT_FILE#$ROOT_DIR/}"
  violations=$((violations + 1))
fi

for case_name in "${cases[@]}"; do
  export_fn="wave8_tls_${case_name}_smoke"
  wrapper_fn="net_tls_wave8_${case_name}_smoke"

  if ! rg -q "pub fn ${export_fn}\\(" "$TLS_EXPORT_FILE"; then
    echo "[verify_net_tls_wave8_required] missing TLS export '${export_fn}' in ${TLS_EXPORT_FILE#$ROOT_DIR/}"
    violations=$((violations + 1))
  fi

  if ! rg -q "pub fn ${wrapper_fn}\\(" "$KERNEL_WRAPPER_FILE"; then
    echo "[verify_net_tls_wave8_required] missing wrapper '${wrapper_fn}' in ${KERNEL_WRAPPER_FILE#$ROOT_DIR/}"
    violations=$((violations + 1))
  fi

  if ! rg -q "${wrapper_fn}" "$KERNEL_SUITE_FILE"; then
    echo "[verify_net_tls_wave8_required] missing suite wiring '${wrapper_fn}' in ${KERNEL_SUITE_FILE#$ROOT_DIR/}"
    violations=$((violations + 1))
  fi

  if rg -q "${case_name}" "$PENDING_FILE"; then
    echo "[verify_net_tls_wave8_required] promoted case '${case_name}' still listed in ${PENDING_FILE#$ROOT_DIR/}"
    violations=$((violations + 1))
  fi
done

if ! rg -q "NET TLS Wave8 Phase A deterministic set is promoted to required suite_kernel" "$PENDING_FILE"; then
  echo "[verify_net_tls_wave8_required] missing Wave8 Phase A marker in ${PENDING_FILE#$ROOT_DIR/}"
  violations=$((violations + 1))
fi

if [[ "$violations" -gt 0 ]]; then
  echo "[verify_net_tls_wave8_required] FAIL: found $violations issues"
  exit 1
fi

echo "[verify_net_tls_wave8_required] PASS"
