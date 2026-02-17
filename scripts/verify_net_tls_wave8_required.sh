#!/usr/bin/env bash
set -euo pipefail

# Validates that NET/TLS Wave8 Phase A+B1+B2+C+D+E+F deterministic exports are wired into suite_kernel.

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

phase_a_cases=(
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

phase_b1_cases=(
  "tls13_early_secret_no_psk"
  "tls13_handshake_secret"
  "tls13_master_secret"
  "tls13_derive_secret"
  "tls13_derive_traffic_keys"
  "tls13_finished_key_and_verify_data"
  "tls13_full_key_schedule"
  "tls13_hkdf_expand_label_rfc8446"
  "tls13_key_schedule_chain_consistency"
  "tls13_finished_round_trip"
  "tls13_initial_state"
)

phase_b2_cases=(
  "tls13_client_hello_key_share"
  "tls13_client_hello_supported_versions"
  "tls13_client_hello_psk_modes"
  "tls13_strip_content_type"
)

phase_c_cases=(
  "hmac_sha256_long_key"
  "hkdf_extract_empty_salt"
  "hkdf_expand_zero_length"
  "chacha20_poly1305_auth_failure"
  "chacha20_poly1305_roundtrip"
  "chacha20_poly1305_empty_plaintext"
  "aes_gcm_256_roundtrip"
  "aes_gcm_corrupted_ciphertext"
  "aes_gcm_empty_plaintext"
  "aes_key_expansion"
  "derive_master_secret_length"
  "derive_key_block_length"
  "derive_master_secret_deterministic"
  "derive_master_secret_differs_with_input"
  "tls12_prf_deterministic"
  "tls12_prf_different_labels"
  "hkdf_expand_label_length"
  "hkdf_expand_label_different_labels"
  "cipher_suite_helpers"
  "base64_decode"
  "tls_version"
  "cipher_suite_defaults"
  "tls_version_ordering"
)

phase_d_cases=(
  "tls_connection_initial_state"
  "tls_connection_client_hello"
  "tls_connection_encrypt_not_established"
  "process_handshake_multiple_messages"
  "process_handshake_truncated_header"
)

phase_e_cases=(
  "generate_random_not_all_zeros"
  "generate_random_different_calls"
  "sha384_empty"
  "sha384_abc"
  "hmac_sha384_rfc4231_case1"
  "hmac_sha384_rfc4231_case2"
)

phase_f_cases=(
  "der_parse_tag_length"
  "der_parse_integer"
  "der_parse_sequence"
  "x509_parse_self_signed"
  "x509_extract_rsa_pubkey"
  "x509_signature_algorithm_oid"
  "rsa_modexp_small"
  "rsa_modexp_medium"
  "rsa_pkcs1_verify"
  "rsa_pkcs1_verify_bad_sig"
  "rsa_biguint_mul_div"
)

violations=0

for suite_group in \
  "net_tls_wave8_phase_a_exports" \
  "net_tls_wave8_phase_b1_exports" \
  "net_tls_wave8_phase_b2_exports" \
  "net_tls_wave8_phase_c_exports" \
  "net_tls_wave8_phase_d_exports" \
  "net_tls_wave8_phase_e_exports" \
  "net_tls_wave8_phase_f_exports"
do
  if ! rg -q "${suite_group}" "$KERNEL_SUITE_FILE"; then
    echo "[verify_net_tls_wave8_required] missing ${suite_group} in ${KERNEL_SUITE_FILE#"$ROOT_DIR"/}"
    violations=$((violations + 1))
  fi
done

if ! rg -q "pub mod qemu_tests" "$TLS_EXPORT_FILE"; then
  echo "[verify_net_tls_wave8_required] missing qemu_tests module in ${TLS_EXPORT_FILE#"$ROOT_DIR"/}"
  violations=$((violations + 1))
fi

if ! rg -q "pub fn qemu_test_set_random_override_seed\(" "$TLS_EXPORT_FILE"; then
  echo "[verify_net_tls_wave8_required] missing qemu random override setter in ${TLS_EXPORT_FILE#"$ROOT_DIR"/}"
  violations=$((violations + 1))
fi

if ! rg -q "pub fn qemu_test_clear_random_override\(" "$TLS_EXPORT_FILE"; then
  echo "[verify_net_tls_wave8_required] missing qemu random override clearer in ${TLS_EXPORT_FILE#"$ROOT_DIR"/}"
  violations=$((violations + 1))
fi

verify_case() {
  local case_name="$1"
  local export_fn="$2"
  local wrapper_fn="$3"

  if ! rg -q "pub fn ${export_fn}\\(" "$TLS_EXPORT_FILE"; then
    echo "[verify_net_tls_wave8_required] missing TLS export '${export_fn}' in ${TLS_EXPORT_FILE#"$ROOT_DIR"/}"
    violations=$((violations + 1))
  fi

  if ! rg -q "pub fn ${wrapper_fn}\\(" "$KERNEL_WRAPPER_FILE"; then
    echo "[verify_net_tls_wave8_required] missing wrapper '${wrapper_fn}' in ${KERNEL_WRAPPER_FILE#"$ROOT_DIR"/}"
    violations=$((violations + 1))
  fi

  if ! rg -q "${wrapper_fn}" "$KERNEL_SUITE_FILE"; then
    echo "[verify_net_tls_wave8_required] missing suite wiring '${wrapper_fn}' in ${KERNEL_SUITE_FILE#"$ROOT_DIR"/}"
    violations=$((violations + 1))
  fi

  if rg -q "${case_name}" "$PENDING_FILE"; then
    echo "[verify_net_tls_wave8_required] promoted case '${case_name}' still listed in ${PENDING_FILE#"$ROOT_DIR"/}"
    violations=$((violations + 1))
  fi
}

for case_name in "${phase_a_cases[@]}"; do
  verify_case "$case_name" "wave8_tls_${case_name}_smoke" "net_tls_wave8_${case_name}_smoke"
done

for case_name in "${phase_b1_cases[@]}"; do
  verify_case "$case_name" "wave8_tls_${case_name}_smoke" "net_tls_wave8_${case_name}_smoke"
done

for case_name in "${phase_b2_cases[@]}"; do
  verify_case "$case_name" "wave8_tls_${case_name}_smoke" "net_tls_wave8_${case_name}_smoke"
done

for case_name in "${phase_c_cases[@]}"; do
  verify_case "$case_name" "wave8_tls_${case_name}_smoke" "net_tls_wave8_${case_name}_smoke"
done

for case_name in "${phase_d_cases[@]}"; do
  verify_case "$case_name" "wave8_tls_${case_name}_smoke" "net_tls_wave8_${case_name}_smoke"
done

for case_name in "${phase_e_cases[@]}"; do
  verify_case "$case_name" "wave8_tls_${case_name}_smoke" "net_tls_wave8_${case_name}_smoke"
done

for case_name in "${phase_f_cases[@]}"; do
  verify_case "$case_name" "wave8_tls_${case_name}_smoke" "net_tls_wave8_${case_name}_smoke"
done

for marker in \
  "NET TLS Wave8 Phase A deterministic set is promoted to required suite_kernel" \
  "NET TLS Wave8 Phase B1 deterministic set is promoted to required suite_kernel" \
  "NET TLS Wave8 Phase B2 deterministic set is promoted to required suite_kernel" \
  "NET TLS Wave8 Phase C deterministic set is promoted to required suite_kernel" \
  "NET TLS Wave8 Phase D deterministic set is promoted to required suite_kernel" \
  "NET TLS Wave8 Phase E deterministic set is promoted to required suite_kernel" \
  "NET TLS Wave8 Phase F deterministic set is promoted to required suite_kernel"
do
  if ! rg -q "${marker}" "$PENDING_FILE"; then
    echo "[verify_net_tls_wave8_required] missing marker '${marker}' in ${PENDING_FILE#"$ROOT_DIR"/}"
    violations=$((violations + 1))
  fi
done

if ! rg -q "NET TLS Wave8 residual monitored cases \(post-Phase F\): none" "$PENDING_FILE"; then
  echo "[verify_net_tls_wave8_required] missing post-Phase F residual marker in ${PENDING_FILE#"$ROOT_DIR"/}"
  violations=$((violations + 1))
fi

if [[ "$violations" -gt 0 ]]; then
  echo "[verify_net_tls_wave8_required] FAIL: found $violations issues"
  exit 1
fi

echo "[verify_net_tls_wave8_required] PASS"
