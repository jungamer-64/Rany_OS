// ============================================================================
// kernel/src/net/security/tls/qemu_tests/mod.rs - セキュリティ / TLS / QEMUテスト モジュール
// ============================================================================

mod connection;
mod crypto;
mod protocol;

pub use connection::{
    wave8_tls_process_handshake_truncated_header_smoke,
    wave8_tls_tls_connection_client_hello_smoke,
    wave8_tls_tls_connection_encrypt_not_established_smoke,
    wave8_tls_tls_connection_initial_state_smoke, wave8_tls_tls13_client_hello_key_share_smoke,
    wave8_tls_tls13_client_hello_supported_versions_smoke,
    wave8_tls_tls13_coalesced_application_records_smoke, wave8_tls_tls13_initial_state_smoke,
    wave8_tls_tls13_strip_content_type_smoke,
};
pub use crypto::{
    wave8_ecdh_group_from_named_group_p256_smoke, wave8_ecdh_p256_key_exchange_symmetry_smoke,
    wave8_ecdh_p256_public_key_length_smoke, wave8_ecdh_p256_reject_invalid_peer_key_smoke,
    wave8_tls_aes_ctr_roundtrip_smoke, wave8_tls_aes_gcm_256_roundtrip_smoke,
    wave8_tls_aes_gcm_auth_failure_smoke, wave8_tls_aes_gcm_corrupted_ciphertext_smoke,
    wave8_tls_aes_gcm_empty_plaintext_smoke,
    wave8_tls_aes_gcm_key_auth_failure_preserves_output_buffer_smoke,
    wave8_tls_aes_gcm_key_in_place_roundtrip_smoke, wave8_tls_aes_gcm_key_invalid_nonce_len_smoke,
    wave8_tls_aes_gcm_roundtrip_smoke, wave8_tls_aes_key_expansion_smoke,
    wave8_tls_chacha20_poly1305_auth_failure_smoke,
    wave8_tls_chacha20_poly1305_empty_plaintext_smoke,
    wave8_tls_chacha20_poly1305_rfc8439_decrypt_smoke,
    wave8_tls_chacha20_poly1305_rfc8439_encrypt_smoke, wave8_tls_chacha20_poly1305_roundtrip_smoke,
    wave8_tls_chacha20_rfc8439_block_smoke, wave8_tls_chacha20_rfc8439_encrypt_smoke,
    wave8_tls_der_parse_integer_smoke, wave8_tls_der_parse_sequence_smoke,
    wave8_tls_der_parse_tag_length_smoke, wave8_tls_generate_random_different_calls_smoke,
    wave8_tls_generate_random_not_all_zeros_smoke, wave8_tls_gf_mul_basic_smoke,
    wave8_tls_gf128_mul_zero_smoke, wave8_tls_hkdf_expand_label_different_labels_smoke,
    wave8_tls_hkdf_expand_label_length_smoke, wave8_tls_hkdf_expand_zero_length_smoke,
    wave8_tls_hkdf_extract_empty_salt_smoke, wave8_tls_hkdf_rfc5869_case1_expand_smoke,
    wave8_tls_hkdf_rfc5869_case1_extract_smoke, wave8_tls_hmac_sha256_long_key_smoke,
    wave8_tls_hmac_sha256_rfc4231_case1_smoke, wave8_tls_hmac_sha256_rfc4231_case2_smoke,
    wave8_tls_hmac_sha256_rfc4231_case3_smoke, wave8_tls_hmac_sha384_rfc4231_case1_smoke,
    wave8_tls_hmac_sha384_rfc4231_case2_smoke, wave8_tls_p256_point_on_curve_smoke,
    wave8_tls_p256_scalar_mul_base_smoke, wave8_tls_poly1305_rfc8439_smoke,
    wave8_tls_rsa_biguint_mul_div_smoke, wave8_tls_rsa_modexp_medium_smoke,
    wave8_tls_rsa_modexp_small_smoke, wave8_tls_rsa_pkcs1_verify_bad_sig_smoke,
    wave8_tls_rsa_pkcs1_verify_smoke, wave8_tls_sha384_abc_smoke, wave8_tls_sha384_empty_smoke,
    wave8_tls_tls13_derive_secret_smoke, wave8_tls_tls13_derive_traffic_keys_smoke,
    wave8_tls_tls13_early_secret_no_psk_smoke, wave8_tls_tls13_finished_key_and_verify_data_smoke,
    wave8_tls_tls13_finished_round_trip_smoke, wave8_tls_tls13_full_key_schedule_smoke,
    wave8_tls_tls13_handshake_secret_smoke, wave8_tls_tls13_hkdf_expand_label_rfc8446_smoke,
    wave8_tls_tls13_key_schedule_chain_consistency_smoke, wave8_tls_tls13_master_secret_smoke,
    wave8_tls_x509_extract_rsa_pubkey_smoke, wave8_tls_x509_parse_self_signed_smoke,
    wave8_tls_x509_rejects_invalid_time_values_smoke,
    wave8_tls_x509_rejects_strict_der_negatives_smoke,
    wave8_tls_x509_signature_algorithm_oid_smoke,
    wave8_tls_x509_tls13_leaf_requires_digital_signature_smoke,
};
pub use protocol::{
    wave8_tls_base64_decode_smoke, wave8_tls_cipher_suite_defaults_smoke,
    wave8_tls_cipher_suite_helpers_smoke, wave8_tls_protocol_config_defaults_smoke,
    wave8_tls_protocol_version_bytes_smoke, wave8_tls_tls_version_smoke,
};
