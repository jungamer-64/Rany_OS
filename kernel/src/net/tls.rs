// ============================================================================
// src/net/tls.rs - TLS/SSL Protocol Support (Module Root)
// ============================================================================
//!
//! # TLS プロトコルサポート
//!
//! 安全な通信のためのTLS 1.2/1.3サポート。
//!
//! ## 機能
//! - TLS 1.0/1.1/1.2/1.3ハンドシェイク
//! - 暗号スイート（AES-GCM, AES-CBC, ChaCha20-Poly1305）
//! - 証明書検証
//! - セッション再開 (TLS 1.2 abbreviated + TLS 1.3 PSK)
//! - 0-RTT Early Data

#![allow(dead_code)]

use alloc::vec::Vec;

// ── Sub-modules ──────────────────────────────────────────────────────────────

pub mod types;
pub mod error;
pub mod connection;
pub mod crypto;

#[cfg(test)]
mod tests;

#[cfg(feature = "qemu-test-export")]
pub mod qemu_tests;

// ── Re-exports (外部インターフェース維持) ──────────────────────────────────────

pub use types::*;
pub use error::{TlsError, TlsResult};
pub use connection::TlsConnection;

// Crypto re-exports (public API)
pub use crypto::{
    // HMAC
    hmac_sha256, hmac_sha384, SHA256_OUTPUT_SIZE, SHA384_OUTPUT_SIZE,
    // HKDF + TLS 1.3 Key Schedule
    hkdf_extract, hkdf_expand, hkdf_expand_label,
    tls13_derive_secret, tls13_early_secret, tls13_handshake_secret,
    tls13_master_secret, tls13_derive_traffic_keys, tls13_finished_key,
    tls13_verify_data,
    // SHA-384 variants
    hkdf_extract_sha384, hkdf_expand_sha384, hkdf_expand_label_sha384,
    tls13_derive_secret_sha384, tls13_early_secret_sha384, tls13_handshake_secret_sha384,
    tls13_master_secret_sha384, tls13_derive_traffic_keys_sha384,
    tls13_finished_key_sha384, tls13_verify_data_sha384,
    // TLS 1.2 PRF
    tls12_prf, derive_master_secret, derive_key_block,
    derive_key_block_sha384, derive_master_secret_tls10,
    derive_master_secret_sha384, p_sha384, tls12_prf_sha384,
    // ChaCha20-Poly1305
    chacha20_encrypt, chacha20_poly1305_encrypt, chacha20_poly1305_decrypt,
    poly1305_mac,
    // Legacy (MD5, SHA-1, TLS 1.0)
    Md5, md5_compute, Sha1, sha1_compute,
    hmac_md5, hmac_sha1, tls10_prf,
};

// Crypto re-exports (crate-internal)
pub(crate) use crypto::{
    // AES Core
    aes_key_expansion, gf_mul, aes_expand_key_schedule,
    aes_encrypt_block, aes_encrypt_block_with_schedule,
    aes_ctr_with_schedule, aes_ctr,
    // AES-GCM
    gf128_mul, aes_gcm_encrypt, aes_gcm_decrypt,
    // AES-CBC
    aes_cbc_encrypt, aes_cbc_decrypt, tls_add_padding, tls_verify_padding,
    // ChaCha20 internals
    chacha20_block,
    // Legacy internals
    compute_tls_mac,
    // Random
    generate_random,
};

#[cfg(feature = "qemu-test-export")]
pub use crypto::{qemu_test_set_random_override_seed, qemu_test_clear_random_override};

// ============================================================================
// Shared Test Fixtures
// ============================================================================

/// TLS 1.2 multi-handshake fixture: ServerHelloDone + valid Finished message
///
/// Used by both unit tests and QEMU integration tests.
#[cfg(any(test, feature = "qemu-test-export"))]
fn tls12_multi_handshake_fixture_server_hello_done_plus_valid_finished() -> Vec<u8> {
    // Handshake #1: ServerHelloDone (len=0)
    let server_hello_done = [14u8, 0, 0, 0];

    // Finished verify_data = PRF(master_secret, "server finished", Hash(handshake_messages))[0..12]
    // For TlsConnection::new(), master_secret starts as all-zero 48 bytes.
    let handshake_hash = crate::loader::sha256::compute(&server_hello_done);
    let master_secret = [0u8; 48];
    let mut verify_data = [0u8; 12];
    tls12_prf(&master_secret, b"server finished", &handshake_hash, &mut verify_data);

    // Handshake #2: Finished (len=12) + verify_data
    let mut data = Vec::with_capacity(server_hello_done.len() + 4 + verify_data.len());
    data.extend_from_slice(&server_hello_done);
    data.extend_from_slice(&[20u8, 0, 0, 12]);
    data.extend_from_slice(&verify_data);
    data
}
