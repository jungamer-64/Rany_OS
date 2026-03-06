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

#[cfg(any(test, feature = "qemu-test-export"))]
use self::crypto::tls12_prf;
#[cfg(any(test, feature = "qemu-test-export"))]
use alloc::vec::Vec;

// ── Sub-modules ──────────────────────────────────────────────────────────────

pub mod connection;
pub mod crypto;
pub mod error;
pub mod types;

#[cfg(all(test, not(feature = "qemu-test-export")))]
mod tests;

#[cfg(feature = "qemu-test-export")]
pub mod qemu_tests;

// ── Re-exports (外部インターフェース維持) ──────────────────────────────────────

pub use types::*;

// Crypto re-exports (public API)

// Crypto re-exports (crate-internal)
pub(crate) use crypto::generate_random;

#[cfg(feature = "qemu-test-export")]
pub use crypto::{qemu_test_clear_random_override, qemu_test_set_random_override_seed};

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
    let handshake_hash = crate::crypto::sha256::compute(&server_hello_done);
    let master_secret = [0u8; 48];
    let mut verify_data = [0u8; 12];
    tls12_prf(
        &master_secret,
        b"server finished",
        &handshake_hash,
        &mut verify_data,
    );

    // Handshake #2: Finished (len=12) + verify_data
    let mut data = Vec::with_capacity(server_hello_done.len() + 4 + verify_data.len());
    data.extend_from_slice(&server_hello_done);
    data.extend_from_slice(&[20u8, 0, 0, 12]);
    data.extend_from_slice(&verify_data);
    data
}
