// ============================================================================
// kernel/src/net/security/tls/mod.rs - TLS/SSL Protocol Support (Module Root)
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

mod buffer;
mod config;
mod credentials;
mod protocol;
mod session;
mod state;

pub mod connection;
pub mod crypto;
pub mod error;

#[cfg(all(test, not(feature = "qemu-test-export")))]
mod tests;

#[cfg(feature = "qemu-test-export")]
pub mod qemu_tests;

pub use connection::TlsConnection;
pub use config::TlsConfig;
pub use credentials::{Certificate, PrivateKey};
pub use error::{TlsError, TlsResult};
pub use protocol::{CipherSuite, TlsVersion};
pub use session::{SessionCache, SessionTicket};
pub use state::TlsState;

pub(crate) use buffer::TlsBytes;
pub(crate) use config::{TLS_CA_CERTS_CAPACITY, TLS_CERT_CHAIN_CAPACITY, TLS_SERVER_NAME_CAPACITY};
pub(crate) use credentials::ServerPublicKey;
pub(crate) use protocol::{AlertDescription, AlertLevel, ContentType, HandshakeType};
pub(crate) use session::{SessionCacheEntry, SessionId};

// ============================================================================
// Shared Test Fixtures
// ============================================================================

/// TLS 1.2 multi-handshake fixture: ServerHelloDone + valid Finished message
///
/// Used by both unit tests and QEMU integration tests.
#[cfg(any(test, feature = "qemu-test-export"))]
fn tls12_multi_handshake_fixture_server_hello_done_plus_valid_finished() -> TlsBytes<20> {
    use self::crypto::tls12_prf;

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
    let Some(mut data) = TlsBytes::<20>::from_slice(&server_hello_done) else {
        return TlsBytes::new();
    };
    if data.append_slice(&[20u8, 0, 0, 12]).is_none() {
        return TlsBytes::new();
    }
    if data.append_slice(&verify_data).is_none() {
        return TlsBytes::new();
    }
    data
}
