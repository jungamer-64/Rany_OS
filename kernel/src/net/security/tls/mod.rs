// ============================================================================
// kernel/src/net/security/tls/mod.rs - TLS/SSL Protocol Support (Module Root)
// ============================================================================
//!
//! # TLS プロトコルサポート
//!
//! 安全な通信のためのTLS 1.3クライアントサポート。
//!
//! ## 機能
//! - TLS 1.3ハンドシェイク
//! - 暗号スイート（AES-GCM, ChaCha20-Poly1305）
//! - 証明書検証

mod buffer;
mod config;
mod credentials;
mod protocol;

mod connection;
pub(crate) mod crypto;
pub mod error;

#[cfg(all(test, not(feature = "qemu-test-export")))]
mod tests;

#[cfg(feature = "qemu-test-export")]
pub mod qemu_tests;

pub use config::{TlsClientConfig, TlsClientConfigError, TlsServerName};
pub use connection::{
    KeyUpdateAction, TlsEstablishedSession, TlsHandshake, TlsHandshakeStep, TlsInboundPlaintext,
};
pub use credentials::Certificate;
pub use error::{TlsError, TlsResult};
pub use protocol::{CipherSuite, TlsVersion};

pub(crate) use buffer::TlsBytes;
pub(crate) use config::{
    NegotiatedCipherSuite, TLS_CA_CERTS_CAPACITY, TLS_CERT_CHAIN_CAPACITY, TLS_SERVER_NAME_CAPACITY,
};
pub(crate) use credentials::ServerPublicKey;
pub(crate) use protocol::{AlertDescription, ContentType, HandshakeType};
