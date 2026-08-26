// ============================================================================
// kernel/src/net/security/tls/qemu_tests/protocol.rs - TLS 1.3 protocol smokes
// ============================================================================

use super::super::credentials::base64_decode_payload;
use super::super::{CipherSuite, TlsClientConfig, TlsTrustAnchors, TlsVersion};

pub fn wave8_tls_cipher_suite_helpers_smoke() -> bool {
    CipherSuite::TLS_CHACHA20_POLY1305_SHA256.is_chacha20_poly1305()
        && !CipherSuite::TLS_AES_128_GCM_SHA256.is_chacha20_poly1305()
        && CipherSuite::TLS_AES_128_GCM_SHA256.is_aes_gcm()
        && CipherSuite::TLS_AES_256_GCM_SHA384.is_aes_gcm()
        && !CipherSuite::TLS_CHACHA20_POLY1305_SHA256.is_aes_gcm()
        && CipherSuite::TLS_AES_128_GCM_SHA256.key_len() == 16
        && CipherSuite::TLS_AES_256_GCM_SHA384.key_len() == 32
        && CipherSuite::TLS_CHACHA20_POLY1305_SHA256.key_len() == 32
        && CipherSuite::TLS_AES_128_GCM_SHA256.iv_len() == 12
        && CipherSuite::TLS_CHACHA20_POLY1305_SHA256.iv_len() == 12
}

pub fn wave8_tls_base64_decode_smoke() -> bool {
    let result = base64_decode_payload("SGVsbG8=");
    let empty = base64_decode_payload("");
    let hello_ok = if let Some(payload) = result {
        crate::net::payload::PayloadSpanRef::from_payload(&payload).eq_bytes(b"Hello")
    } else {
        false
    };
    hello_ok && empty.is_none()
}

pub fn wave8_tls_tls_version_smoke() -> bool {
    TlsVersion::TLS_1_3.major() == 3 && TlsVersion::TLS_1_3.minor() == 4
}

pub fn wave8_tls_cipher_suite_defaults_smoke() -> bool {
    let defaults = TlsClientConfig::for_server_name("example.com", TlsTrustAnchors::empty())
        .expect("test server name fits")
        .cipher_suites;
    defaults.len() == 3
        && defaults.contains(CipherSuite::TLS_AES_128_GCM_SHA256)
        && defaults.contains(CipherSuite::TLS_AES_256_GCM_SHA384)
        && defaults.contains(CipherSuite::TLS_CHACHA20_POLY1305_SHA256)
}
