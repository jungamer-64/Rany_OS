// ============================================================================
// kernel/src/net/security/tls/tests/protocol.rs - TLS 1.3 protocol tests
// ============================================================================

use super::super::credentials::base64_decode_payload;
use super::super::{CipherSuite, TlsClientConfig, TlsVersion};

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub(crate) fn test_tls13_cipher_suite_helpers() {
    assert!(CipherSuite::TLS_CHACHA20_POLY1305_SHA256.is_chacha20_poly1305());
    assert!(!CipherSuite::TLS_AES_128_GCM_SHA256.is_chacha20_poly1305());

    assert!(CipherSuite::TLS_AES_128_GCM_SHA256.is_aes_gcm());
    assert!(CipherSuite::TLS_AES_256_GCM_SHA384.is_aes_gcm());
    assert!(!CipherSuite::TLS_CHACHA20_POLY1305_SHA256.is_aes_gcm());

    assert_eq!(CipherSuite::TLS_AES_128_GCM_SHA256.key_len(), 16);
    assert_eq!(CipherSuite::TLS_AES_256_GCM_SHA384.key_len(), 32);
    assert_eq!(CipherSuite::TLS_CHACHA20_POLY1305_SHA256.key_len(), 32);

    assert_eq!(CipherSuite::TLS_AES_128_GCM_SHA256.iv_len(), 12);
    assert_eq!(CipherSuite::TLS_AES_256_GCM_SHA384.iv_len(), 12);
    assert_eq!(CipherSuite::TLS_CHACHA20_POLY1305_SHA256.iv_len(), 12);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub(crate) fn test_base64_decode() {
    let result = base64_decode_payload("SGVsbG8=");
    assert!(result.is_some());
    let Some(result) = result else {
        return;
    };
    assert!(crate::net::payload::PayloadSpanRef::from_payload(&result).eq_bytes(b"Hello"));

    let empty = base64_decode_payload("");
    assert!(matches!(empty, Some(ref payload) if payload.is_empty()));
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub(crate) fn test_tls_version_is_closed_to_tls13() {
    assert_eq!(TlsVersion::TLS_1_3.major(), 3);
    assert_eq!(TlsVersion::TLS_1_3.minor(), 4);
    assert_eq!(TlsVersion::TLS_1_3.to_bytes(), [0x03, 0x04]);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub(crate) fn test_cipher_suite_defaults_are_tls13_only() {
    let defaults = CipherSuite::defaults();
    assert_eq!(defaults.len(), 3);
    assert!(defaults.contains(&CipherSuite::TLS_AES_128_GCM_SHA256));
    assert!(defaults.contains(&CipherSuite::TLS_AES_256_GCM_SHA384));
    assert!(defaults.contains(&CipherSuite::TLS_CHACHA20_POLY1305_SHA256));
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub(crate) fn test_tls_config_defaults_are_tls13_client_only() {
    let config = TlsClientConfig::new();
    assert_eq!(config.cipher_suites.len(), 3);
    assert!(!config.signature_schemes.is_empty());
    assert!(!config.named_groups.is_empty());
    assert!(config.ca_certs.is_empty());
}
