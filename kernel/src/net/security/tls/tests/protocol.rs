// ============================================================================
// kernel/src/net/security/tls/tests/protocol.rs - セキュリティ / TLS / テスト / プロトコル
// ============================================================================

use super::super::credentials::base64_decode_payload;
use super::super::{CipherSuite, TlsConfig, TlsVersion};

/// CipherSuite helper methods
#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub(crate) fn test_cipher_suite_helpers() {
    assert!(CipherSuite::TLS_CHACHA20_POLY1305_SHA256.is_chacha20_poly1305());
    assert!(CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256.is_chacha20_poly1305());
    assert!(CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256.is_chacha20_poly1305());
    assert!(!CipherSuite::TLS_AES_128_GCM_SHA256.is_chacha20_poly1305());

    assert!(CipherSuite::TLS_AES_128_GCM_SHA256.is_aes_gcm());
    assert!(CipherSuite::TLS_AES_256_GCM_SHA384.is_aes_gcm());
    assert!(CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256.is_aes_gcm());
    assert!(!CipherSuite::TLS_CHACHA20_POLY1305_SHA256.is_aes_gcm());

    assert_eq!(CipherSuite::TLS_AES_128_GCM_SHA256.key_len(), 16);
    assert_eq!(CipherSuite::TLS_AES_256_GCM_SHA384.key_len(), 32);
    assert_eq!(CipherSuite::TLS_CHACHA20_POLY1305_SHA256.key_len(), 32);

    assert_eq!(CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256.iv_len(), 4);
    assert_eq!(CipherSuite::TLS_AES_128_GCM_SHA256.iv_len(), 12);
    assert_eq!(CipherSuite::TLS_CHACHA20_POLY1305_SHA256.iv_len(), 12);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub(crate) fn test_cbc_cipher_suite_helpers() {
    let suite = CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA;
    assert!(suite.is_cbc());
    assert!(suite.is_rsa_key_transport());
    assert!(suite.uses_sha1_mac());
    assert_eq!(suite.mac_key_len(), 20);
    assert_eq!(suite.mac_len(), 20);
    assert_eq!(suite.cbc_iv_len(), 16);
    assert!(suite.is_legacy_compatible());
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub(crate) fn test_cbc_ecdhe_cipher_suite() {
    let suite = CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256;
    assert!(suite.is_cbc());
    assert!(!suite.is_rsa_key_transport());
    assert!(!suite.uses_sha1_mac());
    assert_eq!(suite.mac_key_len(), 32);
    assert_eq!(suite.mac_len(), 32);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub(crate) fn test_aead_not_cbc() {
    let suite = CipherSuite::TLS_AES_128_GCM_SHA256;
    assert!(!suite.is_cbc());
    assert!(!suite.is_rsa_key_transport());
    assert!(!suite.is_legacy_compatible());
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
pub(crate) fn test_tls_version() {
    assert_eq!(TlsVersion::TLS_1_2.major(), 3);
    assert_eq!(TlsVersion::TLS_1_2.minor(), 3);
    assert_eq!(TlsVersion::TLS_1_3.major(), 3);
    assert_eq!(TlsVersion::TLS_1_3.minor(), 4);
    assert_eq!(TlsVersion::TLS_1_0.minor(), 1);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub(crate) fn test_tls_version_ordering() {
    assert!(TlsVersion::TLS_1_0 < TlsVersion::TLS_1_1);
    assert!(TlsVersion::TLS_1_1 < TlsVersion::TLS_1_2);
    assert!(TlsVersion::TLS_1_2 < TlsVersion::TLS_1_3);
    assert!(TlsVersion::TLS_1_3 >= TlsVersion::TLS_1_3);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub(crate) fn test_cipher_suite_defaults() {
    let defaults = CipherSuite::defaults();
    assert!(!defaults.is_empty());
    assert!(defaults.contains(&CipherSuite::TLS_AES_128_GCM_SHA256));
    assert!(defaults.contains(&CipherSuite::TLS_AES_256_GCM_SHA384));
    assert!(defaults.contains(&CipherSuite::TLS_CHACHA20_POLY1305_SHA256));
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub(crate) fn test_tls_config_defaults() {
    let config = TlsConfig::new();
    assert!(!config.cipher_suites.is_empty());
    assert!(!config.signature_schemes.is_empty());
    assert!(!config.named_groups.is_empty());
    assert!(config.ca_certs.is_empty());
    assert!(config.client_cert.is_none());
    assert!(config.client_key.is_none());
}
