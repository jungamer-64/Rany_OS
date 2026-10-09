// ============================================================================
// kernel/src/net/security/tls/tests/protocol.rs - TLS 1.3 protocol tests
// ============================================================================

use super::super::credentials::base64_decode_bytes;
use super::super::{CipherSuite, TlsClientConfig, TlsTrustAnchors, TlsVersion};

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
    assert_eq!(base64_decode_bytes("SGVsbG8=").unwrap(), b"Hello");
    assert_eq!(
        base64_decode_bytes(""),
        Err(super::super::CertificateDataError::Empty)
    );
    assert_eq!(
        base64_decode_bytes("%"),
        Err(super::super::CertificateDataError::InvalidEncoding)
    );
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn configured_certificate_owns_its_encoded_material() {
    use super::super::{Certificate, CertificateDataError};
    let mut source = [0x30, 0x00];
    let certificate = Certificate::from_der_bytes(&source).unwrap();
    source[0] = 0x31;
    assert!(certificate.der_span().eq_bytes(&[0x30, 0x00]));
    assert_eq!(source, [0x31, 0x00]);
    let pem = Certificate::from_pem("-----BEGIN CERTIFICATE-----\nMAA=\n-----END CERTIFICATE-----")
        .unwrap();
    assert!(pem.der_span().eq_bytes(&[0x30, 0x00]));
    assert!(matches!(
        Certificate::from_der_bytes(&[]),
        Err(CertificateDataError::Empty)
    ));
    assert!(matches!(
        Certificate::from_pem("-----BEGIN CERTIFICATE-----\n%\n-----END CERTIFICATE-----"),
        Err(CertificateDataError::InvalidEncoding)
    ));
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
    let defaults = TlsClientConfig::for_server_name("example.com", TlsTrustAnchors::empty())
        .expect("test server name fits")
        .cipher_suites;
    assert_eq!(defaults.len(), 3);
    assert!(defaults.contains(CipherSuite::TLS_AES_128_GCM_SHA256));
    assert!(defaults.contains(CipherSuite::TLS_AES_256_GCM_SHA384));
    assert!(defaults.contains(CipherSuite::TLS_CHACHA20_POLY1305_SHA256));
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub(crate) fn test_tls_config_defaults_are_tls13_client_only() {
    let config = TlsClientConfig::for_server_name("example.com", TlsTrustAnchors::empty())
        .expect("test server name fits");
    assert_eq!(config.cipher_suites.len(), 3);
    assert!(!config.signature_schemes.is_empty());
    assert!(!config.named_groups.is_empty());
    assert!(config.trust_anchors.is_empty());
}
