use super::*;


// ========================================================================
// TLS MAC Tests
// ========================================================================

#[test_case]
pub(crate) fn test_tls_mac_sha1() {
    let key = [0x0Au8; 20];
    let mac = compute_tls_mac(
        &key, 0, ContentType::ApplicationData as u8,
        TlsVersion::TLS_1_0, b"hello", true,
    );
    assert_eq!(mac.len(), 20); // SHA-1 output
    // Should be deterministic
    let mac2 = compute_tls_mac(
        &key, 0, ContentType::ApplicationData as u8,
        TlsVersion::TLS_1_0, b"hello", true,
    );
    assert_eq!(mac, mac2);
}

#[test_case]
pub(crate) fn test_tls_mac_sha256() {
    let key = [0x0Bu8; 32];
    let mac = compute_tls_mac(
        &key, 0, ContentType::ApplicationData as u8,
        TlsVersion::TLS_1_2, b"hello", false,
    );
    assert_eq!(mac.len(), 32); // SHA-256 output
}

#[test_case]
pub(crate) fn test_tls_mac_seq_affects_output() {
    let key = [0x0Au8; 20];
    let mac1 = compute_tls_mac(
        &key, 0, ContentType::ApplicationData as u8,
        TlsVersion::TLS_1_0, b"hello", true,
    );
    let mac2 = compute_tls_mac(
        &key, 1, ContentType::ApplicationData as u8,
        TlsVersion::TLS_1_0, b"hello", true,
    );
    assert_ne!(mac1, mac2);
}

// ========================================================================
// CBC Cipher Suite Helper Tests
// ========================================================================

#[test_case]
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

#[test_case]
pub(crate) fn test_cbc_ecdhe_cipher_suite() {
    let suite = CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256;
    assert!(suite.is_cbc());
    assert!(!suite.is_rsa_key_transport());
    assert!(!suite.uses_sha1_mac());
    assert_eq!(suite.mac_key_len(), 32);
    assert_eq!(suite.mac_len(), 32);
}

#[test_case]
pub(crate) fn test_aead_not_cbc() {
    let suite = CipherSuite::TLS_AES_128_GCM_SHA256;
    assert!(!suite.is_cbc());
    assert!(!suite.is_rsa_key_transport());
    assert!(!suite.is_legacy_compatible());
}
