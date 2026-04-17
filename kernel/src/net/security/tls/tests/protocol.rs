use super::super::credentials::base64_decode_payload;
use super::super::crypto::legacy::compute_tls_mac_into;
use super::super::protocol::ContentType;
use super::super::{CipherSuite, TlsConfig, TlsVersion};
use alloc::vec::Vec;

fn compute_tls_mac(
    mac_key: &[u8],
    seq_num: u64,
    content_type: u8,
    version: TlsVersion,
    fragment: &[u8],
    use_sha1: bool,
) -> Vec<u8> {
    let (mac, len) = compute_tls_mac_into(mac_key, seq_num, content_type, version, fragment, use_sha1);
    mac[..len].to_vec()
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub(crate) fn test_tls_mac_sha1() {
    let key = [0x0Au8; 20];
    let mac = compute_tls_mac(
        &key,
        0,
        ContentType::ApplicationData as u8,
        TlsVersion::TLS_1_0,
        b"hello",
        true,
    );
    assert_eq!(mac.len(), 20);

    let mac2 = compute_tls_mac(
        &key,
        0,
        ContentType::ApplicationData as u8,
        TlsVersion::TLS_1_0,
        b"hello",
        true,
    );
    assert_eq!(mac, mac2);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub(crate) fn test_tls_mac_sha256() {
    let key = [0x0Bu8; 32];
    let mac = compute_tls_mac(
        &key,
        0,
        ContentType::ApplicationData as u8,
        TlsVersion::TLS_1_2,
        b"hello",
        false,
    );
    assert_eq!(mac.len(), 32);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub(crate) fn test_tls_mac_seq_affects_output() {
    let key = [0x0Au8; 20];
    let mac1 = compute_tls_mac(
        &key,
        0,
        ContentType::ApplicationData as u8,
        TlsVersion::TLS_1_0,
        b"hello",
        true,
    );
    let mac2 = compute_tls_mac(
        &key,
        1,
        ContentType::ApplicationData as u8,
        TlsVersion::TLS_1_0,
        b"hello",
        true,
    );
    assert_ne!(mac1, mac2);
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
    let mut bytes = [0u8; 5];
    assert_eq!(result.copy_into(&mut bytes), 5);
    assert_eq!(&bytes, b"Hello");

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
