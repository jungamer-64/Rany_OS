use super::super::credentials::base64_decode_payload;
use super::super::{CipherSuite, SessionCache, TlsConfig, TlsVersion};

pub fn wave8_tls_protocol_version_bytes_smoke() -> bool {
    TlsVersion::TLS_1_2.to_bytes() == [0x03, 0x03]
        && TlsVersion::TLS_1_3.to_bytes() == [0x03, 0x04]
        && TlsVersion::TLS_1_2 < TlsVersion::TLS_1_3
}

pub fn wave8_tls_protocol_config_defaults_smoke() -> bool {
    let config = TlsConfig::new();
    config.cipher_suites.contains(&CipherSuite::TLS_AES_128_GCM_SHA256)
        && config.cipher_suites.contains(&CipherSuite::TLS_CHACHA20_POLY1305_SHA256)
        && !config.signature_schemes.is_empty()
        && !config.named_groups.is_empty()
}

pub fn wave8_tls_protocol_session_cache_empty_smoke() -> bool {
    let cache = SessionCache::new();
    cache.find(&[0u8; 32]).is_none()
}

pub fn wave8_tls_cipher_suite_helpers_smoke() -> bool {
    CipherSuite::TLS_CHACHA20_POLY1305_SHA256.is_chacha20_poly1305()
        && CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256.is_chacha20_poly1305()
        && CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256.is_chacha20_poly1305()
        && !CipherSuite::TLS_AES_128_GCM_SHA256.is_chacha20_poly1305()
        && CipherSuite::TLS_AES_128_GCM_SHA256.is_aes_gcm()
        && CipherSuite::TLS_AES_256_GCM_SHA384.is_aes_gcm()
        && CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256.is_aes_gcm()
        && !CipherSuite::TLS_CHACHA20_POLY1305_SHA256.is_aes_gcm()
        && CipherSuite::TLS_AES_128_GCM_SHA256.key_len() == 16
        && CipherSuite::TLS_AES_256_GCM_SHA384.key_len() == 32
        && CipherSuite::TLS_CHACHA20_POLY1305_SHA256.key_len() == 32
        && CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256.iv_len() == 4
        && CipherSuite::TLS_AES_128_GCM_SHA256.iv_len() == 12
        && CipherSuite::TLS_CHACHA20_POLY1305_SHA256.iv_len() == 12
}

pub fn wave8_tls_base64_decode_smoke() -> bool {
    let result = base64_decode_payload("SGVsbG8=");
    let empty = base64_decode_payload("");
    let hello_ok = if let Some(span) = result {
        let mut bytes = [0u8; 5];
        span.copy_into(&mut bytes) == 5 && &bytes == b"Hello"
    } else {
        false
    };
    hello_ok && matches!(empty, Some(ref v) if v.is_empty())
}

pub fn wave8_tls_tls_version_smoke() -> bool {
    TlsVersion::TLS_1_2.major() == 3
        && TlsVersion::TLS_1_2.minor() == 3
        && TlsVersion::TLS_1_3.major() == 3
        && TlsVersion::TLS_1_3.minor() == 4
        && TlsVersion::TLS_1_0.minor() == 1
}

pub fn wave8_tls_cipher_suite_defaults_smoke() -> bool {
    let defaults = CipherSuite::defaults();
    !defaults.is_empty()
        && defaults.contains(&CipherSuite::TLS_AES_128_GCM_SHA256)
        && defaults.contains(&CipherSuite::TLS_AES_256_GCM_SHA384)
        && defaults.contains(&CipherSuite::TLS_CHACHA20_POLY1305_SHA256)
}

pub fn wave8_tls_tls_version_ordering_smoke() -> bool {
    TlsVersion::TLS_1_0 < TlsVersion::TLS_1_1
        && TlsVersion::TLS_1_1 < TlsVersion::TLS_1_2
        && TlsVersion::TLS_1_2 < TlsVersion::TLS_1_3
        && TlsVersion::TLS_1_3 >= TlsVersion::TLS_1_3
}
