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
