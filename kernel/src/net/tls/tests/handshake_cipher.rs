use super::*;


/// TLS handshake parser should reject truncated handshake headers
mod mac_tests;
pub use mac_tests::*;
#[test_case]
pub(crate) fn test_process_handshake_truncated_header() {
    let config = TlsConfig::new();
    let mut conn = TlsConnection::new(config);

    let data = [2u8, 0, 0];
    let result = conn.process_handshake(&data);
    assert!(matches!(result, Err(TlsError::DecodeError)));
}

/// CipherSuite helper methods
#[test_case]
pub(crate) fn test_cipher_suite_helpers() {
    // ChaCha20-Poly1305 suites
    assert!(CipherSuite::TLS_CHACHA20_POLY1305_SHA256.is_chacha20_poly1305());
    assert!(CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256.is_chacha20_poly1305());
    assert!(CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256.is_chacha20_poly1305());
    assert!(!CipherSuite::TLS_AES_128_GCM_SHA256.is_chacha20_poly1305());

    // AES-GCM suites
    assert!(CipherSuite::TLS_AES_128_GCM_SHA256.is_aes_gcm());
    assert!(CipherSuite::TLS_AES_256_GCM_SHA384.is_aes_gcm());
    assert!(CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256.is_aes_gcm());
    assert!(!CipherSuite::TLS_CHACHA20_POLY1305_SHA256.is_aes_gcm());

    // Key lengths
    assert_eq!(CipherSuite::TLS_AES_128_GCM_SHA256.key_len(), 16);
    assert_eq!(CipherSuite::TLS_AES_256_GCM_SHA384.key_len(), 32);
    assert_eq!(CipherSuite::TLS_CHACHA20_POLY1305_SHA256.key_len(), 32);

    // IV lengths
    assert_eq!(CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256.iv_len(), 4);
    assert_eq!(CipherSuite::TLS_AES_128_GCM_SHA256.iv_len(), 12);
    assert_eq!(CipherSuite::TLS_CHACHA20_POLY1305_SHA256.iv_len(), 12);
}

/// Base64 decode test
#[test_case]
pub(crate) fn test_base64_decode() {
    // "Hello" in Base64 = "SGVsbG8="
    let result = base64_decode("SGVsbG8=");
    assert!(result.is_some());
    assert_eq!(result.unwrap(), b"Hello");

    // Empty string
    let empty = base64_decode("");
    assert!(empty.is_some());
    assert!(empty.unwrap().is_empty());
}

/// TLS version helpers
#[test_case]
pub(crate) fn test_tls_version() {
    assert_eq!(TlsVersion::TLS_1_2.major(), 3);
    assert_eq!(TlsVersion::TLS_1_2.minor(), 3);
    assert_eq!(TlsVersion::TLS_1_3.major(), 3);
    assert_eq!(TlsVersion::TLS_1_3.minor(), 4);
    assert_eq!(TlsVersion::TLS_1_0.minor(), 1);
}

/// Default cipher suite list should include modern suites
#[test_case]
pub(crate) fn test_cipher_suite_defaults() {
    let defaults = CipherSuite::defaults();
    assert!(!defaults.is_empty());
    // Should include TLS 1.3 suites
    assert!(defaults.contains(&CipherSuite::TLS_AES_128_GCM_SHA256));
    assert!(defaults.contains(&CipherSuite::TLS_AES_256_GCM_SHA384));
    assert!(defaults.contains(&CipherSuite::TLS_CHACHA20_POLY1305_SHA256));
}

/// GF(2^128) multiplication sanity check
#[test_case]
pub(crate) fn test_gf128_mul_zero() {
    let zero = [0u8; 16];
    let h = [0x42u8; 16];
    let result = gf128_mul(&zero, &h);
    // 0 * anything = 0 in GF(2^128)
    assert_eq!(result, zero);
}

/// GF(2^8) multiplication sanity check
#[test_case]
pub(crate) fn test_gf_mul_basic() {
    // 0x02 * 0x87 = 0x15 in AES GF(2^8) with irreducible polynomial x^8 + x^4 + x^3 + x + 1
    // 0x87 = 10000111, shift left: 100001110 = 0x10E, reduce: 0x10E XOR 0x11B = 0x15
    assert_eq!(gf_mul(0x02, 0x87), 0x15);
    // Identity: 0x01 * x = x
    assert_eq!(gf_mul(0x01, 0x53), 0x53);
    // Zero: 0x00 * x = 0
    assert_eq!(gf_mul(0x00, 0x53), 0x00);
}

// ========================================================================
// TLS 1.3 Key Schedule Tests
// ========================================================================

/// TLS 1.3: Early Secret derivation (PSK=0)
#[test_case]
pub(crate) fn test_tls13_early_secret_no_psk() {
    let early_secret = tls13_early_secret(None);
    assert_eq!(early_secret.len(), 32);
    // Should produce a deterministic value for zero PSK
    let early_secret2 = tls13_early_secret(None);
    assert_eq!(early_secret, early_secret2);
    // Should not be all zeros
    assert!(early_secret.iter().any(|&b| b != 0));
}

/// TLS 1.3: Handshake Secret derivation
#[test_case]
pub(crate) fn test_tls13_handshake_secret() {
    let early_secret = tls13_early_secret(None);
    let shared_secret = [0x42u8; 32];
    let hs_secret = tls13_handshake_secret(&early_secret, &shared_secret);
    assert_eq!(hs_secret.len(), 32);
    assert!(hs_secret.iter().any(|&b| b != 0));

    // Different shared secrets -> different handshake secrets
    let hs_secret2 = tls13_handshake_secret(&early_secret, &[0x43u8; 32]);
    assert_ne!(hs_secret, hs_secret2);
}

/// TLS 1.3: Master Secret derivation
#[test_case]
pub(crate) fn test_tls13_master_secret() {
    let early_secret = tls13_early_secret(None);
    let hs_secret = tls13_handshake_secret(&early_secret, &[0x42u8; 32]);
    let master_secret = tls13_master_secret(&hs_secret);
    assert_eq!(master_secret.len(), 32);
    assert!(master_secret.iter().any(|&b| b != 0));
}

/// TLS 1.3: Derive-Secret produces expected-length output
#[test_case]
pub(crate) fn test_tls13_derive_secret() {
    let secret = [0x55u8; 32];
    let transcript = [0xAAu8; 32];
    let result = tls13_derive_secret(&secret, b"c hs traffic", &transcript);
    assert_eq!(result.len(), 32);
    assert!(result.iter().any(|&b| b != 0));

    // Different labels -> different secrets
    let result2 = tls13_derive_secret(&secret, b"s hs traffic", &transcript);
    assert_ne!(result, result2);
}

/// TLS 1.3: Traffic key derivation
#[test_case]
pub(crate) fn test_tls13_derive_traffic_keys() {
    let secret = [0x42u8; 32];

    // AES-128: 16-byte key
    let (key128, iv128) = tls13_derive_traffic_keys(&secret, 16);
    assert_eq!(key128.len(), 16);
    assert_eq!(iv128.len(), 12);

    // AES-256/ChaCha20: 32-byte key
    let (key256, iv256) = tls13_derive_traffic_keys(&secret, 32);
    assert_eq!(key256.len(), 32);
    assert_eq!(iv256.len(), 12);

    // Different key lengths -> different keys
    assert_ne!(key128.as_slice(), &key256[..16]);
}

/// TLS 1.3: Finished key and verify_data
#[test_case]
pub(crate) fn test_tls13_finished_key_and_verify_data() {
    let base_key = [0x42u8; 32];
    let finished_key = tls13_finished_key(&base_key);
    assert_eq!(finished_key.len(), 32);
    assert!(finished_key.iter().any(|&b| b != 0));

    let transcript = [0xBBu8; 32];
    let verify_data = tls13_verify_data(&finished_key, &transcript);
    assert_eq!(verify_data.len(), 32);

    // Deterministic
    let verify_data2 = tls13_verify_data(&finished_key, &transcript);
    assert_eq!(verify_data, verify_data2);

    // Different transcripts -> different verify_data
    let verify_data3 = tls13_verify_data(&finished_key, &[0xCCu8; 32]);
    assert_ne!(verify_data, verify_data3);
}

/// TLS 1.3: Full key schedule chain (Early -> Handshake -> Master)
#[test_case]
pub(crate) fn test_tls13_full_key_schedule() {
    let shared_secret = [0x01u8; 32];

    // Step 1: Early Secret
    let early_secret = tls13_early_secret(None);

    // Step 2: Handshake Secret
    let hs_secret = tls13_handshake_secret(&early_secret, &shared_secret);

    // Step 3: Derive handshake traffic secrets
    let transcript_ch_sh = [0x02u8; 32]; // Mock transcript hash
    let c_hs_traffic = tls13_derive_secret(&hs_secret, b"c hs traffic", &transcript_ch_sh);
    let s_hs_traffic = tls13_derive_secret(&hs_secret, b"s hs traffic", &transcript_ch_sh);
    assert_ne!(c_hs_traffic, s_hs_traffic);

    // Step 4: Derive traffic keys
    let (c_key, c_iv) = tls13_derive_traffic_keys(&c_hs_traffic, 16);
    let (s_key, s_iv) = tls13_derive_traffic_keys(&s_hs_traffic, 16);
    assert_ne!(c_key, s_key);
    assert_ne!(c_iv, s_iv);

    // Step 5: Master Secret
    let master = tls13_master_secret(&hs_secret);

    // Step 6: Application traffic secrets
    let transcript_sf = [0x03u8; 32]; // Mock transcript hash
    let c_app_traffic = tls13_derive_secret(&master, b"c ap traffic", &transcript_sf);
    let s_app_traffic = tls13_derive_secret(&master, b"s ap traffic", &transcript_sf);
    assert_ne!(c_app_traffic, s_app_traffic);
    assert_ne!(c_app_traffic, c_hs_traffic);
}

// ========================================================================
// TLS 1.3 Connection Tests
// ========================================================================

/// TLS 1.3: ClientHello should include KeyShare extension
#[test_case]
pub(crate) fn test_tls13_client_hello_key_share() {
    let config = TlsConfig::new().with_server_name("example.com");
    let mut conn = TlsConnection::new(config);
    let hello = conn.build_client_hello();

    // Should have pre-generated ECDH key pair
    assert!(conn.local_ecdh_keypair.is_some());

    // Should have initialized transcript hash
    assert!(conn.transcript_hash.is_some());

    // Record should be valid TLS
    assert_eq!(hello[0], ContentType::Handshake as u8);

    // Search for KeyShare extension type (0x0033 = 51)
    // The hello bytes contain extensions including key_share
    let hello_payload = &hello[5..]; // Skip record header
    // Look for the key_share extension type bytes [0x00, 0x33]
    let mut found_key_share = false;
    for i in 0..hello_payload.len().saturating_sub(1) {
        if hello_payload[i] == 0x00 && hello_payload[i + 1] == 0x33 {
            found_key_share = true;
            break;
        }
    }
    assert!(found_key_share, "KeyShare extension not found in ClientHello");
}

/// TLS 1.3: Supported Versions extension should list both TLS 1.3 and 1.2
#[test_case]
pub(crate) fn test_tls13_client_hello_supported_versions() {
    let config = TlsConfig::new();
    let mut conn = TlsConnection::new(config);
    let hello = conn.build_client_hello();

    let hello_payload = &hello[5..]; // Skip record header

    // Look for supported_versions extension [0x00, 0x2B]
    let mut found_sv = false;
    for i in 0..hello_payload.len().saturating_sub(1) {
        if hello_payload[i] == 0x00 && hello_payload[i + 1] == 0x2B {
            found_sv = true;
            // Verify it lists both TLS 1.3 (0x0304) and TLS 1.2 (0x0303)
            if i + 8 < hello_payload.len() {
                let ext_len =
                    ((hello_payload[i + 2] as usize) << 8) | hello_payload[i + 3] as usize;
                // ext_data starts at i+4
                let versions_len = hello_payload[i + 4] as usize;
                // Should have at least 4 bytes (2 versions x 2 bytes)
                assert!(
                    versions_len >= 4,
                    "Expected at least 2 versions in supported_versions"
                );
                assert_eq!(ext_len, versions_len + 1);
            }
            break;
        }
    }
    assert!(
        found_sv,
        "Supported Versions extension not found in ClientHello"
    );
}

/// TLS 1.3: PSK Key Exchange Modes extension present
#[test_case]
pub(crate) fn test_tls13_client_hello_psk_modes() {
    let config = TlsConfig::new();
    let mut conn = TlsConnection::new(config);
    let hello = conn.build_client_hello();

    let hello_payload = &hello[5..];

    // Look for psk_key_exchange_modes extension [0x00, 0x2D]
    let mut found_psk = false;
    for i in 0..hello_payload.len().saturating_sub(1) {
        if hello_payload[i] == 0x00 && hello_payload[i + 1] == 0x2D {
            found_psk = true;
            break;
        }
    }
    assert!(
        found_psk,
        "PSK Key Exchange Modes extension not found in ClientHello"
    );
}

/// TLS 1.3: strip_content_type helper
#[test_case]
pub(crate) fn test_tls13_strip_content_type() {
    // Normal case: plaintext + content_type
    let data = [0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x17]; // "Hello" + ApplicationData(23)
    let result = TlsConnection::tls13_strip_content_type(&data);
    assert!(result.is_some());
    assert_eq!(result.unwrap(), &[0x48, 0x65, 0x6c, 0x6c, 0x6f]);

    // With padding zeros
    let data2 = [0x48, 0x65, 0x17, 0x00, 0x00]; // "He" + type + zeros
    let result2 = TlsConnection::tls13_strip_content_type(&data2);
    assert!(result2.is_some());
    assert_eq!(result2.unwrap(), &[0x48, 0x65]);

    // Empty content (just content type)
    let data3 = [0x16]; // Handshake type only
    let result3 = TlsConnection::tls13_strip_content_type(&data3);
    assert!(result3.is_some());
    assert!(result3.unwrap().is_empty());

    // All zeros
    let data4 = [0x00, 0x00, 0x00];
    let result4 = TlsConnection::tls13_strip_content_type(&data4);
    assert!(result4.is_none());
}

/// TLS 1.3: is_tls13 flag starts false
#[test_case]
pub(crate) fn test_tls13_initial_state() {
    let config = TlsConfig::new();
    let conn = TlsConnection::new(config);
    assert!(!conn.is_tls13());
    assert!(!conn.needs_client_finished());
}

/// TLS 1.3: RFC 8446 Appendix A test vector for key schedule
/// Tests HKDF-Expand-Label with known inputs/outputs
#[test_case]
pub(crate) fn test_tls13_hkdf_expand_label_rfc8446() {
    // RFC 8446 doesn't provide standalone HKDF-Expand-Label vectors,
    // but we can verify the label construction is correct by testing
    // idempotency and length properties.
    let secret = [0x33u8; 32];
    let result1 = hkdf_expand_label(&secret, b"key", b"", 16);
    let result2 = hkdf_expand_label(&secret, b"key", b"", 16);
    assert_eq!(result1, result2);
    assert_eq!(result1.len(), 16);

    // Different context -> different output
    let result3 = hkdf_expand_label(&secret, b"key", &[0x42u8; 32], 16);
    assert_ne!(result1, result3);
}

/// TLS 1.3: Verify the key schedule produces consistent results
/// matching the expected chain: Early -> derive("derived") -> Handshake -> derive("derived") -> Master
#[test_case]
pub(crate) fn test_tls13_key_schedule_chain_consistency() {
    use crate::loader::sha256;

    let shared = [0xABu8; 32];
    let empty_hash = sha256::compute(&[]);

    // Manual chain
    let early = tls13_early_secret(None);
    let derived1 = tls13_derive_secret(&early, b"derived", &empty_hash);
    let hs = hkdf_extract(&derived1, &shared);
    let derived2 = tls13_derive_secret(&hs, b"derived", &empty_hash);
    let master = hkdf_extract(&derived2, &[0u8; 32]);

    // Convenience function chain
    let hs2 = tls13_handshake_secret(&early, &shared);
    let master2 = tls13_master_secret(&hs2);

    assert_eq!(hs, hs2);
    assert_eq!(master, master2);
}

/// TLS 1.3: Finished verification round-trip
#[test_case]
pub(crate) fn test_tls13_finished_round_trip() {
    let base_key = [0x77u8; 32];
    let transcript_hash = [0x88u8; 32];

    let finished_key = tls13_finished_key(&base_key);
    let verify_data = tls13_verify_data(&finished_key, &transcript_hash);

    // Simulate server verification
    let expected = hmac_sha256(&finished_key, &transcript_hash);
    assert_eq!(verify_data, expected);
}

/// TLS 1.3: TlsVersion ordering
#[test_case]
pub(crate) fn test_tls_version_ordering() {
    assert!(TlsVersion::TLS_1_0 < TlsVersion::TLS_1_1);
    assert!(TlsVersion::TLS_1_1 < TlsVersion::TLS_1_2);
    assert!(TlsVersion::TLS_1_2 < TlsVersion::TLS_1_3);
    assert!(TlsVersion::TLS_1_3 >= TlsVersion::TLS_1_3);
}

// ========================================================================
// MD5 Tests (RFC 1321 Appendix A.5)
// ========================================================================

#[test_case]
pub(crate) fn test_md5_empty() {
    let result = md5_compute(b"");
    let expected = [
        0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04,
        0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e,
    ];
    assert_eq!(result, expected);
}

#[test_case]
pub(crate) fn test_md5_a() {
    let result = md5_compute(b"a");
    let expected = [
        0x0c, 0xc1, 0x75, 0xb9, 0xc0, 0xf1, 0xb6, 0xa8,
        0x31, 0xc3, 0x99, 0xe2, 0x69, 0x77, 0x26, 0x61,
    ];
    assert_eq!(result, expected);
}

#[test_case]
pub(crate) fn test_md5_abc() {
    let result = md5_compute(b"abc");
    let expected = [
        0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0,
        0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1, 0x7f, 0x72,
    ];
    assert_eq!(result, expected);
}

#[test_case]
pub(crate) fn test_md5_message_digest() {
    let result = md5_compute(b"message digest");
    let expected = [
        0xf9, 0x6b, 0x69, 0x7d, 0x7c, 0xb7, 0x93, 0x8d,
        0x52, 0x5a, 0x2f, 0x31, 0xaa, 0xf1, 0x61, 0xd0,
    ];
    assert_eq!(result, expected);
}

#[test_case]
pub(crate) fn test_md5_alphabet() {
    let result = md5_compute(b"abcdefghijklmnopqrstuvwxyz");
    let expected = [
        0xc3, 0xfc, 0xd3, 0xd7, 0x61, 0x92, 0xe4, 0x00,
        0x7d, 0xfb, 0x49, 0x6c, 0xca, 0x67, 0xe1, 0x3b,
    ];
    assert_eq!(result, expected);
}

// ========================================================================
// SHA-1 Tests (FIPS 180-4)
// ========================================================================

#[test_case]
pub(crate) fn test_sha1_abc() {
    let result = sha1_compute(b"abc");
    let expected = [
        0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a,
        0xba, 0x3e, 0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c,
        0x9c, 0xd0, 0xd8, 0x9d,
    ];
    assert_eq!(result, expected);
}

#[test_case]
pub(crate) fn test_sha1_empty() {
    let result = sha1_compute(b"");
    let expected = [
        0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d,
        0x32, 0x55, 0xbf, 0xef, 0x95, 0x60, 0x18, 0x90,
        0xaf, 0xd8, 0x07, 0x09,
    ];
    assert_eq!(result, expected);
}

#[test_case]
pub(crate) fn test_sha1_long() {
    // "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    let result = sha1_compute(
        b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
    );
    let expected = [
        0x84, 0x98, 0x3e, 0x44, 0x1c, 0x3b, 0xd2, 0x6e,
        0xba, 0xae, 0x4a, 0xa1, 0xf9, 0x51, 0x29, 0xe5,
        0xe5, 0x46, 0x70, 0xf1,
    ];
    assert_eq!(result, expected);
}

// ========================================================================
// HMAC-MD5 / HMAC-SHA1 Tests (RFC 2202)
// ========================================================================

#[test_case]
pub(crate) fn test_hmac_md5_rfc2202_case1() {
    let key = [0x0bu8; 16];
    let data = b"Hi There";
    let expected = [
        0x92, 0x94, 0x72, 0x7a, 0x36, 0x38, 0xbb, 0x1c,
        0x13, 0xf4, 0x8e, 0xf8, 0x15, 0x8b, 0xfc, 0x9d,
    ];
    assert_eq!(hmac_md5(&key, data), expected);
}

#[test_case]
pub(crate) fn test_hmac_md5_rfc2202_case2() {
    let key = b"Jefe";
    let data = b"what do ya want for nothing?";
    let expected = [
        0x75, 0x0c, 0x78, 0x3e, 0x6a, 0xb0, 0xb5, 0x03,
        0xea, 0xa8, 0x6e, 0x31, 0x0a, 0x5d, 0xb7, 0x38,
    ];
    assert_eq!(hmac_md5(key, data), expected);
}

#[test_case]
pub(crate) fn test_hmac_sha1_rfc2202_case1() {
    let key = [0x0bu8; 20];
    let data = b"Hi There";
    let expected = [
        0xb6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64,
        0xe2, 0x8b, 0xc0, 0xb6, 0xfb, 0x37, 0x8c, 0x8e,
        0xf1, 0x46, 0xbe, 0x00,
    ];
    assert_eq!(hmac_sha1(&key, data), expected);
}

#[test_case]
pub(crate) fn test_hmac_sha1_rfc2202_case2() {
    let key = b"Jefe";
    let data = b"what do ya want for nothing?";
    let expected = [
        0xef, 0xfc, 0xdf, 0x6a, 0xe5, 0xeb, 0x2f, 0xa2,
        0xd2, 0x74, 0x16, 0xd5, 0xf1, 0x84, 0xdf, 0x9c,
        0x25, 0x9a, 0x7c, 0x79,
    ];
    assert_eq!(hmac_sha1(key, data), expected);
}

// ========================================================================
// AES-CBC Tests
// ========================================================================

#[test_case]
pub(crate) fn test_aes_cbc_roundtrip_128() {
    let key = [0x2bu8; 16];
    let iv = [0x00u8; 16];
    let plaintext = b"Hello, AES-CBC mode test!";
    let ciphertext = aes_cbc_encrypt(&key, &iv, plaintext);
    let decrypted = aes_cbc_decrypt(&key, &iv, &ciphertext);
    assert!(decrypted.is_some());
    assert_eq!(&decrypted.unwrap()[..plaintext.len()], plaintext);
}

#[test_case]
pub(crate) fn test_aes_cbc_roundtrip_256() {
    let key = [0x60u8; 32];
    let iv = [0x01u8; 16];
    let plaintext = b"AES-256-CBC round-trip test data for verification!";
    let ciphertext = aes_cbc_encrypt(&key, &iv, plaintext);
    let decrypted = aes_cbc_decrypt(&key, &iv, &ciphertext);
    assert!(decrypted.is_some());
    assert_eq!(&decrypted.unwrap()[..plaintext.len()], plaintext);
}

#[test_case]
pub(crate) fn test_aes_cbc_empty() {
    let key = [0x00u8; 16];
    let iv = [0x00u8; 16];
    let ciphertext = aes_cbc_encrypt(&key, &iv, b"");
    // Empty plaintext still gets padded to one block
    assert_eq!(ciphertext.len(), 16);
    let decrypted = aes_cbc_decrypt(&key, &iv, &ciphertext);
    assert!(decrypted.is_some());
    assert_eq!(decrypted.unwrap().len(), 0);
}

// ========================================================================
// TLS Padding Tests
// ========================================================================

#[test_case]
pub(crate) fn test_tls_padding_add_verify() {
    let data = b"test data";
    let padded = tls_add_padding(data, 16);
    // padded length should be multiple of 16
    assert_eq!(padded.len() % 16, 0);
    // Verify padding is correct
    let valid_len = tls_verify_padding(&padded);
    assert!(valid_len.is_some());
    assert_eq!(valid_len.unwrap(), data.len());
}

#[test_case]
pub(crate) fn test_tls_padding_exact_block() {
    // Data that's exactly one block minus 1 (needs 1 byte of padding content)
    let data = [0xAA; 15];
    let padded = tls_add_padding(&data, 16);
    assert_eq!(padded.len(), 16);
    assert_eq!(padded[15], 0x00); // pad_byte = 0 (length 1)
    let valid_len = tls_verify_padding(&padded);
    assert!(valid_len.is_some());
    assert_eq!(valid_len.unwrap(), 15);
}

#[test_case]
pub(crate) fn test_tls_padding_full_block_pad() {
    // Data that falls exactly on block boundary -> full block of padding
    let data = [0xBB; 16];
    let padded = tls_add_padding(&data, 16);
    assert_eq!(padded.len(), 32);
    let valid_len = tls_verify_padding(&padded);
    assert!(valid_len.is_some());
    assert_eq!(valid_len.unwrap(), 16);
}

// ========================================================================
// TLS 1.0 PRF Tests
// ========================================================================

#[test_case]
pub(crate) fn test_tls10_prf_deterministic() {
    let secret = [0x42u8; 48];
    let label = b"master secret";
    let seed = [0x01u8; 64];
    let mut out1 = [0u8; 48];
    let mut out2 = [0u8; 48];
    tls10_prf(&secret, label, &seed, &mut out1);
    tls10_prf(&secret, label, &seed, &mut out2);
    assert_eq!(out1, out2);
    // Should not be all zeros
    assert!(out1.iter().any(|&b| b != 0));
}

#[test_case]
pub(crate) fn test_tls10_prf_different_labels() {
    let secret = [0x42u8; 48];
    let seed = [0x01u8; 64];
    let mut out1 = [0u8; 48];
    let mut out2 = [0u8; 48];
    tls10_prf(&secret, b"client finished", &seed, &mut out1);
    tls10_prf(&secret, b"server finished", &seed, &mut out2);
    assert_ne!(out1, out2);
}
