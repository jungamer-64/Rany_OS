use super::*;


pub fn wave8_tls_aes_gcm_empty_plaintext_smoke() -> bool {
    let key = [0x11u8; 16];
    let nonce = [0x22u8; 12];
    let aad = b"aad only, no payload";

    let (ciphertext, tag) = aes_gcm_encrypt(&key, &nonce, aad, &[]);
    if !ciphertext.is_empty() {
        return false;
    }

    match aes_gcm_decrypt(&key, &nonce, aad, &[], &tag) {
        Some(decrypted) => decrypted.is_empty(),
        None => false,
    }
}

pub fn wave8_tls_aes_gcm_key_in_place_roundtrip_smoke() -> bool {
    let key = [0x5au8; 16];
    let nonce = [0x33u8; 12];
    let aad = b"in-place aad";
    let plaintext = b"in-place aes-gcm payload";

    let Some(ctx) = crate::net::tls::crypto::aes_gcm::AesGcmKey::new(&key) else {
        return false;
    };

    let mut ciphertext = alloc::vec![0u8; plaintext.len()];
    let mut tag = [0u8; 16];
    if ctx
        .encrypt_in_place(nonce.as_slice(), aad, plaintext, &mut ciphertext, &mut tag)
        .is_err()
    {
        return false;
    }

    let mut decrypted = alloc::vec![0u8; plaintext.len()];
    if ctx
        .decrypt_in_place(nonce.as_slice(), aad, &ciphertext, &mut decrypted, &tag)
        .is_err()
    {
        return false;
    }

    decrypted.as_slice() == plaintext
}

pub fn wave8_tls_aes_gcm_key_invalid_nonce_len_smoke() -> bool {
    let key = [0x11u8; 16];
    let Some(ctx) = crate::net::tls::crypto::aes_gcm::AesGcmKey::new(&key) else {
        return false;
    };

    let bad_nonce = [0x22u8; 11];
    let mut ciphertext = [0u8; 4];
    let mut tag = [0u8; 16];
    let enc_err = ctx.encrypt_in_place(&bad_nonce, b"", b"test", &mut ciphertext, &mut tag);

    let mut plaintext = [0u8; 4];
    let dec_err = ctx.decrypt_in_place(&bad_nonce, b"", &ciphertext, &mut plaintext, &tag);

    enc_err.is_err() && dec_err.is_err()
}

pub fn wave8_tls_aes_gcm_key_auth_failure_preserves_output_buffer_smoke() -> bool {
    let key = [0x77u8; 16];
    let nonce = [0x88u8; 12];
    let aad = b"aad";
    let plaintext = b"secret";

    let Some(ctx) = crate::net::tls::crypto::aes_gcm::AesGcmKey::new(&key) else {
        return false;
    };

    let mut ciphertext = alloc::vec![0u8; plaintext.len()];
    let mut tag = [0u8; 16];
    if ctx
        .encrypt_in_place(nonce.as_slice(), aad, plaintext, &mut ciphertext, &mut tag)
        .is_err()
    {
        return false;
    }

    tag[0] ^= 0xff;
    let mut out = [0xa5u8; 6];
    let before = out;

    ctx.decrypt_in_place(nonce.as_slice(), aad, &ciphertext, &mut out, &tag)
        .is_err()
        && out == before
}

pub fn wave8_tls_aes_key_expansion_smoke() -> bool {
    let key: [u8; 16] = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
        0x4f, 0x3c,
    ];
    let round_keys = aes_key_expansion(&key);
    if round_keys[0] != key {
        return false;
    }
    for i in 0..10 {
        if round_keys[i] == round_keys[i + 1] {
            return false;
        }
    }
    true
}

pub fn wave8_tls_derive_master_secret_length_smoke() -> bool {
    let pre_master = [0x42u8; 48];
    let client_random = [0x01u8; 32];
    let server_random = [0x02u8; 32];

    let ms = derive_master_secret(&pre_master, &client_random, &server_random);
    ms.len() == 48 && ms.iter().any(|&b| b != 0)
}

pub fn wave8_tls_derive_key_block_length_smoke() -> bool {
    let master_secret = [0x55u8; 48];
    let server_random = [0xAAu8; 32];
    let client_random = [0xBBu8; 32];

    let kb = derive_key_block(&master_secret, &server_random, &client_random, 40);
    let kb256 = derive_key_block(&master_secret, &server_random, &client_random, 72);

    kb.len() == 40 && kb.iter().any(|&b| b != 0) && kb256.len() == 72
}

pub fn wave8_tls_derive_master_secret_deterministic_smoke() -> bool {
    let pre_master = [0x42u8; 48];
    let client_random = [0x01u8; 32];
    let server_random = [0x02u8; 32];

    let ms1 = derive_master_secret(&pre_master, &client_random, &server_random);
    let ms2 = derive_master_secret(&pre_master, &client_random, &server_random);
    ms1 == ms2
}

pub fn wave8_tls_derive_master_secret_differs_with_input_smoke() -> bool {
    let client_random = [0x01u8; 32];
    let server_random = [0x02u8; 32];

    let ms1 = derive_master_secret(&[0x42u8; 48], &client_random, &server_random);
    let ms2 = derive_master_secret(&[0x43u8; 48], &client_random, &server_random);
    ms1 != ms2
}

pub fn wave8_tls_tls12_prf_deterministic_smoke() -> bool {
    let secret = b"test secret";
    let label = b"test label";
    let seed = b"test seed";

    let mut out1 = [0u8; 64];
    let mut out2 = [0u8; 64];
    tls12_prf(secret, label, seed, &mut out1);
    tls12_prf(secret, label, seed, &mut out2);
    out1 == out2
}

pub fn wave8_tls_tls12_prf_different_labels_smoke() -> bool {
    let secret = b"test secret";
    let seed = b"test seed";

    let mut out1 = [0u8; 32];
    let mut out2 = [0u8; 32];
    tls12_prf(secret, b"label A", seed, &mut out1);
    tls12_prf(secret, b"label B", seed, &mut out2);
    out1 != out2
}

pub fn wave8_tls_hkdf_expand_label_length_smoke() -> bool {
    let secret = [0x42u8; 32];
    let result = hkdf_expand_label(&secret, b"key", b"", 16);
    let result32 = hkdf_expand_label(&secret, b"iv", b"", 12);
    result.len() == 16 && result32.len() == 12
}

pub fn wave8_tls_hkdf_expand_label_different_labels_smoke() -> bool {
    let secret = [0x42u8; 32];
    let result1 = hkdf_expand_label(&secret, b"key", b"", 32);
    let result2 = hkdf_expand_label(&secret, b"iv", b"", 32);
    result1 != result2
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
    let result = base64_decode("SGVsbG8=");
    let empty = base64_decode("");
    matches!(result, Some(ref v) if v.as_slice() == b"Hello")
        && matches!(empty, Some(ref v) if v.is_empty())
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

pub fn wave8_tls_generate_random_not_all_zeros_smoke() -> bool {
    qemu_test_set_random_override_seed(0x0123_4567_89AB_CDEF);
    let random = generate_random();
    let ok = random.iter().any(|&b| b != 0);
    qemu_test_clear_random_override();
    ok
}

pub fn wave8_tls_generate_random_different_calls_smoke() -> bool {
    qemu_test_set_random_override_seed(0x89AB_CDEF_0123_4567);
    let first = generate_random();
    let second = generate_random();
    qemu_test_clear_random_override();
    first != second
}

// ========================================================================
// Wave8 Phase E: SHA-384 + HMAC-SHA384 テスト
// ========================================================================

pub fn wave8_tls_sha384_empty_smoke() -> bool {
    use crate::loader::sha384;
    // SHA-384("") -- FIPS 180-4 既知テストベクトル
    let hash = sha384::compute(b"");
    let expected: [u8; 48] = [
        0x38, 0xb0, 0x60, 0xa7, 0x51, 0xac, 0x96, 0x38,
        0x4c, 0xd9, 0x32, 0x7e, 0xb1, 0xb1, 0xe3, 0x6a,
        0x21, 0xfd, 0xb7, 0x11, 0x14, 0xbe, 0x07, 0x43,
        0x4c, 0x0c, 0xc7, 0xbf, 0x63, 0xf6, 0xe1, 0xda,
        0x27, 0x4e, 0xde, 0xbf, 0xe7, 0x6f, 0x65, 0xfb,
        0xd5, 0x1a, 0xd2, 0xf1, 0x48, 0x98, 0xb9, 0x5b,
    ];
    hash == expected
}

pub fn wave8_tls_sha384_abc_smoke() -> bool {
    use crate::loader::sha384;
    // SHA-384("abc") -- FIPS 180-4 既知テストベクトル
    let hash = sha384::compute(b"abc");
    let expected: [u8; 48] = [
        0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b,
        0xb5, 0xa0, 0x3d, 0x69, 0x9a, 0xc6, 0x50, 0x07,
        0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63,
        0x1a, 0x8b, 0x60, 0x5a, 0x43, 0xff, 0x5b, 0xed,
        0x80, 0x86, 0x07, 0x2b, 0xa1, 0xe7, 0xcc, 0x23,
        0x58, 0xba, 0xec, 0xa1, 0x34, 0xc8, 0x25, 0xa7,
    ];
    hash == expected
}

pub fn wave8_tls_hmac_sha384_rfc4231_case1_smoke() -> bool {
    // RFC 4231 Test Case 1: HMAC-SHA384
    let key = [0x0bu8; 20];
    let data = b"Hi There";
    let expected: [u8; 48] = [
        0xaf, 0xd0, 0x39, 0x44, 0xd8, 0x48, 0x95, 0x62,
        0x6b, 0x08, 0x25, 0xf4, 0xab, 0x46, 0x90, 0x7f,
        0x15, 0xf9, 0xda, 0xdb, 0xe4, 0x10, 0x1e, 0xc6,
        0x82, 0xaa, 0x03, 0x4c, 0x7c, 0xeb, 0xc5, 0x9c,
        0xfa, 0xea, 0x9e, 0xa9, 0x07, 0x6e, 0xde, 0x7f,
        0x4a, 0xf1, 0x52, 0xe8, 0xb2, 0xfa, 0x9c, 0xb6,
    ];
    hmac_sha384(&key, data) == expected
}

pub fn wave8_tls_hmac_sha384_rfc4231_case2_smoke() -> bool {
    // RFC 4231 Test Case 2: HMAC-SHA384
    let key = b"Jefe";
    let data = b"what do ya want for nothing?";
    let expected: [u8; 48] = [
        0xaf, 0x45, 0xd2, 0xe3, 0x76, 0x48, 0x40, 0x31,
        0x61, 0x7f, 0x78, 0xd2, 0xb5, 0x8a, 0x6b, 0x1b,
        0x9c, 0x7e, 0xf4, 0x64, 0xf5, 0xa0, 0x1b, 0x47,
        0xe4, 0x2e, 0xc3, 0x73, 0x63, 0x22, 0x44, 0x5e,
        0x8e, 0x22, 0x40, 0xca, 0x5e, 0x69, 0xe2, 0xc7,
        0x8b, 0x32, 0x39, 0xec, 0xfa, 0xb2, 0x16, 0x49,
    ];
    hmac_sha384(key, data) == expected
}

// ========================================================================
// Wave8 Phase B: P-256 ECDH テスト
// ========================================================================

/// P-256 ベースポイントが曲線上にあることを検証 (FIPS 186-4)
pub fn wave8_tls_p256_point_on_curve_smoke() -> bool {
    use crate::net::ecdh::p256::P256Point;
    let g = P256Point::generator();
    g.is_on_curve()
}

/// P-256 [k]G の既知結果照合 (RFC 5903 Section 8.1)
///
/// k = 1 -> [1]G = G を検証する。
pub fn wave8_tls_p256_scalar_mul_base_smoke() -> bool {
    use crate::net::ecdh::p256::{P256Point, scalar_base_mul};
    let g = P256Point::generator();
    let (gx, gy) = match g.to_affine() {
        Some(v) => v,
        None => return false,
    };

    let mut scalar_one = [0u8; 32];
    scalar_one[31] = 1;

    let result = scalar_base_mul(&scalar_one);
    let (rx, ry) = match result.to_affine() {
        Some(v) => v,
        None => return false,
    };

    rx == gx && ry == gy
}

/// P-256 ECDH 鍵交換対称性テスト
pub fn wave8_ecdh_p256_key_exchange_symmetry_smoke() -> bool {
    crate::net::ecdh::qemu_tests::ecdh_p256_key_exchange_symmetry_smoke()
}

/// P-256 公開鍵長テスト (65バイト)
pub fn wave8_ecdh_p256_public_key_length_smoke() -> bool {
    crate::net::ecdh::qemu_tests::ecdh_p256_public_key_length_smoke()
}

/// P-256 不正なピア鍵拒否テスト
pub fn wave8_ecdh_p256_reject_invalid_peer_key_smoke() -> bool {
    crate::net::ecdh::qemu_tests::ecdh_p256_reject_invalid_peer_key_smoke()
}

/// P-256 NamedGroupマッピングテスト
pub fn wave8_ecdh_group_from_named_group_p256_smoke() -> bool {
    crate::net::ecdh::qemu_tests::ecdh_group_from_named_group_p256_smoke()
}

pub fn wave8_tls_tls_connection_initial_state_smoke() -> bool {
    let config = TlsConfig::new();
    let conn = TlsConnection::new(config);
    conn.state() == TlsState::Initial && conn.negotiated_version().is_none()
}

pub fn wave8_tls_tls_connection_client_hello_smoke() -> bool {
    let config = TlsConfig::new().with_server_name("example.com");
    let mut conn = TlsConnection::new(config);
    let hello = conn.build_client_hello();
    hello.len() >= 3
        && hello[0] == ContentType::Handshake as u8
        && hello[1] == 0x03
        && hello[2] == 0x01
        && conn.state() == TlsState::ClientHelloSent
}

pub fn wave8_tls_tls_connection_encrypt_not_established_smoke() -> bool {
    let config = TlsConfig::new();
    let mut conn = TlsConnection::new(config);
    matches!(conn.encrypt(b"hello"), Err(TlsError::NotConnected))
}

pub fn wave8_tls_process_handshake_multiple_messages_smoke() -> bool {
    let config = TlsConfig::new();
    let mut conn = TlsConnection::new(config);
    let data = tls12_multi_handshake_fixture_server_hello_done_plus_valid_finished();
    conn.process_handshake(&data).is_ok()
        && conn.state() == TlsState::Established
        && conn.handshake_messages_ref() == data.as_slice()
}

pub fn wave8_tls_process_handshake_truncated_header_smoke() -> bool {
    let config = TlsConfig::new();
    let mut conn = TlsConnection::new(config);
    let data = [2u8, 0, 0];
    matches!(conn.process_handshake(&data), Err(TlsError::DecodeError))
}

// ====================================================================
// Phase C: X.509 DERパース + RSA署名検証 デリゲート
// ====================================================================

/// DERパーサー基本テスト: タグ・長さ読み取り
pub fn wave8_tls_der_parse_tag_length_smoke() -> bool {
    crate::net::x509::qemu_tests::x509_der_parse_tag_length_smoke()
}

/// DERパーサーINTEGER読み取りテスト
pub fn wave8_tls_der_parse_integer_smoke() -> bool {
    crate::net::x509::qemu_tests::x509_der_parse_integer_smoke()
}

/// DERパーサーSEQUENCEトラバーサルテスト
pub fn wave8_tls_der_parse_sequence_smoke() -> bool {
    crate::net::x509::qemu_tests::x509_der_parse_sequence_smoke()
}

/// X.509証明書パース基本テスト
pub fn wave8_tls_x509_parse_self_signed_smoke() -> bool {
    crate::net::x509::qemu_tests::x509_parse_self_signed_smoke()
}

/// RSA公開鍵抽出テスト
pub fn wave8_tls_x509_extract_rsa_pubkey_smoke() -> bool {
    crate::net::x509::qemu_tests::x509_extract_rsa_pubkey_smoke()
}

/// 署名アルゴリズムOIDマッピングテスト
pub fn wave8_tls_x509_signature_algorithm_oid_smoke() -> bool {
    crate::net::x509::qemu_tests::x509_signature_algorithm_oid_smoke()
}

/// 小さな値のモジュラ冪乗テスト
pub fn wave8_tls_rsa_modexp_small_smoke() -> bool {
    crate::net::rsa::qemu_tests::rsa_modexp_small_smoke()
}

/// 256ビット決定論的モジュラ冪乗テスト
pub fn wave8_tls_rsa_modexp_medium_smoke() -> bool {
    crate::net::rsa::qemu_tests::rsa_modexp_medium_smoke()
}

/// PKCS#1 v1.5 署名検証テスト
pub fn wave8_tls_rsa_pkcs1_verify_smoke() -> bool {
    crate::net::rsa::qemu_tests::rsa_pkcs1_verify_smoke()
}

/// PKCS#1 v1.5 不正署名拒否テスト
pub fn wave8_tls_rsa_pkcs1_verify_bad_sig_smoke() -> bool {
    crate::net::rsa::qemu_tests::rsa_pkcs1_verify_bad_sig_smoke()
}

/// BigUint 乗算・除算ラウンドトリップテスト
pub fn wave8_tls_rsa_biguint_mul_div_smoke() -> bool {
    crate::net::rsa::qemu_tests::rsa_biguint_mul_div_smoke()
}
