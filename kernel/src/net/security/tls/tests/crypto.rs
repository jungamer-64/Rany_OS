// ============================================================================
// kernel/src/net/security/tls/tests/crypto.rs - TLS 1.3 crypto tests
// ============================================================================

use super::super::crypto::aes_gcm::AesGcmKey;
use super::super::crypto::chacha20::{
    chacha20_poly1305_decrypt_in_place, chacha20_poly1305_encrypt_in_place,
};
use super::super::crypto::hkdf::{hkdf_expand, hkdf_expand_label, hkdf_extract};
use super::super::crypto::{
    hmac_sha256, hmac_sha384, tls13_derive_secret, tls13_derive_traffic_keys, tls13_early_secret,
    tls13_finished_key, tls13_handshake_secret, tls13_master_secret, tls13_verify_data,
};

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_hmac_sha256_rfc4231_case1() {
    let key = [0x0bu8; 20];
    let data = b"Hi There";
    let expected: [u8; 32] = [
        0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1,
        0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32,
        0xcf, 0xf7,
    ];

    assert_eq!(hmac_sha256(&key, data), expected);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_hmac_sha384_rfc4231_case1() {
    let key = [0x0bu8; 20];
    let data = b"Hi There";
    let expected: [u8; 48] = [
        0xaf, 0xd0, 0x39, 0x44, 0xd8, 0x48, 0x95, 0x62, 0x6b, 0x08, 0x25, 0xf4, 0xab, 0x46, 0x90,
        0x7f, 0x15, 0xf9, 0xda, 0xdb, 0xe4, 0x10, 0x1e, 0xc6, 0x82, 0xaa, 0x03, 0x4c, 0x7c, 0xeb,
        0xc5, 0x9c, 0xfa, 0xea, 0x9e, 0xa9, 0x07, 0x6e, 0xde, 0x7f, 0x4a, 0xf1, 0x52, 0xe8, 0xb2,
        0xfa, 0x9c, 0xb6,
    ];

    assert_eq!(hmac_sha384(&key, data), expected);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_hkdf_extract_and_expand_are_deterministic() {
    let salt = [0x00u8; 32];
    let ikm = [0x11u8; 32];
    let prk = hkdf_extract(&salt, &ikm);
    let mut first = [0u8; 42];
    let mut second = [0u8; 42];

    hkdf_expand(&prk, b"info", &mut first);
    hkdf_expand(&prk, b"info", &mut second);

    assert_eq!(first, second);
    assert!(first.iter().any(|byte| *byte != 0));
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_hkdf_expand_label_separates_labels() {
    let secret = [0x42u8; 32];
    let mut key = [0u8; 16];
    let mut iv = [0u8; 12];

    hkdf_expand_label(&secret, b"key", b"", &mut key);
    hkdf_expand_label(&secret, b"iv", b"", &mut iv);

    assert!(key.iter().any(|byte| *byte != 0));
    assert!(iv.iter().any(|byte| *byte != 0));
    assert_ne!(&key[..12], iv.as_slice());
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_tls13_key_schedule_chain_is_directional() {
    let shared_secret = [0xABu8; 32];
    let transcript = [0xCDu8; 32];

    let early = tls13_early_secret(None);
    let handshake = tls13_handshake_secret(&early, &shared_secret);
    let client_hs = tls13_derive_secret(&handshake, b"c hs traffic", &transcript);
    let server_hs = tls13_derive_secret(&handshake, b"s hs traffic", &transcript);
    let master = tls13_master_secret(&handshake);
    let client_app = tls13_derive_secret(&master, b"c ap traffic", &transcript);

    assert_ne!(client_hs, server_hs);
    assert_ne!(client_hs, client_app);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_tls13_traffic_keys_have_requested_lengths() {
    let secret = [0x33u8; 32];
    let mut key = [0u8; 16];
    let mut iv = [0u8; 12];

    tls13_derive_traffic_keys(&secret, &mut key, &mut iv);

    assert!(key.iter().any(|byte| *byte != 0));
    assert!(iv.iter().any(|byte| *byte != 0));
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_tls13_finished_verify_data_roundtrip() {
    let base = [0x44u8; 32];
    let transcript = [0x55u8; 32];
    let finished_key = tls13_finished_key(&base);
    let verify_data = tls13_verify_data(&finished_key, &transcript);

    assert_eq!(verify_data, tls13_verify_data(&finished_key, &transcript));
    assert_ne!(verify_data, [0u8; 32]);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_aes_gcm_key_roundtrip() {
    let key = [0x11u8; 16];
    let nonce = [0x22u8; 12];
    let aad = b"tls13 aad";
    let plaintext = b"packet-native plaintext";
    let ctx = AesGcmKey::new(&key).expect("valid AES-GCM key");
    let mut ciphertext = [0u8; 23];
    let mut tag = [0u8; 16];
    let mut decrypted = [0u8; 23];

    ctx.encrypt_in_place(&nonce, aad, plaintext, &mut ciphertext, &mut tag)
        .expect("encrypt");
    ctx.decrypt_in_place(&nonce, aad, &ciphertext, &mut decrypted, &tag)
        .expect("decrypt");

    assert_eq!(&decrypted, plaintext);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_chacha20_poly1305_roundtrip() {
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let aad = b"tls13 aad";
    let mut data = *b"packet-native plaintext";
    let mut tag = [0u8; 16];

    chacha20_poly1305_encrypt_in_place(&key, &nonce, aad, &mut data, &mut tag);
    assert_ne!(&data, b"packet-native plaintext");
    chacha20_poly1305_decrypt_in_place(&key, &nonce, aad, &mut data, &tag).expect("decrypt");

    assert_eq!(&data, b"packet-native plaintext");
}
