// ============================================================================
// kernel/src/net/security/tls/qemu_tests/crypto.rs - セキュリティ / TLS / QEMUテスト / 暗号
// ============================================================================

use super::super::crypto::aes_core::{
    aes_ctr_with_schedule_in_place, aes_expand_key_schedule, aes_key_expansion, gf_mul,
};
use super::super::crypto::aes_gcm::{gf128_mul, AesGcmKey};
use super::super::crypto::chacha20::{
    chacha20_block, chacha20_poly1305_decrypt_in_place, chacha20_poly1305_encrypt_in_place,
    chacha20_xor_in_place, poly1305_mac,
};
use super::super::crypto::hkdf::{hkdf_expand as hkdf_expand_into, hkdf_extract};
use super::super::crypto::{
    aes_gcm_decrypt_into, aes_gcm_encrypt_into, generate_random,
    hkdf_expand_label as hkdf_expand_label_into, hmac_sha256, hmac_sha384,
    qemu_test_clear_random_override, qemu_test_set_random_override_seed, tls13_derive_secret,
    tls13_derive_traffic_keys as tls13_derive_traffic_keys_into, tls13_early_secret,
    tls13_finished_key, tls13_handshake_secret, tls13_master_secret, tls13_verify_data,
};
fn hkdf_expand(prk: &[u8; 32], info: &[u8], output: &mut [u8]) -> bool {
    hkdf_expand_into(prk, info, output);
    true
}

fn hkdf_expand_label(secret: &[u8; 32], label: &[u8], context: &[u8], output: &mut [u8]) -> bool {
    hkdf_expand_label_into(secret, label, context, output);
    true
}

fn tls13_derive_traffic_keys(secret: &[u8; 32], key: &mut [u8], iv: &mut [u8; 12]) -> bool {
    tls13_derive_traffic_keys_into(secret, key, iv);
    true
}

fn chacha20_encrypt_in_place(key: &[u8; 32], nonce: &[u8; 12], counter: u32, data: &mut [u8]) {
    chacha20_xor_in_place(key, nonce, counter, data);
}

fn chacha20_poly1305_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
    ciphertext: &mut [u8],
    tag: &mut [u8; 16],
) -> bool {
    if ciphertext.len() != plaintext.len() {
        return false;
    }
    ciphertext.copy_from_slice(plaintext);
    chacha20_poly1305_encrypt_in_place(key, nonce, aad, ciphertext, tag);
    true
}

fn chacha20_poly1305_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
    plaintext: &mut [u8],
) -> bool {
    if plaintext.len() != ciphertext.len() {
        return false;
    }
    plaintext.copy_from_slice(ciphertext);
    chacha20_poly1305_decrypt_in_place(key, nonce, aad, plaintext, tag).is_ok()
}

fn aes_gcm_encrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    ciphertext: &mut [u8],
    tag: &mut [u8; 16],
) -> bool {
    aes_gcm_encrypt_into(key, nonce, aad, plaintext, ciphertext, tag).is_ok()
}

fn aes_gcm_decrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
    plaintext: &mut [u8],
) -> bool {
    aes_gcm_decrypt_into(key, nonce, aad, ciphertext, plaintext, tag).is_ok()
}

fn aes_ctr(key: &[u8], nonce: &[u8], data: &[u8], output: &mut [u8]) -> bool {
    if output.len() != data.len() {
        return false;
    }
    let Some(schedule) = aes_expand_key_schedule(key) else {
        return false;
    };
    output.copy_from_slice(data);
    aes_ctr_with_schedule_in_place(&schedule, nonce, 1, output);
    true
}

pub fn wave8_tls_hmac_sha256_rfc4231_case1_smoke() -> bool {
    let key = [0x0bu8; 20];
    let data = b"Hi There";
    let expected: [u8; 32] = [
        0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1,
        0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32,
        0xcf, 0xf7,
    ];
    hmac_sha256(&key, data) == expected
}

pub fn wave8_tls_hmac_sha256_rfc4231_case2_smoke() -> bool {
    let key = b"Jefe";
    let data = b"what do ya want for nothing?";
    let expected: [u8; 32] = [
        0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75,
        0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec,
        0x38, 0x43,
    ];
    hmac_sha256(key, data) == expected
}

pub fn wave8_tls_hmac_sha256_rfc4231_case3_smoke() -> bool {
    let key = [0xaau8; 20];
    let data = [0xddu8; 50];
    let expected: [u8; 32] = [
        0x77, 0x3e, 0xa9, 0x1e, 0x36, 0x80, 0x0e, 0x46, 0x85, 0x4d, 0xb8, 0xeb, 0xd0, 0x91, 0x81,
        0xa7, 0x29, 0x59, 0x09, 0x8b, 0x3e, 0xf8, 0xc1, 0x22, 0xd9, 0x63, 0x55, 0x14, 0xce, 0xd5,
        0x65, 0xfe,
    ];
    hmac_sha256(&key, &data) == expected
}

pub fn wave8_tls_hkdf_rfc5869_case1_extract_smoke() -> bool {
    let ikm = [0x0bu8; 22];
    let salt: [u8; 13] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    ];
    let expected_prk: [u8; 32] = [
        0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba,
        0x63, 0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2,
        0xb3, 0xe5,
    ];
    hkdf_extract(&salt, &ikm) == expected_prk
}

pub fn wave8_tls_hkdf_rfc5869_case1_expand_smoke() -> bool {
    let prk: [u8; 32] = [
        0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba,
        0x63, 0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2,
        0xb3, 0xe5,
    ];
    let info: [u8; 10] = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
    let expected_okm: [u8; 42] = [
        0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f,
        0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4,
        0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
    ];
    let mut okm = [0u8; 42];
    hkdf_expand(&prk, &info, &mut okm) && okm == expected_okm
}

pub fn wave8_tls_chacha20_rfc8439_block_smoke() -> bool {
    let key: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    let nonce: [u8; 12] = [
        0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
    ];

    let block = chacha20_block(&key, 1, &nonce);
    let expected_start: [u8; 16] = [
        0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71,
        0xc4,
    ];
    let expected_end: [u8; 16] = [
        0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9, 0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c,
        0x4e,
    ];
    &block[0..16] == expected_start.as_slice() && &block[48..64] == expected_end.as_slice()
}

pub fn wave8_tls_chacha20_rfc8439_encrypt_smoke() -> bool {
    let key: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    let nonce: [u8; 12] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
    ];
    let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    let expected_ciphertext: [u8; 114] = [
        0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69,
        0x81, 0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2, 0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f,
        0xae, 0x0b, 0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab, 0x8f, 0x59, 0x3d, 0xab, 0xcd,
        0x62, 0xb3, 0x57, 0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab, 0x8f, 0x53, 0x0c, 0x35,
        0x9f, 0x08, 0x61, 0xd8, 0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d, 0x6a, 0x61, 0x56, 0xa3, 0x8e,
        0x08, 0x8a, 0x22, 0xb6, 0x5e, 0x52, 0xbc, 0x51, 0x4d, 0x16, 0xcc, 0xf8, 0x06, 0x81, 0x8c,
        0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36, 0x5a, 0xf9, 0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6, 0xb4,
        0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42, 0x87, 0x4d,
    ];

    let mut ciphertext = *plaintext;
    chacha20_encrypt_in_place(&key, &nonce, 1, &mut ciphertext);
    let mut decrypted = ciphertext;
    chacha20_encrypt_in_place(&key, &nonce, 1, &mut decrypted);
    ciphertext.as_slice() == expected_ciphertext.as_slice() && decrypted.as_slice() == plaintext
}

pub fn wave8_tls_poly1305_rfc8439_smoke() -> bool {
    let key: [u8; 32] = [
        0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06,
        0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49,
        0xf5, 0x1b,
    ];
    let message = b"Cryptographic Forum Research Group";
    let expected_tag: [u8; 16] = [
        0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6, 0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27,
        0xa9,
    ];
    poly1305_mac(&key, message) == expected_tag
}

pub fn wave8_tls_chacha20_poly1305_rfc8439_encrypt_smoke() -> bool {
    let key: [u8; 32] = [
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e,
        0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d,
        0x9e, 0x9f,
    ];
    let nonce: [u8; 12] = [
        0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    ];
    let aad: [u8; 12] = [
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
    ];
    let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    let expected_ciphertext: [u8; 114] = [
        0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e,
        0xc2, 0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee,
        0x62, 0xd6, 0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa, 0xfb, 0x69, 0xda,
        0x92, 0x72, 0x8b, 0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29, 0x05, 0xd6, 0xa5, 0xb6,
        0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c, 0x98, 0x03, 0xae,
        0xe3, 0x28, 0x09, 0x1b, 0x58, 0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85,
        0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc, 0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5,
        0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b, 0x61, 0x16,
    ];
    let expected_tag: [u8; 16] = [
        0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06,
        0x91,
    ];

    let mut ciphertext = [0u8; 114];
    let mut tag = [0u8; 16];
    if !chacha20_poly1305_encrypt(&key, &nonce, &aad, plaintext, &mut ciphertext, &mut tag) {
        return false;
    }
    ciphertext.as_slice() == expected_ciphertext.as_slice() && tag == expected_tag
}

pub fn wave8_tls_chacha20_poly1305_rfc8439_decrypt_smoke() -> bool {
    let key: [u8; 32] = [
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e,
        0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d,
        0x9e, 0x9f,
    ];
    let nonce: [u8; 12] = [
        0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    ];
    let aad: [u8; 12] = [
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
    ];
    let ciphertext: [u8; 114] = [
        0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e,
        0xc2, 0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee,
        0x62, 0xd6, 0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa, 0xfb, 0x69, 0xda,
        0x92, 0x72, 0x8b, 0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29, 0x05, 0xd6, 0xa5, 0xb6,
        0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c, 0x98, 0x03, 0xae,
        0xe3, 0x28, 0x09, 0x1b, 0x58, 0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85,
        0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc, 0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5,
        0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b, 0x61, 0x16,
    ];
    let tag: [u8; 16] = [
        0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06,
        0x91,
    ];
    let expected = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

    let mut plaintext = [0u8; 114];
    chacha20_poly1305_decrypt(&key, &nonce, &aad, &ciphertext, &tag, &mut plaintext)
        && plaintext.as_slice() == expected
}

pub fn wave8_tls_aes_gcm_roundtrip_smoke() -> bool {
    let key: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    let nonce: [u8; 12] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    ];
    let aad = b"additional authenticated data";
    let plaintext = b"Hello, AES-GCM encryption!";

    let mut ciphertext = [0u8; 26];
    let mut tag = [0u8; 16];
    if !aes_gcm_encrypt(&key, &nonce, aad, plaintext, &mut ciphertext, &mut tag) {
        return false;
    }
    if ciphertext.as_slice() == plaintext || ciphertext.len() != plaintext.len() {
        return false;
    }
    let mut decrypted = [0u8; 26];
    aes_gcm_decrypt(&key, &nonce, aad, &ciphertext, &tag, &mut decrypted)
        && decrypted.as_slice() == plaintext
}

pub fn wave8_tls_aes_gcm_auth_failure_smoke() -> bool {
    let key = [0x42u8; 16];
    let nonce = [0x01u8; 12];
    let aad = b"test aad";
    let plaintext = b"test data";

    let mut ciphertext = [0u8; 9];
    let mut tag = [0u8; 16];
    if !aes_gcm_encrypt(&key, &nonce, aad, plaintext, &mut ciphertext, &mut tag) {
        return false;
    }
    tag[0] ^= 0xFF;
    let mut decrypted = [0u8; 9];
    !aes_gcm_decrypt(&key, &nonce, aad, &ciphertext, &tag, &mut decrypted)
}

pub fn wave8_tls_aes_ctr_roundtrip_smoke() -> bool {
    let key: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    let nonce: [u8; 12] = [0x00; 12];
    let plaintext = b"AES-CTR mode test data that spans multiple blocks!!!!";

    let mut ciphertext = [0u8; 53];
    if !aes_ctr(&key, &nonce, plaintext, &mut ciphertext) {
        return false;
    }
    if ciphertext.as_slice() == plaintext {
        return false;
    }
    let mut decrypted = [0u8; 53];
    if !aes_ctr(&key, &nonce, &ciphertext, &mut decrypted) {
        return false;
    }
    decrypted.as_slice() == plaintext
}

pub fn wave8_tls_gf128_mul_zero_smoke() -> bool {
    let zero = [0u8; 16];
    let h = [0x42u8; 16];
    gf128_mul(&zero, &h) == zero
}

pub fn wave8_tls_gf_mul_basic_smoke() -> bool {
    gf_mul(0x02, 0x87) == 0x15 && gf_mul(0x01, 0x53) == 0x53 && gf_mul(0x00, 0x53) == 0x00
}

pub fn wave8_tls_tls13_early_secret_no_psk_smoke() -> bool {
    let early_secret = tls13_early_secret(None);
    let early_secret2 = tls13_early_secret(None);
    early_secret.len() == 32
        && early_secret == early_secret2
        && early_secret.iter().any(|&b| b != 0)
}

pub fn wave8_tls_tls13_handshake_secret_smoke() -> bool {
    let early_secret = tls13_early_secret(None);
    let shared_secret = [0x42u8; 32];
    let hs_secret = tls13_handshake_secret(&early_secret, &shared_secret);
    let hs_secret2 = tls13_handshake_secret(&early_secret, &[0x43u8; 32]);
    hs_secret.len() == 32 && hs_secret.iter().any(|&b| b != 0) && hs_secret != hs_secret2
}

pub fn wave8_tls_tls13_master_secret_smoke() -> bool {
    let early_secret = tls13_early_secret(None);
    let hs_secret = tls13_handshake_secret(&early_secret, &[0x42u8; 32]);
    let master_secret = tls13_master_secret(&hs_secret);
    master_secret.len() == 32 && master_secret.iter().any(|&b| b != 0)
}

pub fn wave8_tls_tls13_derive_secret_smoke() -> bool {
    let secret = [0x55u8; 32];
    let transcript = [0xAAu8; 32];
    let result = tls13_derive_secret(&secret, b"c hs traffic", &transcript);
    let result2 = tls13_derive_secret(&secret, b"s hs traffic", &transcript);
    result.len() == 32 && result.iter().any(|&b| b != 0) && result != result2
}

pub fn wave8_tls_tls13_derive_traffic_keys_smoke() -> bool {
    let secret = [0x42u8; 32];
    let mut key128 = [0u8; 16];
    let mut iv128 = [0u8; 12];
    let mut key256 = [0u8; 32];
    let mut iv256 = [0u8; 12];

    tls13_derive_traffic_keys(&secret, &mut key128, &mut iv128)
        && tls13_derive_traffic_keys(&secret, &mut key256, &mut iv256)
        && key128.as_slice() != &key256[..16]
}

pub fn wave8_tls_tls13_finished_key_and_verify_data_smoke() -> bool {
    let base_key = [0x42u8; 32];
    let finished_key = tls13_finished_key(&base_key);
    let transcript = [0xBBu8; 32];
    let verify_data = tls13_verify_data(&finished_key, &transcript);
    let verify_data2 = tls13_verify_data(&finished_key, &transcript);
    let verify_data3 = tls13_verify_data(&finished_key, &[0xCCu8; 32]);

    finished_key.len() == 32
        && finished_key.iter().any(|&b| b != 0)
        && verify_data.len() == 32
        && verify_data == verify_data2
        && verify_data != verify_data3
}

pub fn wave8_tls_tls13_full_key_schedule_smoke() -> bool {
    let shared_secret = [0x01u8; 32];

    let early_secret = tls13_early_secret(None);
    let hs_secret = tls13_handshake_secret(&early_secret, &shared_secret);

    let transcript_ch_sh = [0x02u8; 32];
    let c_hs_traffic = tls13_derive_secret(&hs_secret, b"c hs traffic", &transcript_ch_sh);
    let s_hs_traffic = tls13_derive_secret(&hs_secret, b"s hs traffic", &transcript_ch_sh);

    let mut c_key = [0u8; 16];
    let mut c_iv = [0u8; 12];
    let mut s_key = [0u8; 16];
    let mut s_iv = [0u8; 12];
    if !tls13_derive_traffic_keys(&c_hs_traffic, &mut c_key, &mut c_iv)
        || !tls13_derive_traffic_keys(&s_hs_traffic, &mut s_key, &mut s_iv)
    {
        return false;
    }

    let master = tls13_master_secret(&hs_secret);

    let transcript_sf = [0x03u8; 32];
    let c_app_traffic = tls13_derive_secret(&master, b"c ap traffic", &transcript_sf);
    let s_app_traffic = tls13_derive_secret(&master, b"s ap traffic", &transcript_sf);

    c_hs_traffic != s_hs_traffic
        && c_key != s_key
        && c_iv != s_iv
        && c_app_traffic != s_app_traffic
        && c_app_traffic != c_hs_traffic
}

pub fn wave8_tls_tls13_hkdf_expand_label_rfc8446_smoke() -> bool {
    let secret = [0x33u8; 32];
    let mut result1 = [0u8; 16];
    let mut result2 = [0u8; 16];
    let mut result3 = [0u8; 16];
    if !hkdf_expand_label(&secret, b"key", b"", &mut result1)
        || !hkdf_expand_label(&secret, b"key", b"", &mut result2)
        || !hkdf_expand_label(&secret, b"key", &[0x42u8; 32], &mut result3)
    {
        return false;
    }

    result1 == result2 && result1 != result3
}

pub fn wave8_tls_tls13_key_schedule_chain_consistency_smoke() -> bool {
    use crate::crypto::sha256;

    let shared = [0xABu8; 32];
    let empty_hash = sha256::compute(&[]);

    let early = tls13_early_secret(None);
    let derived1 = tls13_derive_secret(&early, b"derived", &empty_hash);
    let hs = hkdf_extract(&derived1, &shared);
    let derived2 = tls13_derive_secret(&hs, b"derived", &empty_hash);
    let master = hkdf_extract(&derived2, &[0u8; 32]);

    let hs2 = tls13_handshake_secret(&early, &shared);
    let master2 = tls13_master_secret(&hs2);

    hs == hs2 && master == master2
}

pub fn wave8_tls_tls13_finished_round_trip_smoke() -> bool {
    let base_key = [0x77u8; 32];
    let transcript_hash = [0x88u8; 32];

    let finished_key = tls13_finished_key(&base_key);
    let verify_data = tls13_verify_data(&finished_key, &transcript_hash);
    let expected = hmac_sha256(&finished_key, &transcript_hash);

    verify_data == expected
}

pub fn wave8_tls_hmac_sha256_long_key_smoke() -> bool {
    let key = [0xaau8; 131];
    let data = b"Test Using Larger Than Block-Size Key - Hash Key First";
    let expected: [u8; 32] = [
        0x60, 0xe4, 0x31, 0x59, 0x1e, 0xe0, 0xb6, 0x7f, 0x0d, 0x8a, 0x26, 0xaa, 0xcb, 0xf5, 0xb7,
        0x7f, 0x8e, 0x0b, 0xc6, 0x21, 0x37, 0x28, 0xc5, 0x14, 0x05, 0x46, 0x04, 0x0f, 0x0e, 0xe3,
        0x7f, 0x54,
    ];
    hmac_sha256(&key, data) == expected
}

pub fn wave8_tls_hkdf_extract_empty_salt_smoke() -> bool {
    let ikm = [0x0bu8; 22];
    let prk = hkdf_extract(&[], &ikm);
    prk.len() == 32 && prk.iter().any(|&b| b != 0)
}

pub fn wave8_tls_hkdf_expand_zero_length_smoke() -> bool {
    let prk = [0x42u8; 32];
    let mut output = [];
    hkdf_expand(&prk, b"test", &mut output) && output.is_empty()
}

pub fn wave8_tls_chacha20_poly1305_auth_failure_smoke() -> bool {
    let key = [0x42u8; 32];
    let nonce = [0x01u8; 12];
    let aad = b"additional data";
    let plaintext = b"hello, world!";

    let mut ciphertext = [0u8; 13];
    let mut tag = [0u8; 16];
    if !chacha20_poly1305_encrypt(&key, &nonce, aad, plaintext, &mut ciphertext, &mut tag) {
        return false;
    }
    tag[0] ^= 0xFF;

    let mut decrypted = [0u8; 13];
    !chacha20_poly1305_decrypt(&key, &nonce, aad, &ciphertext, &tag, &mut decrypted)
}

pub fn wave8_tls_chacha20_poly1305_roundtrip_smoke() -> bool {
    let key = [0x55u8; 32];
    let nonce = [0xAAu8; 12];
    let aad = b"test aad";
    let plaintext = b"The quick brown fox jumps over the lazy dog";

    let mut ciphertext = [0u8; 43];
    let mut tag = [0u8; 16];
    if !chacha20_poly1305_encrypt(&key, &nonce, aad, plaintext, &mut ciphertext, &mut tag) {
        return false;
    }
    if ciphertext.as_slice() == plaintext {
        return false;
    }

    let mut decrypted = [0u8; 43];
    chacha20_poly1305_decrypt(&key, &nonce, aad, &ciphertext, &tag, &mut decrypted)
        && decrypted.as_slice() == plaintext
}

pub fn wave8_tls_chacha20_poly1305_empty_plaintext_smoke() -> bool {
    let key = [0x33u8; 32];
    let nonce = [0x44u8; 12];
    let aad = b"aad only";

    let mut ciphertext = [];
    let mut tag = [0u8; 16];
    if !chacha20_poly1305_encrypt(&key, &nonce, aad, &[], &mut ciphertext, &mut tag) {
        return false;
    }

    let mut decrypted = [];
    chacha20_poly1305_decrypt(&key, &nonce, aad, &[], &tag, &mut decrypted) && decrypted.is_empty()
}

pub fn wave8_tls_aes_gcm_256_roundtrip_smoke() -> bool {
    let key: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    let nonce: [u8; 12] = [
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
    ];
    let aad = b"aes-256-gcm aad";
    let plaintext = b"AES-256-GCM test payload";

    let mut ciphertext = [0u8; 24];
    let mut tag = [0u8; 16];
    if !aes_gcm_encrypt(&key, &nonce, aad, plaintext, &mut ciphertext, &mut tag) {
        return false;
    }
    if ciphertext.len() != plaintext.len() || ciphertext.as_slice() == plaintext {
        return false;
    }

    let mut decrypted = [0u8; 24];
    aes_gcm_decrypt(&key, &nonce, aad, &ciphertext, &tag, &mut decrypted)
        && decrypted.as_slice() == plaintext
}

pub fn wave8_tls_aes_gcm_corrupted_ciphertext_smoke() -> bool {
    let key = [0x42u8; 16];
    let nonce = [0x01u8; 12];
    let aad = b"test aad";
    let plaintext = b"test data for corruption";

    let mut ciphertext = [0u8; 24];
    let mut tag = [0u8; 16];
    if !aes_gcm_encrypt(&key, &nonce, aad, plaintext, &mut ciphertext, &mut tag) {
        return false;
    }
    ciphertext[0] ^= 0xFF;

    let mut decrypted = [0u8; 24];
    !aes_gcm_decrypt(&key, &nonce, aad, &ciphertext, &tag, &mut decrypted)
}

pub fn wave8_tls_aes_gcm_empty_plaintext_smoke() -> bool {
    let key = [0x11u8; 16];
    let nonce = [0x22u8; 12];
    let aad = b"aad only, no payload";

    let mut ciphertext = [];
    let mut tag = [0u8; 16];
    if !aes_gcm_encrypt(&key, &nonce, aad, &[], &mut ciphertext, &mut tag) {
        return false;
    }

    let mut decrypted = [];
    aes_gcm_decrypt(&key, &nonce, aad, &[], &tag, &mut decrypted) && decrypted.is_empty()
}

pub fn wave8_tls_aes_gcm_key_in_place_roundtrip_smoke() -> bool {
    let key = [0x5au8; 16];
    let nonce = [0x33u8; 12];
    let aad = b"in-place aad";
    let plaintext = b"in-place aes-gcm payload";

    let Some(ctx) = AesGcmKey::new(&key) else {
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
    let Some(ctx) = AesGcmKey::new(&key) else {
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

    let Some(ctx) = AesGcmKey::new(&key) else {
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
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
        0x3c,
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

pub fn wave8_tls_hkdf_expand_label_length_smoke() -> bool {
    let secret = [0x42u8; 32];
    let mut key = [0u8; 16];
    let mut iv = [0u8; 12];
    hkdf_expand_label(&secret, b"key", b"", &mut key)
        && hkdf_expand_label(&secret, b"iv", b"", &mut iv)
}

pub fn wave8_tls_hkdf_expand_label_different_labels_smoke() -> bool {
    let secret = [0x42u8; 32];
    let mut result1 = [0u8; 32];
    let mut result2 = [0u8; 32];
    if !hkdf_expand_label(&secret, b"key", b"", &mut result1)
        || !hkdf_expand_label(&secret, b"iv", b"", &mut result2)
    {
        return false;
    }
    result1 != result2
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

pub fn wave8_tls_sha384_empty_smoke() -> bool {
    use crate::crypto::sha384;

    let hash = sha384::compute(b"");
    let expected: [u8; 48] = [
        0x38, 0xb0, 0x60, 0xa7, 0x51, 0xac, 0x96, 0x38, 0x4c, 0xd9, 0x32, 0x7e, 0xb1, 0xb1, 0xe3,
        0x6a, 0x21, 0xfd, 0xb7, 0x11, 0x14, 0xbe, 0x07, 0x43, 0x4c, 0x0c, 0xc7, 0xbf, 0x63, 0xf6,
        0xe1, 0xda, 0x27, 0x4e, 0xde, 0xbf, 0xe7, 0x6f, 0x65, 0xfb, 0xd5, 0x1a, 0xd2, 0xf1, 0x48,
        0x98, 0xb9, 0x5b,
    ];
    hash == expected
}

pub fn wave8_tls_sha384_abc_smoke() -> bool {
    use crate::crypto::sha384;

    let hash = sha384::compute(b"abc");
    let expected: [u8; 48] = [
        0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b, 0xb5, 0xa0, 0x3d, 0x69, 0x9a, 0xc6, 0x50,
        0x07, 0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63, 0x1a, 0x8b, 0x60, 0x5a, 0x43, 0xff,
        0x5b, 0xed, 0x80, 0x86, 0x07, 0x2b, 0xa1, 0xe7, 0xcc, 0x23, 0x58, 0xba, 0xec, 0xa1, 0x34,
        0xc8, 0x25, 0xa7,
    ];
    hash == expected
}

pub fn wave8_tls_hmac_sha384_rfc4231_case1_smoke() -> bool {
    let key = [0x0bu8; 20];
    let data = b"Hi There";
    let expected: [u8; 48] = [
        0xaf, 0xd0, 0x39, 0x44, 0xd8, 0x48, 0x95, 0x62, 0x6b, 0x08, 0x25, 0xf4, 0xab, 0x46, 0x90,
        0x7f, 0x15, 0xf9, 0xda, 0xdb, 0xe4, 0x10, 0x1e, 0xc6, 0x82, 0xaa, 0x03, 0x4c, 0x7c, 0xeb,
        0xc5, 0x9c, 0xfa, 0xea, 0x9e, 0xa9, 0x07, 0x6e, 0xde, 0x7f, 0x4a, 0xf1, 0x52, 0xe8, 0xb2,
        0xfa, 0x9c, 0xb6,
    ];
    hmac_sha384(&key, data) == expected
}

pub fn wave8_tls_hmac_sha384_rfc4231_case2_smoke() -> bool {
    let key = b"Jefe";
    let data = b"what do ya want for nothing?";
    let expected: [u8; 48] = [
        0xaf, 0x45, 0xd2, 0xe3, 0x76, 0x48, 0x40, 0x31, 0x61, 0x7f, 0x78, 0xd2, 0xb5, 0x8a, 0x6b,
        0x1b, 0x9c, 0x7e, 0xf4, 0x64, 0xf5, 0xa0, 0x1b, 0x47, 0xe4, 0x2e, 0xc3, 0x73, 0x63, 0x22,
        0x44, 0x5e, 0x8e, 0x22, 0x40, 0xca, 0x5e, 0x69, 0xe2, 0xc7, 0x8b, 0x32, 0x39, 0xec, 0xfa,
        0xb2, 0x16, 0x49,
    ];
    hmac_sha384(key, data) == expected
}

pub fn wave8_tls_p256_point_on_curve_smoke() -> bool {
    use crate::net::security::ecdh::p256::P256Point;
    let g = P256Point::generator();
    g.is_on_curve()
}

pub fn wave8_tls_p256_scalar_mul_base_smoke() -> bool {
    use crate::net::security::ecdh::p256::P256Point;
    use crate::net::security::ecdh::scalar_base_mul;

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

pub fn wave8_ecdh_p256_key_exchange_symmetry_smoke() -> bool {
    crate::net::security::ecdh::qemu_tests::ecdh_p256_key_exchange_symmetry_smoke()
}

pub fn wave8_ecdh_p256_public_key_length_smoke() -> bool {
    crate::net::security::ecdh::qemu_tests::ecdh_p256_public_key_length_smoke()
}

pub fn wave8_ecdh_p256_reject_invalid_peer_key_smoke() -> bool {
    crate::net::security::ecdh::qemu_tests::ecdh_p256_reject_invalid_peer_key_smoke()
}

pub fn wave8_ecdh_group_from_named_group_p256_smoke() -> bool {
    crate::net::security::ecdh::qemu_tests::ecdh_group_from_named_group_p256_smoke()
}

pub fn wave8_tls_der_parse_tag_length_smoke() -> bool {
    crate::net::security::x509::qemu_tests::x509_der_parse_tag_length_smoke()
}

pub fn wave8_tls_der_parse_integer_smoke() -> bool {
    crate::net::security::x509::qemu_tests::x509_der_parse_integer_smoke()
}

pub fn wave8_tls_der_parse_sequence_smoke() -> bool {
    crate::net::security::x509::qemu_tests::x509_der_parse_sequence_smoke()
}

pub fn wave8_tls_x509_parse_self_signed_smoke() -> bool {
    crate::net::security::x509::qemu_tests::x509_parse_self_signed_smoke()
}

pub fn wave8_tls_x509_extract_rsa_pubkey_smoke() -> bool {
    crate::net::security::x509::qemu_tests::x509_extract_rsa_pubkey_smoke()
}

pub fn wave8_tls_x509_signature_algorithm_oid_smoke() -> bool {
    crate::net::security::x509::qemu_tests::x509_signature_algorithm_oid_smoke()
}

pub fn wave8_tls_rsa_modexp_small_smoke() -> bool {
    crate::net::security::rsa::qemu_tests::rsa_modexp_small_smoke()
}

pub fn wave8_tls_rsa_modexp_medium_smoke() -> bool {
    crate::net::security::rsa::qemu_tests::rsa_modexp_medium_smoke()
}

pub fn wave8_tls_rsa_pkcs1_verify_smoke() -> bool {
    crate::net::security::rsa::qemu_tests::rsa_pkcs1_verify_smoke()
}

pub fn wave8_tls_rsa_pkcs1_verify_bad_sig_smoke() -> bool {
    crate::net::security::rsa::qemu_tests::rsa_pkcs1_verify_bad_sig_smoke()
}

pub fn wave8_tls_rsa_biguint_mul_div_smoke() -> bool {
    crate::net::security::rsa::qemu_tests::rsa_biguint_mul_div_smoke()
}
