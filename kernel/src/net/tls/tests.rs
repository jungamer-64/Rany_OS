// ============================================================================
// tls/tests.rs - Unit Tests
// ============================================================================

use super::*;

// ========================================================================
// HMAC-SHA256 Tests (RFC 4231)
// ========================================================================

/// RFC 4231 Test Case 1
/// Key  = 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (20 bytes)
/// Data = "Hi There"
#[test_case]
fn test_hmac_sha256_rfc4231_case1() {
    let key = [0x0bu8; 20];
    let data = b"Hi There";
    let expected: [u8; 32] = [
        0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
        0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
        0x2e, 0x32, 0xcf, 0xf7,
    ];
    let result = hmac_sha256(&key, data);
    assert_eq!(result, expected);
}

/// RFC 4231 Test Case 2
/// Key  = "Jefe"
/// Data = "what do ya want for nothing?"
#[test_case]
fn test_hmac_sha256_rfc4231_case2() {
    let key = b"Jefe";
    let data = b"what do ya want for nothing?";
    let expected: [u8; 32] = [
        0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95,
        0x75, 0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9,
        0x64, 0xec, 0x38, 0x43,
    ];
    let result = hmac_sha256(key, data);
    assert_eq!(result, expected);
}

/// RFC 4231 Test Case 3
/// Key  = 0xaaaa... (20 bytes)
/// Data = 0xdddd... (50 bytes)
#[test_case]
fn test_hmac_sha256_rfc4231_case3() {
    let key = [0xaau8; 20];
    let data = [0xddu8; 50];
    let expected: [u8; 32] = [
        0x77, 0x3e, 0xa9, 0x1e, 0x36, 0x80, 0x0e, 0x46, 0x85, 0x4d, 0xb8, 0xeb, 0xd0, 0x91,
        0x81, 0xa7, 0x29, 0x59, 0x09, 0x8b, 0x3e, 0xf8, 0xc1, 0x22, 0xd9, 0x63, 0x55, 0x14,
        0xce, 0xd5, 0x65, 0xfe,
    ];
    let result = hmac_sha256(&key, &data);
    assert_eq!(result, expected);
}

/// HMAC-SHA256 with key longer than block size (64 bytes)
/// RFC 4231 Test Case 6
/// Key = 0xaaaa... (131 bytes)
/// Data = "Test Using Larger Than Block-Size Key - Hash Key First"
#[test_case]
fn test_hmac_sha256_long_key() {
    let key = [0xaau8; 131];
    let data = b"Test Using Larger Than Block-Size Key - Hash Key First";
    let expected: [u8; 32] = [
        0x60, 0xe4, 0x31, 0x59, 0x1e, 0xe0, 0xb6, 0x7f, 0x0d, 0x8a, 0x26, 0xaa, 0xcb, 0xf5,
        0xb7, 0x7f, 0x8e, 0x0b, 0xc6, 0x21, 0x37, 0x28, 0xc5, 0x14, 0x05, 0x46, 0x04, 0x0f,
        0x0e, 0xe3, 0x7f, 0x54,
    ];
    let result = hmac_sha256(&key, data);
    assert_eq!(result, expected);
}

// ========================================================================
// HKDF Tests (RFC 5869)
// ========================================================================

/// RFC 5869 Test Case 1 - HKDF-Extract
/// IKM  = 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (22 bytes)
/// Salt = 0x000102030405060708090a0b0c (13 bytes)
#[test_case]
fn test_hkdf_rfc5869_case1_extract() {
    let ikm = [0x0bu8; 22];
    let salt: [u8; 13] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    ];
    let expected_prk: [u8; 32] = [
        0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b,
        0xba, 0x63, 0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a,
        0xd7, 0xc2, 0xb3, 0xe5,
    ];
    let prk = hkdf_extract(&salt, &ikm);
    assert_eq!(prk, expected_prk);
}

/// RFC 5869 Test Case 1 - HKDF-Expand
/// PRK  = (from extract above)
/// Info = 0xf0f1f2f3f4f5f6f7f8f9 (10 bytes)
/// L    = 42
#[test_case]
fn test_hkdf_rfc5869_case1_expand() {
    let prk: [u8; 32] = [
        0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b,
        0xba, 0x63, 0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a,
        0xd7, 0xc2, 0xb3, 0xe5,
    ];
    let info: [u8; 10] = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
    let expected_okm: [u8; 42] = [
        0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
        0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
        0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
    ];
    let okm = hkdf_expand(&prk, &info, 42);
    assert_eq!(okm.as_slice(), &expected_okm);
}

/// HKDF-Extract with empty salt (uses zero-filled hash-length key)
#[test_case]
fn test_hkdf_extract_empty_salt() {
    let ikm = [0x0bu8; 22];
    let prk = hkdf_extract(&[], &ikm);
    // Should not panic and should produce a 32-byte output
    assert_eq!(prk.len(), 32);
    // Verify it's not all zeros (statistically impossible for valid HMAC)
    assert!(prk.iter().any(|&b| b != 0));
}

/// HKDF-Expand with zero-length output
#[test_case]
fn test_hkdf_expand_zero_length() {
    let prk = [0x42u8; 32];
    let okm = hkdf_expand(&prk, b"test", 0);
    assert!(okm.is_empty());
}

// ========================================================================
// ChaCha20 Tests (RFC 8439)
// ========================================================================

/// RFC 8439 Section 2.3.2 - ChaCha20 Block Function Test Vector
#[test_case]
fn test_chacha20_rfc8439_block() {
    let key: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
        0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
        0x1c, 0x1d, 0x1e, 0x1f,
    ];
    let nonce: [u8; 12] = [
        0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
    ];
    let counter = 1u32;

    let block = chacha20_block(&key, counter, &nonce);

    // RFC 8439 Section 2.3.2 expected output (first 16 bytes)
    let expected_start: [u8; 16] = [
        0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20,
        0x71, 0xc4,
    ];
    assert_eq!(&block[0..16], &expected_start);

    // Last 16 bytes
    let expected_end: [u8; 16] = [
        0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9, 0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50,
        0x3c, 0x4e,
    ];
    assert_eq!(&block[48..64], &expected_end);
}

/// RFC 8439 Section 2.4.2 - ChaCha20 Encryption Test Vector
#[test_case]
fn test_chacha20_rfc8439_encrypt() {
    let key: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
        0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
        0x1c, 0x1d, 0x1e, 0x1f,
    ];
    let nonce: [u8; 12] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
    ];

    let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

    let expected_ciphertext: [u8; 114] = [
        0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d,
        0x69, 0x81, 0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2, 0x0a, 0x27, 0xaf, 0xcc,
        0xfd, 0x9f, 0xae, 0x0b, 0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab, 0x8f, 0x59,
        0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57, 0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab,
        0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8, 0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d,
        0x6a, 0x61, 0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e, 0x52, 0xbc, 0x51, 0x4d,
        0x16, 0xcc, 0xf8, 0x06, 0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36, 0x5a, 0xf9,
        0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6, 0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42,
        0x87, 0x4d,
    ];

    let ciphertext = chacha20_encrypt(&key, &nonce, 1, plaintext);
    assert_eq!(ciphertext.as_slice(), &expected_ciphertext);

    // Verify decryption (ChaCha20 is symmetric)
    let decrypted = chacha20_encrypt(&key, &nonce, 1, &ciphertext);
    assert_eq!(decrypted.as_slice(), &plaintext[..]);
}

// ========================================================================
// Poly1305 Tests (RFC 8439)
// ========================================================================

/// RFC 8439 Section 2.5.2 - Poly1305 MAC Test Vector
#[test_case]
fn test_poly1305_rfc8439() {
    let key: [u8; 32] = [
        0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5,
        0x06, 0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf,
        0x41, 0x49, 0xf5, 0x1b,
    ];
    let message = b"Cryptographic Forum Research Group";
    let expected_tag: [u8; 16] = [
        0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6, 0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01,
        0x27, 0xa9,
    ];

    let tag = poly1305_mac(&key, message);
    assert_eq!(tag, expected_tag);
}

// ========================================================================
// ChaCha20-Poly1305 AEAD Tests (RFC 8439)
// ========================================================================

/// RFC 8439 Section 2.8.2 - AEAD Encryption Test Vector
#[test_case]
fn test_chacha20_poly1305_rfc8439_encrypt() {
    let key: [u8; 32] = [
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
        0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
        0x9c, 0x9d, 0x9e, 0x9f,
    ];
    let nonce: [u8; 12] = [
        0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    ];
    let aad: [u8; 12] = [
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
    ];
    let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

    let expected_ciphertext: [u8; 114] = [
        0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef,
        0x7e, 0xc2, 0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7,
        0x36, 0xee, 0x62, 0xd6, 0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa,
        0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b, 0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
        0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77,
        0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58, 0xfa, 0xb3, 0x24, 0xe4,
        0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc, 0x3f, 0xf4,
        0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
        0x61, 0x16,
    ];
    let expected_tag: [u8; 16] = [
        0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60,
        0x06, 0x91,
    ];

    let (ciphertext, tag) = chacha20_poly1305_encrypt(&key, &nonce, &aad, plaintext);
    assert_eq!(ciphertext.as_slice(), &expected_ciphertext);
    assert_eq!(tag, expected_tag);
}

/// RFC 8439 Section 2.8.2 - AEAD Decryption Test Vector
#[test_case]
fn test_chacha20_poly1305_rfc8439_decrypt() {
    let key: [u8; 32] = [
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
        0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
        0x9c, 0x9d, 0x9e, 0x9f,
    ];
    let nonce: [u8; 12] = [
        0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    ];
    let aad: [u8; 12] = [
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
    ];
    let ciphertext: [u8; 114] = [
        0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef,
        0x7e, 0xc2, 0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7,
        0x36, 0xee, 0x62, 0xd6, 0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa,
        0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b, 0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
        0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77,
        0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58, 0xfa, 0xb3, 0x24, 0xe4,
        0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc, 0x3f, 0xf4,
        0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
        0x61, 0x16,
    ];
    let tag: [u8; 16] = [
        0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60,
        0x06, 0x91,
    ];

    let plaintext = chacha20_poly1305_decrypt(&key, &nonce, &aad, &ciphertext, &tag);
    assert!(plaintext.is_some());
    let pt = plaintext.unwrap();
    assert_eq!(
        &pt,
        b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
    );
}

/// ChaCha20-Poly1305 authentication failure test
#[test_case]
fn test_chacha20_poly1305_auth_failure() {
    let key = [0x42u8; 32];
    let nonce = [0x01u8; 12];
    let aad = b"additional data";
    let plaintext = b"hello, world!";

    let (ciphertext, mut tag) = chacha20_poly1305_encrypt(&key, &nonce, aad, plaintext);

    // Corrupt the tag
    tag[0] ^= 0xFF;

    let result = chacha20_poly1305_decrypt(&key, &nonce, aad, &ciphertext, &tag);
    assert!(result.is_none());
}

/// ChaCha20-Poly1305 roundtrip test
#[test_case]
fn test_chacha20_poly1305_roundtrip() {
    let key = [0x55u8; 32];
    let nonce = [0xAAu8; 12];
    let aad = b"test aad";
    let plaintext = b"The quick brown fox jumps over the lazy dog";

    let (ciphertext, tag) = chacha20_poly1305_encrypt(&key, &nonce, aad, plaintext);

    // Verify ciphertext differs from plaintext
    assert_ne!(ciphertext.as_slice(), &plaintext[..]);

    let decrypted = chacha20_poly1305_decrypt(&key, &nonce, aad, &ciphertext, &tag);
    assert!(decrypted.is_some());
    assert_eq!(decrypted.unwrap().as_slice(), &plaintext[..]);
}

/// ChaCha20-Poly1305 with empty plaintext
#[test_case]
fn test_chacha20_poly1305_empty_plaintext() {
    let key = [0x33u8; 32];
    let nonce = [0x44u8; 12];
    let aad = b"aad only";

    let (ciphertext, tag) = chacha20_poly1305_encrypt(&key, &nonce, aad, &[]);
    assert!(ciphertext.is_empty());

    // Tag should still be valid (authenticating AAD only)
    let result = chacha20_poly1305_decrypt(&key, &nonce, aad, &[], &tag);
    assert!(result.is_some());
    assert!(result.unwrap().is_empty());
}

// ========================================================================
// AES-GCM Tests
// ========================================================================

/// AES-128-GCM roundtrip encrypt/decrypt
#[test_case]
fn test_aes_gcm_roundtrip() {
    let key: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
        0x0e, 0x0f,
    ];
    let nonce: [u8; 12] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    ];
    let aad = b"additional authenticated data";
    let plaintext = b"Hello, AES-GCM encryption!";

    let (ciphertext, tag) = aes_gcm_encrypt(&key, &nonce, aad, plaintext);

    // Verify ciphertext differs from plaintext
    assert_ne!(ciphertext.as_slice(), &plaintext[..]);
    assert_eq!(ciphertext.len(), plaintext.len());

    // Decrypt and verify
    let decrypted = aes_gcm_decrypt(&key, &nonce, aad, &ciphertext, &tag);
    assert!(decrypted.is_some());
    assert_eq!(decrypted.unwrap().as_slice(), &plaintext[..]);
}

/// AES-256-GCM roundtrip encrypt/decrypt
#[test_case]
fn test_aes_gcm_256_roundtrip() {
    let key: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
        0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
        0x1c, 0x1d, 0x1e, 0x1f,
    ];
    let nonce: [u8; 12] = [
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
    ];
    let aad = b"aes-256-gcm aad";
    let plaintext = b"AES-256-GCM test payload";

    let (ciphertext, tag) = aes_gcm_encrypt(&key, &nonce, aad, plaintext);
    assert_eq!(ciphertext.len(), plaintext.len());
    assert_ne!(ciphertext.as_slice(), &plaintext[..]);

    let decrypted = aes_gcm_decrypt(&key, &nonce, aad, &ciphertext, &tag);
    assert!(decrypted.is_some());
    assert_eq!(decrypted.unwrap().as_slice(), &plaintext[..]);
}

/// AES-128-GCM authentication failure
#[test_case]
fn test_aes_gcm_auth_failure() {
    let key = [0x42u8; 16];
    let nonce = [0x01u8; 12];
    let aad = b"test aad";
    let plaintext = b"test data";

    let (ciphertext, mut tag) = aes_gcm_encrypt(&key, &nonce, aad, plaintext);

    // Corrupt the tag
    tag[0] ^= 0xFF;

    let result = aes_gcm_decrypt(&key, &nonce, aad, &ciphertext, &tag);
    assert!(result.is_none());
}

/// AES-128-GCM with corrupted ciphertext
#[test_case]
fn test_aes_gcm_corrupted_ciphertext() {
    let key = [0x42u8; 16];
    let nonce = [0x01u8; 12];
    let aad = b"test aad";
    let plaintext = b"test data for corruption";

    let (mut ciphertext, tag) = aes_gcm_encrypt(&key, &nonce, aad, plaintext);

    // Corrupt a byte in the ciphertext
    if !ciphertext.is_empty() {
        ciphertext[0] ^= 0xFF;
    }

    let result = aes_gcm_decrypt(&key, &nonce, aad, &ciphertext, &tag);
    assert!(result.is_none());
}

/// AES-128-GCM with empty plaintext
#[test_case]
fn test_aes_gcm_empty_plaintext() {
    let key = [0x11u8; 16];
    let nonce = [0x22u8; 12];
    let aad = b"aad only, no payload";

    let (ciphertext, tag) = aes_gcm_encrypt(&key, &nonce, aad, &[]);
    assert!(ciphertext.is_empty());

    let result = aes_gcm_decrypt(&key, &nonce, aad, &[], &tag);
    assert!(result.is_some());
    assert!(result.unwrap().is_empty());
}

// ========================================================================
// AES-128 Core Tests
// ========================================================================

/// AES-128 key expansion sanity check
#[test_case]
fn test_aes_key_expansion() {
    let key: [u8; 16] = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
        0x4f, 0x3c,
    ];
    let round_keys = aes_key_expansion(&key);

    // Round key 0 should be the original key
    assert_eq!(round_keys[0], key);

    // Round keys should all be different
    for i in 0..10 {
        assert_ne!(round_keys[i], round_keys[i + 1]);
    }
}

/// AES-128 encrypt/decrypt roundtrip via CTR mode
#[test_case]
fn test_aes_ctr_roundtrip() {
    let key: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
        0x0e, 0x0f,
    ];
    let nonce: [u8; 12] = [0x00; 12];
    let plaintext = b"AES-CTR mode test data that spans multiple blocks!!!!";

    let ciphertext = aes_ctr(&key, &nonce, plaintext);
    assert_ne!(ciphertext.as_slice(), &plaintext[..]);

    // CTR mode decryption is the same as encryption
    let decrypted = aes_ctr(&key, &nonce, &ciphertext);
    assert_eq!(decrypted.as_slice(), &plaintext[..]);
}

// ========================================================================
// Hardware RNG Tests
// ========================================================================

/// Random output should not be all zeros
#[test_case]
fn test_generate_random_not_all_zeros() {
    let random = generate_random();
    assert!(random.iter().any(|&b| b != 0));
}

/// Two consecutive random calls should produce different results
#[test_case]
fn test_generate_random_different_calls() {
    let r1 = generate_random();
    let r2 = generate_random();
    // Statistically, two 32-byte random values should differ
    assert_ne!(r1, r2);
}

// ========================================================================
// TLS Key Derivation Tests
// ========================================================================

/// Master secret derivation should produce 48 bytes
#[test_case]
fn test_derive_master_secret_length() {
    let pre_master = [0x42u8; 48];
    let client_random = [0x01u8; 32];
    let server_random = [0x02u8; 32];

    let ms = derive_master_secret(&pre_master, &client_random, &server_random);
    assert_eq!(ms.len(), 48);
    // Should not be all zeros
    assert!(ms.iter().any(|&b| b != 0));
}

/// Key block derivation should produce requested length
#[test_case]
fn test_derive_key_block_length() {
    let master_secret = [0x55u8; 48];
    let server_random = [0xAAu8; 32];
    let client_random = [0xBBu8; 32];

    // AES-128-GCM: 2 * 16 (keys) + 2 * 4 (IVs) = 40 bytes
    let kb = derive_key_block(&master_secret, &server_random, &client_random, 40);
    assert_eq!(kb.len(), 40);
    assert!(kb.iter().any(|&b| b != 0));

    // AES-256-GCM: 2 * 32 (keys) + 2 * 4 (IVs) = 72 bytes
    let kb256 = derive_key_block(&master_secret, &server_random, &client_random, 72);
    assert_eq!(kb256.len(), 72);
}

/// Master secret should be deterministic for same inputs
#[test_case]
fn test_derive_master_secret_deterministic() {
    let pre_master = [0x42u8; 48];
    let client_random = [0x01u8; 32];
    let server_random = [0x02u8; 32];

    let ms1 = derive_master_secret(&pre_master, &client_random, &server_random);
    let ms2 = derive_master_secret(&pre_master, &client_random, &server_random);
    assert_eq!(ms1, ms2);
}

/// Different pre-master secrets should produce different master secrets
#[test_case]
fn test_derive_master_secret_differs_with_input() {
    let client_random = [0x01u8; 32];
    let server_random = [0x02u8; 32];

    let ms1 = derive_master_secret(&[0x42u8; 48], &client_random, &server_random);
    let ms2 = derive_master_secret(&[0x43u8; 48], &client_random, &server_random);
    assert_ne!(ms1, ms2);
}

// ========================================================================
// TLS 1.2 PRF Tests
// ========================================================================

/// PRF output should be deterministic
#[test_case]
fn test_tls12_prf_deterministic() {
    let secret = b"test secret";
    let label = b"test label";
    let seed = b"test seed";

    let mut out1 = [0u8; 64];
    let mut out2 = [0u8; 64];
    tls12_prf(secret, label, seed, &mut out1);
    tls12_prf(secret, label, seed, &mut out2);
    assert_eq!(out1, out2);
}

/// PRF with different labels should produce different output
#[test_case]
fn test_tls12_prf_different_labels() {
    let secret = b"test secret";
    let seed = b"test seed";

    let mut out1 = [0u8; 32];
    let mut out2 = [0u8; 32];
    tls12_prf(secret, b"label A", seed, &mut out1);
    tls12_prf(secret, b"label B", seed, &mut out2);
    assert_ne!(out1, out2);
}

// ========================================================================
// HKDF-Expand-Label Tests (TLS 1.3)
// ========================================================================

/// HKDF-Expand-Label should produce correct length output
#[test_case]
fn test_hkdf_expand_label_length() {
    let secret = [0x42u8; 32];
    let result = hkdf_expand_label(&secret, b"key", b"", 16);
    assert_eq!(result.len(), 16);

    let result32 = hkdf_expand_label(&secret, b"iv", b"", 12);
    assert_eq!(result32.len(), 12);
}

/// HKDF-Expand-Label with different labels should produce different output
#[test_case]
fn test_hkdf_expand_label_different_labels() {
    let secret = [0x42u8; 32];
    let result1 = hkdf_expand_label(&secret, b"key", b"", 32);
    let result2 = hkdf_expand_label(&secret, b"iv", b"", 32);
    assert_ne!(result1, result2);
}

// ========================================================================
// TLS Connection Integration Tests
// ========================================================================

/// TLS connection state machine: initial state
#[test_case]
fn test_tls_connection_initial_state() {
    let config = TlsConfig::new();
    let conn = TlsConnection::new(config);
    assert_eq!(conn.state(), TlsState::Initial);
    assert!(conn.negotiated_version().is_none());
}

/// TLS connection: build ClientHello
#[test_case]
fn test_tls_connection_client_hello() {
    let config = TlsConfig::new().with_server_name("example.com");
    let mut conn = TlsConnection::new(config);

    let hello = conn.build_client_hello();

    // Should start with TLS record header
    assert_eq!(hello[0], ContentType::Handshake as u8);
    // Version should be TLS 1.0 for compatibility
    assert_eq!(hello[1], 0x03);
    assert_eq!(hello[2], 0x01);

    // State should advance
    assert_eq!(conn.state(), TlsState::ClientHelloSent);
}

/// TLS connection: encrypt fails when not established
#[test_case]
fn test_tls_connection_encrypt_not_established() {
    let config = TlsConfig::new();
    let mut conn = TlsConnection::new(config);
    let result = conn.encrypt(b"hello");
    assert!(matches!(result, Err(TlsError::NotConnected)));
}

/// TLS handshake parser should handle multiple handshake messages in one record
#[test_case]
fn test_process_handshake_multiple_messages() {
    let config = TlsConfig::new();
    let mut conn = TlsConnection::new(config);

    let data = tls12_multi_handshake_fixture_server_hello_done_plus_valid_finished();
    let result = conn.process_handshake(&data);
    assert!(result.is_ok());
    assert_eq!(conn.state(), TlsState::Established);
    assert_eq!(conn.handshake_messages.as_slice(), data.as_slice());
}

/// Finished(len=0) is invalid for TLS 1.2 and must be rejected.
#[test_case]
fn test_process_handshake_finished_without_verify_data_rejected() {
    let config = TlsConfig::new();
    let mut conn = TlsConnection::new(config);

    let data = [20u8, 0, 0, 0];
    let result = conn.process_handshake(&data);
    assert!(matches!(result, Err(TlsError::DecodeError)));
}

/// TLS handshake parser should reject truncated handshake headers
#[test_case]
fn test_process_handshake_truncated_header() {
    let config = TlsConfig::new();
    let mut conn = TlsConnection::new(config);

    let data = [2u8, 0, 0];
    let result = conn.process_handshake(&data);
    assert!(matches!(result, Err(TlsError::DecodeError)));
}

/// CipherSuite helper methods
#[test_case]
fn test_cipher_suite_helpers() {
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
fn test_base64_decode() {
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
fn test_tls_version() {
    assert_eq!(TlsVersion::TLS_1_2.major(), 3);
    assert_eq!(TlsVersion::TLS_1_2.minor(), 3);
    assert_eq!(TlsVersion::TLS_1_3.major(), 3);
    assert_eq!(TlsVersion::TLS_1_3.minor(), 4);
    assert_eq!(TlsVersion::TLS_1_0.minor(), 1);
}

/// Default cipher suite list should include modern suites
#[test_case]
fn test_cipher_suite_defaults() {
    let defaults = CipherSuite::defaults();
    assert!(!defaults.is_empty());
    // Should include TLS 1.3 suites
    assert!(defaults.contains(&CipherSuite::TLS_AES_128_GCM_SHA256));
    assert!(defaults.contains(&CipherSuite::TLS_AES_256_GCM_SHA384));
    assert!(defaults.contains(&CipherSuite::TLS_CHACHA20_POLY1305_SHA256));
}

/// GF(2^128) multiplication sanity check
#[test_case]
fn test_gf128_mul_zero() {
    let zero = [0u8; 16];
    let h = [0x42u8; 16];
    let result = gf128_mul(&zero, &h);
    // 0 * anything = 0 in GF(2^128)
    assert_eq!(result, zero);
}

/// GF(2^8) multiplication sanity check
#[test_case]
fn test_gf_mul_basic() {
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
fn test_tls13_early_secret_no_psk() {
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
fn test_tls13_handshake_secret() {
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
fn test_tls13_master_secret() {
    let early_secret = tls13_early_secret(None);
    let hs_secret = tls13_handshake_secret(&early_secret, &[0x42u8; 32]);
    let master_secret = tls13_master_secret(&hs_secret);
    assert_eq!(master_secret.len(), 32);
    assert!(master_secret.iter().any(|&b| b != 0));
}

/// TLS 1.3: Derive-Secret produces expected-length output
#[test_case]
fn test_tls13_derive_secret() {
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
fn test_tls13_derive_traffic_keys() {
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
fn test_tls13_finished_key_and_verify_data() {
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
fn test_tls13_full_key_schedule() {
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
fn test_tls13_client_hello_key_share() {
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
fn test_tls13_client_hello_supported_versions() {
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
fn test_tls13_client_hello_psk_modes() {
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
fn test_tls13_strip_content_type() {
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
fn test_tls13_initial_state() {
    let config = TlsConfig::new();
    let conn = TlsConnection::new(config);
    assert!(!conn.is_tls13());
    assert!(!conn.needs_client_finished());
}

/// TLS 1.3: RFC 8446 Appendix A test vector for key schedule
/// Tests HKDF-Expand-Label with known inputs/outputs
#[test_case]
fn test_tls13_hkdf_expand_label_rfc8446() {
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
fn test_tls13_key_schedule_chain_consistency() {
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
fn test_tls13_finished_round_trip() {
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
fn test_tls_version_ordering() {
    assert!(TlsVersion::TLS_1_0 < TlsVersion::TLS_1_1);
    assert!(TlsVersion::TLS_1_1 < TlsVersion::TLS_1_2);
    assert!(TlsVersion::TLS_1_2 < TlsVersion::TLS_1_3);
    assert!(TlsVersion::TLS_1_3 >= TlsVersion::TLS_1_3);
}

// ========================================================================
// MD5 Tests (RFC 1321 Appendix A.5)
// ========================================================================

#[test_case]
fn test_md5_empty() {
    let result = md5_compute(b"");
    let expected = [
        0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04,
        0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e,
    ];
    assert_eq!(result, expected);
}

#[test_case]
fn test_md5_a() {
    let result = md5_compute(b"a");
    let expected = [
        0x0c, 0xc1, 0x75, 0xb9, 0xc0, 0xf1, 0xb6, 0xa8,
        0x31, 0xc3, 0x99, 0xe2, 0x69, 0x77, 0x26, 0x61,
    ];
    assert_eq!(result, expected);
}

#[test_case]
fn test_md5_abc() {
    let result = md5_compute(b"abc");
    let expected = [
        0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0,
        0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1, 0x7f, 0x72,
    ];
    assert_eq!(result, expected);
}

#[test_case]
fn test_md5_message_digest() {
    let result = md5_compute(b"message digest");
    let expected = [
        0xf9, 0x6b, 0x69, 0x7d, 0x7c, 0xb7, 0x93, 0x8d,
        0x52, 0x5a, 0x2f, 0x31, 0xaa, 0xf1, 0x61, 0xd0,
    ];
    assert_eq!(result, expected);
}

#[test_case]
fn test_md5_alphabet() {
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
fn test_sha1_abc() {
    let result = sha1_compute(b"abc");
    let expected = [
        0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a,
        0xba, 0x3e, 0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c,
        0x9c, 0xd0, 0xd8, 0x9d,
    ];
    assert_eq!(result, expected);
}

#[test_case]
fn test_sha1_empty() {
    let result = sha1_compute(b"");
    let expected = [
        0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d,
        0x32, 0x55, 0xbf, 0xef, 0x95, 0x60, 0x18, 0x90,
        0xaf, 0xd8, 0x07, 0x09,
    ];
    assert_eq!(result, expected);
}

#[test_case]
fn test_sha1_long() {
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
fn test_hmac_md5_rfc2202_case1() {
    let key = [0x0bu8; 16];
    let data = b"Hi There";
    let expected = [
        0x92, 0x94, 0x72, 0x7a, 0x36, 0x38, 0xbb, 0x1c,
        0x13, 0xf4, 0x8e, 0xf8, 0x15, 0x8b, 0xfc, 0x9d,
    ];
    assert_eq!(hmac_md5(&key, data), expected);
}

#[test_case]
fn test_hmac_md5_rfc2202_case2() {
    let key = b"Jefe";
    let data = b"what do ya want for nothing?";
    let expected = [
        0x75, 0x0c, 0x78, 0x3e, 0x6a, 0xb0, 0xb5, 0x03,
        0xea, 0xa8, 0x6e, 0x31, 0x0a, 0x5d, 0xb7, 0x38,
    ];
    assert_eq!(hmac_md5(key, data), expected);
}

#[test_case]
fn test_hmac_sha1_rfc2202_case1() {
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
fn test_hmac_sha1_rfc2202_case2() {
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
fn test_aes_cbc_roundtrip_128() {
    let key = [0x2bu8; 16];
    let iv = [0x00u8; 16];
    let plaintext = b"Hello, AES-CBC mode test!";
    let ciphertext = aes_cbc_encrypt(&key, &iv, plaintext);
    let decrypted = aes_cbc_decrypt(&key, &iv, &ciphertext);
    assert!(decrypted.is_some());
    assert_eq!(&decrypted.unwrap()[..plaintext.len()], plaintext);
}

#[test_case]
fn test_aes_cbc_roundtrip_256() {
    let key = [0x60u8; 32];
    let iv = [0x01u8; 16];
    let plaintext = b"AES-256-CBC round-trip test data for verification!";
    let ciphertext = aes_cbc_encrypt(&key, &iv, plaintext);
    let decrypted = aes_cbc_decrypt(&key, &iv, &ciphertext);
    assert!(decrypted.is_some());
    assert_eq!(&decrypted.unwrap()[..plaintext.len()], plaintext);
}

#[test_case]
fn test_aes_cbc_empty() {
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
fn test_tls_padding_add_verify() {
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
fn test_tls_padding_exact_block() {
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
fn test_tls_padding_full_block_pad() {
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
fn test_tls10_prf_deterministic() {
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
fn test_tls10_prf_different_labels() {
    let secret = [0x42u8; 48];
    let seed = [0x01u8; 64];
    let mut out1 = [0u8; 48];
    let mut out2 = [0u8; 48];
    tls10_prf(&secret, b"client finished", &seed, &mut out1);
    tls10_prf(&secret, b"server finished", &seed, &mut out2);
    assert_ne!(out1, out2);
}

// ========================================================================
// TLS MAC Tests
// ========================================================================

#[test_case]
fn test_tls_mac_sha1() {
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
fn test_tls_mac_sha256() {
    let key = [0x0Bu8; 32];
    let mac = compute_tls_mac(
        &key, 0, ContentType::ApplicationData as u8,
        TlsVersion::TLS_1_2, b"hello", false,
    );
    assert_eq!(mac.len(), 32); // SHA-256 output
}

#[test_case]
fn test_tls_mac_seq_affects_output() {
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
fn test_cbc_cipher_suite_helpers() {
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
fn test_cbc_ecdhe_cipher_suite() {
    let suite = CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256;
    assert!(suite.is_cbc());
    assert!(!suite.is_rsa_key_transport());
    assert!(!suite.uses_sha1_mac());
    assert_eq!(suite.mac_key_len(), 32);
    assert_eq!(suite.mac_len(), 32);
}

#[test_case]
fn test_aead_not_cbc() {
    let suite = CipherSuite::TLS_AES_128_GCM_SHA256;
    assert!(!suite.is_cbc());
    assert!(!suite.is_rsa_key_transport());
    assert!(!suite.is_legacy_compatible());
}
