// tls/crypto/prf.rs - TLS 1.2 PRF and Key Derivation (RFC 5246)

use super::hmac::{SHA256_OUTPUT_SIZE, SHA384_OUTPUT_SIZE, hmac_sha256, hmac_sha384};
use super::legacy::tls10_prf;
use alloc::vec;
use alloc::vec::Vec;

// ============================================================================
// TLS 1.2 PRF (RFC 5246 Section 5)
// ============================================================================

/// P_SHA256 expansion function (RFC 5246 Section 5)
///
/// P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
///                         HMAC_hash(secret, A(2) + seed) + ...
/// where A(0) = seed, A(i) = HMAC_hash(secret, A(i-1))
fn p_sha256(secret: &[u8], seed: &[u8], output: &mut [u8]) {
    let mut a = hmac_sha256(secret, seed); // A(1)
    let mut offset = 0;

    while offset < output.len() {
        // HMAC_hash(secret, A(i) + seed)
        let mut a_seed = Vec::with_capacity(a.len() + seed.len());
        a_seed.extend_from_slice(&a);
        a_seed.extend_from_slice(seed);

        let block = hmac_sha256(secret, &a_seed);

        let copy_len = (output.len() - offset).min(SHA256_OUTPUT_SIZE);
        output[offset..offset + copy_len].copy_from_slice(&block[..copy_len]);
        offset += copy_len;

        // A(i+1) = HMAC_hash(secret, A(i))
        a = hmac_sha256(secret, &a);
    }
}

/// TLS 1.2 PRF using SHA-256 (RFC 5246 Section 5)
///
/// PRF(secret, label, seed) = P_SHA256(secret, label + seed)
pub fn tls12_prf(secret: &[u8], label: &[u8], seed: &[u8], output: &mut [u8]) {
    let mut combined_seed = Vec::with_capacity(label.len() + seed.len());
    combined_seed.extend_from_slice(label);
    combined_seed.extend_from_slice(seed);

    p_sha256(secret, &combined_seed, output);
}

/// Derive TLS 1.2 master secret (RFC 5246 Section 8.1)
///
/// master_secret = PRF(pre_master_secret, "master secret",
///                      ClientHello.random + ServerHello.random)[0..47]
pub fn derive_master_secret(
    pre_master_secret: &[u8],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
) -> [u8; 48] {
    let mut seed = [0u8; 64];
    seed[..32].copy_from_slice(client_random);
    seed[32..].copy_from_slice(server_random);

    let mut master_secret = [0u8; 48];
    tls12_prf(
        pre_master_secret,
        b"master secret",
        &seed,
        &mut master_secret,
    );
    master_secret
}

/// Derive TLS 1.2 key block (RFC 5246 Section 6.3)
///
/// key_block = PRF(SecurityParameters.master_secret, "key expansion",
///                  SecurityParameters.server_random +
///                  SecurityParameters.client_random)
pub fn derive_key_block(
    master_secret: &[u8; 48],
    server_random: &[u8; 32],
    client_random: &[u8; 32],
    key_material_len: usize,
) -> Vec<u8> {
    let mut seed = [0u8; 64];
    seed[..32].copy_from_slice(server_random);
    seed[32..].copy_from_slice(client_random);

    let mut key_block = vec![0u8; key_material_len];
    tls12_prf(master_secret, b"key expansion", &seed, &mut key_block);
    key_block
}

/// Derive TLS 1.2 SHA-384 key block
pub fn derive_key_block_sha384(
    master_secret: &[u8; 48],
    server_random: &[u8; 32],
    client_random: &[u8; 32],
    key_material_len: usize,
) -> Vec<u8> {
    let mut seed = [0u8; 64];
    seed[..32].copy_from_slice(server_random);
    seed[32..].copy_from_slice(client_random);

    let mut key_block = vec![0u8; key_material_len];
    tls12_prf_sha384(master_secret, b"key expansion", &seed, &mut key_block);
    key_block
}

/// Derive TLS 1.0/1.1 master secret (RFC 2246 Section 8.1)
///
/// デュアルハッシュPRFを使用する。
pub fn derive_master_secret_tls10(
    pre_master_secret: &[u8],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
) -> [u8; 48] {
    let mut seed = [0u8; 64];
    seed[..32].copy_from_slice(client_random);
    seed[32..].copy_from_slice(server_random);

    let mut master_secret = [0u8; 48];
    tls10_prf(
        pre_master_secret,
        b"master secret",
        &seed,
        &mut master_secret,
    );
    master_secret
}

/// Derive TLS 1.2 SHA-384 master secret
pub fn derive_master_secret_sha384(
    pre_master_secret: &[u8],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
) -> [u8; 48] {
    let mut seed = [0u8; 64];
    seed[..32].copy_from_slice(client_random);
    seed[32..].copy_from_slice(server_random);

    let mut master_secret = [0u8; 48];
    tls12_prf_sha384(
        pre_master_secret,
        b"master secret",
        &seed,
        &mut master_secret,
    );
    master_secret
}

// ============================================================================
// P_SHA384 and TLS 1.2 PRF-SHA384
// ============================================================================

/// P_SHA384 expansion (RFC 5246 Section 5)
///
/// P_SHA384(secret, seed) = HMAC_SHA384(secret, A(1) + seed) +
///                           HMAC_SHA384(secret, A(2) + seed) + ...
/// A(0) = seed
/// A(i) = HMAC_SHA384(secret, A(i-1))
pub fn p_sha384(secret: &[u8], seed: &[u8], output: &mut [u8]) {
    let mut a = hmac_sha384(secret, seed); // A(1)
    let mut offset = 0;

    while offset < output.len() {
        // P_i = HMAC(secret, A(i) || seed)
        let mut input = Vec::with_capacity(SHA384_OUTPUT_SIZE + seed.len());
        input.extend_from_slice(&a);
        input.extend_from_slice(seed);

        let p = hmac_sha384(secret, &input);
        let copy_len = (output.len() - offset).min(SHA384_OUTPUT_SIZE);
        output[offset..offset + copy_len].copy_from_slice(&p[..copy_len]);
        offset += copy_len;

        // A(i+1) = HMAC(secret, A(i))
        a = hmac_sha384(secret, &a);
    }
}

/// TLS 1.2 PRF using SHA-384 (for AES-256-GCM-SHA384 cipher suites)
pub fn tls12_prf_sha384(secret: &[u8], label: &[u8], seed: &[u8], output: &mut [u8]) {
    let mut combined_seed = Vec::with_capacity(label.len() + seed.len());
    combined_seed.extend_from_slice(label);
    combined_seed.extend_from_slice(seed);

    p_sha384(secret, &combined_seed, output);
}
