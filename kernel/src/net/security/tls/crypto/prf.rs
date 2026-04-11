// tls/crypto/prf.rs - TLS 1.2 PRF and Key Derivation (RFC 5246)

use super::hmac::{
    SHA256_OUTPUT_SIZE, SHA384_OUTPUT_SIZE, hmac_sha256, hmac_sha256_parts, hmac_sha384,
    hmac_sha384_parts,
};
use super::legacy::tls10_prf;

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

    // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
    while offset < output.len() {
        let block = hmac_sha256_parts(secret, &[&a, seed]);

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
    let mut a = hmac_sha256_parts(secret, &[label, seed]);
    let mut offset = 0usize;
    while offset < output.len() {
        let block = hmac_sha256_parts(secret, &[&a, label, seed]);
        let copy_len = (output.len() - offset).min(SHA256_OUTPUT_SIZE);
        output[offset..offset + copy_len].copy_from_slice(&block[..copy_len]);
        offset += copy_len;
        a = hmac_sha256(secret, &a);
    }
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
    output: &mut [u8],
) {
    let mut seed = [0u8; 64];
    seed[..32].copy_from_slice(server_random);
    seed[32..].copy_from_slice(client_random);

    tls12_prf(master_secret, b"key expansion", &seed, output);
}

/// Derive TLS 1.2 SHA-384 key block
pub fn derive_key_block_sha384(
    master_secret: &[u8; 48],
    server_random: &[u8; 32],
    client_random: &[u8; 32],
    output: &mut [u8],
) {
    let mut seed = [0u8; 64];
    seed[..32].copy_from_slice(server_random);
    seed[32..].copy_from_slice(client_random);

    tls12_prf_sha384(master_secret, b"key expansion", &seed, output);
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

    // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
    while offset < output.len() {
        // P_i = HMAC(secret, A(i) || seed)
        let p = hmac_sha384_parts(secret, &[&a, seed]);
        let copy_len = (output.len() - offset).min(SHA384_OUTPUT_SIZE);
        output[offset..offset + copy_len].copy_from_slice(&p[..copy_len]);
        offset += copy_len;

        // A(i+1) = HMAC(secret, A(i))
        a = hmac_sha384(secret, &a);
    }
}

/// TLS 1.2 PRF using SHA-384 (for AES-256-GCM-SHA384 cipher suites)
pub fn tls12_prf_sha384(secret: &[u8], label: &[u8], seed: &[u8], output: &mut [u8]) {
    let mut a = hmac_sha384_parts(secret, &[label, seed]);
    let mut offset = 0usize;
    while offset < output.len() {
        let block = hmac_sha384_parts(secret, &[&a, label, seed]);
        let copy_len = (output.len() - offset).min(SHA384_OUTPUT_SIZE);
        output[offset..offset + copy_len].copy_from_slice(&block[..copy_len]);
        offset += copy_len;
        a = hmac_sha384(secret, &a);
    }
}
