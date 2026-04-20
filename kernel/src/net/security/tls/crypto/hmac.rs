// ============================================================================
// kernel/src/net/security/tls/crypto/hmac.rs - HMAC-SHA256/384 (RFC 2104)
// ============================================================================

/// SHA-256 block size in bytes
pub(crate) const SHA256_BLOCK_SIZE: usize = 64;

/// SHA-256 output size in bytes
pub const SHA256_OUTPUT_SIZE: usize = 32;

/// HMAC-SHA256 (RFC 2104)
///
/// Computes HMAC using SHA-256 as the underlying hash function.
/// Used as the foundation for TLS PRF and HKDF.
///
/// # Arguments
/// * `key` - HMAC key (any length; keys > 64 bytes are first hashed)
/// * `data` - Message to authenticate
///
/// # Returns
/// 32-byte MAC value
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; SHA256_OUTPUT_SIZE] {
    hmac_sha256_parts(key, &[data])
}

pub(crate) fn hmac_sha256_parts(key: &[u8], parts: &[&[u8]]) -> [u8; SHA256_OUTPUT_SIZE] {
    use crate::crypto::sha256;

    // Step 1: If key > block size, hash it to get a shorter key
    let hashed_key;
    let key_bytes: &[u8] = if key.len() > SHA256_BLOCK_SIZE {
        hashed_key = sha256::compute(key);
        &hashed_key
    } else {
        key
    };

    // Step 2: Pad key to block size, XOR with ipad/opad
    let mut ipad = [0x36u8; SHA256_BLOCK_SIZE];
    let mut opad = [0x5cu8; SHA256_BLOCK_SIZE];

    for i in 0..key_bytes.len() {
        ipad[i] ^= key_bytes[i];
        opad[i] ^= key_bytes[i];
    }

    // Step 3: Inner hash = SHA-256(ipad || data)
    let mut inner_hasher = sha256::Sha256::new();
    inner_hasher.update(&ipad);
    for part in parts {
        inner_hasher.update(part);
    }
    let inner_hash = inner_hasher.finalize();

    // Step 4: Outer hash = SHA-256(opad || inner_hash)
    let mut outer_hasher = sha256::Sha256::new();
    outer_hasher.update(&opad);
    outer_hasher.update(&inner_hash);
    outer_hasher.finalize()
}

/// SHA-384 block size in bytes (SHA-384 uses SHA-512 internals)
pub(crate) const SHA384_BLOCK_SIZE: usize = 128;

/// SHA-384 output size in bytes
pub const SHA384_OUTPUT_SIZE: usize = 48;

/// HMAC-SHA384 (RFC 2104)
///
/// Computes HMAC using SHA-384 as the underlying hash function.
/// Used for TLS 1.2 PRF when negotiating AES-256-GCM-SHA384 cipher suites.
///
/// # Arguments
/// * `key` - HMAC key (any length; keys > 128 bytes are first hashed)
/// * `data` - Message to authenticate
///
/// # Returns
/// 48-byte MAC value
pub fn hmac_sha384(key: &[u8], data: &[u8]) -> [u8; SHA384_OUTPUT_SIZE] {
    hmac_sha384_parts(key, &[data])
}

pub(crate) fn hmac_sha384_parts(key: &[u8], parts: &[&[u8]]) -> [u8; SHA384_OUTPUT_SIZE] {
    use crate::crypto::sha384;

    // Step 1: If key > block size, hash it to get a shorter key
    let hashed_key;
    let key_bytes: &[u8] = if key.len() > SHA384_BLOCK_SIZE {
        hashed_key = sha384::compute(key);
        &hashed_key
    } else {
        key
    };

    // Step 2: Pad key to block size, XOR with ipad/opad
    let mut ipad = [0x36u8; SHA384_BLOCK_SIZE];
    let mut opad = [0x5cu8; SHA384_BLOCK_SIZE];

    for i in 0..key_bytes.len() {
        ipad[i] ^= key_bytes[i];
        opad[i] ^= key_bytes[i];
    }

    // Step 3: Inner hash = SHA-384(ipad || data)
    let mut inner_hasher = sha384::Sha384::new();
    inner_hasher.update(&ipad);
    for part in parts {
        inner_hasher.update(part);
    }
    let inner_hash = inner_hasher.finalize();

    // Step 4: Outer hash = SHA-384(opad || inner_hash)
    let mut outer_hasher = sha384::Sha384::new();
    outer_hasher.update(&opad);
    outer_hasher.update(&inner_hash);
    outer_hasher.finalize()
}
