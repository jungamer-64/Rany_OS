// tls/crypto/chacha20.rs - ChaCha20-Poly1305 AEAD (RFC 8439)

use alloc::vec::Vec;

/// ChaCha20 quarter round operation (RFC 8439 Section 2.1)
#[inline]
fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);

    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

/// ChaCha20 block function (RFC 8439 Section 2.3)
///
/// Generates 64 bytes of keystream from key, counter, and nonce.
pub(crate) fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    // Initialize state:
    // "expand 32-byte k" constants + key(8 words) + counter(1 word) + nonce(3 words)
    let mut state = [0u32; 16];

    // Constants: "expand 32-byte k"
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;

    // Key (little-endian words)
    for i in 0..8 {
        let offset = i * 4;
        state[4 + i] = u32::from_le_bytes([
            key[offset],
            key[offset + 1],
            key[offset + 2],
            key[offset + 3],
        ]);
    }

    // Counter
    state[12] = counter;

    // Nonce (little-endian words)
    state[13] = u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]);
    state[14] = u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]);
    state[15] = u32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]);

    // Save initial state for final addition
    let initial = state;

    // 20 rounds (10 iterations of double-round)
    for _ in 0..10 {
        // Column rounds
        quarter_round(&mut state, 0, 4, 8, 12);
        quarter_round(&mut state, 1, 5, 9, 13);
        quarter_round(&mut state, 2, 6, 10, 14);
        quarter_round(&mut state, 3, 7, 11, 15);
        // Diagonal rounds
        quarter_round(&mut state, 0, 5, 10, 15);
        quarter_round(&mut state, 1, 6, 11, 12);
        quarter_round(&mut state, 2, 7, 8, 13);
        quarter_round(&mut state, 3, 4, 9, 14);
    }

    // Add initial state
    for i in 0..16 {
        state[i] = state[i].wrapping_add(initial[i]);
    }

    // Serialize to little-endian bytes
    let mut result = [0u8; 64];
    for i in 0..16 {
        let bytes = state[i].to_le_bytes();
        result[i * 4] = bytes[0];
        result[i * 4 + 1] = bytes[1];
        result[i * 4 + 2] = bytes[2];
        result[i * 4 + 3] = bytes[3];
    }

    result
}

/// ChaCha20 encryption/decryption (RFC 8439 Section 2.4)
///
/// XOR data with ChaCha20 keystream. Works for both encryption and decryption
/// since ChaCha20 is a stream cipher.
pub fn chacha20_encrypt(key: &[u8; 32], nonce: &[u8; 12], counter: u32, data: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(data.len());
    let mut block_counter = counter;

    for chunk in data.chunks(64) {
        let keystream = chacha20_block(key, block_counter, nonce);
        for (i, &byte) in chunk.iter().enumerate() {
            result.push(byte ^ keystream[i]);
        }
        block_counter = block_counter.wrapping_add(1);
    }

    result
}

/// Poly1305 MAC computation (RFC 8439 Section 2.5)
///
/// Computes a 16-byte authentication tag using the Poly1305 algorithm.
/// The 32-byte key is split: r = key[0..16] (clamped), s = key[16..32].
pub fn poly1305_mac(key: &[u8; 32], message: &[u8]) -> [u8; 16] {
    // Clamp r according to RFC 8439 Section 2.5.1.
    let mut r = [0u8; 16];
    r.copy_from_slice(&key[..16]);
    r[3] &= 15;
    r[7] &= 15;
    r[11] &= 15;
    r[15] &= 15;
    r[4] &= 252;
    r[8] &= 252;
    r[12] &= 252;

    // Represent r as 26-bit limbs.
    let t0 = u32::from_le_bytes([r[0], r[1], r[2], r[3]]) as u64;
    let t1 = u32::from_le_bytes([r[4], r[5], r[6], r[7]]) as u64;
    let t2 = u32::from_le_bytes([r[8], r[9], r[10], r[11]]) as u64;
    let t3 = u32::from_le_bytes([r[12], r[13], r[14], r[15]]) as u64;

    let r0 = t0 & 0x3ffffff;
    let r1 = ((t0 >> 26) | (t1 << 6)) & 0x3ffff03;
    let r2 = ((t1 >> 20) | (t2 << 12)) & 0x3ffc0ff;
    let r3 = ((t2 >> 14) | (t3 << 18)) & 0x3f03fff;
    let r4 = (t3 >> 8) & 0x00fffff;

    let r1_5 = r1 * 5;
    let r2_5 = r2 * 5;
    let r3_5 = r3 * 5;
    let r4_5 = r4 * 5;

    // Accumulator h in 26-bit limbs.
    let mut h0 = 0u64;
    let mut h1 = 0u64;
    let mut h2 = 0u64;
    let mut h3 = 0u64;
    let mut h4 = 0u64;

    let mut offset = 0usize;
    while offset < message.len() {
        let block_len = (message.len() - offset).min(16);
        let mut block = [0u8; 17];
        block[..block_len].copy_from_slice(&message[offset..offset + block_len]);
        block[block_len] = 1;
        let m = poly1305_block_to_limbs(&block);

        h0 += m[0];
        h1 += m[1];
        h2 += m[2];
        h3 += m[3];
        h4 += m[4];

        let d0 = (h0 as u128 * r0 as u128)
            + (h1 as u128 * r4_5 as u128)
            + (h2 as u128 * r3_5 as u128)
            + (h3 as u128 * r2_5 as u128)
            + (h4 as u128 * r1_5 as u128);
        let d1 = (h0 as u128 * r1 as u128)
            + (h1 as u128 * r0 as u128)
            + (h2 as u128 * r4_5 as u128)
            + (h3 as u128 * r3_5 as u128)
            + (h4 as u128 * r2_5 as u128);
        let d2 = (h0 as u128 * r2 as u128)
            + (h1 as u128 * r1 as u128)
            + (h2 as u128 * r0 as u128)
            + (h3 as u128 * r4_5 as u128)
            + (h4 as u128 * r3_5 as u128);
        let d3 = (h0 as u128 * r3 as u128)
            + (h1 as u128 * r2 as u128)
            + (h2 as u128 * r1 as u128)
            + (h3 as u128 * r0 as u128)
            + (h4 as u128 * r4_5 as u128);
        let d4 = (h0 as u128 * r4 as u128)
            + (h1 as u128 * r3 as u128)
            + (h2 as u128 * r2 as u128)
            + (h3 as u128 * r1 as u128)
            + (h4 as u128 * r0 as u128);

        let mut c = (d0 >> 26) as u64;
        h0 = (d0 as u64) & 0x3ffffff;

        let d1 = d1 + c as u128;
        c = (d1 >> 26) as u64;
        h1 = (d1 as u64) & 0x3ffffff;

        let d2 = d2 + c as u128;
        c = (d2 >> 26) as u64;
        h2 = (d2 as u64) & 0x3ffffff;

        let d3 = d3 + c as u128;
        c = (d3 >> 26) as u64;
        h3 = (d3 as u64) & 0x3ffffff;

        let d4 = d4 + c as u128;
        c = (d4 >> 26) as u64;
        h4 = (d4 as u64) & 0x3ffffff;

        h0 += c * 5;
        c = h0 >> 26;
        h0 &= 0x3ffffff;
        h1 += c;

        offset += block_len;
    }

    // Final carry propagation.
    let mut c = h1 >> 26;
    h1 &= 0x3ffffff;
    h2 += c;
    c = h2 >> 26;
    h2 &= 0x3ffffff;
    h3 += c;
    c = h3 >> 26;
    h3 &= 0x3ffffff;
    h4 += c;
    c = h4 >> 26;
    h4 &= 0x3ffffff;
    h0 += c * 5;
    c = h0 >> 26;
    h0 &= 0x3ffffff;
    h1 += c;

    // If h >= p (2^130 - 5), subtract p.
    const P0: u64 = 0x3fffffb;
    const P1: u64 = 0x3ffffff;
    const P2: u64 = 0x3ffffff;
    const P3: u64 = 0x3ffffff;
    const P4: u64 = 0x3ffffff;

    let ge_p = (h4 > P4)
        || (h4 == P4
            && ((h3 > P3)
                || (h3 == P3
                    && ((h2 > P2) || (h2 == P2 && ((h1 > P1) || (h1 == P1 && h0 >= P0)))))));

    if ge_p {
        let mut borrow = 0u64;

        let mut t0 = h0.wrapping_sub(P0 + borrow);
        borrow = if h0 < P0 + borrow { 1 } else { 0 };
        if borrow != 0 {
            t0 = t0.wrapping_add(1 << 26);
        }

        let mut t1 = h1.wrapping_sub(P1 + borrow);
        borrow = if h1 < P1 + borrow { 1 } else { 0 };
        if borrow != 0 {
            t1 = t1.wrapping_add(1 << 26);
        }

        let mut t2 = h2.wrapping_sub(P2 + borrow);
        borrow = if h2 < P2 + borrow { 1 } else { 0 };
        if borrow != 0 {
            t2 = t2.wrapping_add(1 << 26);
        }

        let mut t3 = h3.wrapping_sub(P3 + borrow);
        borrow = if h3 < P3 + borrow { 1 } else { 0 };
        if borrow != 0 {
            t3 = t3.wrapping_add(1 << 26);
        }

        let t4 = h4.wrapping_sub(P4 + borrow);

        h0 = t0;
        h1 = t1;
        h2 = t2;
        h3 = t3;
        h4 = t4;
    }

    // Serialize h (130 bits) into 128 bits and add s (mod 2^128).
    let f0 = h0 | (h1 << 26);
    let f1 = (h1 >> 6) | (h2 << 20);
    let f2 = (h2 >> 12) | (h3 << 14);
    let f3 = (h3 >> 18) | (h4 << 8);

    let s0 = u32::from_le_bytes([key[16], key[17], key[18], key[19]]) as u64;
    let s1 = u32::from_le_bytes([key[20], key[21], key[22], key[23]]) as u64;
    let s2 = u32::from_le_bytes([key[24], key[25], key[26], key[27]]) as u64;
    let s3 = u32::from_le_bytes([key[28], key[29], key[30], key[31]]) as u64;

    let mut g0 = (f0 & 0xffff_ffff).wrapping_add(s0);
    let mut g1 = (f1 & 0xffff_ffff).wrapping_add(s1).wrapping_add(g0 >> 32);
    g0 &= 0xffff_ffff;
    let mut g2 = (f2 & 0xffff_ffff).wrapping_add(s2).wrapping_add(g1 >> 32);
    g1 &= 0xffff_ffff;
    let g3 = (f3 & 0xffff_ffff).wrapping_add(s3).wrapping_add(g2 >> 32);
    g2 &= 0xffff_ffff;

    let mut tag = [0u8; 16];
    tag[0..4].copy_from_slice(&(g0 as u32).to_le_bytes());
    tag[4..8].copy_from_slice(&(g1 as u32).to_le_bytes());
    tag[8..12].copy_from_slice(&(g2 as u32).to_le_bytes());
    tag[12..16].copy_from_slice(&(g3 as u32).to_le_bytes());
    tag
}

/// Parse a Poly1305 block (16-byte chunk plus 0x01 pad byte) into 26-bit limbs.
fn poly1305_block_to_limbs(block: &[u8; 17]) -> [u64; 5] {
    let lo = u64::from_le_bytes([
        block[0], block[1], block[2], block[3], block[4], block[5], block[6], block[7],
    ]);
    let hi = u64::from_le_bytes([
        block[8], block[9], block[10], block[11], block[12], block[13], block[14], block[15],
    ]);
    let top = block[16] as u64;

    [
        lo & 0x3ffffff,
        (lo >> 26) & 0x3ffffff,
        ((lo >> 52) | (hi << 12)) & 0x3ffffff,
        (hi >> 14) & 0x3ffffff,
        ((hi >> 40) | (top << 24)) & 0x3ffffff,
    ]
}

/// Construct Poly1305 AEAD MAC input (RFC 8439 Section 2.8)
///
/// The MAC input for AEAD is:
///   AAD || pad16(AAD) || ciphertext || pad16(ciphertext) ||
///   le64(aad_len) || le64(ciphertext_len)
fn poly1305_aead_construct(aad: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let aad_pad = (16 - (aad.len() % 16)) % 16;
    let ct_pad = (16 - (ciphertext.len() % 16)) % 16;

    let total = aad.len() + aad_pad + ciphertext.len() + ct_pad + 16;
    let mut mac_data = Vec::with_capacity(total);

    mac_data.extend_from_slice(aad);
    mac_data.resize(mac_data.len() + aad_pad, 0);

    mac_data.extend_from_slice(ciphertext);
    mac_data.resize(mac_data.len() + ct_pad, 0);

    mac_data.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    mac_data.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());

    mac_data
}

/// ChaCha20-Poly1305 AEAD encryption (RFC 8439 Section 2.8)
///
/// # Returns
/// (ciphertext, 16-byte authentication tag)
pub fn chacha20_poly1305_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> (Vec<u8>, [u8; 16]) {
    // Generate Poly1305 one-time key from first ChaCha20 block (counter=0)
    let poly_key_block = chacha20_block(key, 0, nonce);
    let mut poly_key = [0u8; 32];
    poly_key.copy_from_slice(&poly_key_block[..32]);

    // Encrypt payload starting from counter=1
    let ciphertext = chacha20_encrypt(key, nonce, 1, plaintext);

    // Compute authentication tag
    let mac_input = poly1305_aead_construct(aad, &ciphertext);
    let tag = poly1305_mac(&poly_key, &mac_input);

    (ciphertext, tag)
}

/// ChaCha20-Poly1305 AEAD decryption (RFC 8439 Section 2.8)
///
/// # Returns
/// `Some(plaintext)` if authentication succeeds, `None` otherwise.
/// Uses constant-time tag comparison to prevent timing attacks.
pub fn chacha20_poly1305_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
) -> Option<Vec<u8>> {
    // Generate Poly1305 one-time key from first ChaCha20 block (counter=0)
    let poly_key_block = chacha20_block(key, 0, nonce);
    let mut poly_key = [0u8; 32];
    poly_key.copy_from_slice(&poly_key_block[..32]);

    // Compute expected authentication tag
    let mac_input = poly1305_aead_construct(aad, ciphertext);
    let expected_tag = poly1305_mac(&poly_key, &mac_input);

    // Constant-time tag comparison
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= tag[i] ^ expected_tag[i];
    }

    if diff != 0 {
        return None; // Authentication failed
    }

    // Decrypt payload starting from counter=1
    let plaintext = chacha20_encrypt(key, nonce, 1, ciphertext);
    Some(plaintext)
}
