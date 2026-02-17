// tls/crypto/aes_gcm.rs - AES-GCM AEAD

use alloc::vec::Vec;
use super::aes_core::{AesRoundKeySchedule, aes_expand_key_schedule, aes_encrypt_block_with_schedule, aes_ctr_with_schedule};

/// GCM GHASH演算
fn ghash(h: &[u8; 16], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    let mut y = [0u8; 16];

    // Process AAD
    for chunk in aad.chunks(16) {
        let mut block = [0u8; 16];
        block[..chunk.len()].copy_from_slice(chunk);
        for i in 0..16 {
            y[i] ^= block[i];
        }
        y = gf128_mul(&y, h);
    }

    // Process ciphertext
    for chunk in ciphertext.chunks(16) {
        let mut block = [0u8; 16];
        block[..chunk.len()].copy_from_slice(chunk);
        for i in 0..16 {
            y[i] ^= block[i];
        }
        y = gf128_mul(&y, h);
    }

    // Process length block
    let aad_bits = (aad.len() as u64) * 8;
    let ct_bits = (ciphertext.len() as u64) * 8;
    let mut len_block = [0u8; 16];
    len_block[0..8].copy_from_slice(&aad_bits.to_be_bytes());
    len_block[8..16].copy_from_slice(&ct_bits.to_be_bytes());

    for i in 0..16 {
        y[i] ^= len_block[i];
    }
    y = gf128_mul(&y, h);

    y
}

/// GF(2^128) 乗算 (GHASH用)
pub(crate) fn gf128_mul(x: &[u8; 16], h: &[u8; 16]) -> [u8; 16] {
    let mut z = [0u8; 16];
    let mut v = *h;

    for i in 0..128 {
        let byte_idx = i / 8;
        let bit_idx = 7 - (i % 8);

        if (x[byte_idx] >> bit_idx) & 1 == 1 {
            for j in 0..16 {
                z[j] ^= v[j];
            }
        }

        // V = V >> 1 in GF(2^128)
        let lsb = v[15] & 1;
        for j in (1..16).rev() {
            v[j] = (v[j] >> 1) | ((v[j - 1] & 1) << 7);
        }
        v[0] >>= 1;

        if lsb == 1 {
            v[0] ^= 0xe1; // R = 0xe1 << 120
        }
    }

    z
}

/// AES-GCM 暗号化
pub(crate) fn aes_gcm_encrypt(key: &[u8], nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> (Vec<u8>, [u8; 16]) {
    if nonce.len() != 12 {
        return (Vec::new(), [0u8; 16]);
    }

    let Some(schedule) = aes_expand_key_schedule(key) else {
        return (Vec::new(), [0u8; 16]);
    };

    // Generate H = AES(K, 0^128)
    let h = aes_encrypt_block_with_schedule(&[0u8; 16], &schedule);

    // Encrypt plaintext with CTR mode
    let ciphertext = aes_ctr_with_schedule(&schedule, nonce, plaintext);

    // Calculate GHASH
    let s = ghash(&h, aad, &ciphertext);

    // Calculate tag: T = GHASH XOR AES(K, Y0)
    let mut y0 = [0u8; 16];
    y0[0..12].copy_from_slice(nonce);
    y0[15] = 1; // Counter = 1
    let encrypted_y0 = aes_encrypt_block_with_schedule(&y0, &schedule);

    let mut tag = [0u8; 16];
    for i in 0..16 {
        tag[i] = s[i] ^ encrypted_y0[i];
    }

    (ciphertext, tag)
}

/// AES-GCM 復号
pub(crate) fn aes_gcm_decrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
) -> Option<Vec<u8>> {
    if nonce.len() != 12 {
        return None;
    }

    let schedule = aes_expand_key_schedule(key)?;

    // Generate H
    let h = aes_encrypt_block_with_schedule(&[0u8; 16], &schedule);

    // Calculate expected tag
    let s = ghash(&h, aad, ciphertext);

    let mut y0 = [0u8; 16];
    y0[0..12].copy_from_slice(nonce);
    y0[15] = 1;
    let encrypted_y0 = aes_encrypt_block_with_schedule(&y0, &schedule);

    let mut expected_tag = [0u8; 16];
    for i in 0..16 {
        expected_tag[i] = s[i] ^ encrypted_y0[i];
    }

    // Verify tag (constant-time comparison)
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= tag[i] ^ expected_tag[i];
    }

    if diff != 0 {
        return None; // Authentication failed
    }

    // Decrypt
    let plaintext = aes_ctr_with_schedule(&schedule, nonce, ciphertext);
    Some(plaintext)
}
