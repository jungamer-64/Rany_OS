// tls/crypto/aes_gcm.rs - AES-GCM AEAD

use alloc::vec;
use alloc::vec::Vec;
use core::ptr;
use super::aes_core::{AesRoundKeySchedule, aes_expand_key_schedule, aes_encrypt_block_with_schedule, aes_ctr_with_schedule};

/// constant‑time comparison for 16‑byte tags.  The `read_volatile` prevents LLVM
/// from optimizing the loop into a branch/early return.
#[inline(never)]
fn ct_eq_16(a: &[u8; 16], b: &[u8; 16]) -> bool {
    let mut diff: u8 = 0;
    for i in 0..16 {
        diff |= a[i] ^ b[i];
    }
    // separate the volatile read to make parsing unambiguous
    let v = unsafe { ptr::read_volatile(&diff) };
    v == 0
}

/// Precomputed AES‑GCM key material.  Creates the key schedule and H = AES(K,0)
/// once; subsequent encrypt/decrypt calls reuse them.  The API operates in-place
/// on caller‑provided buffers to enable zero‑copy operation.
pub struct AesGcmKey {
    schedule: AesRoundKeySchedule,
    h: [u8; 16],
}

impl AesGcmKey {
    /// Build a new AES‑GCM context from raw key bytes.
    pub fn new(key: &[u8]) -> Option<Self> {
        let schedule = aes_expand_key_schedule(key)?;
        let h = aes_encrypt_block_with_schedule(&[0u8; 16], &schedule);
        Some(AesGcmKey { schedule, h })
    }

    /// Encrypt `plaintext` into `ciphertext_out` and produce `tag_out`.
    /// `ciphertext_out` must be at least as long as `plaintext`.
    pub fn encrypt_in_place(
        &self,
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        ciphertext_out: &mut [u8],
        tag_out: &mut [u8; 16],
    ) -> Result<(), ()> {
        if nonce.len() != 12 || ciphertext_out.len() < plaintext.len() {
            return Err(());
        }
        // CTR encrypt
        let ct = aes_ctr_with_schedule(&self.schedule, nonce, plaintext, 2);
        ciphertext_out[..plaintext.len()].copy_from_slice(&ct);
        let s = ghash(&self.h, aad, &ct);
        let mut y0 = [0u8; 16];
        y0[0..12].copy_from_slice(nonce);
        y0[15] = 1;
        let enc_y0 = aes_encrypt_block_with_schedule(&y0, &self.schedule);
        for i in 0..16 {
            tag_out[i] = s[i] ^ enc_y0[i];
        }
        Ok(())
    }

    /// Decrypt `ciphertext` into `plaintext_out` if `tag` matches.  Returns
    /// `Ok(())` on success, `Err(())` if authentication failed or lengths are
    /// incorrect.
    pub fn decrypt_in_place(
        &self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        plaintext_out: &mut [u8],
        tag: &[u8; 16],
    ) -> Result<(), ()> {
        if nonce.len() != 12 || plaintext_out.len() < ciphertext.len() {
            return Err(());
        }
        let s = ghash(&self.h, aad, ciphertext);
        let mut y0 = [0u8; 16];
        y0[0..12].copy_from_slice(nonce);
        y0[15] = 1;
        let enc_y0 = aes_encrypt_block_with_schedule(&y0, &self.schedule);
        let mut expected_tag = [0u8; 16];
        for i in 0..16 {
            expected_tag[i] = s[i] ^ enc_y0[i];
        }
        if !ct_eq_16(tag, &expected_tag) {
            return Err(());
        }
        // perform decryption now that tag has been verified
        let pt = aes_ctr_with_schedule(&self.schedule, nonce, ciphertext, 2);
        plaintext_out[..ciphertext.len()].copy_from_slice(&pt);
        Ok(())
    }
}


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
    // constant‑time implementation of GHASH field multiplication.
    // eliminate data‑dependent branches by using bit masks.
    let mut z = [0u8; 16];
    let mut v = *h;

    for i in 0..128 {
        let byte_idx = i >> 3;                   // i/8
        let bit_idx = 7 - (i & 7);               // 7 - (i%8)
        let bit = (x[byte_idx] >> bit_idx) & 1;
        // mask is 0xFF if bit == 1, 0x00 otherwise
        let mask = 0u8.wrapping_sub(bit);        
        for j in 0..16 {
            z[j] ^= v[j] & mask;
        }

        // V = V >> 1 in GF(2^128) with reduction
        let carry = v[15] & 1;
        // shift right by one bit
        for j in (1..16).rev() {
            v[j] = (v[j] >> 1) | ((v[j - 1] & 1) << 7);
        }
        v[0] >>= 1;
        // conditional xor with R constant without branching
        let carry_mask = 0u8.wrapping_sub(carry);
        v[0] ^= 0xe1 & carry_mask; // R = 0xe1 << 120
    }

    z
}

/// AES-GCM convenience wrapper.  This allocates a temporary context on
/// every call; use `AesGcmKey` directly for high‑volume cases to avoid
/// recomputing the key schedule repeatedly.
pub(crate) fn aes_gcm_encrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> (Vec<u8>, [u8; 16]) {
    if nonce.len() != 12 {
        return (Vec::new(), [0u8; 16]);
    }

    if let Some(ctx) = AesGcmKey::new(key) {
        let mut ciphertext = vec![0u8; plaintext.len()];
        let mut tag = [0u8; 16];
        if ctx
            .encrypt_in_place(nonce, aad, plaintext, &mut ciphertext, &mut tag)
            .is_ok()
        {
            return (ciphertext, tag);
        }
    }

    (Vec::new(), [0u8; 16])
}

/// AES-GCM decryption convenience wrapper.  See `aes_gcm_encrypt`.
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

    if let Some(ctx) = AesGcmKey::new(key) {
        let mut plaintext = vec![0u8; ciphertext.len()];
        if ctx
            .decrypt_in_place(nonce, aad, ciphertext, &mut plaintext, tag)
            .is_ok()
        {
            return Some(plaintext);
        }
    }

    None
}
