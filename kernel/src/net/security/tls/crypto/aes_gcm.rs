// tls/crypto/aes_gcm.rs - AES-GCM AEAD

use super::aes_core::{
    AesRoundKeySchedule, aes_encrypt_block_with_schedule, aes_expand_key_schedule,
};
use alloc::vec;
use alloc::vec::Vec;
use core::ptr;

/// Constant-time 16-byte tag comparison to prevent timing side-channels.
/// The comparison always iterates through all 16 bytes and uses bitwise
/// logic to check for equality.
#[inline(never)]
fn ct_eq_16(a: &[u8; 16], b: &[u8; 16]) -> bool {
    let mut diff: u8 = 0;
    for i in 0..16 {
        // Security: XOR all bytes to accumulate differences without branching.
        diff |= a[i] ^ b[i];
    }

    // Security: Constant-time check if diff == 0.
    // If diff is 0, (diff-1) will have the high bit set (underflow).
    // If diff is > 0, (diff-1) will NOT have the high bit set.
    // We use u32 to ensure we have enough bits for the shift.
    let diff_u32 = diff as u32;
    let is_zero = ((diff_u32.wrapping_sub(1) >> 31) & 1) as u8;

    // The volatile read helps prevent the compiler from optimizing away the
    // constant-time property of the arithmetic above.
    unsafe { ptr::read_volatile(&is_zero) == 1 }
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
        // Security: avoid heap allocation in the data path
        ciphertext_out[..plaintext.len()].copy_from_slice(plaintext);
        super::aes_core::aes_ctr_with_schedule_in_place(
            &self.schedule,
            nonce,
            2,
            &mut ciphertext_out[..plaintext.len()],
        );

        let s = ghash(&self.h, aad, &ciphertext_out[..plaintext.len()]);
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
        // Security: avoid heap allocation in the data path
        plaintext_out[..ciphertext.len()].copy_from_slice(ciphertext);
        super::aes_core::aes_ctr_with_schedule_in_place(
            &self.schedule,
            nonce,
            2,
            &mut plaintext_out[..ciphertext.len()],
        );
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
    // Security: use saturating or checked math to avoid overflow in length block (RFC 5116)
    // NIST SP 800-38D: length of AAD and Ciphertext in bits.
    let aad_bits = (aad.len() as u64).saturating_mul(8);
    let ct_bits = (ciphertext.len() as u64).saturating_mul(8);
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
/// NIST SP 800-38D, Algorithm 1 (GCM Multiplication)
pub(crate) fn gf128_mul(x: &[u8; 16], h: &[u8; 16]) -> [u8; 16] {
    let mut z = [0u8; 16];
    let mut v = *h;

    for i in 0..128 {
        // If i-th bit of x is 1, Z = Z XOR V
        let bit = (x[i / 8] >> (7 - (i % 8))) & 1;
        let mask = 0u8.wrapping_sub(bit);
        for j in 0..16 {
            z[j] ^= v[j] & mask;
        }

        // V = V >> 1 (in GCM's polynomial representation)
        let carry = v[15] & 1;
        for j in (1..16).rev() {
            v[j] = (v[j] >> 1) | ((v[j - 1] & 1) << 7);
        }
        v[0] >>= 1;

        // If carry, V = V XOR R
        // R = 0xe100...0000 (standard GCM reduction polynomial)
        let carry_mask = 0u8.wrapping_sub(carry);
        v[0] ^= 0xe1 & carry_mask;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_aes_gcm_nist_vector() {
        // NIST SP 800-38D Test Case 1 (AES-128)
        // Key: 00000000000000000000000000000000
        // IV:  000000000000000000000000 (12 bytes)
        // PT:  (empty)
        // AAD: (empty)
        // CT:  (empty)
        // Tag: 58e2fccefa7e3061367f1d57a4e7455a

        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let aad = [];
        let plaintext = [];

        let (ct, tag) = aes_gcm_encrypt(&key, &nonce, &aad, &plaintext);

        assert_eq!(ct.len(), 0);
        let expected_tag = [
            0x58, 0xe2, 0xfc, 0xce, 0xfa, 0x7e, 0x30, 0x61, 0x36, 0x7f, 0x1d, 0x57, 0xa4, 0xe7,
            0x45, 0x5a,
        ];
        assert_eq!(tag, expected_tag);

        // Test decryption
        let decrypted = aes_gcm_decrypt(&key, &nonce, &aad, &ct, &tag);
        assert!(decrypted.is_some());
        assert_eq!(decrypted.unwrap().len(), 0);
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_aes_gcm_nist_vector_2() {
        // NIST SP 800-38D Test Case 2 (AES-128)
        // Key: 00000000000000000000000000000000
        // IV:  000000000000000000000000
        // PT:  00000000000000000000000000000000 (16 bytes)
        // AAD: (empty)
        // CT:  0388dace60b6a392f328c2b971b2fe78
        // Tag: ab6e47d42cec13bdf53a67b21251b397

        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let aad = [];
        let plaintext = [0u8; 16];

        let (ct, tag) = aes_gcm_encrypt(&key, &nonce, &aad, &plaintext);

        let expected_ct = [
            0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2,
            0xfe, 0x78,
        ];
        let expected_tag = [
            0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd, 0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x51,
            0xb3, 0x97,
        ];

        assert_eq!(ct, expected_ct);
        assert_eq!(tag, expected_tag);

        // Test decryption
        let decrypted = aes_gcm_decrypt(&key, &nonce, &aad, &ct, &tag);
        assert!(decrypted.is_some());
        assert_eq!(decrypted.unwrap(), plaintext.to_vec());
    }
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
