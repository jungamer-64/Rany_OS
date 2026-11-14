// ============================================================================
// kernel/src/net/security/tls/crypto/test_support.rs - contiguous AEAD vectors
// ============================================================================
//! Contiguous-buffer adapters over the chunked primitives the record layer
//! uses, so known-answer vectors exercise the production code path.

use super::aes_core::{AesRoundKeySchedule, aes_encrypt_block_with_schedule};
use super::aes_gcm::AesGcmKey;
use super::chacha20::{
    Poly1305State, chacha20_block, chacha20_poly1305_tag_chunks, chacha20_xor_chunks_in_place,
};

fn chacha20_poly1305_key(key: &[u8; 32], nonce: &[u8; 12]) -> [u8; 32] {
    let block = chacha20_block(key, 0, nonce);
    let mut poly_key = [0u8; 32];
    poly_key.copy_from_slice(&block[..32]);
    poly_key
}

fn tags_equal(lhs: &[u8; 16], rhs: &[u8; 16]) -> bool {
    lhs.iter().zip(rhs).fold(0u8, |diff, (a, b)| diff | (a ^ b)) == 0
}

pub(crate) fn chacha20_xor_in_place(
    key: &[u8; 32],
    nonce: &[u8; 12],
    counter: u32,
    data: &mut [u8],
) {
    chacha20_xor_chunks_in_place(key, nonce, counter, |visit| visit(data));
}

pub(crate) fn poly1305_mac(key: &[u8; 32], message: &[u8]) -> [u8; 16] {
    let mut state = Poly1305State::new(key);
    state.update(message);
    state.finalize()
}

/// RFC 8439 Section 2.8 sealing of `data` in place.
pub(crate) fn chacha20_poly1305_encrypt_in_place(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    data: &mut [u8],
    tag_out: &mut [u8; 16],
) {
    let poly_key = chacha20_poly1305_key(key, nonce);
    chacha20_xor_in_place(key, nonce, 1, data);
    let len = data.len();
    *tag_out = chacha20_poly1305_tag_chunks(&poly_key, aad, len, |visit| visit(data))
        .expect("a single chunk covers the ciphertext length");
}

/// RFC 8439 Section 2.8 opening; `data` is unchanged when authentication fails.
pub(crate) fn chacha20_poly1305_decrypt_in_place(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    data: &mut [u8],
    tag: &[u8; 16],
) -> Result<(), ()> {
    let poly_key = chacha20_poly1305_key(key, nonce);
    let len = data.len();
    let expected =
        chacha20_poly1305_tag_chunks(&poly_key, aad, len, |visit| visit(data)).ok_or(())?;
    if !tags_equal(tag, &expected) {
        return Err(());
    }
    chacha20_xor_in_place(key, nonce, 1, data);
    Ok(())
}

/// AES-GCM sealing (NIST SP 800-38D) through the record-layer key API.
pub(crate) fn aes_gcm_key_encrypt(
    key: &AesGcmKey,
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    ciphertext_out: &mut [u8],
    tag_out: &mut [u8; 16],
) -> Result<(), ()> {
    if ciphertext_out.len() < plaintext.len() {
        return Err(());
    }
    let ciphertext = &mut ciphertext_out[..plaintext.len()];
    ciphertext.copy_from_slice(plaintext);
    key.xor_chunks_in_place(nonce, |visit| visit(ciphertext))?;
    let len = ciphertext.len();
    *tag_out = key.tag_for_ciphertext_chunks(nonce, aad, len, |visit| visit(ciphertext))?;
    Ok(())
}

/// AES-GCM opening; `plaintext_out` is unchanged when authentication fails.
pub(crate) fn aes_gcm_key_decrypt(
    key: &AesGcmKey,
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    plaintext_out: &mut [u8],
    tag: &[u8; 16],
) -> Result<(), ()> {
    if plaintext_out.len() < ciphertext.len() {
        return Err(());
    }
    key.verify_ciphertext_chunks(nonce, aad, ciphertext.len(), |visit| visit(ciphertext), tag)?;
    let plaintext = &mut plaintext_out[..ciphertext.len()];
    plaintext.copy_from_slice(ciphertext);
    key.xor_chunks_in_place(nonce, |visit| visit(plaintext))
}

pub(crate) fn aes_gcm_encrypt_into(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    ciphertext_out: &mut [u8],
    tag_out: &mut [u8; 16],
) -> Result<(), ()> {
    let key = AesGcmKey::new(key).ok_or(())?;
    aes_gcm_key_encrypt(&key, nonce, aad, plaintext, ciphertext_out, tag_out)
}

pub(crate) fn aes_gcm_decrypt_into(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    plaintext_out: &mut [u8],
    tag: &[u8; 16],
) -> Result<(), ()> {
    let key = AesGcmKey::new(key).ok_or(())?;
    aes_gcm_key_decrypt(&key, nonce, aad, ciphertext, plaintext_out, tag)
}

/// AES-CTR keystream (NIST SP 800-38A) from the production block cipher.
pub(crate) fn aes_ctr_with_schedule_in_place(
    schedule: &AesRoundKeySchedule,
    nonce: &[u8],
    initial_counter: u32,
    data: &mut [u8],
) {
    let mut counter_block = [0u8; 16];
    counter_block[..12].copy_from_slice(nonce);
    for (index, chunk) in data.chunks_mut(16).enumerate() {
        let counter = (index as u32).wrapping_add(initial_counter);
        counter_block[12..].copy_from_slice(&counter.to_be_bytes());
        let keystream = aes_encrypt_block_with_schedule(&counter_block, schedule);
        for (byte, key) in chunk.iter_mut().zip(keystream) {
            *byte ^= key;
        }
    }
}
