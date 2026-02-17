// ============================================================================
// tls/crypto/mod.rs - Cryptographic Primitives for TLS
// ============================================================================

pub mod hmac;
pub mod hkdf;
pub mod prf;
pub mod aes_core;
pub mod aes_gcm;
pub mod aes_cbc;
pub mod chacha20;
pub mod legacy;
pub mod random;

// ── HMAC ────────────────────────────────────────────────────────────────────
pub use hmac::{hmac_sha256, hmac_sha384, SHA256_OUTPUT_SIZE, SHA384_OUTPUT_SIZE};

// ── HKDF + TLS 1.3 Key Schedule ─────────────────────────────────────────────
pub use hkdf::{
    hkdf_extract, hkdf_expand, hkdf_expand_label,
    tls13_derive_secret, tls13_early_secret, tls13_handshake_secret,
    tls13_master_secret, tls13_derive_traffic_keys, tls13_finished_key,
    tls13_verify_data,
    // SHA-384 variants
    hkdf_extract_sha384, hkdf_expand_sha384, hkdf_expand_label_sha384,
    tls13_derive_secret_sha384, tls13_early_secret_sha384, tls13_handshake_secret_sha384,
    tls13_master_secret_sha384, tls13_derive_traffic_keys_sha384,
    tls13_finished_key_sha384, tls13_verify_data_sha384,
};

// ── TLS 1.2 PRF ─────────────────────────────────────────────────────────────
pub use prf::{
    tls12_prf, derive_master_secret, derive_key_block,
    derive_key_block_sha384, derive_master_secret_tls10,
    derive_master_secret_sha384, p_sha384, tls12_prf_sha384,
};

// ── AES Core ─────────────────────────────────────────────────────────────────
pub(crate) use aes_core::{
    AesRoundKeySchedule, AES_SBOX, aes_key_expansion, gf_mul,
    aes_expand_key_schedule, aes_encrypt_block, aes_encrypt_block_with_schedule,
    aes_ctr_with_schedule, aes_ctr, aes_add_round_key,
};

// ── AES-GCM ──────────────────────────────────────────────────────────────────
pub(crate) use aes_gcm::{gf128_mul, aes_gcm_encrypt, aes_gcm_decrypt};

// ── AES-CBC ──────────────────────────────────────────────────────────────────
pub(crate) use aes_cbc::{
    aes_cbc_encrypt, aes_cbc_decrypt, tls_add_padding, tls_verify_padding,
};

// ── ChaCha20-Poly1305 ────────────────────────────────────────────────────────
pub use chacha20::{
    chacha20_encrypt, chacha20_poly1305_encrypt, chacha20_poly1305_decrypt,
    poly1305_mac,
};
pub(crate) use chacha20::chacha20_block;

// ── Legacy (MD5, SHA-1, TLS 1.0) ────────────────────────────────────────────
pub use legacy::{
    Md5, md5_compute, Sha1, sha1_compute,
    hmac_md5, hmac_sha1, tls10_prf,
};
pub(crate) use legacy::compute_tls_mac;

// ── Random ───────────────────────────────────────────────────────────────────
pub(crate) use random::generate_random;
#[cfg(feature = "qemu-test-export")]
pub use random::{qemu_test_set_random_override_seed, qemu_test_clear_random_override};
