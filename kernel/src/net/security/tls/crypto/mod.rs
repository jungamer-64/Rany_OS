// ============================================================================
// tls/crypto/mod.rs - Cryptographic Primitives for TLS
// ============================================================================

pub mod aes_cbc;
pub mod aes_core;
pub mod aes_gcm;
pub mod chacha20;
pub mod hkdf;
pub mod hmac;
pub mod legacy;
pub mod prf;
pub mod random;

// ── HMAC ────────────────────────────────────────────────────────────────────
pub use hmac::{SHA256_OUTPUT_SIZE, SHA384_OUTPUT_SIZE, hmac_sha256, hmac_sha384};

// ── HKDF + TLS 1.3 Key Schedule ─────────────────────────────────────────────
pub use hkdf::{
    hkdf_expand_label, hkdf_expand_label_sha384, tls13_derive_secret, tls13_derive_secret_sha384,
    tls13_derive_traffic_keys, tls13_derive_traffic_keys_sha384, tls13_early_secret,
    tls13_early_secret_sha384, tls13_finished_key, tls13_finished_key_sha384,
    tls13_handshake_secret, tls13_handshake_secret_sha384, tls13_master_secret,
    tls13_master_secret_sha384, tls13_verify_data, tls13_verify_data_sha384,
};

// ── TLS 1.2 PRF ─────────────────────────────────────────────────────────────
pub use prf::{
    derive_key_block, derive_key_block_sha384, derive_master_secret, derive_master_secret_sha384,
    derive_master_secret_tls10, tls12_prf, tls12_prf_sha384,
};

// ── AES Core ─────────────────────────────────────────────────────────────────

// ── AES-GCM ──────────────────────────────────────────────────────────────────
pub(crate) use aes_gcm::{aes_gcm_decrypt, aes_gcm_encrypt};

// ── AES-CBC ──────────────────────────────────────────────────────────────────
pub(crate) use aes_cbc::{aes_cbc_decrypt, aes_cbc_encrypt, tls_add_padding, tls_verify_padding};

// ── ChaCha20-Poly1305 ────────────────────────────────────────────────────────
pub use chacha20::{chacha20_poly1305_decrypt, chacha20_poly1305_encrypt};

// ── Legacy (MD5, SHA-1, TLS 1.0) ────────────────────────────────────────────
pub(crate) use legacy::compute_tls_mac;
pub use legacy::tls10_prf;

// ── Random ───────────────────────────────────────────────────────────────────
pub(crate) use random::generate_random;
pub(crate) use random::has_secure_random;
#[cfg(feature = "qemu-test-export")]
pub use random::{qemu_test_clear_random_override, qemu_test_set_random_override_seed};
