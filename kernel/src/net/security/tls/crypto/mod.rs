// ============================================================================
// kernel/src/net/security/tls/crypto/mod.rs - Cryptographic Primitives for TLS
// ============================================================================

pub mod aes_core;
pub mod aes_gcm;
pub mod chacha20;
pub mod hkdf;
pub mod hmac;
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

// ── AES Core ─────────────────────────────────────────────────────────────────

// ── AES-GCM ──────────────────────────────────────────────────────────────────
pub(crate) use aes_gcm::AesGcmKey;
#[cfg(any(test, feature = "qemu-test-export"))]
pub(crate) use aes_gcm::{aes_gcm_decrypt_into, aes_gcm_encrypt_into};

// ── ChaCha20-Poly1305 ────────────────────────────────────────────────────────
pub use chacha20::{chacha20_poly1305_decrypt_in_place, chacha20_poly1305_encrypt_in_place};
pub(crate) use chacha20::{chacha20_poly1305_tag_chunks, chacha20_xor_chunks_in_place};

// ── Random ───────────────────────────────────────────────────────────────────
pub(crate) use random::{RandomError, generate_random};
#[cfg(feature = "qemu-test-export")]
pub use random::{qemu_test_clear_random_override, qemu_test_set_random_override_seed};
