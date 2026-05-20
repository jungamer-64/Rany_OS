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
pub use hmac::{SHA256_OUTPUT_SIZE, SHA384_OUTPUT_SIZE};

// ── AES Core ─────────────────────────────────────────────────────────────────
#[cfg(any(test, feature = "qemu-test-export"))]
pub(crate) use aes_gcm::{aes_gcm_decrypt_into, aes_gcm_encrypt_into};

// ── ChaCha20-Poly1305 ────────────────────────────────────────────────────────
pub(crate) use chacha20::{chacha20_poly1305_tag_chunks, chacha20_xor_chunks_in_place};

// ── Random ───────────────────────────────────────────────────────────────────
pub(crate) use random::{RandomError, generate_random};
#[cfg(feature = "qemu-test-export")]
pub use random::{qemu_test_clear_random_override, qemu_test_set_random_override_seed};
