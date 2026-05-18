// ============================================================================
// kernel/src/net/security/tls/crypto/random.rs - TLS random generation boundary
// ============================================================================

#[cfg(feature = "qemu-test-export")]
use core::sync::atomic::AtomicU64;
#[cfg(feature = "qemu-test-export")]
use core::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RandomError {
    SecureEntropyUnavailable,
    HardwareFailure,
}

#[cfg(feature = "qemu-test-export")]
static QEMU_TEST_RANDOM_OVERRIDE_ENABLED: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "qemu-test-export")]
static QEMU_TEST_RANDOM_OVERRIDE_SEED: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "qemu-test-export")]
static QEMU_TEST_RANDOM_OVERRIDE_COUNTER: AtomicU64 = AtomicU64::new(0);

#[cfg(feature = "qemu-test-export")]
pub fn qemu_test_set_random_override_seed(seed: u64) {
    QEMU_TEST_RANDOM_OVERRIDE_SEED.store(seed, AtomicOrdering::Release);
    QEMU_TEST_RANDOM_OVERRIDE_COUNTER.store(0, AtomicOrdering::Release);
    QEMU_TEST_RANDOM_OVERRIDE_ENABLED.store(true, AtomicOrdering::Release);
}

#[cfg(feature = "qemu-test-export")]
pub fn qemu_test_clear_random_override() {
    QEMU_TEST_RANDOM_OVERRIDE_ENABLED.store(false, AtomicOrdering::Release);
    QEMU_TEST_RANDOM_OVERRIDE_COUNTER.store(0, AtomicOrdering::Release);
}

#[cfg(feature = "qemu-test-export")]
fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E3779B97F4A7C15);
    let mut z = x;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
    z ^ (z >> 31)
}

#[cfg(feature = "qemu-test-export")]
fn generate_qemu_test_random() -> [u8; 32] {
    let seed = QEMU_TEST_RANDOM_OVERRIDE_SEED.load(AtomicOrdering::Acquire);
    let call_index = QEMU_TEST_RANDOM_OVERRIDE_COUNTER.fetch_add(1, AtomicOrdering::AcqRel);

    let mut result = [0u8; 32];
    for (chunk_index, chunk) in result.chunks_exact_mut(8).enumerate() {
        let input = seed
            .wrapping_add(call_index)
            .wrapping_add(chunk_index as u64);
        let mixed = splitmix64(input);
        chunk.copy_from_slice(&mixed.to_ne_bytes());
    }
    result
}

/// Generate 32 bytes of secure random data.
///
/// Entropy comes from the network runtime entropy provider. A deterministic
/// override exists only for `qemu-test-export`; normal builds fail closed when
/// secure entropy is absent.
pub(crate) fn generate_random() -> Result<[u8; 32], RandomError> {
    #[cfg(feature = "qemu-test-export")]
    {
        if QEMU_TEST_RANDOM_OVERRIDE_ENABLED.load(AtomicOrdering::Acquire) {
            return Ok(generate_qemu_test_random());
        }
    }

    let mut result = [0u8; 32];
    match crate::net::runtime::entropy::fill_secure_random(&mut result) {
        Ok(()) => Ok(result),
        Err(crate::net::runtime::entropy::NetEntropyError::SecureEntropyUnavailable) => {
            Err(RandomError::SecureEntropyUnavailable)
        }
        Err(crate::net::runtime::entropy::NetEntropyError::HardwareFailure) => {
            Err(RandomError::HardwareFailure)
        }
    }
}
