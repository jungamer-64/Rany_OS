// ============================================================================
// kernel/src/net/security/tls/crypto/random.rs - Random Generation (RDRAND Hardware RNG)
// ============================================================================

#[cfg(feature = "qemu-test-export")]
use core::sync::atomic::AtomicU64;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering as AtomicOrdering};

/// Whether RDRAND availability has been checked
static RDRAND_CHECKED: AtomicBool = AtomicBool::new(false);
/// 0 = unknown, 1 = available, 2 = not available
static RDRAND_STATUS: AtomicU8 = AtomicU8::new(0);

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

/// Check if the CPU supports RDRAND via CPUID
fn has_rdrand() -> bool {
    let status = RDRAND_STATUS.load(AtomicOrdering::Relaxed);
    if RDRAND_CHECKED.load(AtomicOrdering::Acquire) {
        return status == 1;
    }

    // CPUID leaf 1, ECX bit 30 = RDRAND support
    let available = {
        #[cfg(target_arch = "x86_64")]
        {
            let cpuid = core::arch::x86_64::__cpuid(1);
            ((cpuid.ecx >> 30) & 1) == 1
        }

        #[cfg(target_arch = "x86")]
        {
            let cpuid = core::arch::x86::__cpuid(1);
            ((cpuid.ecx >> 30) & 1) == 1
        }

        #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
        {
            false
        }
    };

    RDRAND_STATUS.store(if available { 1 } else { 2 }, AtomicOrdering::Relaxed);
    RDRAND_CHECKED.store(true, AtomicOrdering::Release);
    available
}

/// Generate a 64-bit random value using RDRAND
///
/// Retries up to 10 times on transient failures.
fn rdrand64() -> Option<u64> {
    for _ in 0..10 {
        let value: u64;
        let success: u8;
        unsafe {
            core::arch::asm!(
                "rdrand {val}",
                "setc {ok}",
                val = out(reg) value,
                ok = out(reg_byte) success,
            );
        }
        if success != 0 {
            return Some(value);
        }
    }
    None
}

/// Generate 32 bytes of random data
///
/// Uses RDRAND hardware instruction when available (x86_64).
/// Falls back to a weak LCG for development/boot environments where
/// RDRAND is not yet available. The LCG fallback MUST NOT be used
/// for production cryptographic operations.
pub(crate) fn generate_random() -> [u8; 32] {
    #[cfg(feature = "qemu-test-export")]
    {
        if QEMU_TEST_RANDOM_OVERRIDE_ENABLED.load(AtomicOrdering::Acquire) {
            return generate_qemu_test_random();
        }
    }

    let mut result = [0u8; 32];

    if has_rdrand() {
        // Fill 32 bytes using 4 RDRAND calls (8 bytes each)
        for chunk in result.chunks_exact_mut(8) {
            if let Some(val) = rdrand64() {
                chunk.copy_from_slice(&val.to_ne_bytes());
            } else {
                // RDRAND failed after retries
                #[cfg(not(debug_assertions))]
                {
                    panic!(
                        "[CRITICAL SECURITY] RDRAND hardware RNG failed after retries. System cannot proceed safely."
                    );
                }
                #[cfg(debug_assertions)]
                {
                    log::warn!(
                        "[SECURITY] RDRAND failed after retries, falling back to weak RNG (DEBUG ONLY)"
                    );
                    return generate_random_fallback();
                }
            }
        }
        return result;
    }

    #[cfg(not(debug_assertions))]
    {
        panic!(
            "[CRITICAL SECURITY] RDRAND hardware RNG is not available on this CPU. TLS/Crypto cannot be used safely in production without a secure entropy source."
        );
    }

    #[cfg(debug_assertions)]
    {
        log::warn!(
            "********************************************************************************"
        );
        log::warn!("[SECURITY WARNING] RDRAND not available. Using INSECURE LCG fallback!");
        log::warn!("[SECURITY WARNING] This build is for DEVELOPMENT/DEBUG only.");
        log::warn!("[SECURITY WARNING] TLS communication and keys are NOT PROTECTED.");
        log::warn!(
            "********************************************************************************"
        );
        generate_random_fallback()
    }
}

/// Check whether hardware-backed cryptographic random number generation is available.
///
/// Returns `true` if RDRAND is supported and functional.
/// When this returns `false`, `generate_random()` will fall back to a weak LCG
/// that is NOT cryptographically secure.
pub(crate) fn has_secure_random() -> bool {
    has_rdrand()
}

/// Fallback LCG-based random generation (development/boot only)
///
/// WARNING: This is NOT cryptographically secure. It exists only as a
/// fallback for environments where RDRAND is unavailable.
/// Uses AtomicU64 to avoid undefined behavior from concurrent access.
fn generate_random_fallback() -> [u8; 32] {
    static SEED: core::sync::atomic::AtomicU64 =
        core::sync::atomic::AtomicU64::new(0x1234567890abcdef);

    // Try to mix in some entropy from RDTSC if available
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    {
        let tsc = unsafe { core::arch::x86_64::_rdtsc() };
        SEED.fetch_xor(tsc, AtomicOrdering::Relaxed);
    }

    let mut result = [0u8; 32];

    for byte in result.iter_mut() {
        // Atomically advance the LCG state via CAS loop.
        // fetch_update returns Ok(previous_value); recompute new value for output.
        let prev = SEED
            .fetch_update(AtomicOrdering::Relaxed, AtomicOrdering::Relaxed, |s| {
                Some(
                    s.wrapping_mul(6364136223846793005)
                        .wrapping_add(1442695040888963407),
                )
            })
            .unwrap(); // always succeeds (closure always returns Some)
        let new_val = prev
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        *byte = (new_val >> 56) as u8;
    }

    result
}
