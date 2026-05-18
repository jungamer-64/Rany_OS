// ============================================================================
// kernel/src/net/runtime/entropy.rs - Network runtime entropy provider
// ============================================================================

use core::sync::atomic::{AtomicBool, AtomicU8, Ordering as AtomicOrdering};

static RDRAND_CHECKED: AtomicBool = AtomicBool::new(false);
/// 0 = unknown, 1 = available, 2 = not available
static RDRAND_STATUS: AtomicU8 = AtomicU8::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NetEntropyError {
    SecureEntropyUnavailable,
    HardwareFailure,
}

fn has_rdrand() -> bool {
    let status = RDRAND_STATUS.load(AtomicOrdering::Relaxed);
    if RDRAND_CHECKED.load(AtomicOrdering::Acquire) {
        return status == 1;
    }

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

#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
fn rdrand64() -> Option<u64> {
    for _ in 0..10 {
        let value: u64;
        let success: u8;
        // SAFETY: RDRAND is a CPU instruction with no memory operands. CPUID
        // gating happens before this function is called.
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

#[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
fn rdrand64() -> Option<u64> {
    None
}

pub(crate) fn fill_secure_random(output: &mut [u8]) -> Result<(), NetEntropyError> {
    if !has_rdrand() {
        return Err(NetEntropyError::SecureEntropyUnavailable);
    }

    let mut cursor = 0usize;
    while cursor < output.len() {
        let value = rdrand64().ok_or(NetEntropyError::HardwareFailure)?;
        let bytes = value.to_ne_bytes();
        let remaining = output.len() - cursor;
        let copy_len = remaining.min(bytes.len());
        output[cursor..cursor + copy_len].copy_from_slice(&bytes[..copy_len]);
        cursor += copy_len;
    }

    Ok(())
}
