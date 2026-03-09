// ============================================================================
// kernel/src/io/iommu/vendors/intel/controller/utils.rs
// ============================================================================

//! Utility methods for IommuController

use super::IommuController;
use crate::io::iommu::types::IommuError;

#[inline]
fn wait_until<F, G, H>(
    condition: &F,
    mut should_wait: G,
    mut on_pending: H,
) -> Result<(), IommuError>
where
    F: Fn() -> bool,
    G: FnMut() -> bool,
    H: FnMut(),
{
    // LOOP_PROOF: mode=condition; reason=Shared wait helper rechecks condition each pass and exits when timeout predicate stops waiting.;
    while {
        if condition() {
            return Ok(());
        }
        should_wait()
    } {
        on_pending();
    }

    Err(IommuError::Timeout)
}

/// Timer/Wait Utilities
pub trait IommuUtils {
    /// Wait for a condition to be true with a timeout
    fn wait_for_condition<F>(
        &self,
        condition: F,
        timeout_us: u64,
        can_yield: bool,
    ) -> Result<(), IommuError>
    where
        F: Fn() -> bool;
}

impl IommuController {
    /// Busy-wait using precise_time_nanos(). Returns None if timer not available.
    fn busy_wait_precise<F>(&self, condition: &F, timeout_us: u64) -> Option<Result<(), IommuError>>
    where
        F: Fn() -> bool,
    {
        let start_ns = crate::time::precise_time_nanos();
        if start_ns == 0 {
            return None;
        }
        let timeout_ns = timeout_us.saturating_mul(1000);
        Some(wait_until(
            condition,
            || crate::time::precise_time_nanos().saturating_sub(start_ns) < timeout_ns,
            || core::hint::spin_loop(),
        ))
    }

    /// Busy-wait using rdtsc (early boot fallback with conservative 3GHz assumption).
    fn busy_wait_rdtsc<F>(&self, condition: &F, timeout_us: u64) -> Result<(), IommuError>
    where
        F: Fn() -> bool,
    {
        let cycles = timeout_us.saturating_mul(3000);
        let start = unsafe { core::arch::x86_64::_rdtsc() };
        wait_until(
            condition,
            || {
                let current = unsafe { core::arch::x86_64::_rdtsc() };
                current.saturating_sub(start) <= cycles
            },
            || core::hint::spin_loop(),
        )
    }
}

impl IommuUtils for IommuController {
    fn wait_for_condition<F>(
        &self,
        condition: F,
        timeout_us: u64,
        can_yield: bool,
    ) -> Result<(), IommuError>
    where
        F: Fn() -> bool,
    {
        // Fast-path: if condition is already true, return immediately
        if condition() {
            return Ok(());
        }

        // If it's safe to yield and scheduler is present, use tick-based waiting
        if can_yield {
            if let Some(_cpu_id) = crate::per_cpu::try_current_cpu_id() {
                // Convert microseconds to milliseconds (ceiling)
                let timeout_ms = (timeout_us + 999) / 1000;
                let end_tick = crate::task::timer::current_tick().saturating_add(timeout_ms);

                return wait_until(
                    &condition,
                    || crate::task::timer::current_tick() < end_tick,
                    || {
                        // Best-effort cooperative yield to avoid busy-looping
                        crate::task::preemption::voluntary_yield();
                        crate::task::preemption::yield_point();
                    },
                );
            }
            // If scheduler isn't available, fallthrough to busy-wait below
        }

        // Busy-wait path: prefer kernel's precise time API
        if let Some(result) = self.busy_wait_precise(&condition, timeout_us) {
            return result;
        }

        // Fallback for very early boot: rdtsc-based busy wait
        self.busy_wait_rdtsc(&condition, timeout_us)
    }
}
