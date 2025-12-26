//! Utility methods for IommuController

use super::super::{IommuController, IommuError};

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

impl IommuUtils for IommuController {
    /// Wait for a condition to be true with a timeout
    ///
    /// # Arguments
    /// * `condition` - Predicate to check
    /// * `timeout_us` - Timeout in microseconds
    /// * `can_yield` - Whether it's safe to yield (must be false in ISR or early boot)
    ///
    /// Uses the kernel timer APIs when possible:
    /// - If yielding is allowed and the scheduler is available, use the millisecond tick and yield
    /// - Otherwise use `time::precise_time_nanos()` for high-resolution busy-waiting
    /// - If timers are not yet initialized (early boot), fall back to an rdtsc-based busy-wait
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
            if let Some(cpu_id) = crate::mm::per_cpu::try_current_cpu_id() {
                // Convert microseconds to milliseconds (ceiling)
                let timeout_ms = (timeout_us + 999) / 1000;
                let end_tick = crate::task::timer::current_tick().saturating_add(timeout_ms);

                loop {
                    if condition() {
                        return Ok(());
                    }

                    if crate::task::timer::current_tick() >= end_tick {
                        return Err(IommuError::Timeout);
                    }

                    // Yield to scheduler to avoid busy-looping
                    #[cfg(feature = "legacy-scheduler")]
                    {
                        crate::task::scheduler::yield_current(cpu_id);
                    }
                    #[cfg(not(feature = "legacy-scheduler"))]
                    {
                        // Legacy scheduler disabled -> best-effort cooperative yield
                        crate::task::preemption::voluntary_yield();
                        crate::task::preemption::yield_point();
                    }
                }
            }
            // If scheduler isn't available, fallthrough to busy-wait below
        }

        // Busy-wait path: prefer kernel's precise time API
        let start_ns = crate::time::precise_time_nanos();
        if start_ns != 0 {
            let timeout_ns = timeout_us.saturating_mul(1000);
            loop {
                if condition() {
                    return Ok(());
                }

                let now_ns = crate::time::precise_time_nanos();
                if now_ns.saturating_sub(start_ns) >= timeout_ns {
                    return Err(IommuError::Timeout);
                }

                core::hint::spin_loop();
            }
        }

        // Fallback for very early boot: rdtsc-based busy wait (conservative 3GHz assumption)
        let cycles = timeout_us.saturating_mul(3000);
        let start = unsafe { core::arch::x86_64::_rdtsc() };

        loop {
            if condition() {
                return Ok(());
            }

            let current = unsafe { core::arch::x86_64::_rdtsc() };
            if current.saturating_sub(start) > cycles {
                return Err(IommuError::Timeout);
            }

            core::hint::spin_loop();
        }
    }
}
