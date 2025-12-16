// ============================================================================
// kernel/src/task/fuel.rs - Fuel-Based Execution for Starvation Prevention
// ============================================================================
//!
//! # Fuel-Based Execution for Starvation Prevention
//!
//! This module implements a "fuel" mechanism to limit the execution time of
//! cooperative tasks (futures). This prevents a single task from monopolizing
//! the CPU by forcing it to yield after consuming its budget.
//!
//! ## Concept
//! - **Fuel**: A unit of execution budget (arbitrary scale, e.g., 1 fuel ~ 100-1000 cycles).
//! - **Injector**: The executor injects fuel into the task context before polling.
//! - **Consumption**: The task consumes fuel during loops or heavy operations.
//! - **Yielding**: When fuel is exhausted, the task yields (returns `Poll::Pending`).

use core::cell::Cell;
use core::sync::atomic::{AtomicU64, Ordering};

/// Global fuel configuration
pub struct FuelConfig {
    /// Default fuel per task slice
    pub default_fuel: u64,
}

impl FuelConfig {
    pub const DEFAULT: Self = Self {
        default_fuel: 10_000,
    };
}

/// Thread-local storage for current task's fuel
/// specific to the current core/thread.
#[thread_local]
static CURRENT_FUEL: Cell<u64> = Cell::new(0);

/// Fuel manager
pub struct Fuel;

impl Fuel {
    /// Refill the current task's fuel
    #[inline]
    pub fn refill(amount: u64) {
        CURRENT_FUEL.set(amount);
    }

    /// Consume fuel. Returns false if exhausted (should yield).
    #[inline]
    pub fn consume(amount: u64) -> bool {
        let current = CURRENT_FUEL.get();
        if let Some(remaining) = current.checked_sub(amount) {
            CURRENT_FUEL.set(remaining);
            true
        } else {
            CURRENT_FUEL.set(0);
            false
        }
    }

    /// Check remaining fuel
    #[inline]
    pub fn remaining() -> u64 {
        CURRENT_FUEL.get()
    }

    /// Force exhaustion (e.g. on yield)
    #[inline]
    pub fn exhaust() {
        CURRENT_FUEL.set(0);
    }
}

/// Helper macro to check fuel in loops
#[macro_export]
macro_rules! check_fuel {
    ($cost:expr) => {
        if !$crate::task::fuel::Fuel::consume($cost) {
            $crate::task::yield_now().await;
        }
    };
}
