// ============================================================================
// kernel/src/io/iommu/runtime/stats.rs
// ============================================================================

//! IOMMU Statistics & Diagnostics
//!
//! Tracks usage counters for IOMMU operations.

use core::sync::atomic::{AtomicU64, Ordering};

#[cfg(not(feature = "qemu-test-export"))]
use crate::per_cpu::MAX_CPUS;

#[cfg(feature = "qemu-test-export")]
const MAX_CPUS: usize = 1;

// Instrumentation counters for testing / diagnostics.
// These use Relaxed ordering as they are only for diagnostic purposes
// and do not require synchronization with other memory operations.
static MAP_COUNTS: [AtomicU64; MAX_CPUS] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; MAX_CPUS]
};
static UNMAP_COUNTS: [AtomicU64; MAX_CPUS] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; MAX_CPUS]
};
static IDENTITY_FALLBACK_COUNTS: [AtomicU64; MAX_CPUS] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; MAX_CPUS]
};

fn for_current_cpu(counters: &[AtomicU64; MAX_CPUS]) -> &AtomicU64 {
    let cpu_id = crate::per_cpu::try_current_cpu_id().unwrap_or(0);
    if cpu_id < MAX_CPUS {
        &counters[cpu_id]
    } else {
        &counters[0]
    }
}

/// Reset map/unmap counters (for tests)
pub fn reset_map_unmap_counts() {
    for i in 0..MAX_CPUS {
        MAP_COUNTS[i].store(0, Ordering::Relaxed);
        UNMAP_COUNTS[i].store(0, Ordering::Relaxed);
        IDENTITY_FALLBACK_COUNTS[i].store(0, Ordering::Relaxed);
    }
}

/// Get number of successful map operations recorded
pub fn get_map_count() -> u64 {
    let mut total = 0;
    for i in 0..MAX_CPUS {
        total += MAP_COUNTS[i].load(Ordering::Relaxed);
    }
    total
}

/// Get number of successful unmap operations recorded
pub fn get_unmap_count() -> u64 {
    let mut total = 0;
    for i in 0..MAX_CPUS {
        total += UNMAP_COUNTS[i].load(Ordering::Relaxed);
    }
    total
}

pub fn get_identity_fallback_count() -> u64 {
    let mut total = 0;
    for i in 0..MAX_CPUS {
        total += IDENTITY_FALLBACK_COUNTS[i].load(Ordering::Relaxed);
    }
    total
}

pub(crate) fn inc_map_count() {
    for_current_cpu(&MAP_COUNTS).fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn inc_unmap_count() {
    for_current_cpu(&UNMAP_COUNTS).fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn inc_identity_fallback_count() {
    for_current_cpu(&IDENTITY_FALLBACK_COUNTS).fetch_add(1, Ordering::Relaxed);
}
