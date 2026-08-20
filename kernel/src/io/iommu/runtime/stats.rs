// ============================================================================
// kernel/src/io/iommu/runtime/stats.rs
// ============================================================================

//! IOMMU Statistics & Diagnostics
//!
//! Tracks usage counters for IOMMU operations.

use core::sync::atomic::{AtomicU64, Ordering};

// Instrumentation counters for testing / diagnostics.
// These use Relaxed ordering as they are only for diagnostic purposes
// and do not require synchronization with other memory operations.
static MAP_COUNT: AtomicU64 = AtomicU64::new(0);
static UNMAP_COUNT: AtomicU64 = AtomicU64::new(0);

/// Reset map/unmap counters (for tests)
pub fn reset_map_unmap_counts() {
    MAP_COUNT.store(0, Ordering::Relaxed);
    UNMAP_COUNT.store(0, Ordering::Relaxed);
}

/// Get number of successful map operations recorded
pub fn get_map_count() -> u64 {
    MAP_COUNT.load(Ordering::Relaxed)
}

/// Get number of successful unmap operations recorded
pub fn get_unmap_count() -> u64 {
    UNMAP_COUNT.load(Ordering::Relaxed)
}

pub(crate) fn inc_map_count() {
    MAP_COUNT.fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn inc_unmap_count() {
    UNMAP_COUNT.fetch_add(1, Ordering::Relaxed);
}
