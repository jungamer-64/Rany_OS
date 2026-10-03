//! One pressure pass attempts each shared pool once. A deferred pool retains
//! every backing owner; retry is a later pass, never an acquisition wait.

/// Physical RAM return and reusable capacity in retained heaps are separate
/// observations; neither is a domain quota refund.
/// A busy pool can be retried; a poisoned pool requires invariant recovery.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PoolReclaim {
    pub(crate) reclaimed_bytes: usize,
    /// Returned Buddy capacity now published in retained free lists. This is
    /// progress even when another live block prevents whole-region PMM return.
    /// It is neither a quota refund nor additional physical RAM.
    pub(crate) heap_recovered_bytes: usize,
    pub(crate) busy_pools: usize,
    pub(crate) poisoned_pools: usize,
}

impl PoolReclaim {
    pub(crate) fn made_progress(self) -> bool {
        self.reclaimed_bytes != 0 || self.heap_recovered_bytes != 0
    }

    pub(crate) fn merge(self, other: Self) -> Self {
        Self {
            reclaimed_bytes: self.reclaimed_bytes + other.reclaimed_bytes,
            heap_recovered_bytes: self.heap_recovered_bytes + other.heap_recovered_bytes,
            busy_pools: self.busy_pools + other.busy_pools,
            poisoned_pools: self.poisoned_pools + other.poisoned_pools,
        }
    }
}
