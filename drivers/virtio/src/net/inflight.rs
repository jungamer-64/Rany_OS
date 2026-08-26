// ============================================================================
// drivers/virtio/src/net/inflight.rs - Generic Inflight Request Tracker
// ============================================================================

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;
use exorust_sync::IrqPoisonLock;

/// A fixed-capacity tracker for in-flight VirtIO requests.
///
/// Every descriptor has one preallocated ownership slot. Submission and
/// completion only move values into or out of those slots and never allocate.
pub struct InflightTracker<T> {
    slots: Box<[IrqPoisonLock<Option<T>>]>,
}

impl<T> fmt::Debug for InflightTracker<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InflightTracker")
            .field("capacity", &self.slots.len())
            .finish_non_exhaustive()
    }
}

impl<T> InflightTracker<T> {
    /// Create a new tracker with the specified number of slots (queue size).
    pub fn new(size: u16) -> Self {
        let mut slots = Vec::with_capacity(size as usize);
        for _ in 0..size {
            slots.push(IrqPoisonLock::new(None));
        }
        Self {
            slots: slots.into_boxed_slice(),
        }
    }

    /// Place an in-flight object into a slot.
    ///
    /// Returns the previous owner if a caller violates the descriptor lifecycle
    /// by reusing a slot before completion.
    pub fn put(&self, desc_idx: u16, value: T) -> Result<(), T> {
        let Some(slot) = self.slots.get(desc_idx as usize) else {
            return Err(value);
        };
        let mut guard = slot.lock().unwrap_or_else(|error| error.into_inner());
        if guard.is_some() {
            return Err(value);
        }
        *guard = Some(value);
        Ok(())
    }

    /// Take an in-flight object from a slot.
    ///
    /// Returns `None` if the slot was empty.
    pub fn take(&self, desc_idx: u16) -> Option<T> {
        let slot = self.slots.get(desc_idx as usize)?;
        slot.lock()
            .unwrap_or_else(|error| error.into_inner())
            .take()
    }

    /// Drops every tracked request after device DMA authority has been
    /// quiesced or revoked.
    pub fn clear(&self) {
        for slot in self.slots.iter() {
            drop(
                slot.lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .take(),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::InflightTracker;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicUsize, Ordering};

    struct DropProbe(Arc<AtomicUsize>);

    impl Drop for DropProbe {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn occupied_slot_returns_the_unaccepted_owner() {
        let tracker = InflightTracker::new(1);
        assert_eq!(tracker.put(0, 10), Ok(()));
        assert_eq!(tracker.put(0, 20), Err(20));
        assert_eq!(tracker.take(0), Some(10));
        assert_eq!(tracker.take(0), None);
    }

    #[test]
    fn invalid_slot_returns_the_unaccepted_owner() {
        let tracker = InflightTracker::new(1);
        assert_eq!(tracker.put(1, 20), Err(20));
    }

    #[test]
    fn clear_releases_each_tracked_owner_once() {
        let drops = Arc::new(AtomicUsize::new(0));
        let tracker = InflightTracker::new(2);
        assert!(tracker.put(0, DropProbe(drops.clone())).is_ok());
        assert!(tracker.put(1, DropProbe(drops.clone())).is_ok());

        tracker.clear();
        assert_eq!(drops.load(Ordering::Relaxed), 2);
        tracker.clear();
        assert_eq!(drops.load(Ordering::Relaxed), 2);
    }
}
