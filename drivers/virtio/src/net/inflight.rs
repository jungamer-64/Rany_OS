// ============================================================================
// drivers/virtio/src/net/inflight.rs - Generic Inflight Request Tracker
// ============================================================================

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicPtr, Ordering};

/// A lock-free tracker for in-flight VirtIO requests.
///
/// Maps descriptor indices to heap-allocated state objects.
#[derive(Debug)]
pub struct InflightTracker<T> {
    slots: Box<[AtomicPtr<T>]>,
}

impl<T> InflightTracker<T> {
    /// Create a new tracker with the specified number of slots (queue size).
    pub fn new(size: u16) -> Self {
        let mut slots = Vec::with_capacity(size as usize);
        for _ in 0..size {
            slots.push(AtomicPtr::new(core::ptr::null_mut()));
        }
        Self {
            slots: slots.into_boxed_slice(),
        }
    }

    /// Place an in-flight object into a slot.
    ///
    /// # Safety
    /// The caller must ensure that `desc_idx` is valid (within queue size).
    pub fn put(&self, desc_idx: u16, value: T) {
        let slot = &self.slots[desc_idx as usize];
        let ptr = Box::into_raw(Box::new(value));
        // We expect the slot to be null. If not, we might be leaking or double-using.
        let old = slot.swap(ptr, Ordering::AcqRel);
        if !old.is_null() {
            // This should not happen in a well-behaved driver.
            // Safety: reclaim the old one to avoid leak, but it's a bug.
            unsafe {
                let _ = Box::from_raw(old);
            }
        }
    }

    /// Take an in-flight object from a slot.
    ///
    /// Returns `None` if the slot was empty.
    pub fn take(&self, desc_idx: u16) -> Option<T> {
        let slot = self.slots.get(desc_idx as usize)?;
        let ptr = slot.swap(core::ptr::null_mut(), Ordering::AcqRel);
        if ptr.is_null() {
            None
        } else {
            unsafe { Some(*Box::from_raw(ptr)) }
        }
    }

    /// Peek at a slot without removing it.
    ///
    /// # Safety
    /// Returns a raw pointer. The caller must not drop it or move it while
    /// the tracker still owns it.
    pub fn peek_raw(&self, desc_idx: u16) -> *mut T {
        self.slots
            .get(desc_idx as usize)
            .map(|s| s.load(Ordering::Acquire))
            .unwrap_or(core::ptr::null_mut())
    }

    /// Swap a slot with a new pointer and return the old one.
    pub fn swap_raw(&self, desc_idx: u16, new_ptr: *mut T) -> *mut T {
        self.slots
            .get(desc_idx as usize)
            .map(|s| s.swap(new_ptr, Ordering::AcqRel))
            .unwrap_or(core::ptr::null_mut())
    }
}

impl<T> Drop for InflightTracker<T> {
    fn drop(&mut self) {
        for slot in self.slots.iter() {
            let ptr = slot.swap(core::ptr::null_mut(), Ordering::AcqRel);
            if !ptr.is_null() {
                unsafe {
                    let _ = Box::from_raw(ptr);
                }
            }
        }
    }
}

unsafe impl<T: Send> Send for InflightTracker<T> {}
unsafe impl<T: Sync> Sync for InflightTracker<T> {}
