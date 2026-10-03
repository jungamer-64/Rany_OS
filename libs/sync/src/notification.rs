//! Allocation-free deferred notification publication with retained owners.

use alloc::sync::Arc;
use core::marker::PhantomData;
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering};

/// One notification target, allocated by its owner before interrupt delivery.
/// Repeated publications coalesce until a consumer takes this target. The
/// queue retains a strong reference even if the original owner disappears.
pub struct DeferredNotification<T> {
    next: AtomicPtr<Self>,
    queued: AtomicBool,
    value: T,
}

impl<T> DeferredNotification<T> {
    pub const fn new(value: T) -> Self {
        Self {
            next: AtomicPtr::new(ptr::null_mut()),
            queued: AtomicBool::new(false),
            value,
        }
    }

    pub fn value(&self) -> &T {
        &self.value
    }

    pub fn is_pending(&self) -> bool {
        self.queued.load(Ordering::Acquire)
    }
}

/// Notifications have no separately allocated queue entries or event-volume
/// limit. The set of existing targets bounds queue memory. Publication only
/// clones an Arc and performs atomics, so interrupt code can use it without
/// allocating or executing the target's callback.
///
/// Draining takes a finite snapshot. A target is released for republication
/// before its callback runs, allowing a racing event to request another pass.
/// Drop cancels the remaining requests and releases their retained owners.
pub struct NotificationQueue<T> {
    head: AtomicPtr<DeferredNotification<T>>,
    pending: AtomicUsize,
    _owners: PhantomData<Arc<DeferredNotification<T>>>,
}

impl<T> NotificationQueue<T> {
    pub const fn new() -> Self {
        Self {
            head: AtomicPtr::new(ptr::null_mut()),
            pending: AtomicUsize::new(0),
            _owners: PhantomData,
        }
    }

    pub fn publish(&self, target: &Arc<DeferredNotification<T>>) {
        if target
            .queued
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        // The queued bit grants exclusive access to this link. One raw Arc
        // strong reference is transferred to the queue before publication.
        let pointer = Arc::into_raw(Arc::clone(target)).cast_mut();
        self.pending.fetch_add(1, Ordering::AcqRel);
        let mut head = self.head.load(Ordering::Acquire);
        // LOOP_PROOF: mode=event; reason=Each failed head CAS observes another completed queue publication or snapshot drain, and success transfers this retained target to the queue.;
        loop {
            target.next.store(head, Ordering::Relaxed);
            match self.head.compare_exchange_weak(
                head,
                pointer,
                Ordering::Release,
                Ordering::Acquire,
            ) {
                Ok(_) => return,
                Err(actual) => head = actual,
            }
        }
    }

    /// Includes requests in a snapshot not yet taken by its consumer. A
    /// concurrent publication can be counted just before its head becomes
    /// visible, so this observation does not grant a drain or shutdown claim.
    pub fn pending_count(&self) -> usize {
        self.pending.load(Ordering::Acquire)
    }

    /// Deliver one finite snapshot. If a callback panics, that delivery has
    /// been consumed, and the remaining targets are republished by the batch
    /// owner. The caller owns callback success/failure and shutdown policy.
    pub fn drain(&self, mut deliver: impl FnMut(&T)) {
        let mut batch = NotificationBatch {
            queue: self,
            next: self.head.swap(ptr::null_mut(), Ordering::AcqRel),
        };
        // LOOP_PROOF: mode=condition; reason=Each take removes one retained target from the finite detached snapshot, and publications belong to a later snapshot.;
        while let Some(target) = batch.take() {
            deliver(target.value());
        }
    }
}

impl<T> Default for NotificationQueue<T> {
    fn default() -> Self {
        Self::new()
    }
}

struct NotificationBatch<'a, T> {
    queue: &'a NotificationQueue<T>,
    next: *mut DeferredNotification<T>,
}

impl<T> NotificationBatch<'_, T> {
    fn take(&mut self) -> Option<Arc<DeferredNotification<T>>> {
        if self.next.is_null() {
            return None;
        }
        // SAFETY: head publication transferred exactly one strong reference
        // for each link. The detached batch uniquely owns its linked chain.
        let target = unsafe { Arc::from_raw(self.next) };
        // Capture the successor before releasing queued: another publisher
        // may immediately reuse this target's link for a different snapshot.
        self.next = target.next.swap(ptr::null_mut(), Ordering::Relaxed);
        target.queued.store(false, Ordering::Release);
        self.queue.pending.fetch_sub(1, Ordering::AcqRel);
        Some(target)
    }
}

impl<T> Drop for NotificationBatch<'_, T> {
    fn drop(&mut self) {
        // LOOP_PROOF: mode=condition; reason=Each take consumes one undelivered target from this detached snapshot and republication preserves its owner for a later drain.;
        while let Some(target) = self.take() {
            self.queue.publish(&target);
        }
    }
}

impl<T> Drop for NotificationQueue<T> {
    fn drop(&mut self) {
        let mut batch = NotificationBatch {
            queue: self,
            next: self.head.swap(ptr::null_mut(), Ordering::AcqRel),
        };
        // LOOP_PROOF: mode=condition; reason=Exclusive queue destruction cancels each retained request in the finite final snapshot and releases its Arc owner.;
        while let Some(target) = batch.take() {
            drop(target);
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::atomic::AtomicUsize;

    #[test]
    fn repeated_requests_coalesce_and_delivery_can_request_another_pass() {
        let queue = NotificationQueue::new();
        let target = Arc::new(DeferredNotification::new(AtomicUsize::new(0)));
        for _ in 0..10_000 {
            queue.publish(&target);
        }
        assert_eq!(queue.pending_count(), 1);
        queue.drain(|count| {
            count.fetch_add(1, Ordering::Relaxed);
            queue.publish(&target);
        });
        assert_eq!(target.value().load(Ordering::Relaxed), 1);
        assert_eq!(queue.pending_count(), 1);
        queue.drain(|count| {
            count.fetch_add(1, Ordering::Relaxed);
        });
        assert_eq!(target.value().load(Ordering::Relaxed), 2);
        assert_eq!(queue.pending_count(), 0);
    }

    #[test]
    fn deferred_delivery_retains_a_target_after_the_original_owner_drops() {
        let queue = NotificationQueue::new();
        let target = Arc::new(DeferredNotification::new(7));
        let weak = Arc::downgrade(&target);
        queue.publish(&target);
        drop(target);
        assert!(weak.upgrade().is_some());
        queue.drain(|value| assert_eq!(*value, 7));
        assert!(weak.upgrade().is_none());
    }

    #[test]
    fn concurrent_interrupt_producers_publish_one_retained_request() {
        let queue = NotificationQueue::new();
        let target = Arc::new(DeferredNotification::new(3));
        std::thread::scope(|scope| {
            for _ in 0..4 {
                scope.spawn(|| {
                    for _ in 0..10_000 {
                        queue.publish(&target);
                    }
                });
            }
        });
        assert_eq!(queue.pending_count(), 1);
        let mut delivered = 0;
        queue.drain(|_| delivered += 1);
        assert_eq!(delivered, 1);
        assert_eq!(Arc::strong_count(&target), 1);
    }

    #[test]
    fn cancelling_the_queue_releases_owners_and_allows_republication() {
        let queue = NotificationQueue::new();
        let targets = [1, 2, 3].map(|value| Arc::new(DeferredNotification::new(value)));
        for target in &targets {
            queue.publish(target);
        }
        drop(queue);
        for target in &targets {
            assert!(!target.is_pending());
            assert_eq!(Arc::strong_count(target), 1);
        }
        let queue = NotificationQueue::new();
        for target in &targets {
            queue.publish(target);
        }
        let mut delivered = 0;
        queue.drain(|_| delivered += 1);
        assert_eq!(delivered, 3);
    }
}
