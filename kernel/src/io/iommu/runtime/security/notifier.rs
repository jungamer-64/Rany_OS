// ============================================================================
// kernel/src/io/iommu/runtime/security/notifier.rs
// ============================================================================

use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};

use spin::{Once, RwLock};

use super::{FaultSummary, IsolationDecision, SecurityEvent, SecurityNotifier};
use crate::io::iommu::types::IommuError;
use crate::sync::MpscRingBuffer;

const SECURITY_EVENT_QUEUE_CAPACITY: usize = 256;
const SECURITY_EVENT_QUEUE_BACKING_CAPACITY: usize = SECURITY_EVENT_QUEUE_CAPACITY + 1;

#[derive(Debug)]
struct SecurityEventQueue {
    queue: MpscRingBuffer<SecurityEvent, SECURITY_EVENT_QUEUE_BACKING_CAPACITY>,
    dropped: AtomicUsize,
}

impl SecurityEventQueue {
    const CAPACITY: usize = SECURITY_EVENT_QUEUE_CAPACITY;

    const fn new() -> Self {
        Self {
            queue: MpscRingBuffer::new(),
            dropped: AtomicUsize::new(0),
        }
    }

    fn push(&self, event: SecurityEvent) {
        const MAX_RETRIES: usize = 16;
        for _ in 0..MAX_RETRIES {
            if self.queue.try_push(event).is_ok() {
                return;
            }
            if self.len() >= self.capacity() {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                return;
            }
            core::hint::spin_loop();
        }
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }

    fn pop(&self) -> Option<SecurityEvent> {
        self.queue.pop()
    }

    fn len(&self) -> usize {
        self.queue.len()
    }

    fn capacity(&self) -> usize {
        Self::CAPACITY
    }

    #[cfg(test)]
    fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    fn take_dropped(&self) -> usize {
        self.dropped.swap(0, Ordering::Relaxed)
    }
}

/// Default IOMMU security monitor that buffers events in a lock-free ring.
#[derive(Debug)]
pub struct IommuSecurityMonitor {
    queue: SecurityEventQueue,
}

impl IommuSecurityMonitor {
    fn new() -> Self {
        Self {
            queue: SecurityEventQueue::new(),
        }
    }

    /// Drain buffered events and pass them to the handler.
    pub fn drain_events<F>(&self, max: usize, mut handler: F) -> usize
    where
        F: FnMut(SecurityEvent),
    {
        let mut count = 0;
        // LOOP_PROOF: mode=condition; reason=Security-event drain is bounded by max and exits early when the queue becomes empty.;
        while count < max {
            let Some(event) = self.queue.pop() else {
                break;
            };
            handler(event);
            count += 1;
        }
        count
    }

    /// Return number of dropped events since the last call.
    pub fn take_dropped_events(&self) -> usize {
        self.queue.take_dropped()
    }
}

impl SecurityNotifier for IommuSecurityMonitor {
    fn notify(&self, event: SecurityEvent) {
        self.queue.push(event);
        wake_security_monitor_from_isr();
    }

    fn decide(&self, _fault: &FaultSummary) -> IsolationDecision {
        IsolationDecision::default()
    }
}

static DEFAULT_SECURITY_MONITOR: Once<Arc<IommuSecurityMonitor>> = Once::new();

/// Waker for the security monitor task (signals new events or isolation requests).
static SECURITY_MONITOR_WAKER: crate::sync::AtomicWaker = crate::sync::AtomicWaker::new();

/// Get the default IOMMU security notifier instance.
pub fn default_security_notifier() -> Arc<dyn SecurityNotifier> {
    default_security_monitor() as Arc<dyn SecurityNotifier>
}

/// Get the default IOMMU security monitor instance.
pub fn default_security_monitor() -> Arc<IommuSecurityMonitor> {
    DEFAULT_SECURITY_MONITOR.call_once(|| Arc::new(IommuSecurityMonitor::new()));
    let monitor = DEFAULT_SECURITY_MONITOR
        .get()
        .expect("IOMMU security monitor not initialized");
    Arc::clone(monitor)
}

pub(crate) fn wake_security_monitor_from_isr() {
    SECURITY_MONITOR_WAKER.wake_from_isr();
}

pub(crate) fn is_security_monitor_wake_pending() -> bool {
    SECURITY_MONITOR_WAKER.is_wake_pending()
}

pub(crate) fn register_security_monitor_waker(waker: &core::task::Waker) {
    SECURITY_MONITOR_WAKER.register(waker);
}

static SECURITY_NOTIFIER: RwLock<Option<Arc<dyn SecurityNotifier>>> = RwLock::new(None);

/// Register a custom security event notifier.
pub fn set_security_notifier(notifier: Arc<dyn SecurityNotifier>) -> Result<bool, IommuError> {
    let mut lock = SECURITY_NOTIFIER.write();
    if lock.is_some() {
        return Ok(false);
    }
    *lock = Some(notifier);
    Ok(true)
}

/// QEMU test hook: clear global notifier state for deterministic canonical smoke tests.
#[cfg(feature = "qemu-test-export")]
pub fn qemu_test_clear_security_notifier() {
    *SECURITY_NOTIFIER.write() = None;
}

/// Notify the registered security listener (if any).
pub(crate) fn notify_security_listener(event: SecurityEvent) {
    if let Some(notifier) = SECURITY_NOTIFIER.read().as_ref() {
        notifier.notify(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn security_event_queue_preserves_reserved_slot_capacity() {
        let queue = SecurityEventQueue::new();
        let event = SecurityEvent::EventsDropped { count: 1 };

        for _ in 0..SECURITY_EVENT_QUEUE_CAPACITY {
            queue.push(event);
        }
        queue.push(event);

        assert_eq!(queue.take_dropped(), 1);
        assert_eq!(queue.len(), SECURITY_EVENT_QUEUE_CAPACITY);
        assert_eq!(queue.capacity(), SECURITY_EVENT_QUEUE_CAPACITY);
        assert!(!queue.is_empty());

        for _ in 0..SECURITY_EVENT_QUEUE_CAPACITY {
            assert!(queue.pop().is_some());
        }
        assert!(queue.pop().is_none());
        assert!(queue.is_empty());
    }
}
