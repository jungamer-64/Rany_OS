//! Broadcast receipt with registration owned by each waiting Future.
//!
//! Notifications complete listeners registered at the delivery boundary. An
//! event without listeners is discarded. Polling again, or receiving another
//! task notification, does not constitute receipt. Cancellation removes only
//! that listener; it cannot clear another listener's registration.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll};

use crate::{Mutex, WakerSlot};

/// Ordinary-context broadcast event. Neither registration nor notification is
/// ISR safe: callers must defer interrupt delivery before accessing the set.
#[derive(Debug)]
pub struct BroadcastEvent {
    listeners: Mutex<Vec<Arc<Receipt>>>,
}

impl BroadcastEvent {
    pub const fn new() -> Self {
        Self {
            listeners: Mutex::new(Vec::new()),
        }
    }

    /// Registration begins on the first poll. Dropping the returned listener
    /// cancels its registration without affecting other listeners.
    pub fn listen(&self) -> EventListener<'_> {
        EventListener {
            event: self,
            state: ListenerState::Unregistered,
        }
    }

    /// Detaches the current set under the lock, then records receipt and calls
    /// wakers after releasing it. Listeners registered by callbacks belong to
    /// the next delivery. Hardware event data must be published before this call.
    pub fn notify(&self) {
        let listeners = {
            let mut registered = self.listeners.lock();
            core::mem::take(&mut *registered)
        };
        for receipt in listeners {
            receipt.received.store(true, Ordering::Release);
            receipt.waker.wake();
        }
    }

    /// Counts current registrations, excluding receipts already detached for
    /// delivery. This is an observation, not a cancellation capability.
    pub fn listener_count(&self) -> usize {
        self.listeners.lock().len()
    }

    fn cancel(&self, receipt: &Arc<Receipt>) {
        let retired = {
            let mut registered = self.listeners.lock();
            registered
                .iter()
                .position(|entry| Arc::ptr_eq(entry, receipt))
                .map(|index| registered.swap_remove(index))
        };
        // Releasing wakers can execute RawWaker destructors. Never do that
        // while the registration lock owns mutation authority.
        drop(retired);
        receipt.waker.clear();
    }
}

impl Default for BroadcastEvent {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
struct Receipt {
    received: AtomicBool,
    waker: WakerSlot,
}

enum ListenerState {
    Unregistered,
    Waiting(Arc<Receipt>),
    Complete,
}

/// Borrowing the event retains the registration owner until completion or
/// cancellation. The receipt owns the task waker and survives a racing delivery.
pub struct EventListener<'event> {
    event: &'event BroadcastEvent,
    state: ListenerState,
}

impl Future for EventListener<'_> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<()> {
        if matches!(self.state, ListenerState::Unregistered) {
            let receipt = Arc::new(Receipt {
                received: AtomicBool::new(false),
                waker: WakerSlot::new(),
            });
            receipt.waker.register(context.waker());
            self.event.listeners.lock().push(Arc::clone(&receipt));
            self.state = ListenerState::Waiting(receipt);
        } else if let ListenerState::Waiting(receipt) = &self.state {
            receipt.waker.register(context.waker());
        }

        match &self.state {
            ListenerState::Waiting(receipt) if !receipt.received.load(Ordering::Acquire) => {
                Poll::Pending
            }
            ListenerState::Waiting(receipt) => {
                self.event.cancel(receipt);
                self.state = ListenerState::Complete;
                Poll::Ready(())
            }
            ListenerState::Complete => Poll::Ready(()),
            ListenerState::Unregistered => unreachable!("first poll registers its receipt"),
        }
    }
}

impl Drop for EventListener<'_> {
    fn drop(&mut self) {
        if let ListenerState::Waiting(receipt) = &self.state {
            self.event.cancel(receipt);
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use alloc::task::Wake;
    use core::sync::atomic::AtomicUsize;
    use core::task::Waker;

    struct Counter(AtomicUsize);
    impl Wake for Counter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn repoll_and_unrelated_wake_do_not_complete_a_listener() {
        let event = BroadcastEvent::new();
        let counter = Arc::new(Counter(AtomicUsize::new(0)));
        let waker = Waker::from(Arc::clone(&counter));
        let mut context = Context::from_waker(&waker);
        let mut listener = event.listen();
        assert!(Pin::new(&mut listener).poll(&mut context).is_pending());
        waker.wake_by_ref();
        assert!(Pin::new(&mut listener).poll(&mut context).is_pending());
        assert_eq!(event.listener_count(), 1);
        event.notify();
        assert!(Pin::new(&mut listener).poll(&mut context).is_ready());
        assert_eq!(event.listener_count(), 0);
    }

    #[test]
    fn cancellation_does_not_remove_other_listeners() {
        let event = BroadcastEvent::new();
        let mut context = Context::from_waker(Waker::noop());
        let mut first = event.listen();
        let mut second = event.listen();
        assert!(Pin::new(&mut first).poll(&mut context).is_pending());
        assert!(Pin::new(&mut second).poll(&mut context).is_pending());
        assert_eq!(event.listener_count(), 2);
        drop(first);
        assert_eq!(event.listener_count(), 1);
        event.notify();
        assert!(Pin::new(&mut second).poll(&mut context).is_ready());
        let mut later = event.listen();
        assert!(Pin::new(&mut later).poll(&mut context).is_pending());
        drop(later);
        assert_eq!(event.listener_count(), 0);
    }

    #[test]
    fn delivery_racing_repoll_retains_receipt() {
        let event = BroadcastEvent::new();
        let counter = Arc::new(Counter(AtomicUsize::new(0)));
        let waker = Waker::from(Arc::clone(&counter));
        let mut context = Context::from_waker(&waker);
        let mut listener = event.listen();
        assert!(Pin::new(&mut listener).poll(&mut context).is_pending());
        let observed = std::thread::scope(|scope| {
            let notify = scope.spawn(|| event.notify());
            let observed = Pin::new(&mut listener).poll(&mut context);
            notify.join().expect("notification thread completes");
            observed
        });
        assert!(Pin::new(&mut listener).poll(&mut context).is_ready());
        let callbacks = counter.0.load(Ordering::Relaxed);
        assert!(callbacks <= 1);
        if observed.is_pending() {
            assert_eq!(callbacks, 1);
        }
    }
}
