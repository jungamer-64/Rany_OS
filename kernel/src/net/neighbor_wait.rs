//! Runtime-owned ARP/NDP completion storage. Registration, readiness and Waker
//! replacement share one publication lock. Waker callbacks and destruction run
//! after unlocking, including cancellation and timeout reclamation.

use core::task::{Context, Poll, Waker};

use crate::net::l2::ethernet::MacAddress;
use crate::net::runtime::manager::NetIfId;
use crate::sync::PoisonLock;

const WAITER_CAPACITY: usize = 32;
const RESOLVE_TIMEOUT_MS: u64 = 5_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NeighborWaitError {
    CapacityExhausted,
    IdentityExhausted,
    RegistryPoisoned,
    Timeout,
}

enum Resolution {
    Pending {
        created_at_ms: u64,
    },
    Resolved {
        mac: MacAddress,
        completed_at_ms: u64,
    },
}

impl Resolution {
    fn expired(&self, now_ms: u64) -> bool {
        let since_ms = match self {
            Self::Pending { created_at_ms } => *created_at_ms,
            Self::Resolved {
                completed_at_ms, ..
            } => *completed_at_ms,
        };
        now_ms.saturating_sub(since_ms) > RESOLVE_TIMEOUT_MS
    }
}

struct NeighborWaiter<const N: usize> {
    id: u64,
    if_id: NetIfId,
    ip: [u8; N],
    resolution: Resolution,
    waker: Option<Waker>,
}

struct WaiterStorage<const N: usize> {
    slots: [Option<NeighborWaiter<N>>; WAITER_CAPACITY],
    next_id: u64,
}

pub(crate) struct NeighborWaiters<const N: usize> {
    storage: PoisonLock<WaiterStorage<N>>,
}

impl<const N: usize> NeighborWaiters<N> {
    pub(crate) const fn new() -> Self {
        Self {
            storage: PoisonLock::new(WaiterStorage {
                slots: [const { None }; WAITER_CAPACITY],
                next_id: 1,
            }),
        }
    }

    /// Admission does not allocate. A ticket borrows its owning registry, and
    /// dropping it cancels only its own monotonically issued identity.
    ///
    /// # Errors
    /// Returns capacity or identity exhaustion without publication, or poison
    /// when the registry cannot accept further operations.
    pub(crate) fn register(
        &self,
        if_id: NetIfId,
        ip: [u8; N],
        now_ms: u64,
    ) -> Result<NeighborWait<'_, N>, NeighborWaitError> {
        let mut storage = self
            .storage
            .lock()
            .map_err(|_| NeighborWaitError::RegistryPoisoned)?;
        let index = storage
            .slots
            .iter()
            .position(Option::is_none)
            .ok_or(NeighborWaitError::CapacityExhausted)?;
        let id = storage.next_id;
        storage.next_id = id
            .checked_add(1)
            .ok_or(NeighborWaitError::IdentityExhausted)?;
        storage.slots[index] = Some(NeighborWaiter {
            id,
            if_id,
            ip,
            resolution: Resolution::Pending {
                created_at_ms: now_ms,
            },
            waker: None,
        });
        Ok(NeighborWait { registry: self, id })
    }

    /// Completion persists even before the first poll or while a task is
    /// suspended. Duplicate replies cannot replace a committed result.
    pub(crate) fn notify(&self, if_id: NetIfId, ip: [u8; N], mac: MacAddress, now_ms: u64) {
        let mut notifications: [Option<Waker>; WAITER_CAPACITY] = [const { None }; WAITER_CAPACITY];
        {
            let Ok(mut storage) = self.storage.lock() else {
                return;
            };
            for (slot, notification) in storage.slots.iter_mut().zip(&mut notifications) {
                if let Some(waiter) = slot
                    && waiter.if_id == if_id
                    && waiter.ip == ip
                    && matches!(waiter.resolution, Resolution::Pending { .. })
                {
                    waiter.resolution = Resolution::Resolved {
                        mac,
                        completed_at_ms: now_ms,
                    };
                    *notification = waiter.waker.take();
                }
            }
        }
        for waker in notifications.into_iter().flatten() {
            waker.wake();
        }
    }

    /// Maintenance removes expired records before waking their owners. A late
    /// poll observes Timeout; an old ticket never addresses a reused slot.
    pub(crate) fn expire(&self, now_ms: u64) {
        let mut retired: [Option<NeighborWaiter<N>>; WAITER_CAPACITY] =
            [const { None }; WAITER_CAPACITY];
        {
            let Ok(mut storage) = self.storage.lock() else {
                return;
            };
            for (slot, retired_slot) in storage.slots.iter_mut().zip(&mut retired) {
                if slot
                    .as_ref()
                    .is_some_and(|waiter| waiter.resolution.expired(now_ms))
                {
                    *retired_slot = slot.take();
                }
            }
        }
        for mut waiter in retired.into_iter().flatten() {
            if matches!(waiter.resolution, Resolution::Pending { .. })
                && let Some(waker) = waiter.waker.take()
            {
                waker.wake();
            }
        }
    }

    fn remove(&self, id: u64) {
        let retired = {
            let Ok(mut storage) = self.storage.lock() else {
                return;
            };
            storage
                .slots
                .iter_mut()
                .find(|slot| slot.as_ref().is_some_and(|waiter| waiter.id == id))
                .and_then(Option::take)
        };
        drop(retired);
    }
}

/// Cancellation and readiness authority is limited to one registry entry.
pub(crate) struct NeighborWait<'a, const N: usize> {
    registry: &'a NeighborWaiters<N>,
    id: u64,
}

impl<const N: usize> NeighborWait<'_, N> {
    /// Pending publishes this poll's Waker under the same lock used to commit
    /// replies. Clone/drop callbacks are outside that lock, so a reply racing
    /// Waker preparation is observed as Ready or wakes the published Waker.
    pub(crate) fn poll(
        &mut self,
        cx: &mut Context<'_>,
        now_ms: u64,
    ) -> Poll<Result<MacAddress, NeighborWaitError>> {
        let prepared_waker = cx.waker().clone();
        let (result, retired, replaced_waker) = {
            let Ok(mut storage) = self.registry.storage.lock() else {
                return Poll::Ready(Err(NeighborWaitError::RegistryPoisoned));
            };
            let Some(slot) = storage
                .slots
                .iter_mut()
                .find(|slot| slot.as_ref().is_some_and(|waiter| waiter.id == self.id))
            else {
                return Poll::Ready(Err(NeighborWaitError::Timeout));
            };
            let Some(waiter) = slot.as_mut() else {
                return Poll::Ready(Err(NeighborWaitError::Timeout));
            };
            match &waiter.resolution {
                Resolution::Resolved { mac, .. } => (Poll::Ready(Ok(*mac)), slot.take(), None),
                Resolution::Pending { created_at_ms }
                    if now_ms.saturating_sub(*created_at_ms) > RESOLVE_TIMEOUT_MS =>
                {
                    (
                        Poll::Ready(Err(NeighborWaitError::Timeout)),
                        slot.take(),
                        None,
                    )
                }
                Resolution::Pending { .. } => {
                    let replaced = waiter.waker.replace(prepared_waker);
                    (Poll::Pending, None, replaced)
                }
            }
        };
        drop(retired);
        drop(replaced_waker);
        result
    }
}

impl<const N: usize> Drop for NeighborWait<'_, N> {
    fn drop(&mut self) {
        self.registry.remove(self.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use alloc::task::Wake;
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicUsize, Ordering};

    struct WakeCount(AtomicUsize);

    impl Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn counted_waker() -> (Arc<WakeCount>, Waker) {
        let count = Arc::new(WakeCount(AtomicUsize::new(0)));
        let waker = Waker::from(Arc::clone(&count));
        (count, waker)
    }

    #[test]
    fn reply_before_poll_completes_all_matching_arp_waiters_once() {
        let registry = NeighborWaiters::new();
        let ip = [10, 0, 0, 42];
        let mac = MacAddress::new([2, 0, 0, 0, 0, 42]);
        let mut first = registry
            .register(NetIfId(1), ip, 0)
            .expect("first admission");
        let mut second = registry
            .register(NetIfId(1), ip, 0)
            .expect("second admission");
        let mut other = registry
            .register(NetIfId(1), [10, 0, 0, 43], 0)
            .expect("other IP admission");
        registry.notify(NetIfId(1), ip, mac, 1);
        registry.notify(NetIfId(1), ip, MacAddress::BROADCAST, 2);
        let mut cx = Context::from_waker(Waker::noop());
        assert_eq!(first.poll(&mut cx, 2), Poll::Ready(Ok(mac)));
        assert_eq!(second.poll(&mut cx, 2), Poll::Ready(Ok(mac)));
        assert_eq!(other.poll(&mut cx, 2), Poll::Pending);
    }

    #[test]
    fn ndp_reply_preserves_interface_scope_and_wakes_latest_registration() {
        let registry = NeighborWaiters::<16>::new();
        let ip = [1; 16];
        let mac = MacAddress::new([2, 0, 0, 0, 0, 77]);
        let mut first = registry.register(NetIfId(1), ip, 0).expect("if1 admission");
        let mut second = registry.register(NetIfId(2), ip, 0).expect("if2 admission");
        let (old_count, old_waker) = counted_waker();
        let (new_count, new_waker) = counted_waker();
        assert!(
            first
                .poll(&mut Context::from_waker(&old_waker), 0)
                .is_pending()
        );
        assert!(
            first
                .poll(&mut Context::from_waker(&new_waker), 0)
                .is_pending()
        );
        registry.notify(NetIfId(1), ip, mac, 1);
        assert_eq!(old_count.0.load(Ordering::Relaxed), 0);
        assert_eq!(new_count.0.load(Ordering::Relaxed), 1);
        assert_eq!(
            first.poll(&mut Context::from_waker(&new_waker), 1),
            Poll::Ready(Ok(mac))
        );
        assert!(
            second
                .poll(&mut Context::from_waker(&old_waker), 1)
                .is_pending()
        );
    }

    #[test]
    fn elapsed_timeout_ignores_poll_storms_and_returns_capacity() {
        let registry = NeighborWaiters::<4>::new();
        let mut tickets: Vec<_> = (0..WAITER_CAPACITY)
            .map(|_| {
                registry
                    .register(NetIfId(1), [1; 4], 100)
                    .expect("bounded admission")
            })
            .collect();
        assert!(matches!(
            registry.register(NetIfId(1), [1; 4], 100),
            Err(NeighborWaitError::CapacityExhausted)
        ));
        let mut cx = Context::from_waker(Waker::noop());
        for _ in 0..100 {
            assert_eq!(tickets[0].poll(&mut cx, 100), Poll::Pending);
        }
        assert_eq!(tickets[0].poll(&mut cx, 5_100), Poll::Pending);
        assert_eq!(
            tickets[0].poll(&mut cx, 5_101),
            Poll::Ready(Err(NeighborWaitError::Timeout))
        );
        let mut replacement = registry
            .register(NetIfId(1), [2; 4], 5_101)
            .expect("expired capacity returned");
        drop(tickets.remove(0));
        assert_eq!(replacement.poll(&mut cx, 5_101), Poll::Pending);
        drop(tickets);
        let replacement2 = registry
            .register(NetIfId(1), [3; 4], 5_101)
            .expect("cancelled capacity returned");
        drop(replacement2);
    }

    #[test]
    fn maintenance_wakes_expired_waiters_and_retains_completed_result() {
        let registry = NeighborWaiters::<4>::new();
        let mut expired = registry
            .register(NetIfId(1), [1; 4], 0)
            .expect("pending admission");
        let mut completed = registry
            .register(NetIfId(1), [2; 4], 0)
            .expect("resolved admission");
        let (count, waker) = counted_waker();
        assert!(
            expired
                .poll(&mut Context::from_waker(&waker), 0)
                .is_pending()
        );
        registry.notify(NetIfId(1), [2; 4], MacAddress::BROADCAST, 4_000);
        registry.expire(5_001);
        assert_eq!(count.0.load(Ordering::Relaxed), 1);
        assert_eq!(
            expired.poll(&mut Context::from_waker(&waker), 5_001),
            Poll::Ready(Err(NeighborWaitError::Timeout))
        );
        assert_eq!(
            completed.poll(&mut Context::from_waker(&waker), 5_001),
            Poll::Ready(Ok(MacAddress::BROADCAST))
        );
    }

    struct ReentrantWake {
        registry: Arc<NeighborWaiters<4>>,
        count: AtomicUsize,
    }

    impl Wake for ReentrantWake {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            // Re-entering the same owner would deadlock if callbacks ran while
            // its publication lock remained held.
            self.registry
                .notify(NetIfId(2), [2; 4], MacAddress::BROADCAST, 1);
            self.count.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn reply_and_expiry_callbacks_run_after_unlocking() {
        let registry = Arc::new(NeighborWaiters::new());
        let wake = Arc::new(ReentrantWake {
            registry: Arc::clone(&registry),
            count: AtomicUsize::new(0),
        });
        let waker = Waker::from(Arc::clone(&wake));
        let mut first = registry
            .register(NetIfId(1), [1; 4], 0)
            .expect("reply admission");
        let mut second = registry
            .register(NetIfId(1), [3; 4], 0)
            .expect("expiry admission");
        assert!(first.poll(&mut Context::from_waker(&waker), 0).is_pending());
        assert!(
            second
                .poll(&mut Context::from_waker(&waker), 0)
                .is_pending()
        );
        registry.notify(NetIfId(1), [1; 4], MacAddress::BROADCAST, 1);
        registry.expire(5_001);
        assert_eq!(wake.count.load(Ordering::Relaxed), 2);
    }

    #[cfg(any(feature = "std", target_os = "linux"))]
    #[test]
    fn racing_reply_is_ready_or_wakes_the_current_poll() {
        for _ in 0..64 {
            let registry = NeighborWaiters::new();
            let mut wait = registry.register(NetIfId(1), [1; 4], 0).expect("admission");
            let (_, old_waker) = counted_waker();
            let (new_count, new_waker) = counted_waker();
            assert!(
                wait.poll(&mut Context::from_waker(&old_waker), 0)
                    .is_pending()
            );
            let result = std::thread::scope(|scope| {
                scope.spawn(|| registry.notify(NetIfId(1), [1; 4], MacAddress::BROADCAST, 1));
                wait.poll(&mut Context::from_waker(&new_waker), 1)
            });
            if result.is_pending() {
                assert_eq!(new_count.0.load(Ordering::Relaxed), 1);
                assert_eq!(
                    wait.poll(&mut Context::from_waker(&new_waker), 1),
                    Poll::Ready(Ok(MacAddress::BROADCAST))
                );
            } else {
                assert_eq!(result, Poll::Ready(Ok(MacAddress::BROADCAST)));
            }
        }
    }
}
