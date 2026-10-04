// ============================================================================
// drivers/time/src/lib.rs - Time Management Driver (Cell)
// ============================================================================
//!
//! # Time Management Driver
//!
//! ExoRust アーキテクチャにおける時間管理セル（ドライバ）。
//! 高レベルのタイマーサービスを提供する。

#![no_std]

extern crate alloc;

use alloc::collections::BinaryHeap;
use core::cmp::Ordering as Compare;
use core::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use exorust_sync::PoisonLock;
use kernel_api::service::time::{
    TimeService, TimerError, TimerMode, TimerOutcome, TimerRegistration, TimerSchedule,
    TimerServiceStats, TimerSignal,
};

const NANOS_PER_MILLI: u64 = 1_000_000;
const NANOS_PER_SEC: u64 = 1_000_000_000;

struct TimerEntry {
    deadline: u64,
    order: u64,
    period: Option<u64>,
    signal: TimerSignal,
}

// The heap is an index of pending deadlines. Cancellation authority and task
// liveness reside solely in the receipt's event, never in a numeric timer ID.
impl PartialEq for TimerEntry {
    fn eq(&self, other: &Self) -> bool {
        (self.deadline, self.order) == (other.deadline, other.order)
    }
}
impl Eq for TimerEntry {}
impl PartialOrd for TimerEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Compare> {
        Some(self.cmp(other))
    }
}
impl Ord for TimerEntry {
    fn cmp(&self, other: &Self) -> Compare {
        (other.deadline, other.order).cmp(&(self.deadline, self.order))
    }
}

struct TimerRegistry {
    entries: BinaryHeap<TimerEntry>,
    next_order: u64,
}

impl TimerRegistry {
    const fn new() -> Self {
        Self {
            entries: BinaryHeap::new(),
            next_order: 0,
        }
    }

    fn insert(
        &mut self,
        deadline: u64,
        period: Option<u64>,
        signal: TimerSignal,
    ) -> Result<(), TimerError> {
        // Retaining weak endpoints cannot run a task's RawWaker destructor under
        // this lock. Delivery upgrades only after removing the endpoint.
        self.entries.retain(|entry| entry.signal.is_retained());
        let next_order = self
            .next_order
            .checked_add(1)
            .ok_or(TimerError::OrderExhausted)?;
        self.entries
            .try_reserve(1)
            .map_err(|_| TimerError::MemoryExhausted)?;
        self.entries.push(TimerEntry {
            deadline,
            order: self.next_order,
            period,
            signal,
        });
        self.next_order = next_order;
        Ok(())
    }

    fn take_due(&mut self, now: u64) -> Option<(TimerSignal, TimerOutcome)> {
        // LOOP_PROOF: mode=condition; reason=Each cancelled head is removed from this finite heap under the same exclusive guard; a live head ends cleanup.
        while self
            .entries
            .peek()
            .is_some_and(|entry| !entry.signal.is_retained())
        {
            self.entries.pop();
        }
        if !self
            .entries
            .peek()
            .is_some_and(|entry| entry.deadline <= now)
        {
            return None;
        }
        let mut entry = self.entries.pop()?;
        let outcome = match entry.period {
            None => TimerOutcome::Tick,
            Some(period) => match now.checked_add(period) {
                Some(next) => {
                    entry.deadline = next;
                    // The pop left one free heap slot. Reinsertion under the
                    // same lock requires no allocation after consuming this tick.
                    let signal = entry.signal;
                    let retained = signal.clone();
                    entry.signal = retained;
                    self.entries.push(entry);
                    return Some((signal, TimerOutcome::Tick));
                }
                None => TimerOutcome::ClockExhausted,
            },
        };
        Some((entry.signal, outcome))
    }

    fn active_len(&self) -> usize {
        self.entries
            .iter()
            .filter(|entry| entry.signal.is_retained())
            .count()
    }

    fn due_len(&self, now: u64) -> usize {
        self.entries
            .iter()
            .filter(|entry| entry.deadline <= now && entry.signal.is_retained())
            .count()
    }
}

/// Timer ISR updates only the clock. An ordinary scheduler context delivers a
/// finite batch of notifications, with every RawWaker callback outside locks.
/// CPU runtime accounting belongs to the scheduler's execution fragments.
pub struct TimeManagement {
    ticks: AtomicU64,
    wall_clock_offset_ns: AtomicI64,
    timers: PoisonLock<TimerRegistry>,
    total_fired: AtomicU64,
    waker_dispatches: AtomicU64,
}

impl TimeManagement {
    pub const fn new() -> Self {
        Self {
            ticks: AtomicU64::new(0),
            wall_clock_offset_ns: AtomicI64::new(0),
            timers: PoisonLock::new(TimerRegistry::new()),
            total_fired: AtomicU64::new(0),
            waker_dispatches: AtomicU64::new(0),
        }
    }

    fn wall_clock_ns(&self) -> u64 {
        let uptime = i128::from(self.uptime_ns());
        let offset = i128::from(self.wall_clock_offset_ns.load(Ordering::Relaxed));
        clamp_i128_to_u64(uptime + offset)
    }
}

impl Default for TimeManagement {
    fn default() -> Self {
        Self::new()
    }
}

impl TimeService for TimeManagement {
    fn register_timer(&self, schedule: TimerSchedule) -> Result<TimerRegistration, TimerError> {
        let (deadline, period) = match schedule {
            TimerSchedule::At(deadline) => (deadline, None),
            TimerSchedule::After { interval_ms, mode } => {
                if mode == TimerMode::Periodic && interval_ms == 0 {
                    return Err(TimerError::ZeroPeriodicInterval);
                }
                let deadline = self
                    .current_tick_ms()
                    .checked_add(interval_ms)
                    .ok_or(TimerError::ClockExhausted)?;
                (
                    deadline,
                    (mode == TimerMode::Periodic).then_some(interval_ms),
                )
            }
        };
        let (receipt, signal) = TimerRegistration::new()?;
        let admission = self
            .timers
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .insert(deadline, period, signal);
        // Failure drops the receipt after the registry guard has released.
        admission?;
        Ok(receipt)
    }

    fn current_tick_ms(&self) -> u64 {
        self.ticks.load(Ordering::Acquire)
    }
    fn uptime_ns(&self) -> u64 {
        self.current_tick_ms().saturating_mul(NANOS_PER_MILLI)
    }
    fn unix_timestamp(&self) -> u64 {
        self.wall_clock_ns() / NANOS_PER_SEC
    }
    fn unix_timestamp_ms(&self) -> u64 {
        self.wall_clock_ns() / NANOS_PER_MILLI
    }

    fn stats(&self) -> TimerServiceStats {
        let registry = self
            .timers
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        TimerServiceStats {
            active_timers: registry.active_len(),
            total_fired: self.total_fired.load(Ordering::Relaxed),
            notifications: self.waker_dispatches.load(Ordering::Relaxed),
            due_timers: registry.due_len(self.current_tick_ms()),
        }
    }
}

impl TimeManagement {
    /// Updates only the monotonic clock; the interrupt path neither allocates
    /// nor locks the timer registry or invokes notification callbacks.
    pub fn on_timer_interrupt(&self) {
        // Saturation preserves a monotonic clock and exposes overflow during
        // relative admission or periodic rescheduling instead of wrapping.
        let _previous = self
            .ticks
            .try_update(Ordering::AcqRel, Ordering::Acquire, |tick| {
                Some(tick.saturating_add(1))
            });
    }

    /// Drains a finite batch outside interrupt context. Notifications execute
    /// after releasing the timer registry, including concurrent cancellation.
    pub fn process_pending_wakers(&self) {
        let now = self.current_tick_ms();
        let limit = self
            .timers
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .entries
            .len();
        // LOOP_PROOF: mode=condition; reason=The captured entry count bounds this delivery pass; timer callbacks and concurrent producers belong to a later pass and cannot make it unbounded.;
        for _ in 0..limit {
            let due = self
                .timers
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .take_due(now);
            let Some((signal, outcome)) = due else { break };
            self.total_fired.fetch_add(1, Ordering::Relaxed);
            if signal.notify(outcome) {
                self.waker_dispatches.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// The provider owns correction policy; timer consumers cannot change it.
    pub fn adjust_wall_clock(&self, delta_ns: i64) {
        let _previous =
            self.wall_clock_offset_ns
                .try_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                    Some(current.saturating_add(delta_ns))
                });
    }
}

static TIME_MANAGER: TimeManagement = TimeManagement::new();
pub fn time_service() -> &'static TimeManagement {
    &TIME_MANAGER
}

fn clamp_i128_to_u64(value: i128) -> u64 {
    u64::try_from(value).unwrap_or(if value < 0 { 0 } else { u64::MAX })
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use alloc::sync::Arc;
    use alloc::task::Wake;
    use alloc::vec::Vec;
    use core::future::Future;
    use core::pin::Pin;
    use core::sync::atomic::AtomicUsize;
    use core::task::{Context, Poll, Waker};
    use exorust_sync::Mutex;

    struct CountingWaker(AtomicUsize);
    impl Wake for CountingWaker {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    fn count_waker() -> (Arc<CountingWaker>, Waker) {
        let owner = Arc::new(CountingWaker(AtomicUsize::new(0)));
        let waker = Waker::from(Arc::clone(&owner));
        (owner, waker)
    }
    fn arm(receipt: &mut TimerRegistration, waker: &Waker) {
        assert_eq!(
            Pin::new(receipt).poll(&mut Context::from_waker(waker)),
            Poll::Pending
        );
    }
    fn take_tick(receipt: &mut TimerRegistration, waker: &Waker) {
        assert_eq!(
            Pin::new(receipt).poll(&mut Context::from_waker(waker)),
            Poll::Ready(Ok(()))
        );
    }
    fn advance(time: &TimeManagement, count: usize) {
        for _ in 0..count {
            time.on_timer_interrupt();
        }
    }

    #[test]
    fn interrupt_updates_clock_without_delivering_callbacks() {
        let time = TimeManagement::new();
        let (count, waker) = count_waker();
        let mut receipt = time.register_timer(TimerSchedule::At(2)).unwrap();
        arm(&mut receipt, &waker);
        advance(&time, 2);
        assert_eq!(time.current_tick_ms(), 2);
        assert_eq!(count.0.load(Ordering::Relaxed), 0);
        time.process_pending_wakers();
        assert_eq!(count.0.load(Ordering::Relaxed), 1);
        take_tick(&mut receipt, &waker);
        assert_eq!(time.stats().active_timers, 0);
    }

    #[test]
    fn cancelling_same_deadline_retains_the_other_registration() {
        let time = TimeManagement::new();
        let (first, first_waker) = count_waker();
        let (second, second_waker) = count_waker();
        let mut a = time.register_timer(TimerSchedule::At(2)).unwrap();
        let mut b = time.register_timer(TimerSchedule::At(2)).unwrap();
        arm(&mut a, &first_waker);
        arm(&mut b, &second_waker);
        drop(b);
        advance(&time, 2);
        time.process_pending_wakers();
        assert_eq!(first.0.load(Ordering::Relaxed), 1);
        assert_eq!(second.0.load(Ordering::Relaxed), 0);
        take_tick(&mut a, &first_waker);
    }

    #[test]
    fn completion_before_poll_is_retained_and_waker_can_change() {
        let time = TimeManagement::new();
        let (_, old_waker) = count_waker();
        let (new_count, new_waker) = count_waker();
        let mut receipt = time.register_timer(TimerSchedule::At(2)).unwrap();
        arm(&mut receipt, &old_waker);
        arm(&mut receipt, &new_waker);
        advance(&time, 2);
        time.process_pending_wakers();
        assert_eq!(new_count.0.load(Ordering::Relaxed), 1);
        take_tick(&mut receipt, &new_waker);
        let mut early = time.register_timer(TimerSchedule::At(2)).unwrap();
        time.process_pending_wakers();
        take_tick(&mut early, &new_waker);
    }

    #[test]
    fn periodic_ticks_coalesce_and_drop_cancels_future_ticks() {
        let time = TimeManagement::new();
        let (count, waker) = count_waker();
        let mut receipt = time
            .register_timer(TimerSchedule::After {
                interval_ms: 2,
                mode: TimerMode::Periodic,
            })
            .unwrap();
        arm(&mut receipt, &waker);
        advance(&time, 2);
        time.process_pending_wakers();
        take_tick(&mut receipt, &waker);
        arm(&mut receipt, &waker);
        advance(&time, 2);
        time.process_pending_wakers();
        assert_eq!(count.0.load(Ordering::Relaxed), 2);
        drop(receipt);
        advance(&time, 2);
        time.process_pending_wakers();
        assert_eq!(count.0.load(Ordering::Relaxed), 2);
        assert_eq!(time.stats().active_timers, 0);
    }

    struct OrderedWake(u64, Arc<Mutex<Vec<u64>>>);
    impl Wake for OrderedWake {
        fn wake(self: Arc<Self>) {
            self.1.lock().push(self.0);
        }
    }

    #[test]
    fn delivery_is_in_deadline_and_registration_order() {
        let time = TimeManagement::new();
        let order = Arc::new(Mutex::new(Vec::new()));
        let mut receipts = Vec::new();
        for (deadline, id) in [(2, 20), (2, 21), (3, 30), (1, 10)] {
            let mut receipt = time.register_timer(TimerSchedule::At(deadline)).unwrap();
            let waker = Waker::from(Arc::new(OrderedWake(id, Arc::clone(&order))));
            arm(&mut receipt, &waker);
            receipts.push(receipt);
        }
        advance(&time, 3);
        time.process_pending_wakers();
        assert_eq!(*order.lock(), alloc::vec![10, 20, 21, 30]);
    }

    struct CancelOther(Mutex<Option<TimerRegistration>>);
    impl Wake for CancelOther {
        fn wake(self: Arc<Self>) {
            self.0.lock().take();
        }
    }

    #[test]
    fn callback_can_cancel_another_timer_without_registry_lock_reentry() {
        let time = TimeManagement::new();
        let (_, waker) = count_waker();
        let mut victim = time.register_timer(TimerSchedule::At(1)).unwrap();
        arm(&mut victim, &waker);
        let cancellation = Arc::new(CancelOther(Mutex::new(Some(victim))));
        let mut first = time.register_timer(TimerSchedule::At(0)).unwrap();
        arm(&mut first, &Waker::from(Arc::clone(&cancellation)));
        advance(&time, 1);
        time.process_pending_wakers();
        assert!(cancellation.0.lock().is_none());
        assert_eq!(time.stats().active_timers, 0);
    }

    #[test]
    fn interval_errors_and_terminal_clock_overflow_are_distinct() {
        let time = TimeManagement::new();
        assert!(matches!(
            time.register_timer(TimerSchedule::After {
                interval_ms: 0,
                mode: TimerMode::Periodic
            }),
            Err(TimerError::ZeroPeriodicInterval)
        ));
        time.ticks.store(u64::MAX - 1, Ordering::Release);
        assert!(matches!(
            time.register_timer(TimerSchedule::After {
                interval_ms: 2,
                mode: TimerMode::OneShot
            }),
            Err(TimerError::ClockExhausted)
        ));
        let mut receipt = time
            .register_timer(TimerSchedule::After {
                interval_ms: 1,
                mode: TimerMode::Periodic,
            })
            .unwrap();
        let (_, waker) = count_waker();
        arm(&mut receipt, &waker);
        advance(&time, 2);
        assert_eq!(time.current_tick_ms(), u64::MAX);
        time.process_pending_wakers();
        assert_eq!(
            Pin::new(&mut receipt).poll(&mut Context::from_waker(&waker)),
            Poll::Ready(Err(TimerError::ClockExhausted))
        );
        assert_eq!(time.stats().active_timers, 0);
    }

    #[test]
    fn wall_clock_adjustments_preserve_one_offset_authority() {
        let time = TimeManagement::new();
        time.adjust_wall_clock(10_000_000_000);
        advance(&time, 3);
        assert_eq!(time.unix_timestamp_ms(), 10_003);
        time.adjust_wall_clock(-10_003_000_000);
        assert_eq!(time.unix_timestamp_ms(), 0);
    }

    #[test]
    fn concurrent_consumers_deliver_a_periodic_deadline_once() {
        let time = TimeManagement::new();
        let (counter, waker) = count_waker();
        let mut receipt = time
            .register_timer(TimerSchedule::After {
                interval_ms: 1,
                mode: TimerMode::Periodic,
            })
            .unwrap();
        arm(&mut receipt, &waker);
        advance(&time, 1);
        std::thread::scope(|scope| {
            for _ in 0..4 {
                scope.spawn(|| time.process_pending_wakers());
            }
        });
        assert_eq!(counter.0.load(Ordering::Relaxed), 1);
        assert_eq!(time.stats().total_fired, 1);
        take_tick(&mut receipt, &waker);
    }

    struct RegisterOnWake {
        time: Arc<TimeManagement>,
        registered: Mutex<Option<TimerRegistration>>,
    }
    impl Wake for RegisterOnWake {
        fn wake(self: Arc<Self>) {
            *self.registered.lock() = Some(self.time.register_timer(TimerSchedule::At(0)).unwrap());
        }
    }

    #[test]
    fn callback_registration_reenters_the_provider_and_belongs_to_the_next_pass() {
        let time = Arc::new(TimeManagement::new());
        let callback = Arc::new(RegisterOnWake {
            time: Arc::clone(&time),
            registered: Mutex::new(None),
        });
        let mut receipt = time.register_timer(TimerSchedule::At(0)).unwrap();
        arm(&mut receipt, &Waker::from(Arc::clone(&callback)));
        time.process_pending_wakers();
        assert!(callback.registered.lock().is_some());
        assert_eq!(time.stats().due_timers, 1);
        time.process_pending_wakers();
        assert_eq!(time.stats().due_timers, 0);
    }

    #[test]
    fn exhausted_ordering_does_not_publish_a_registration() {
        let time = TimeManagement::new();
        time.timers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .next_order = u64::MAX;
        assert!(matches!(
            time.register_timer(TimerSchedule::At(0)),
            Err(TimerError::OrderExhausted)
        ));
        assert_eq!(time.stats().active_timers, 0);
    }

    #[test]
    fn imported_periodic_timer_retains_notification_and_cancellation_ownership() {
        use kernel_api::abi::driver::{AbiTimerAdmission, AbiTimerRegistration};
        let time = TimeManagement::new();
        let (count, waker) = count_waker();
        let registration = AbiTimerRegistration::register(|| {
            time.register_timer(TimerSchedule::After {
                interval_ms: 2,
                mode: TimerMode::Periodic,
            })
        });
        let mut receipt = AbiTimerAdmission::from_result(registration)
            .into_result()
            .unwrap();
        arm(&mut receipt, &waker);
        advance(&time, 2);
        assert_eq!(count.0.load(Ordering::Relaxed), 0);
        time.process_pending_wakers();
        assert_eq!(count.0.load(Ordering::Relaxed), 1);
        take_tick(&mut receipt, &waker);
        arm(&mut receipt, &waker);
        drop(receipt);
        advance(&time, 2);
        time.process_pending_wakers();
        assert_eq!(count.0.load(Ordering::Relaxed), 1);
        assert_eq!(time.stats().active_timers, 0);
    }

    #[test]
    fn imported_timer_keeps_terminal_clock_overflow_and_rejection_distinct() {
        use kernel_api::abi::driver::{AbiTimerAdmission, AbiTimerRegistration};
        let time = TimeManagement::new();
        time.ticks.store(u64::MAX - 1, Ordering::Release);
        let (_, waker) = count_waker();
        let mut receipt = AbiTimerAdmission::from_result(AbiTimerRegistration::register(|| {
            time.register_timer(TimerSchedule::After {
                interval_ms: 1,
                mode: TimerMode::Periodic,
            })
        }))
        .into_result()
        .unwrap();
        arm(&mut receipt, &waker);
        advance(&time, 1);
        time.process_pending_wakers();
        assert_eq!(
            Pin::new(&mut receipt).poll(&mut Context::from_waker(&waker)),
            Poll::Ready(Err(TimerError::ClockExhausted))
        );
        assert!(matches!(
            AbiTimerAdmission::from_result(Err(TimerError::MemoryExhausted)).into_result(),
            Err(TimerError::MemoryExhausted)
        ));
    }
}
