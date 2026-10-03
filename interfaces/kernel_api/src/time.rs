// ============================================================================
// kernel_api/src/time.rs - Time Service Interface for ExoRust OS
// ============================================================================
//!
//! # Time Service Interface
//!
//! Defines the `TimeService` trait representing the high-level time management
//! cell interface. The kernel framework provides low-level hardware primitives
//! (PIT, TSC, APIC timer), while the time management driver (Cell) implements
//! user-facing timer functionality through this trait.
//!
//! ## Framework vs Cell 分離
//!
//! - **Framework (kernel)**: PIT/TSC/APIC 制御、割り込みソース、Fuel
//! - **Cell (time_driver)**: スリープ管理、タイマー登録、NTP

extern crate alloc;

use alloc::sync::{Arc, Weak};
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicU8, Ordering};
use core::task::{Context, Poll};
use exorust_sync::WakerSlot;

/// Timer admission and clock failures remain observable by the waiting owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerError {
    InvalidOptions,
    InvalidAbiResponse,
    RuntimeAbiMismatch,
    ServiceUnavailable,
    MemoryExhausted,
    OrderExhausted,
    ZeroPeriodicInterval,
    ClockExhausted,
}

impl core::fmt::Display for TimerError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "timer failed: {self:?}")
    }
}

/// タイマーモード
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerMode {
    /// ワンショット: 1回だけ発火
    OneShot,
    /// 周期的: 指定間隔で繰り返し発火
    Periodic,
}

/// Absolute deadlines and relative periodic intervals have distinct semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerSchedule {
    At(u64),
    After { interval_ms: u64, mode: TimerMode },
}

/// The provider can publish ticks or report that its clock cannot represent the
/// next period. Timer cancellation belongs exclusively to the registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerOutcome {
    Tick,
    ClockExhausted,
}

const QUIET: u8 = 0;
const TICK: u8 = 1;
const CLOCK_EXHAUSTED: u8 = 2;
const CANCELLED: u8 = 3;

struct TimerEvent {
    state: AtomicU8,
    waker: WakerSlot,
}

/// Linear cancellation authority for one timer. Dropping it cancels only this
/// registration, even if other registrations share its deadline. A callback
/// already dequeued by another CPU may finish; it cannot revive the timer.
///
/// Polling consumes one coalesced tick and registers the current task's waker.
/// Periodic users poll again to wait for another tick. Clock exhaustion remains
/// terminal. Provider notifications never keep a cancelled task alive.
pub struct TimerRegistration {
    backend: TimerBackend,
}

enum TimerBackend {
    Local(Arc<TimerEvent>),
    Foreign(crate::abi::driver::AbiTimerRegistration),
}

/// Notification authority retained by a timer provider. This weak endpoint
/// cannot cancel a registration or keep its task/waker alive after cancellation.
#[derive(Clone)]
pub struct TimerSignal {
    event: Weak<TimerEvent>,
}

impl TimerRegistration {
    /// Providers create the receipt before publishing its notification endpoint.
    /// Failed admission drops the receipt and leaves no live registration.
    ///
    /// # Errors
    /// Allocation failure occurs before any provider publication.
    pub fn new() -> Result<(Self, TimerSignal), TimerError> {
        let event = Arc::try_new(TimerEvent {
            state: AtomicU8::new(QUIET),
            waker: WakerSlot::new(),
        })
        .map_err(|_| TimerError::MemoryExhausted)?;
        let signal = TimerSignal {
            event: Arc::downgrade(&event),
        };
        Ok((
            Self {
                backend: TimerBackend::Local(event),
            },
            signal,
        ))
    }

    /// The ABI importer has validated that this receipt owns a provider timer.
    /// Cancellation stays with the paired provider callback and allocation.
    pub(crate) fn from_abi(registration: crate::abi::driver::AbiTimerRegistration) -> Self {
        Self {
            backend: TimerBackend::Foreign(registration),
        }
    }
}

impl Future for TimerRegistration {
    type Output = Result<(), TimerError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let event = match &mut self.get_mut().backend {
            TimerBackend::Local(event) => event,
            TimerBackend::Foreign(registration) => return Pin::new(registration).poll(cx),
        };
        event.waker.register(cx.waker());
        // LOOP_PROOF: mode=event; reason=A CAS consumes a pending tick or observes a terminal outcome; quiet returns Pending and a racing notification wakes the current registration.;
        loop {
            match event.state.load(Ordering::Acquire) {
                QUIET => return Poll::Pending,
                TICK => {
                    if event
                        .state
                        .compare_exchange(TICK, QUIET, Ordering::AcqRel, Ordering::Acquire)
                        .is_err()
                    {
                        continue;
                    }
                    event.waker.clear();
                    return Poll::Ready(Ok(()));
                }
                CLOCK_EXHAUSTED => {
                    event.waker.clear();
                    return Poll::Ready(Err(TimerError::ClockExhausted));
                }
                _ => unreachable!("a live registration cannot be cancelled"),
            }
        }
    }
}

impl Drop for TimerRegistration {
    fn drop(&mut self) {
        if let TimerBackend::Local(event) = &self.backend {
            event.state.store(CANCELLED, Ordering::Release);
            event.waker.clear();
        }
        // A foreign backend invokes its provider's cancellation on field drop.
    }
}

impl TimerSignal {
    /// This is a storage-cleanup hint, not a quiescence or notification claim.
    /// A concurrent delivery may temporarily retain the event after cancellation.
    pub fn is_retained(&self) -> bool {
        self.event.strong_count() != 0
    }

    /// Call outside provider locks and interrupt context: waking runs arbitrary
    /// RawWaker code. Ticks coalesce, and a terminal outcome cannot be overwritten.
    pub fn notify(&self, outcome: TimerOutcome) -> bool {
        let Some(event) = self.event.upgrade() else {
            return false;
        };
        let next = match outcome {
            TimerOutcome::Tick => TICK,
            TimerOutcome::ClockExhausted => CLOCK_EXHAUSTED,
        };
        // LOOP_PROOF: mode=event; reason=Each CAS either publishes a notification or observes another completed publication or cancellation; terminal states reject later notifications.;
        loop {
            let current = event.state.load(Ordering::Acquire);
            if current >= CLOCK_EXHAUSTED {
                return false;
            }
            if event
                .state
                .compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                event.waker.wake();
                return true;
            }
        }
    }
}

/// タイマーサービス統計
#[derive(Debug, Clone, Copy, Default)]
pub struct TimerServiceStats {
    /// 現在登録されているタイマー数
    pub active_timers: usize,
    /// 処理済みタイマー発火回数
    pub total_fired: u64,
    /// Accepted coalesced notifications, whether or not a task had registered a waker.
    pub notifications: u64,
    /// Live deadlines due at the observed clock, still awaiting ordinary-context delivery.
    pub due_timers: usize,
}

/// 時間管理サービスのトレイト
///
/// time_driver (Cell) がこのトレイトを実装し、KernelServices経由で提供する。
/// Consumers receive timer admission and time queries. Interrupt clock updates,
/// deferred delivery and wall-clock correction belong to the concrete provider.
pub trait TimeService: Send + Sync {
    // ========================================================================
    // Sleep / Timer
    // ========================================================================

    /// Publish a timer only after acquiring its receipt and registry storage.
    /// The caller owns cancellation and every asynchronous outcome.
    ///
    /// # Errors
    /// Rejects unavailable service, exhausted storage/order, an unrepresentable
    /// deadline, or a zero periodic interval before publishing a registration.
    fn register_timer(&self, schedule: TimerSchedule) -> Result<TimerRegistration, TimerError>;

    // ========================================================================
    // Time Queries
    // ========================================================================

    /// 現在のティック数（ミリ秒単位、起動からの経過）
    fn current_tick_ms(&self) -> u64;

    /// 起動からの経過時間（ナノ秒）
    fn uptime_ns(&self) -> u64;

    /// Unix タイムスタンプ (秒)
    fn unix_timestamp(&self) -> u64;

    /// Unix タイムスタンプ (ミリ秒)
    fn unix_timestamp_ms(&self) -> u64;

    // ========================================================================
    // Statistics
    // ========================================================================

    /// タイマーサービス統計を取得
    fn stats(&self) -> TimerServiceStats;
}

enum SleepState {
    Waiting {
        service: &'static dyn TimeService,
        deadline: u64,
        registration: Option<TimerRegistration>,
    },
    Done(Result<(), TimerError>),
}

/// One sleep implementation for kernel and cell callers. The selected provider
/// stays fixed for this wait; cancellation never re-resolves an ambient service.
pub struct SleepFuture {
    state: SleepState,
}

impl SleepFuture {
    pub fn new(service: &'static dyn TimeService, duration_ms: u64) -> Self {
        match service.current_tick_ms().checked_add(duration_ms) {
            Some(deadline) => Self::until(service, deadline),
            None => Self {
                state: SleepState::Done(Err(TimerError::ClockExhausted)),
            },
        }
    }

    pub fn until(service: &'static dyn TimeService, deadline: u64) -> Self {
        Self {
            state: SleepState::Waiting {
                service,
                deadline,
                registration: None,
            },
        }
    }
}

impl Future for SleepFuture {
    type Output = Result<(), TimerError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let result = match &mut self.state {
            SleepState::Done(result) => return Poll::Ready(*result),
            SleepState::Waiting {
                service,
                deadline,
                registration,
            } => {
                if service.current_tick_ms() >= *deadline {
                    Ok(())
                } else {
                    if registration.is_none() {
                        match service.register_timer(TimerSchedule::At(*deadline)) {
                            Ok(receipt) => *registration = Some(receipt),
                            Err(cause) => {
                                self.state = SleepState::Done(Err(cause));
                                return Poll::Ready(Err(cause));
                            }
                        }
                    }
                    match registration.as_mut() {
                        Some(receipt) => match Pin::new(receipt).poll(cx) {
                            Poll::Ready(result) => result,
                            Poll::Pending => return Poll::Pending,
                        },
                        None => unreachable!("successful timer admission installs the receipt"),
                    }
                }
            }
        };
        self.state = SleepState::Done(result);
        Poll::Ready(result)
    }
}

pub fn sleep_ms(duration_ms: u64) -> SleepFuture {
    match try_instance() {
        Some(service) => SleepFuture::new(service, duration_ms),
        None => SleepFuture {
            state: SleepState::Done(Err(TimerError::ServiceUnavailable)),
        },
    }
}

/// Access the registered time service if the kernel installed one.
#[inline]
pub fn try_instance() -> Option<&'static dyn TimeService> {
    if !crate::service::kernel::is_installed() {
        return None;
    }

    crate::service::kernel::instance().time_service()
}

/// Access the registered time service.
///
/// # Panics
/// Panics when the kernel runtime has not installed a time service yet.
#[inline]
pub fn instance() -> &'static dyn TimeService {
    try_instance().expect("TimeService not installed")
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use alloc::task::Wake;
    use core::sync::atomic::AtomicUsize;
    use core::task::Waker;
    use std::sync::Barrier;

    struct CountWake(AtomicUsize);
    impl Wake for CountWake {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn notification_bursts_are_consumed_once_and_cancel_does_not_retain_the_task() {
        let (mut receipt, signal) = TimerRegistration::new().unwrap();
        let counter = Arc::new(CountWake(AtomicUsize::new(0)));
        let waker = Waker::from(Arc::clone(&counter));
        let mut context = Context::from_waker(&waker);
        assert_eq!(Pin::new(&mut receipt).poll(&mut context), Poll::Pending);
        for _ in 0..1_000 {
            assert!(signal.notify(TimerOutcome::Tick));
        }
        assert_eq!(
            Pin::new(&mut receipt).poll(&mut context),
            Poll::Ready(Ok(()))
        );
        assert_eq!(Pin::new(&mut receipt).poll(&mut context), Poll::Pending);
        let weak_task = Arc::downgrade(&counter);
        drop(waker);
        drop(counter);
        assert!(weak_task.upgrade().is_some());
        drop(receipt);
        assert!(!signal.notify(TimerOutcome::Tick));
        assert!(!signal.is_retained());
        assert!(weak_task.upgrade().is_none());
    }

    #[test]
    fn registration_racing_delivery_preserves_exactly_one_tick() {
        for _ in 0..64 {
            let (mut receipt, signal) = TimerRegistration::new().unwrap();
            let barrier = Barrier::new(2);
            let counter = Arc::new(CountWake(AtomicUsize::new(0)));
            let waker = Waker::from(counter);
            let first = std::thread::scope(|scope| {
                scope.spawn(|| {
                    barrier.wait();
                    signal.notify(TimerOutcome::Tick);
                });
                barrier.wait();
                Pin::new(&mut receipt).poll(&mut Context::from_waker(&waker))
            });
            let second = Pin::new(&mut receipt).poll(&mut Context::from_waker(&waker));
            let consumed = [first, second]
                .into_iter()
                .filter(|value| *value == Poll::Ready(Ok(())))
                .count();
            assert_eq!(consumed, 1);
        }
    }

    #[test]
    fn cancellation_racing_delivery_never_revives_the_receipt() {
        for _ in 0..64 {
            let (mut receipt, signal) = TimerRegistration::new().unwrap();
            let barrier = Barrier::new(2);
            let counter = Arc::new(CountWake(AtomicUsize::new(0)));
            let waker = Waker::from(Arc::clone(&counter));
            assert_eq!(
                Pin::new(&mut receipt).poll(&mut Context::from_waker(&waker)),
                Poll::Pending
            );
            std::thread::scope(|scope| {
                scope.spawn(|| {
                    barrier.wait();
                    signal.notify(TimerOutcome::Tick);
                });
                barrier.wait();
                drop(receipt);
            });
            assert!(!signal.is_retained());
            assert!(!signal.notify(TimerOutcome::Tick));
            assert!(counter.0.load(Ordering::Relaxed) <= 1);
        }
    }

    #[test]
    fn try_instance_is_none_before_kernel_install() {
        assert!(try_instance().is_none());
    }
}
