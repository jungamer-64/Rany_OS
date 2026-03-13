use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

use kernel_api::service::time::TimeService;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingTimerWakerStats {
    pub pending: usize,
    pub capacity: usize,
}

/// The concrete time cell implementation linked into the kernel.
#[inline]
pub(crate) fn concrete_service() -> &'static dyn TimeService {
    time_driver::time_service()
}

#[inline]
pub fn register_builtin_service() {
    crate::provider_registry::provider_registry().register_builtin_time(concrete_service());
}

/// Preferred time access path for kernel code.
///
/// Once the kernel service table is installed, this resolves through
/// `kernel_api`. During early boot or unit tests it falls back to the
/// statically linked time driver instance.
#[inline]
pub fn service() -> &'static dyn TimeService {
    kernel_api::service::time::try_instance().unwrap_or_else(concrete_service)
}

#[inline]
pub fn handle_timer_interrupt() {
    // ISR/hot paths must not consult the provider registry because that path
    // is lock-based and can deadlock if an interrupt lands while the same CPU
    // is already resolving the active provider.
    concrete_service().on_timer_interrupt();
}

#[inline]
pub fn process_pending_timer_wakers() {
    concrete_service().process_pending_wakers();
}

#[inline]
pub fn pending_timer_waker_count() -> usize {
    concrete_service().stats().pending_wakers
}

#[inline]
pub fn pending_waker_stats() -> PendingTimerWakerStats {
    PendingTimerWakerStats {
        pending: service().stats().pending_wakers,
        capacity: 0,
    }
}

#[inline]
pub fn current_tick() -> u64 {
    concrete_service().current_tick_ms()
}

#[inline]
pub fn unix_timestamp() -> u64 {
    concrete_service().unix_timestamp()
}

#[inline]
pub fn unix_timestamp_ms() -> u64 {
    concrete_service().unix_timestamp_ms()
}

#[inline]
pub fn adjust_wall_clock(delta_ns: i64) {
    concrete_service().adjust_wall_clock(delta_ns);
}

#[inline]
pub fn set_unix_timestamp(unix_secs: u64) {
    set_unix_timestamp_ms(unix_secs.saturating_mul(1000));
}

pub fn set_unix_timestamp_ms(target_ms: u64) {
    let current_ms = unix_timestamp_ms();
    let delta_ms = target_ms as i128 - current_ms as i128;
    let delta_ns = delta_ms.saturating_mul(crate::time::NANOS_PER_MILLI as i128);
    adjust_wall_clock(delta_ns.clamp(i64::MIN as i128, i64::MAX as i128) as i64);
}

#[inline]
pub async fn sleep_ms(duration_ms: u64) {
    SleepFuture::new(duration_ms).await;
}

pub struct SleepFuture {
    wake_tick: u64,
    registered: bool,
}

impl SleepFuture {
    pub fn new(duration_ms: u64) -> Self {
        Self {
            wake_tick: concrete_service().compute_wake_tick(duration_ms),
            registered: false,
        }
    }
}

impl Future for SleepFuture {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let time_service = concrete_service();
        if time_service.current_tick_ms() >= self.wake_tick {
            return Poll::Ready(());
        }

        if !self.registered {
            time_service.register_sleep(self.wake_tick, cx.waker().clone());
            self.registered = true;
        }

        Poll::Pending
    }
}

impl Drop for SleepFuture {
    fn drop(&mut self) {
        if self.registered {
            concrete_service().unregister_sleep(self.wake_tick);
        }
    }
}
