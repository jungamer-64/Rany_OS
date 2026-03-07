use kernel_api::service::time::TimeService;

/// The concrete time cell implementation linked into the kernel.
#[inline]
pub(crate) fn concrete_service() -> &'static dyn TimeService {
    time_driver::time_service()
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
    service().on_timer_interrupt();
}

#[inline]
pub fn process_pending_timer_wakers() {
    service().process_pending_wakers();
}

#[inline]
pub fn pending_timer_waker_count() -> usize {
    service().stats().pending_wakers
}

#[inline]
pub fn pending_waker_stats() -> (usize, usize) {
    let stats = service().stats();
    (stats.waker_enqueued, stats.waker_dropped)
}

#[inline]
pub fn current_tick() -> u64 {
    service().current_tick_ms()
}

#[inline]
pub async fn sleep_ms(duration_ms: u64) {
    if kernel_api::service::time::try_instance().is_some() {
        kernel_api::service::time::sleep_ms(duration_ms).await;
        return;
    }

    time_driver::sleep_ms(duration_ms).await;
}
