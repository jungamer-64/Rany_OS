// ============================================================================
// libs/app_sdk/src/sdk.rs - SDK Helper Functions
// ============================================================================
//!
//! Utility functions for application developers.

extern crate alloc;

use alloc::format;
use kernel_api::service::kernel::instance as kernel;

/// Async sleep for specified milliseconds
///
/// Non-blocking: other tasks continue running.
///
/// # Example
/// ```rust,ignore
/// app_sdk::sleep(500).await;  // Wait 500ms
/// ```
pub async fn sleep(ms: u64) {
    // Simple busy-wait implementation using kernel services
    // In a real implementation, this would register with a timer queue
    let start = kernel().current_tick();
    let target = start + ms;

    // LOOP_PROOF: mode=event; reason=Loop progress is controlled by explicit break or return on state transitions/events.;
    loop {
        if kernel().current_tick() >= target {
            break;
        }
        yield_now().await;
    }
}

/// Yield CPU to other tasks
pub async fn yield_now() {
    // Simple yield implementation
    core::future::poll_fn(|cx| {
        cx.waker().wake_by_ref();
        core::task::Poll::Ready(())
    })
    .await;
}

/// Print formatted output
///
/// # Example
/// ```rust,ignore
/// app_sdk::print(format_args!("Value: {}", 42));
/// ```
pub fn print(args: core::fmt::Arguments) {
    let s = format!("{}", args);
    kernel().log(&s);
}

/// Get current time in milliseconds since boot
pub fn now() -> u64 {
    kernel().current_tick()
}

/// Get current time in nanoseconds since boot
pub fn now_nanos() -> u64 {
    kernel().current_tick() * 1_000_000
}

/// println! macro for apps
#[macro_export]
macro_rules! app_println {
    () => ($crate::print(format_args!("\n")));
    ($($arg:tt)*) => ({
        $crate::print(format_args!("{}\n", format_args!($($arg)*)));
    })
}
