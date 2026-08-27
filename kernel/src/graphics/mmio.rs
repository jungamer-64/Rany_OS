//! Benchmark diagnostics for framebuffer device writes.
#![forbid(unsafe_code)]

#[cfg(all(feature = "std", feature = "bench"))]
use std::sync::atomic::{AtomicUsize, Ordering};

// Bench debug printing throttle. When `RANY_DEBUG_DRAW=1` this limits the
// number of per-write debug messages that are emitted so benchmarks don't
// get overwhelmed by millions of lines and appear to run forever.
#[cfg(all(feature = "std", feature = "bench"))]
static BENCH_DEBUG_PRINTS_LEFT: AtomicUsize = AtomicUsize::new(0);

#[cfg(all(feature = "std", feature = "bench"))]
/// Returns true when a debug print is allowed. This respects the
/// `RANY_DEBUG_DRAW` env var and an optional `RANY_DEBUG_DRAW_LIMIT` which
/// sets how many individual per-write messages are allowed (defaults to 128).
pub(crate) fn bench_debug_print_allowed() -> bool {
    if std::env::var("RANY_DEBUG_DRAW").ok().as_deref() != Some("1") {
        return false;
    }

    // Initialize the counter on first use.
    let cur = BENCH_DEBUG_PRINTS_LEFT.load(Ordering::Relaxed);
    if cur == 0 {
        let limit = std::env::var("RANY_DEBUG_DRAW_LIMIT")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(128usize);
        BENCH_DEBUG_PRINTS_LEFT.store(limit, Ordering::Relaxed);
    }

    // Decrement and check if we had quota remaining.
    // fetch_sub returns old value; if old > 0, we had quota.
    let old = BENCH_DEBUG_PRINTS_LEFT.fetch_sub(1, Ordering::AcqRel);
    if old > 0 {
        true
    } else {
        // Restore to 0 if we went negative (shouldn't happen, but be safe)
        BENCH_DEBUG_PRINTS_LEFT.store(0, Ordering::Relaxed);
        false
    }
}
