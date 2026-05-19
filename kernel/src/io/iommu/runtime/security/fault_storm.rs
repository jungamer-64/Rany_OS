// ============================================================================
// kernel/src/io/iommu/runtime/security/fault_storm.rs
// ============================================================================

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use super::IsolationReason;

/// Maximum number of devices to track for fault rate limiting.
const MAX_TRACKED_DEVICES: usize = 256;

/// Fault threshold: number of faults within the time window before isolation.
const FAULT_STORM_THRESHOLD: u32 = 20;

/// Time window for fault rate calculation in milliseconds.
const FAULT_STORM_WINDOW_MS: u32 = 1000;

/// Stale entry threshold: if no faults for this long, the entry can be reused.
const STALE_ENTRY_TIMEOUT_MS: u64 = 60_000; // 1 minute

/// Per-device fault tracking entry.
struct DeviceFaultEntry {
    source_id: AtomicU32,
    fault_count: AtomicU32,
    window_start: AtomicU64,
    last_fault_time: AtomicU64,
    isolated: AtomicU32,
}

impl DeviceFaultEntry {
    const fn new() -> Self {
        Self {
            source_id: AtomicU32::new(0),
            fault_count: AtomicU32::new(0),
            window_start: AtomicU64::new(0),
            last_fault_time: AtomicU64::new(0),
            isolated: AtomicU32::new(0),
        }
    }

    fn is_unused(&self) -> bool {
        self.source_id.load(Ordering::Relaxed) == 0
    }

    fn is_stale(&self, current_time_ms: u64) -> bool {
        if self.is_isolated() {
            return false;
        }
        let last = self.last_fault_time.load(Ordering::Relaxed);
        current_time_ms.saturating_sub(last) > STALE_ENTRY_TIMEOUT_MS
    }

    fn matches(&self, source_id: u16) -> bool {
        self.source_id.load(Ordering::Relaxed) == source_id as u32
    }

    fn is_isolated(&self) -> bool {
        self.isolated.load(Ordering::Relaxed) != 0
    }

    fn mark_isolated(&self) {
        self.isolated.store(1, Ordering::Relaxed);
    }

    fn record_fault(&self, current_time_ms: u64) -> (u32, bool) {
        self.last_fault_time
            .store(current_time_ms, Ordering::Relaxed);
        let window_start = self.window_start.load(Ordering::Relaxed);
        let elapsed = current_time_ms.saturating_sub(window_start);

        if elapsed > FAULT_STORM_WINDOW_MS as u64 {
            self.window_start.store(current_time_ms, Ordering::Relaxed);
            self.fault_count.store(1, Ordering::Relaxed);
            (1, false)
        } else {
            let new_count = self.fault_count.fetch_add(1, Ordering::Relaxed) + 1;
            let triggered = new_count >= FAULT_STORM_THRESHOLD && !self.is_isolated();
            (new_count, triggered)
        }
    }

    fn try_claim(&self, source_id: u16, current_time_ms: u64) -> bool {
        // Try to claim if unused or stale
        let current_sid = self.source_id.load(Ordering::Relaxed);
        if current_sid != 0 && !self.is_stale(current_time_ms) {
            return false;
        }

        if self
            .source_id
            .compare_exchange(
                current_sid,
                source_id as u32,
                Ordering::AcqRel,
                Ordering::Relaxed,
            )
            .is_ok()
        {
            self.window_start.store(current_time_ms, Ordering::Relaxed);
            self.last_fault_time
                .store(current_time_ms, Ordering::Relaxed);
            self.fault_count.store(0, Ordering::Relaxed);
            self.isolated.store(0, Ordering::Relaxed);
            true
        } else {
            false
        }
    }
}

/// Global fault rate limiter for detecting fault storms.
pub struct FaultRateLimiter {
    entries: [DeviceFaultEntry; MAX_TRACKED_DEVICES],
}

impl FaultRateLimiter {
    pub const fn new() -> Self {
        const INIT: DeviceFaultEntry = DeviceFaultEntry::new();
        Self {
            entries: [INIT; MAX_TRACKED_DEVICES],
        }
    }

    /// Record a fault for a device and check for fault storm.
    pub fn record_fault(&self, source_id: u16, current_time_ms: u64) -> Option<IsolationReason> {
        for entry in &self.entries {
            if entry.matches(source_id) {
                if entry.is_isolated() {
                    return None;
                }
                let (count, triggered) = entry.record_fault(current_time_ms);
                if triggered {
                    entry.mark_isolated();
                    log::warn!(
                        "[IOMMU][Security] Fault storm detected: device 0x{:x} had {} faults in {}ms",
                        source_id,
                        count,
                        FAULT_STORM_WINDOW_MS
                    );
                    return Some(IsolationReason::FaultStorm);
                }
                return None;
            }
        }

        for entry in &self.entries {
            if entry.is_unused() && entry.try_claim(source_id, current_time_ms) {
                entry.record_fault(current_time_ms);
                return None;
            }
        }

        log::debug!(
            "[IOMMU][Security] Fault rate limiter full, cannot track device 0x{:x}",
            source_id
        );
        None
    }
}

static FAULT_RATE_LIMITER: FaultRateLimiter = FaultRateLimiter::new();

/// Get the global fault rate limiter.
pub fn fault_rate_limiter() -> &'static FaultRateLimiter {
    &FAULT_RATE_LIMITER
}

/// Approximate current time in milliseconds (for ISR context).
pub(crate) fn current_time_ms_approx() -> u64 {
    crate::time::get_uptime_ms()
}
