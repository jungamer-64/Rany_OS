use super::*;


pub(crate) const SECURITY_MONITOR_INTERVAL_MS: u64 = 100;
pub(crate) const SECURITY_MONITOR_BATCH: usize = 128;

/// GC (Garbage Collection) interval for zombie DMA handles
pub(crate) const ZOMBIE_GC_INTERVAL_MS: u64 = 5000; // 5 seconds

/// Interval for flushing aggregated events (milliseconds)
pub(crate) const EVENT_AGGREGATE_FLUSH_MS: u64 = 1000; // 1 second

/// Drain IOMMU security events and forward them to the audit pipeline.
///
/// This task also performs periodic housekeeping:
/// 1. Processes pending emergency device isolations (IOTLB flush)
/// 2. Garbage collects zombie DMA handles (idle/memory pressure)
/// 3. Aggregates and summarizes repeated security events
pub async fn security_monitor_task() {
    let monitor = default_security_monitor();
    let mut gc_counter: u64 = 0;
    let mut aggregate_counter: u64 = 0;
    let mut aggregator = EventAggregator::new();

    loop {
        // 1. Drain security events with aggregation
        let _ = monitor.drain_events(SECURITY_MONITOR_BATCH, |event| {
            // Log immediately for first occurrence, aggregate duplicates
            let is_first = aggregator.record(event);
            if is_first {
                crate::security::audit::log_event(security_event_to_audit(event));
            }
        });

        let dropped = monitor.take_dropped_events();
        if dropped > 0 {
            crate::security::audit::log_event(
                AuditEvent::new(AuditEventType::IommuEvent, 0)
                    .success(false)
                    .message("monitor_events_dropped")
                    .field("count", alloc::format!("{}", dropped)),
            );
        }

        // 1b. Periodically flush aggregated event summaries
        aggregate_counter += SECURITY_MONITOR_INTERVAL_MS;
        if aggregate_counter >= EVENT_AGGREGATE_FLUSH_MS {
            aggregate_counter = 0;
            aggregator.drain(|key, aggregate| {
                // Skip if only 1 occurrence (already logged)
                if aggregate.count <= 1 {
                    return;
                }
                // Log summary for repeated events
                log_aggregated_event_summary(key, aggregate);
            });
        }

        // 2. Process pending emergency isolations (fault storm handling)
        let isolated_count = EMERGENCY_REGISTRY.process_pending_isolations();
        if isolated_count > 0 {
            log::info!(
                "[IOMMU][Security] Processed {} pending device isolations",
                isolated_count
            );
        }

        // 3. Periodic zombie DMA handle GC (every ZOMBIE_GC_INTERVAL_MS)
        gc_counter += SECURITY_MONITOR_INTERVAL_MS;
        if gc_counter >= ZOMBIE_GC_INTERVAL_MS {
            gc_counter = 0;
            run_zombie_dma_gc();
        }

        crate::task::sleep_ms(SECURITY_MONITOR_INTERVAL_MS).await;
    }
}

/// Run garbage collection for zombie DMA handles.
///
/// A "zombie" DMA handle is one that:
/// 1. Was created but never unmapped (leaked)
/// 2. Belongs to a domain that has exceeded its resource threshold
/// 3. Has been idle for too long (future enhancement)
///
/// This function processes entries from the zombie_queue and performs
/// the actual unmap operations asynchronously (from GC task context,
/// not from Drop which must be O(1) and lock-free).
pub(crate) fn run_zombie_dma_gc() {
    use crate::io::iommu::runtime::zombie;

    // Always process some zombies if there are any pending
    let pending = zombie_queue::has_pending_zombies();
    let memory_pressure = crate::mm::phys::unified_alloc::memory_pressure_level();

    // Determine how many to process based on pressure
    let max_process = if memory_pressure >= 80 {
        256  // High pressure: aggressive cleanup
    } else if memory_pressure >= 50 || pending {
        64   // Medium pressure or pending: moderate cleanup
    } else {
        0    // No pressure and no pending: skip
    };

    if max_process == 0 {
        return;
    }

    // Process zombies using the zombie_queue API
    let processed = zombie_queue::run_zombie_gc(max_process);

    if processed > 0 {
        let stats = zombie_queue::zombie_stats();
        log::debug!(
            "[IOMMU][GC] Processed {} zombies (total: enqueued={}, processed={}, dropped={})",
            processed,
            stats.total_enqueued,
            stats.total_processed,
            stats.total_dropped
        );
    }

    // Log emergency registry stats for debugging
    if memory_pressure >= 50 {
        let stats = EMERGENCY_REGISTRY.stats();
        log::debug!(
            "[IOMMU][GC] Memory pressure {} - emergency registry: total={} pending={} active={}",
            memory_pressure,
            stats.total_isolations,
            stats.pending_count,
            stats.active_count
        );
    }
}

/// Spawn the default IOMMU security monitor task (idempotent).
pub fn spawn_security_monitor_task() {
    SECURITY_MONITOR_TASK.call_once(|| {
        crate::task::per_core_executor::spawn(security_monitor_task());
    });
}

// ============================================================================
// Fault Storm Protection (Per-Device Rate Limiting)
// ============================================================================

/// Maximum number of devices to track for fault rate limiting.
/// Using a fixed-size array to avoid allocation in ISR context.
pub(crate) const MAX_TRACKED_DEVICES: usize = 64;

/// Fault threshold: number of faults within the time window before isolation.
pub(crate) const FAULT_STORM_THRESHOLD: u32 = 10;

/// Time window for fault rate calculation in milliseconds.
pub(crate) const FAULT_STORM_WINDOW_MS: u32 = 1000;

/// Per-device fault tracking entry.
///
/// Uses atomic operations for ISR-safe updates.
pub(crate) struct DeviceFaultEntry {
    /// Device source ID (0 = unused slot)
    source_id: AtomicU32,
    /// Fault count in current window
    fault_count: AtomicU32,
    /// Window start timestamp (TSC or milliseconds)
    window_start: AtomicU64,
    /// Whether the device has been flagged for isolation
    isolated: AtomicU32,
}

impl DeviceFaultEntry {
    pub(super) const fn new() -> Self {
        Self {
            source_id: AtomicU32::new(0),
            fault_count: AtomicU32::new(0),
            window_start: AtomicU64::new(0),
            isolated: AtomicU32::new(0),
        }
    }

    pub(super) fn is_unused(&self) -> bool {
        self.source_id.load(Ordering::Relaxed) == 0
    }

    pub(super) fn matches(&self, source_id: u16) -> bool {
        self.source_id.load(Ordering::Relaxed) == source_id as u32
    }

    pub(super) fn is_isolated(&self) -> bool {
        self.isolated.load(Ordering::Relaxed) != 0
    }

    pub(super) fn mark_isolated(&self) {
        self.isolated.store(1, Ordering::Relaxed);
    }

    /// Record a fault and return (new_count, triggered_storm) tuple.
    pub(super) fn record_fault(&self, current_time_ms: u64) -> (u32, bool) {
        let window_start = self.window_start.load(Ordering::Relaxed);
        let elapsed = current_time_ms.saturating_sub(window_start);

        if elapsed > FAULT_STORM_WINDOW_MS as u64 {
            // Window expired, reset counter
            self.window_start.store(current_time_ms, Ordering::Relaxed);
            self.fault_count.store(1, Ordering::Relaxed);
            (1, false)
        } else {
            // Within window, increment counter
            let new_count = self.fault_count.fetch_add(1, Ordering::Relaxed) + 1;
            let triggered = new_count >= FAULT_STORM_THRESHOLD && !self.is_isolated();
            (new_count, triggered)
        }
    }

    /// Try to claim this slot for a new device.
    pub(super) fn try_claim(&self, source_id: u16, current_time_ms: u64) -> bool {
        if self
            .source_id
            .compare_exchange(0, source_id as u32, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            self.window_start.store(current_time_ms, Ordering::Relaxed);
            self.fault_count.store(0, Ordering::Relaxed);
            self.isolated.store(0, Ordering::Relaxed);
            true
        } else {
            false
        }
    }
}

/// Global fault rate limiter for detecting fault storms.
///
/// Tracks per-device fault rates and triggers isolation when thresholds are exceeded.
pub struct FaultRateLimiter {
    entries: [DeviceFaultEntry; MAX_TRACKED_DEVICES],
}

impl FaultRateLimiter {
    /// Create a new fault rate limiter.
    pub const fn new() -> Self {
        // SAFETY: DeviceFaultEntry::new() is const, so this is safe
        const INIT: DeviceFaultEntry = DeviceFaultEntry::new();
        Self {
            entries: [INIT; MAX_TRACKED_DEVICES],
        }
    }

    /// Record a fault for a device and check for fault storm.
    ///
    /// Returns `Some(IsolationReason::FaultStorm)` if the device should be isolated.
    /// Returns `None` if the fault is within acceptable limits.
    ///
    /// # ISR Safety
    /// This method is ISR-safe (lock-free, bounded time).
    pub fn record_fault(&self, source_id: u16, current_time_ms: u64) -> Option<IsolationReason> {
        // First, try to find existing entry for this device
        for entry in &self.entries {
            if entry.matches(source_id) {
                if entry.is_isolated() {
                    // Already isolated, no need to re-trigger
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

        // Device not found, try to allocate a new slot
        for entry in &self.entries {
            if entry.is_unused() && entry.try_claim(source_id, current_time_ms) {
                // New device, first fault - no storm yet
                entry.record_fault(current_time_ms);
                return None;
            }
        }

        // No slots available - log and continue without tracking
        // This is a resource limitation, not a security event
        log::debug!(
            "[IOMMU][Security] Fault rate limiter full, cannot track device 0x{:x}",
            source_id
        );
        None
    }

    /// Check if a device is currently marked as isolated due to fault storm.
    pub fn is_isolated(&self, source_id: u16) -> bool {
        self.entries
            .iter()
            .any(|e| e.matches(source_id) && e.is_isolated())
    }

    /// Clear isolation status for a device (for recovery/debugging).
    pub fn clear_isolation(&self, source_id: u16) {
        for entry in &self.entries {
            if entry.matches(source_id) {
                entry.isolated.store(0, Ordering::Relaxed);
                entry.fault_count.store(0, Ordering::Relaxed);
                entry
                    .window_start
                    .store(current_time_ms_approx(), Ordering::Relaxed);
                return;
            }
        }
    }

    /// Get fault statistics for a device.
    pub fn get_device_stats(&self, source_id: u16) -> Option<(u32, bool)> {
        for entry in &self.entries {
            if entry.matches(source_id) {
                return Some((
                    entry.fault_count.load(Ordering::Relaxed),
                    entry.is_isolated(),
                ));
            }
        }
        None
    }
}

// Global fault rate limiter instance
pub(crate) static FAULT_RATE_LIMITER: FaultRateLimiter = FaultRateLimiter::new();

/// Get the global fault rate limiter.
pub fn fault_rate_limiter() -> &'static FaultRateLimiter {
    &FAULT_RATE_LIMITER
}

/// Approximate current time in milliseconds (for ISR context).
///
/// Uses the system clock's uptime value (based on TSC or PIT).
pub(crate) fn current_time_ms_approx() -> u64 {
    // Use system clock's uptime in milliseconds
    crate::time::get_uptime_ms()
}

// ============================================================================
// Emergency Device Isolation (Lock-Free Fast Path)
// ============================================================================

use core::sync::atomic::AtomicU8;

/// Maximum number of devices that can be emergency-isolated simultaneously.
pub(crate) const MAX_EMERGENCY_ISOLATED: usize = 32;

/// Emergency isolation slot for a device.
///
/// Stores the source ID and isolation status atomically.
/// - `status == 0`: Slot is unused
/// - `status == 1`: Device is pending isolation (awaiting IOTLB flush)
/// - `status == 2`: Device is fully isolated (IOTLB flushed)
pub(crate) struct EmergencyIsolationSlot {
    /// Device source ID (BDF), stored as u32 for atomic access
    source_id: AtomicU32,
    /// Isolation status: 0=unused, 1=pending, 2=isolated
    status: AtomicU8,
    /// Timestamp when isolation was triggered (TSC)
    isolation_tsc: AtomicU64,
}

impl EmergencyIsolationSlot {
    pub(super) const fn new() -> Self {
        Self {
            source_id: AtomicU32::new(0),
            status: AtomicU8::new(0),
            isolation_tsc: AtomicU64::new(0),
        }
    }

    /// Check if slot is unused
    pub(super) fn is_unused(&self) -> bool {
        self.status.load(Ordering::Acquire) == 0
    }

    /// Try to claim this slot for emergency isolation.
    ///
    /// Returns `true` if successfully claimed, `false` if slot was already taken.
    pub(super) fn try_claim(&self, source_id: u16) -> bool {
        if self
            .status
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            self.source_id.store(source_id as u32, Ordering::Release);
            self.isolation_tsc
                .store(current_time_ms_approx(), Ordering::Release);
            true
        } else {
            false
        }
    }

    /// Mark device as fully isolated (IOTLB flush completed).
    pub(super) fn mark_fully_isolated(&self) {
        self.status.store(2, Ordering::Release);
    }

    /// Check if device matches this slot
    pub(super) fn matches(&self, source_id: u16) -> bool {
        self.source_id.load(Ordering::Acquire) == source_id as u32
            && self.status.load(Ordering::Acquire) != 0
    }

    /// Get current status
    pub(super) fn status(&self) -> u8 {
        self.status.load(Ordering::Acquire)
    }

    /// Clear slot (for recovery/reset)
    pub(super) fn clear(&self) {
        self.status.store(0, Ordering::Release);
        self.source_id.store(0, Ordering::Release);
        self.isolation_tsc.store(0, Ordering::Release);
    }
}

/// Global emergency isolation registry.
///
/// This lock-free structure allows ISR-context code to mark devices for
/// immediate isolation without acquiring any locks.
///
/// # How It Works
///
/// 1. **ISR detects fault storm** → calls `emergency_isolate_device()`
/// 2. **This function atomically claims a slot** and marks device as "pending"
/// 3. **ISR returns immediately** (no lock acquisition)
/// 4. **Background task** scans pending slots, performs IOTLB flush, marks "isolated"
///
/// # Memory Safety
///
/// - All operations are atomic with appropriate memory ordering
/// - Slots are never freed during runtime (static lifetime)
/// - Double-isolation is safely ignored (idempotent)
pub struct EmergencyIsolationRegistry {
    slots: [EmergencyIsolationSlot; MAX_EMERGENCY_ISOLATED],
    /// Total isolations triggered (statistics)
    total_isolations: AtomicU64,
    /// Current pending count (for monitoring)
    pending_count: AtomicU32,
}

impl EmergencyIsolationRegistry {
    /// Create a new empty registry.
    pub const fn new() -> Self {
        const INIT: EmergencyIsolationSlot = EmergencyIsolationSlot::new();
        Self {
            slots: [INIT; MAX_EMERGENCY_ISOLATED],
            total_isolations: AtomicU64::new(0),
            pending_count: AtomicU32::new(0),
        }
    }

    /// Request emergency isolation for a device.
    ///
    /// This is the **ISR-safe fast path**. It atomically marks the device for
    /// isolation without acquiring any locks. The actual IOMMU page table
    /// invalidation is performed by `process_pending_isolations()`.
    ///
    /// # ISR Safety
    ///
    /// - Lock-free: Uses only atomic operations
    /// - Bounded time: O(MAX_EMERGENCY_ISOLATED) scan
    /// - No allocation: Uses pre-allocated slots
    ///
    /// # Returns
    ///
    /// - `Ok(true)`: Device was newly marked for isolation
    /// - `Ok(false)`: Device was already marked (idempotent)
    /// - `Err(())`: No slots available (registry full)
    pub fn request_isolation(&self, source_id: u16) -> Result<bool, ()> {
        // Check if already isolated
        for slot in &self.slots {
            if slot.matches(source_id) {
                return Ok(false); // Already in registry
            }
        }

        // Find an unused slot
        for slot in &self.slots {
            if slot.try_claim(source_id) {
                self.total_isolations.fetch_add(1, Ordering::Relaxed);
                self.pending_count.fetch_add(1, Ordering::Relaxed);

                log::warn!(
                    "[IOMMU][Emergency] Device 0x{:x} marked for isolation (pending IOTLB flush)",
                    source_id
                );

                return Ok(true);
            }
        }

        // Registry full - this is a critical situation
        log::error!(
            "[IOMMU][Emergency] Cannot isolate device 0x{:x}: registry full ({} devices)",
            source_id,
            MAX_EMERGENCY_ISOLATED
        );
        Err(())
    }

    /// Check if a device is in emergency isolation (pending or complete).
    ///
    /// # ISR Safety
    ///
    /// Lock-free, O(n) scan.
    pub fn is_isolated(&self, source_id: u16) -> bool {
        self.slots.iter().any(|slot| slot.matches(source_id))
    }

    /// Check if a device has pending isolation (needs IOTLB flush).
    pub fn is_pending(&self, source_id: u16) -> bool {
        self.slots
            .iter()
            .any(|slot| slot.matches(source_id) && slot.status() == 1)
    }

    /// Process pending isolations (called from non-ISR context).
    ///
    /// This function scans for devices marked as "pending" and performs
    /// the actual IOMMU invalidation. It should be called periodically
    /// by the security monitor task.
    ///
    /// # Returns
    ///
    /// Number of devices that were fully isolated in this call.
    pub fn process_pending_isolations(&self) -> usize {
        let mut processed = 0;

        for slot in &self.slots {
            if slot.status() == 1 {
                let source_id = slot.source_id.load(Ordering::Acquire) as u16;

                // Perform IOTLB flush for this device
                if let Err(e) = invalidate_device_iotlb(source_id) {
                    log::error!(
                        "[IOMMU][Emergency] IOTLB flush failed for device 0x{:x}: {:?}",
                        source_id,
                        e
                    );
                    // Still mark as isolated to prevent further DMA
                }

                slot.mark_fully_isolated();
                self.pending_count.fetch_sub(1, Ordering::Relaxed);
                processed += 1;

                log::info!(
                    "[IOMMU][Emergency] Device 0x{:x} fully isolated (IOTLB flushed)",
                    source_id
                );
            }
        }

        processed
    }

    /// Clear isolation for a device (for recovery).
    ///
    /// # Warning
    ///
    /// Only call this after ensuring the device is safe to re-enable.
    pub fn clear_isolation(&self, source_id: u16) {
        for slot in &self.slots {
            if slot.matches(source_id) {
                if slot.status() == 1 {
                    self.pending_count.fetch_sub(1, Ordering::Relaxed);
                }
                slot.clear();
                log::info!(
                    "[IOMMU][Emergency] Isolation cleared for device 0x{:x}",
                    source_id
                );
                return;
            }
        }
    }

    /// Get statistics about emergency isolations.
    pub fn stats(&self) -> EmergencyIsolationStats {
        EmergencyIsolationStats {
            total_isolations: self.total_isolations.load(Ordering::Relaxed),
            pending_count: self.pending_count.load(Ordering::Relaxed),
            active_count: self
                .slots
                .iter()
                .filter(|s| s.status() != 0)
                .count() as u32,
        }
    }
}

/// Statistics for emergency isolation.
#[derive(Debug, Clone, Copy)]
pub struct EmergencyIsolationStats {
    /// Total number of emergency isolations triggered since boot
    pub total_isolations: u64,
    /// Number of devices pending IOTLB flush
    pub pending_count: u32,
    /// Number of currently isolated devices
    pub active_count: u32,
}

// Global emergency isolation registry
pub(crate) static EMERGENCY_REGISTRY: EmergencyIsolationRegistry = EmergencyIsolationRegistry::new();

/// Get the global emergency isolation registry.
///
/// Use this for ISR-context emergency device isolation.
pub fn emergency_isolation_registry() -> &'static EmergencyIsolationRegistry {
    &EMERGENCY_REGISTRY
}

/// Request emergency isolation for a device (convenience function).
///
/// This is the primary entry point for ISR-context isolation.
/// Call this when a fault storm is detected.
///
/// # ISR Safety
///
/// This function is fully ISR-safe (lock-free, bounded time, no allocation).
pub fn emergency_isolate_device(source_id: u16) -> Result<bool, ()> {
    EMERGENCY_REGISTRY.request_isolation(source_id)
}

/// Check if a device is in emergency isolation.
pub fn is_device_emergency_isolated(source_id: u16) -> bool {
    EMERGENCY_REGISTRY.is_isolated(source_id)
}

/// Invalidate IOTLB entries for a device.
///
/// This performs device-selective IOTLB invalidation to ensure
/// the device cannot use any cached translations.
pub(crate) fn invalidate_device_iotlb(source_id: u16) -> Result<(), IommuError> {
    use crate::io::iommu::flush;

    // Use device-selective invalidation for maximum isolation
    flush::invalidate_iotlb_device(source_id)?;

    // Also invalidate context cache for the device
    flush::invalidate_context_device(source_id)?;

    // Memory barrier to ensure invalidation is visible
    core::sync::atomic::fence(Ordering::SeqCst);

    Ok(())
}

use crate::io::iommu::types::IommuError;

// ============================================================================
// Identity Mapping & Global Controls
// ============================================================================

use core::sync::atomic::AtomicBool;

/// Identity mapping fallback gate (default: false).
///
/// # Security Warning
///
/// **CRITICAL**: Enabling identity mapping completely bypasses IOMMU protection
/// and exposes the system to DMA attacks. A malicious or buggy device can:
///
/// - Read/write arbitrary physical memory (including kernel code and secrets)
/// - Escalate privileges by modifying kernel data structures
/// - Exfiltrate cryptographic keys and other sensitive data
/// - Bypass all isolation guarantees provided by the IOMMU
///
/// This flag is available **only** when:
/// - `feature = "unsafe_iommu_bypass"` is enabled, OR
/// - `debug_assertions` are enabled (debug builds)
///
/// In release builds without `unsafe_iommu_bypass`, this flag does not exist
/// and identity mapping is unconditionally prohibited.
///
/// ## RMRR (Reserved Memory Region Reporting) Exception
///
/// The **only** legitimate use of identity mapping in production is for RMRR
/// regions declared by system firmware (ACPI DMAR table). These regions are:
///
/// - Legacy USB controllers that require specific physical addresses
/// - BIOS/UEFI video buffers that firmware expects at fixed locations
/// - Other firmware-reserved regions that cannot be relocated
///
/// RMRR mappings are handled automatically by the IOMMU driver during
/// initialization and do NOT require enabling this global flag.
///
/// ## Acceptable Use Cases (Non-Production Only)
/// - Very early boot (before IOMMU initialization completes)
/// - Hardware debugging on trusted systems with no external devices
/// - IOMMU hardware bring-up on new platforms
///
/// ## Never Use When
/// - Untrusted PCIe devices are present
/// - System processes sensitive data
/// - Production deployments
#[cfg(any(feature = "unsafe_iommu_bypass", debug_assertions))]
pub(crate) static UNSAFE_ALLOW_IDENTITY_MAPPING: AtomicBool = AtomicBool::new(false);

/// Global DMA mapping gate (device-scoped mappings remain allowed).
pub(crate) static ALLOW_GLOBAL_MAPPINGS: AtomicBool = AtomicBool::new(cfg!(debug_assertions));

/// Enable/disable identity mapping fallback.
///
/// # Safety
///
/// **DANGEROUS**: This function weakens or completely removes IOMMU protection.
///
/// The caller must guarantee:
/// - This is called during a trusted early initialization phase
/// - No untrusted PCIe/Thunderbolt devices are present
/// - The system is in a controlled debugging environment
/// - Identity mapping will be disabled before untrusted code runs
///
/// Enabling identity mapping in production environments is a **critical security vulnerability**.
/// See [`UNSAFE_ALLOW_IDENTITY_MAPPING`] for detailed security implications.
///
/// # Platform Behavior
/// - Debug builds: Sets the flag (with warning log)
/// - Release builds with `unsafe_iommu_bypass`: Sets the flag (with warning log)
/// - **Release builds without `unsafe_iommu_bypass`: Function does not exist (linker error if called)**
///
/// # Compile-Time Enforcement
///
/// In production release builds, this function is **not compiled at all**.
/// Any attempt to call it will result in a linker error, preventing accidental usage.
#[cfg(any(feature = "unsafe_iommu_bypass", debug_assertions))]
pub unsafe fn set_unsafe_identity_mapping_allowed(allowed: bool) {
    if allowed {
        log::error!(
            "[IOMMU][SECURITY][CRITICAL] Identity mapping ENABLED - \
             system is VULNERABLE to DMA attacks! \
             This should NEVER be enabled in production!"
        );
        log::error!("[IOMMU][SECURITY][TAINTED] TAINTED: IOMMU BYPASS ENABLED");
        // Additional compile-time warning
        #[cfg(all(not(debug_assertions), feature = "unsafe_iommu_bypass"))]
        log::error!(
            "[IOMMU][SECURITY] You are using unsafe_iommu_bypass in a release build. \
             This feature should only be used for hardware bring-up and debugging."
        );
    } else {
        log::info!("[IOMMU][SECURITY] Identity mapping DISABLED - DMA protection restored");
    }
    UNSAFE_ALLOW_IDENTITY_MAPPING.store(allowed, Ordering::Release);
}

// NOTE: In release builds without `unsafe_iommu_bypass`, this function is intentionally
// **not defined**. This ensures that any code attempting to use identity mapping
// will fail to compile/link in production builds.
//
// If you see a linker error about `set_unsafe_identity_mapping_allowed` not found,
// it means you are trying to use identity mapping in a release build without
// explicitly enabling the `unsafe_iommu_bypass` feature. This is by design.

/// Check whether identity mapping fallback is allowed.
///
/// In release builds without `unsafe_iommu_bypass`, this always returns `false`
/// and is marked `#[inline(always)]` to allow dead code elimination.
#[cfg(any(feature = "unsafe_iommu_bypass", debug_assertions))]
pub fn is_unsafe_identity_mapping_allowed() -> bool {
    UNSAFE_ALLOW_IDENTITY_MAPPING.load(Ordering::Acquire)
}

/// Check whether identity mapping fallback is allowed.
///
/// In production release builds, this always returns `false` and is optimized
/// away by the compiler, allowing all identity mapping code paths to be
/// eliminated as dead code.
#[cfg(not(any(feature = "unsafe_iommu_bypass", debug_assertions)))]
#[inline(always)]
pub fn is_unsafe_identity_mapping_allowed() -> bool {
    false // Compile-time constant, enables dead code elimination
}

/// Enable/disable global DMA mappings (non device-scoped).
pub fn set_global_dma_mapping_allowed(allowed: bool) {
    ALLOW_GLOBAL_MAPPINGS.store(allowed, Ordering::Release);
}

/// Check whether global DMA mappings are allowed.
pub fn is_global_dma_mapping_allowed() -> bool {
    ALLOW_GLOBAL_MAPPINGS.load(Ordering::Acquire)
}

// ============================================================================
// Security Notifier Registration
// ============================================================================

// use alloc::sync::Arc; // Already imported at top
use spin::RwLock;

pub(crate) static SECURITY_NOTIFIER: RwLock<Option<Arc<dyn SecurityNotifier>>> = RwLock::new(None);

/// Register a custom security event notifier.
///
/// This allows higher-level subsystems (like the Exoshell or Userspace Monitor)
/// to receive and log IOMMU security events.
///
/// Returns:
/// - `Ok(true)` if registered successfully
/// - `Ok(false)` if a notifier was already registered (no-op)
/// - `Err` if registration failed (not used currently, but reserved)
pub fn set_security_notifier(notifier: Arc<dyn SecurityNotifier>) -> Result<bool, IommuError> {
    let mut lock = SECURITY_NOTIFIER.write();
    if lock.is_some() {
        return Ok(false);
    }
    *lock = Some(notifier);
    Ok(true)
}

/// Clear the global security notifier for qemu-test-export deterministic runs.
#[cfg(feature = "qemu-test-export")]
pub fn qemu_test_clear_security_notifier() {
    let mut lock = SECURITY_NOTIFIER.write();
    *lock = None;
}

/// Notify the registered security listener (if any)
pub(crate) fn notify_security_listener(event: SecurityEvent) {
    if let Some(notifier) = SECURITY_NOTIFIER.read().as_ref() {
        notifier.notify(event);
    }
}

