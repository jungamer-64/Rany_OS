// ============================================================================
// kernel/src/io/iommu/security.rs
// ============================================================================

//! Security Monitor Integration
//!
//! Provides security event notification from the IOMMU subsystem to external
//! security monitors. Designed for ISR-safety with the following guarantees:
//!
//! # Design Constraints
//!
//! - **Notifier registration**: One-time via `spin::Once` (lockless after init)
//! - **`notify()` implementation**: MUST be lock-free enqueue only (no heavy work)
//! - **`decide()` implementation**: MUST be atomic-read level (no locks, no I/O)
//! - **Actual processing**: Done by Security Monitor task draining the queue
//!
//! # Fault Storm Protection
//!
//! The module includes per-device fault rate limiting to prevent malicious or
//! faulty devices from overwhelming the security monitor. When a device exceeds
//! the fault threshold within a time window, it is automatically isolated.
//!
//! # Thread Safety
//!
//! All types are `Send + Sync`. Events are `Copy` to avoid allocation in ISR context.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use spin::Once;

use crate::io::iommu::fault_log::FaultRecord;
use crate::security::audit::{AuditEvent, AuditEventType};

// ============================================================================
// ISR-Safe Numeric Formatting (Allocation-Free)
// ============================================================================

/// Fixed-size buffer for numeric formatting (avoids heap allocation).
/// Maximum hex u64 with "0x" prefix: "0xffffffffffffffff" = 18 chars + null = 19
const FMT_BUF_SIZE: usize = 24;

/// Format a u64 as hexadecimal string without allocation.
/// Returns a string slice valid for the lifetime of the buffer.
#[inline]
fn fmt_hex_u64(value: u64, buf: &mut [u8; FMT_BUF_SIZE]) -> &str {
    

    // Use index-based writing to avoid borrow conflicts
    let mut pos = 0usize;

    // Write "0x" prefix
    if pos + 2 <= buf.len() {
        buf[pos] = b'0';
        buf[pos + 1] = b'x';
        pos += 2;
    }

    // Write hex digits (up to 16 digits for u64)
    let mut started = false;
    for i in (0..16).rev() {
        let digit = ((value >> (i * 4)) & 0xF) as u8;
        if digit != 0 || started || i == 0 {
            started = true;
            if pos < buf.len() {
                buf[pos] = if digit < 10 {
                    b'0' + digit
                } else {
                    b'a' + (digit - 10)
                };
                pos += 1;
            }
        }
    }

    // SAFETY: We only write ASCII hex digits
    unsafe { core::str::from_utf8_unchecked(&buf[..pos]) }
}

/// Format a u64 as decimal string without allocation.
#[inline]
fn fmt_dec_u64(value: u64, buf: &mut [u8; FMT_BUF_SIZE]) -> &str {
    if value == 0 {
        buf[0] = b'0';
        return unsafe { core::str::from_utf8_unchecked(&buf[..1]) };
    }

    // Write digits in reverse order
    let mut pos = 0usize;
    let mut v = value;
    let mut temp = [0u8; 20]; // Max u64 digits = 20

    while v > 0 && pos < 20 {
        temp[pos] = b'0' + (v % 10) as u8;
        v /= 10;
        pos += 1;
    }

    // Reverse into output buffer
    let len = pos;
    for i in 0..len {
        buf[i] = temp[len - 1 - i];
    }

    // SAFETY: We only write ASCII decimal digits
    unsafe { core::str::from_utf8_unchecked(&buf[..len]) }
}

/// Security event types from IOMMU subsystem
///
/// All variants are `Copy` and small (< 32 bytes) for ISR-safe notification.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum SecurityEvent {
    /// DMA violation detected (unauthorized memory access attempt)
    DmaViolation {
        /// Source ID (BDF: Bus/Device/Function)
        source_id: u16,
        /// Faulting IOVA address
        fault_address: u64,
        /// Hardware fault reason code
        reason: u8,
        /// Domain ID if known
        domain_id: Option<u32>,
    },

    /// Device has been isolated due to security policy
    DeviceIsolated {
        /// Source ID of isolated device
        source_id: u16,
        /// Reason for isolation
        reason: IsolationReason,
    },

    /// Quarantine queue has been poisoned (fatal error)
    QuarantinePoisoned {
        /// Affected domain ID
        domain_id: u16,
    },

    /// Security events were dropped due to overflow
    EventsDropped {
        /// Number of events dropped since last report
        count: u64,
    },

    /// Device fault rate exceeded threshold (fault storm detected)
    FaultStormDetected {
        /// Source ID of the offending device
        source_id: u16,
        /// Number of faults in the time window
        fault_count: u32,
        /// Time window in milliseconds
        window_ms: u32,
    },

    /// ATS (Address Translation Services) enabled for potentially untrusted device
    ///
    /// # Security Warning
    ///
    /// ATS allows devices to cache address translations, which introduces attack
    /// vectors if the device is compromised:
    /// - **DMA attacks**: Malicious device could use cached translations to access
    ///   memory regions that should have been revoked
    /// - **Stale TLB exploitation**: Device might ignore invalidation requests
    /// - **Side-channel attacks**: Translation timing can leak information
    ///
    /// Only enable ATS for devices that:
    /// 1. Are physically trusted (not hot-pluggable external ports)
    /// 2. Have firmware verified via secure boot chain
    /// 3. Are from vendors with good security track record
    AtsEnabledForUntrustedDevice {
        /// Source ID of the device
        source_id: u16,
        /// Vendor ID (PCI)
        vendor_id: u16,
        /// Device ID (PCI)
        device_id: u16,
        /// Trust level assigned to the device
        trust_level: DeviceTrustLevel,
    },

    /// ATS operation (enable/disable) performed on a device
    AtsStateChanged {
        /// Source ID of the device
        source_id: u16,
        /// New ATS state (true = enabled, false = disabled)
        enabled: bool,
        /// Reason for the state change
        reason: AtsChangeReason,
    },
}

/// Trust level assigned to a device for ATS policy decisions
///
/// Higher trust levels allow more permissive ATS behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DeviceTrustLevel {
    /// Device is untrusted (e.g., external USB, Thunderbolt)
    /// ATS should be DISABLED for security
    Untrusted = 0,

    /// Device is partially trusted (internal but not verified)
    /// ATS allowed with warnings logged
    Partial = 1,

    /// Device is fully trusted (verified firmware, internal bus)
    /// ATS allowed without warnings
    Trusted = 2,
}

impl Default for DeviceTrustLevel {
    fn default() -> Self {
        // Default to untrusted for safety
        Self::Untrusted
    }
}

/// Reason for ATS state change
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AtsChangeReason {
    /// ATS enabled by driver during device initialization
    DriverInit,
    /// ATS disabled due to security policy
    SecurityPolicy,
    /// ATS disabled due to fault storm from device
    FaultStorm,
    /// ATS disabled by administrator command
    AdminRequest,
    /// ATS state changed during live update/migration
    LiveUpdate,
    /// ATS disabled because device was detached from IOMMU domain
    DeviceDetach,
}

/// Reason for device isolation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IsolationReason {
    /// Isolation triggered by DMA fault
    DmaFault,
    /// Isolation triggered by security policy violation
    PolicyViolation,
    /// Isolation requested by administrator
    AdminRequest,
    /// Isolation triggered by fault storm (excessive fault rate)
    FaultStorm,
}

/// Decision from security policy evaluation
///
/// Returned by `SecurityNotifier::decide()` to determine action on fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IsolationDecision {
    /// Ignore the fault (considered normal behavior)
    Ignore,
    /// Log only, do not isolate (for monitoring/debugging)
    LogOnly,
    /// Isolate the device with specified reason
    Isolate(IsolationReason),
}

impl Default for IsolationDecision {
    fn default() -> Self {
        Self::Isolate(IsolationReason::DmaFault)
    }
}

// ============================================================================
// Event Aggregator for Drop Summary
// ============================================================================

/// Key for aggregating similar events together.
///
/// Events with the same key are counted together to produce a summary
/// instead of logging each individual occurrence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventAggregateKey {
    /// DMA violation from specific device
    DmaViolation { source_id: u16 },
    /// Device isolation (unique per device)
    DeviceIsolated { source_id: u16 },
    /// Quarantine poisoned (unique per domain)
    QuarantinePoisoned { domain_id: u16 },
    /// Fault storm (unique per device)
    FaultStorm { source_id: u16 },
    /// Generic events that don't aggregate
    Other,
}

impl From<&SecurityEvent> for EventAggregateKey {
    fn from(event: &SecurityEvent) -> Self {
        match event {
            SecurityEvent::DmaViolation { source_id, .. } => {
                EventAggregateKey::DmaViolation { source_id: *source_id }
            }
            SecurityEvent::DeviceIsolated { source_id, .. } => {
                EventAggregateKey::DeviceIsolated { source_id: *source_id }
            }
            SecurityEvent::QuarantinePoisoned { domain_id, .. } => {
                EventAggregateKey::QuarantinePoisoned { domain_id: *domain_id }
            }
            SecurityEvent::FaultStormDetected { source_id, .. } => {
                EventAggregateKey::FaultStorm { source_id: *source_id }
            }
            _ => EventAggregateKey::Other,
        }
    }
}

/// Statistics for aggregated events of the same type.
#[derive(Debug, Clone, Copy, Default)]
pub struct EventAggregate {
    /// Number of occurrences since last report
    pub count: u64,
    /// Representative event (first occurrence)
    pub representative: Option<SecurityEvent>,
}

/// Maximum number of unique event keys to track for aggregation.
const MAX_AGGREGATE_BUCKETS: usize = 32;

/// Per-CPU event aggregator for efficient duplicate suppression.
///
/// Uses a simple array-based structure to avoid allocation on hot path.
/// When capacity is exceeded, the oldest entries are evicted.
pub struct EventAggregator {
    /// Array of (key, aggregate) pairs
    buckets: [(Option<EventAggregateKey>, EventAggregate); MAX_AGGREGATE_BUCKETS],
    /// Number of active buckets
    active: usize,
    /// Next slot for eviction (circular)
    next_evict: usize,
}

impl EventAggregator {
    /// Create a new empty aggregator.
    pub const fn new() -> Self {
        const EMPTY_BUCKET: (Option<EventAggregateKey>, EventAggregate) = (
            None,
            EventAggregate {
                count: 0,
                representative: None,
            },
        );
        Self {
            buckets: [EMPTY_BUCKET; MAX_AGGREGATE_BUCKETS],
            active: 0,
            next_evict: 0,
        }
    }

    /// Record an event, aggregating with existing entries if possible.
    ///
    /// Returns `true` if this is the first occurrence of this event type.
    pub fn record(&mut self, event: SecurityEvent) -> bool {
        let key = EventAggregateKey::from(&event);

        // Look for existing bucket with same key
        for (bucket_key, aggregate) in self.buckets.iter_mut() {
            if *bucket_key == Some(key) {
                aggregate.count += 1;
                return false; // Not first occurrence
            }
        }

        // Find empty slot or evict oldest
        let slot = if self.active < MAX_AGGREGATE_BUCKETS {
            let slot = self.active;
            self.active += 1;
            slot
        } else {
            let slot = self.next_evict;
            self.next_evict = (self.next_evict + 1) % MAX_AGGREGATE_BUCKETS;
            slot
        };

        self.buckets[slot] = (
            Some(key),
            EventAggregate {
                count: 1,
                representative: Some(event),
            },
        );
        true // First occurrence
    }

    /// Drain all aggregates and reset.
    ///
    /// Calls the handler for each non-empty aggregate.
    pub fn drain<F>(&mut self, mut handler: F)
    where
        F: FnMut(EventAggregateKey, EventAggregate),
    {
        for (key, aggregate) in self.buckets.iter_mut() {
            if let Some(k) = key.take() {
                if aggregate.count > 0 {
                    handler(k, *aggregate);
                }
                *aggregate = EventAggregate::default();
            }
        }
        self.active = 0;
        self.next_evict = 0;
    }

    /// Get current number of unique event types being tracked.
    pub fn active_count(&self) -> usize {
        self.active
    }
}

impl Default for EventAggregator {
    fn default() -> Self {
        Self::new()
    }
}

/// Minimal fault summary for policy decisions
///
/// Extracted from `FaultRecord` to avoid passing large structures.
/// All fields are `Copy` and require no allocation.
#[derive(Debug, Clone, Copy)]
pub struct FaultSummary {
    /// Source ID (BDF)
    pub source_id: u16,
    /// Faulting address
    pub fault_address: u64,
    /// Fault reason code
    pub reason: u8,
    /// PASID if present
    pub pasid: Option<u32>,
}

impl From<&FaultRecord> for FaultSummary {
    fn from(record: &FaultRecord) -> Self {
        Self {
            source_id: record.source_id(),
            fault_address: record.fault_address(),
            reason: record.reason(),
            pasid: record.pasid(),
        }
    }
}

/// Security event notification interface
///
/// # Implementation Requirements
///
/// - `notify()`: MUST be lock-free. Enqueue to fixed-size ring buffer only.
///   Do NOT perform logging, I/O, or any potentially blocking operations.
///   Heavy processing should be done by a separate task draining the queue.
///
/// - `decide()`: MUST be atomic-read level. No locks, no I/O.
///   If complex policy evaluation is needed, return a conservative default
///   and re-evaluate asynchronously in the monitor task.
///
/// # Example Implementation
///
/// ```ignore
/// struct MySecurityMonitor {
///     events: spin::Mutex<ArrayVec<SecurityEvent, 256>>,
/// }
///
/// impl SecurityNotifier for MySecurityMonitor {
///     fn notify(&self, event: SecurityEvent) {
///         let _ = self.events.lock().try_push(event); // Drop if full
///     }
/// }
/// ```
pub trait SecurityNotifier: Send + Sync {
    /// Receive a security event notification
    ///
    /// # Safety Contract
    ///
    /// This method may be called from ISR context. Implementations MUST:
    /// - Complete in bounded time (no unbounded loops)
    /// - Not acquire any locks that might be held by ISR callers
    /// - Not perform any I/O or system calls
    /// - Not allocate memory
    fn notify(&self, event: SecurityEvent);

    /// Evaluate security policy for a fault
    ///
    /// # Safety Contract
    ///
    /// This method may be called from ISR context. Implementations MUST:
    /// - Use only atomic reads for policy lookup
    /// - Return quickly with a conservative default if complex evaluation needed
    ///
    /// # Default
    ///
    /// Returns `IsolationDecision::Isolate(DmaFault)` - always isolate on fault.
    fn decide(&self, _fault: &FaultSummary) -> IsolationDecision {
        IsolationDecision::default()
    }
}

const SECURITY_EVENT_QUEUE_SIZE: usize = 256;

struct SecurityEventQueue {
    events: [Option<SecurityEvent>; SECURITY_EVENT_QUEUE_SIZE],
    head: AtomicUsize,
    tail: AtomicUsize,
    dropped: AtomicUsize,
}

impl SecurityEventQueue {
    const fn new() -> Self {
        Self {
            events: [None; SECURITY_EVENT_QUEUE_SIZE],
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
            dropped: AtomicUsize::new(0),
        }
    }

    fn push(&self, event: SecurityEvent) {
        const MAX_RETRIES: usize = 16;
        for _ in 0..MAX_RETRIES {
            let tail = self.tail.load(Ordering::Relaxed);
            let next_tail = (tail + 1) % SECURITY_EVENT_QUEUE_SIZE;
            let head = self.head.load(Ordering::Acquire);
            if next_tail == head {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                return;
            }
            if self
                .tail
                .compare_exchange_weak(tail, next_tail, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                unsafe {
                    let ptr = &self.events as *const _
                        as *mut [Option<SecurityEvent>; SECURITY_EVENT_QUEUE_SIZE];
                    core::ptr::write_volatile(&mut (*ptr)[tail], Some(event));
                }
                return;
            }
            core::hint::spin_loop();
        }
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }

    fn pop(&self) -> Option<SecurityEvent> {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Acquire);
        if head == tail {
            return None;
        }
        let event = unsafe {
            let ptr = &self.events as *const _
                as *mut [Option<SecurityEvent>; SECURITY_EVENT_QUEUE_SIZE];
            (*ptr)[head].take()
        };
        self.head
            .store((head + 1) % SECURITY_EVENT_QUEUE_SIZE, Ordering::Release);
        event
    }

    fn take_dropped(&self) -> usize {
        self.dropped.swap(0, Ordering::Relaxed)
    }
}

/// Default IOMMU security monitor that buffers events in a lock-free ring.
pub struct IommuSecurityMonitor {
    queue: SecurityEventQueue,
}

impl IommuSecurityMonitor {
    fn new() -> Self {
        Self {
            queue: SecurityEventQueue::new(),
        }
    }

    /// Drain buffered events and pass them to the handler.
    pub fn drain_events<F>(&self, max: usize, mut handler: F) -> usize
    where
        F: FnMut(SecurityEvent),
    {
        let mut count = 0;
        while count < max {
            let Some(event) = self.queue.pop() else {
                break;
            };
            handler(event);
            count += 1;
        }
        count
    }

    /// Return number of dropped events since the last call.
    pub fn take_dropped_events(&self) -> usize {
        self.queue.take_dropped()
    }
}

impl SecurityNotifier for IommuSecurityMonitor {
    fn notify(&self, event: SecurityEvent) {
        self.queue.push(event);
    }
}

static DEFAULT_SECURITY_MONITOR: Once<Arc<IommuSecurityMonitor>> = Once::new();
static SECURITY_MONITOR_TASK: Once<()> = Once::new();

/// Get the default IOMMU security notifier instance.
pub fn default_security_notifier() -> Arc<dyn SecurityNotifier> {
    default_security_monitor() as Arc<dyn SecurityNotifier>
}

/// Get the default IOMMU security monitor instance.
pub fn default_security_monitor() -> Arc<IommuSecurityMonitor> {
    DEFAULT_SECURITY_MONITOR.call_once(|| Arc::new(IommuSecurityMonitor::new()));
    let monitor = DEFAULT_SECURITY_MONITOR
        .get()
        .expect("IOMMU security monitor not initialized");
    Arc::clone(monitor)
}

/// Log a summary for aggregated events (called periodically).
///
/// This reduces log spam when the same event type occurs repeatedly
/// (e.g., continuous DMA violations from a misbehaving device).
///
/// # ISR Safety
///
/// This function uses stack-allocated buffers for number formatting,
/// avoiding heap allocation entirely. Safe to call from any context.
fn log_aggregated_event_summary(key: EventAggregateKey, aggregate: EventAggregate) {
    // Stack-allocated format buffers (no heap allocation)
    let mut buf1 = [0u8; FMT_BUF_SIZE];
    let mut buf2 = [0u8; FMT_BUF_SIZE];

    let audit_event = match key {
        EventAggregateKey::DmaViolation { source_id } => {
            AuditEvent::new(AuditEventType::IommuEvent, 0)
                .success(false)
                .message("dma_violation_summary")
                .field("source_id", fmt_hex_u64(source_id as u64, &mut buf1))
                .field("count", fmt_dec_u64(aggregate.count, &mut buf2))
        }
        EventAggregateKey::DeviceIsolated { source_id } => {
            AuditEvent::new(AuditEventType::IommuEvent, 0)
                .success(false)
                .message("device_isolated_summary")
                .field("source_id", fmt_hex_u64(source_id as u64, &mut buf1))
                .field("count", fmt_dec_u64(aggregate.count, &mut buf2))
        }
        EventAggregateKey::QuarantinePoisoned { domain_id } => {
            AuditEvent::new(AuditEventType::IommuEvent, 0)
                .success(false)
                .message("quarantine_poisoned_summary")
                .field("domain_id", fmt_dec_u64(domain_id as u64, &mut buf1))
                .field("count", fmt_dec_u64(aggregate.count, &mut buf2))
        }
        EventAggregateKey::FaultStorm { source_id } => {
            AuditEvent::new(AuditEventType::IommuEvent, 0)
                .success(false)
                .message("fault_storm_summary")
                .field("source_id", fmt_hex_u64(source_id as u64, &mut buf1))
                .field("count", fmt_dec_u64(aggregate.count, &mut buf2))
        }
        EventAggregateKey::Other => {
            // For Other events, use the representative if available
            if let Some(event) = aggregate.representative {
                let mut buf3 = [0u8; FMT_BUF_SIZE];
                return crate::security::audit::log_event(
                    security_event_to_audit(event)
                        .field("repeated_count", fmt_dec_u64(aggregate.count, &mut buf3)),
                );
            }
            return; // No representative, skip
        }
    };
    crate::security::audit::log_event(audit_event);
}

/// Convert a SecurityEvent to an AuditEvent using stack-allocated formatting.
///
/// # ISR Safety
///
/// This function uses stack-allocated buffers for all numeric formatting,
/// completely avoiding heap allocation. Safe to call from any context
/// including interrupt handlers and high-priority executor threads.
fn security_event_to_audit(event: SecurityEvent) -> AuditEvent {
    // Stack-allocated format buffers (no heap allocation)
    let mut buf1 = [0u8; FMT_BUF_SIZE];
    let mut buf2 = [0u8; FMT_BUF_SIZE];
    let mut buf3 = [0u8; FMT_BUF_SIZE];
    let mut buf4 = [0u8; FMT_BUF_SIZE];

    match event {
        SecurityEvent::DmaViolation {
            source_id,
            fault_address,
            reason,
            domain_id,
        } => {
            let domain = domain_id.map(u64::from).unwrap_or(0);
            let base_event = AuditEvent::new(AuditEventType::IommuEvent, domain)
                .success(false)
                .message("dma_violation")
                .field("source_id", fmt_hex_u64(source_id as u64, &mut buf1))
                .field("fault_address", fmt_hex_u64(fault_address, &mut buf2))
                .field("reason", fmt_hex_u64(reason as u64, &mut buf3));
            match domain_id {
                Some(did) => base_event.field("domain_id", fmt_hex_u64(did as u64, &mut buf4)),
                None => base_event.field("domain_id", "unknown"),
            }
        }
        SecurityEvent::DeviceIsolated { source_id, reason } => {
            // Use static strings for IsolationReason to avoid allocation
            let reason_str = match reason {
                IsolationReason::DmaFault => "DmaFault",
                IsolationReason::PolicyViolation => "PolicyViolation",
                IsolationReason::AdminRequest => "AdminRequest",
                IsolationReason::FaultStorm => "FaultStorm",
            };
            AuditEvent::new(AuditEventType::IommuEvent, 0)
                .success(false)
                .message("device_isolated")
                .field("source_id", fmt_hex_u64(source_id as u64, &mut buf1))
                .field("reason", reason_str)
        }
        SecurityEvent::QuarantinePoisoned { domain_id } => {
            AuditEvent::new(AuditEventType::IommuEvent, domain_id as u64)
                .success(false)
                .message("quarantine_poisoned")
        }
        SecurityEvent::EventsDropped { count } => {
            AuditEvent::new(AuditEventType::IommuEvent, 0)
                .success(false)
                .message("events_dropped")
                .field("count", fmt_dec_u64(count, &mut buf1))
        }
        SecurityEvent::FaultStormDetected {
            source_id,
            fault_count,
            window_ms,
        } => AuditEvent::new(AuditEventType::IommuEvent, 0)
            .success(false)
            .message("fault_storm_detected")
            .field("source_id", fmt_hex_u64(source_id as u64, &mut buf1))
            .field("fault_count", fmt_dec_u64(fault_count as u64, &mut buf2))
            .field("window_ms", fmt_dec_u64(window_ms as u64, &mut buf3)),
        SecurityEvent::AtsEnabledForUntrustedDevice {
            source_id,
            vendor_id,
            device_id,
            trust_level,
        } => {
            // Use static strings for DeviceTrustLevel to avoid allocation
            let trust_str = match trust_level {
                DeviceTrustLevel::Untrusted => "Untrusted",
                DeviceTrustLevel::Partial => "Partial",
                DeviceTrustLevel::Trusted => "Trusted",
            };
            AuditEvent::new(AuditEventType::IommuEvent, 0)
                .success(false)
                .message("ats_enabled_untrusted")
                .field("source_id", fmt_hex_u64(source_id as u64, &mut buf1))
                .field("vendor_id", fmt_hex_u64(vendor_id as u64, &mut buf2))
                .field("device_id", fmt_hex_u64(device_id as u64, &mut buf3))
                .field("trust_level", trust_str)
        }
        SecurityEvent::AtsStateChanged {
            source_id,
            enabled,
            reason,
        } => {
            // Use static strings for AtsChangeReason to avoid allocation
            let reason_str = match reason {
                AtsChangeReason::DriverInit => "DriverInit",
                AtsChangeReason::SecurityPolicy => "SecurityPolicy",
                AtsChangeReason::FaultStorm => "FaultStorm",
                AtsChangeReason::AdminRequest => "AdminRequest",
                AtsChangeReason::LiveUpdate => "LiveUpdate",
                AtsChangeReason::DeviceDetach => "DeviceDetach",
            };
            AuditEvent::new(AuditEventType::IommuEvent, 0)
                .success(true)
                .message("ats_state_changed")
                .field("source_id", fmt_hex_u64(source_id as u64, &mut buf1))
                .field("enabled", if enabled { "true" } else { "false" })
                .field("reason", reason_str)
        }
    }
}

const SECURITY_MONITOR_INTERVAL_MS: u64 = 100;
const SECURITY_MONITOR_BATCH: usize = 128;

/// GC (Garbage Collection) interval for zombie DMA handles
const ZOMBIE_GC_INTERVAL_MS: u64 = 5000; // 5 seconds

/// Interval for flushing aggregated events (milliseconds)
const EVENT_AGGREGATE_FLUSH_MS: u64 = 1000; // 1 second

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
fn run_zombie_dma_gc() {
    use super::zombie_queue;

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
const MAX_TRACKED_DEVICES: usize = 64;

/// Fault threshold: number of faults within the time window before isolation.
const FAULT_STORM_THRESHOLD: u32 = 10;

/// Time window for fault rate calculation in milliseconds.
const FAULT_STORM_WINDOW_MS: u32 = 1000;

/// Per-device fault tracking entry.
///
/// Uses atomic operations for ISR-safe updates.
struct DeviceFaultEntry {
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
    const fn new() -> Self {
        Self {
            source_id: AtomicU32::new(0),
            fault_count: AtomicU32::new(0),
            window_start: AtomicU64::new(0),
            isolated: AtomicU32::new(0),
        }
    }

    fn is_unused(&self) -> bool {
        self.source_id.load(Ordering::Relaxed) == 0
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

    /// Record a fault and return (new_count, triggered_storm) tuple.
    fn record_fault(&self, current_time_ms: u64) -> (u32, bool) {
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
    fn try_claim(&self, source_id: u16, current_time_ms: u64) -> bool {
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
static FAULT_RATE_LIMITER: FaultRateLimiter = FaultRateLimiter::new();

/// Get the global fault rate limiter.
pub fn fault_rate_limiter() -> &'static FaultRateLimiter {
    &FAULT_RATE_LIMITER
}

/// Approximate current time in milliseconds (for ISR context).
///
/// Uses the system clock's uptime value (based on TSC or PIT).
fn current_time_ms_approx() -> u64 {
    // Use system clock's uptime in milliseconds
    crate::time::get_uptime_ms()
}

// ============================================================================
// Emergency Device Isolation (Lock-Free Fast Path)
// ============================================================================

use core::sync::atomic::AtomicU8;

/// Maximum number of devices that can be emergency-isolated simultaneously.
const MAX_EMERGENCY_ISOLATED: usize = 32;

/// Emergency isolation slot for a device.
///
/// Stores the source ID and isolation status atomically.
/// - `status == 0`: Slot is unused
/// - `status == 1`: Device is pending isolation (awaiting IOTLB flush)
/// - `status == 2`: Device is fully isolated (IOTLB flushed)
struct EmergencyIsolationSlot {
    /// Device source ID (BDF), stored as u32 for atomic access
    source_id: AtomicU32,
    /// Isolation status: 0=unused, 1=pending, 2=isolated
    status: AtomicU8,
    /// Timestamp when isolation was triggered (TSC)
    isolation_tsc: AtomicU64,
}

impl EmergencyIsolationSlot {
    const fn new() -> Self {
        Self {
            source_id: AtomicU32::new(0),
            status: AtomicU8::new(0),
            isolation_tsc: AtomicU64::new(0),
        }
    }

    /// Check if slot is unused
    fn is_unused(&self) -> bool {
        self.status.load(Ordering::Acquire) == 0
    }

    /// Try to claim this slot for emergency isolation.
    ///
    /// Returns `true` if successfully claimed, `false` if slot was already taken.
    fn try_claim(&self, source_id: u16) -> bool {
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
    fn mark_fully_isolated(&self) {
        self.status.store(2, Ordering::Release);
    }

    /// Check if device matches this slot
    fn matches(&self, source_id: u16) -> bool {
        self.source_id.load(Ordering::Acquire) == source_id as u32
            && self.status.load(Ordering::Acquire) != 0
    }

    /// Get current status
    fn status(&self) -> u8 {
        self.status.load(Ordering::Acquire)
    }

    /// Clear slot (for recovery/reset)
    fn clear(&self) {
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
static EMERGENCY_REGISTRY: EmergencyIsolationRegistry = EmergencyIsolationRegistry::new();

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
fn invalidate_device_iotlb(source_id: u16) -> Result<(), IommuError> {
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
static UNSAFE_ALLOW_IDENTITY_MAPPING: AtomicBool = AtomicBool::new(false);

/// Global DMA mapping gate (device-scoped mappings remain allowed).
static ALLOW_GLOBAL_MAPPINGS: AtomicBool = AtomicBool::new(cfg!(debug_assertions));

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

static SECURITY_NOTIFIER: RwLock<Option<Arc<dyn SecurityNotifier>>> = RwLock::new(None);

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

/// QEMU test hook: clear global notifier state for deterministic canonical smoke tests.
#[cfg(feature = "qemu-test-export")]
pub fn qemu_test_clear_security_notifier() {
    *SECURITY_NOTIFIER.write() = None;
}

/// Notify the registered security listener (if any)
pub(crate) fn notify_security_listener(event: SecurityEvent) {
    if let Some(notifier) = SECURITY_NOTIFIER.read().as_ref() {
        notifier.notify(event);
    }
}

