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
mod monitor_task;
pub use monitor_task::*;
mod audit_convert;
use audit_convert::*;
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
