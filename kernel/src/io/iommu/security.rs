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
//! # Thread Safety
//!
//! All types are `Send + Sync`. Events are `Copy` to avoid allocation in ISR context.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::Once;

use crate::io::iommu::fault_log::FaultRecord;
use crate::security::audit::{AuditEvent, AuditEventType};

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

fn security_event_to_audit(event: SecurityEvent) -> AuditEvent {
    match event {
        SecurityEvent::DmaViolation {
            source_id,
            fault_address,
            reason,
            domain_id,
        } => {
            let domain = domain_id.map(u64::from).unwrap_or(0);
            let mut event = AuditEvent::new(AuditEventType::IommuEvent, domain)
                .success(false)
                .message("dma_violation")
                .field("source_id", alloc::format!("{:#x}", source_id))
                .field("fault_address", alloc::format!("{:#x}", fault_address))
                .field("reason", alloc::format!("{:#x}", reason));
            event = match domain_id {
                Some(domain_id) => event.field("domain_id", alloc::format!("{:#x}", domain_id)),
                None => event.field("domain_id", "unknown"),
            };
            event
        }
        SecurityEvent::DeviceIsolated { source_id, reason } => {
            AuditEvent::new(AuditEventType::IommuEvent, 0)
                .success(false)
                .message("device_isolated")
                .field("source_id", alloc::format!("{:#x}", source_id))
                .field("reason", alloc::format!("{:?}", reason))
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
                .field("count", alloc::format!("{}", count))
        }
    }
}

const SECURITY_MONITOR_INTERVAL_MS: u64 = 100;
const SECURITY_MONITOR_BATCH: usize = 128;

/// Drain IOMMU security events and forward them to the audit pipeline.
pub async fn security_monitor_task() {
    let monitor = default_security_monitor();
    loop {
        let _ = monitor.drain_events(SECURITY_MONITOR_BATCH, |event| {
            crate::security::audit::log_event(security_event_to_audit(event));
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

        crate::task::sleep_ms(SECURITY_MONITOR_INTERVAL_MS).await;
    }
}

/// Spawn the default IOMMU security monitor task (idempotent).
pub fn spawn_security_monitor_task() {
    SECURITY_MONITOR_TASK.call_once(|| {
        crate::task::per_core_executor::spawn(security_monitor_task());
    });
}
