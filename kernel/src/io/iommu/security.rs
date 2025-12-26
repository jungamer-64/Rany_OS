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

use crate::io::iommu::fault_log::FaultRecord;

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
