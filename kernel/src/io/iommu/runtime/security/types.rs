// ============================================================================
// kernel/src/io/iommu/runtime/security/types.rs
// ============================================================================

use crate::io::iommu::runtime::fault_log::FaultRecord;

/// Security event types from IOMMU subsystem.
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

    /// ATS enabled for potentially untrusted device.
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

    /// ATS operation (enable/disable) performed on a device.
    AtsStateChanged {
        /// Source ID of the device
        source_id: u16,
        /// New ATS state (true = enabled, false = disabled)
        enabled: bool,
        /// Reason for the state change
        reason: AtsChangeReason,
    },
}

/// Trust level assigned to a device for ATS policy decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DeviceTrustLevel {
    /// Device is untrusted (e.g., external USB, Thunderbolt).
    Untrusted = 0,
    /// Device is partially trusted (internal but not verified).
    Partial = 1,
    /// Device is fully trusted (verified firmware, internal bus).
    Trusted = 2,
}

impl Default for DeviceTrustLevel {
    fn default() -> Self {
        Self::Untrusted
    }
}

/// Reason for ATS state change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AtsChangeReason {
    DriverInit,
    SecurityPolicy,
    FaultStorm,
    AdminRequest,
    LiveUpdate,
    DeviceDetach,
}

/// Reason for device isolation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IsolationReason {
    DmaFault,
    PolicyViolation,
    AdminRequest,
    FaultStorm,
}

/// Decision from security policy evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IsolationDecision {
    Ignore,
    LogOnly,
    Isolate(IsolationReason),
}

impl Default for IsolationDecision {
    fn default() -> Self {
        Self::Isolate(IsolationReason::DmaFault)
    }
}

/// Key for aggregating similar events together.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventAggregateKey {
    DmaViolation { source_id: u16 },
    DeviceIsolated { source_id: u16 },
    QuarantinePoisoned { domain_id: u16 },
    FaultStorm { source_id: u16 },
    Other,
}

impl From<&SecurityEvent> for EventAggregateKey {
    fn from(event: &SecurityEvent) -> Self {
        match event {
            SecurityEvent::DmaViolation { source_id, .. } => EventAggregateKey::DmaViolation {
                source_id: *source_id,
            },
            SecurityEvent::DeviceIsolated { source_id, .. } => EventAggregateKey::DeviceIsolated {
                source_id: *source_id,
            },
            SecurityEvent::QuarantinePoisoned { domain_id, .. } => {
                EventAggregateKey::QuarantinePoisoned {
                    domain_id: *domain_id,
                }
            }
            SecurityEvent::FaultStormDetected { source_id, .. } => EventAggregateKey::FaultStorm {
                source_id: *source_id,
            },
            _ => EventAggregateKey::Other,
        }
    }
}

/// Statistics for aggregated events of the same type.
#[derive(Debug, Clone, Copy, Default)]
pub struct EventAggregate {
    pub count: u64,
    pub representative: Option<SecurityEvent>,
}

/// Maximum number of unique event keys to track for aggregation.
const MAX_AGGREGATE_BUCKETS: usize = 32;

/// Per-CPU event aggregator for efficient duplicate suppression.
#[derive(Debug)]
pub struct EventAggregator {
    buckets: [(Option<EventAggregateKey>, EventAggregate); MAX_AGGREGATE_BUCKETS],
    active: usize,
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
    pub fn record(&mut self, event: SecurityEvent) -> bool {
        let key = EventAggregateKey::from(&event);

        for (bucket_key, aggregate) in self.buckets.iter_mut() {
            if *bucket_key == Some(key) {
                aggregate.count += 1;
                return false;
            }
        }

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
        true
    }

    /// Drain all aggregates and reset.
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
}

impl Default for EventAggregator {
    fn default() -> Self {
        Self::new()
    }
}

/// Minimal fault summary for policy decisions.
#[derive(Debug, Clone, Copy)]
pub struct FaultSummary {
    pub source_id: u16,
    pub fault_address: u64,
    pub reason: u8,
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

/// Security event notification interface.
pub trait SecurityNotifier: Send + Sync + core::fmt::Debug {
    /// Receive a security event notification.
    fn notify(&self, event: SecurityEvent);

    /// Evaluate security policy for a fault.
    fn decide(&self, _fault: &FaultSummary) -> IsolationDecision {
        IsolationDecision::default()
    }
}
