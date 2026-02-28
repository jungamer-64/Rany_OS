// ============================================================================
// kernel/src/io/iommu/runtime/security/audit_convert.rs
// ============================================================================

use crate::security::audit::{AuditEvent, AuditEventType};

use super::{
    AtsChangeReason,
    DeviceTrustLevel,
    EventAggregate,
    EventAggregateKey,
    FMT_BUF_SIZE,
    IsolationReason,
    SecurityEvent,
    fmt_dec_u64,
    fmt_hex_u64,
};

/// Log a summary for aggregated events (called periodically).
pub(crate) fn log_aggregated_event_summary(key: EventAggregateKey, aggregate: EventAggregate) {
    let mut buf1 = [0u8; FMT_BUF_SIZE];
    let mut buf2 = [0u8; FMT_BUF_SIZE];

    let audit_event = match key {
        EventAggregateKey::DmaViolation { source_id } => AuditEvent::new(AuditEventType::IommuEvent, 0)
            .success(false)
            .message("dma_violation_summary")
            .field("source_id", fmt_hex_u64(source_id as u64, &mut buf1))
            .field("count", fmt_dec_u64(aggregate.count, &mut buf2)),
        EventAggregateKey::DeviceIsolated { source_id } => AuditEvent::new(AuditEventType::IommuEvent, 0)
            .success(false)
            .message("device_isolated_summary")
            .field("source_id", fmt_hex_u64(source_id as u64, &mut buf1))
            .field("count", fmt_dec_u64(aggregate.count, &mut buf2)),
        EventAggregateKey::QuarantinePoisoned { domain_id } => AuditEvent::new(AuditEventType::IommuEvent, 0)
            .success(false)
            .message("quarantine_poisoned_summary")
            .field("domain_id", fmt_dec_u64(domain_id as u64, &mut buf1))
            .field("count", fmt_dec_u64(aggregate.count, &mut buf2)),
        EventAggregateKey::FaultStorm { source_id } => AuditEvent::new(AuditEventType::IommuEvent, 0)
            .success(false)
            .message("fault_storm_summary")
            .field("source_id", fmt_hex_u64(source_id as u64, &mut buf1))
            .field("count", fmt_dec_u64(aggregate.count, &mut buf2)),
        EventAggregateKey::Other => {
            if let Some(event) = aggregate.representative {
                let mut buf3 = [0u8; FMT_BUF_SIZE];
                return crate::security::audit::log_event(
                    security_event_to_audit(event)
                        .field("repeated_count", fmt_dec_u64(aggregate.count, &mut buf3)),
                );
            }
            return;
        }
    };
    crate::security::audit::log_event(audit_event);
}

/// Convert a SecurityEvent to an AuditEvent using stack-allocated formatting.
pub(crate) fn security_event_to_audit(event: SecurityEvent) -> AuditEvent {
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
        SecurityEvent::QuarantinePoisoned { domain_id } => AuditEvent::new(AuditEventType::IommuEvent, domain_id as u64)
            .success(false)
            .message("quarantine_poisoned"),
        SecurityEvent::EventsDropped { count } => AuditEvent::new(AuditEventType::IommuEvent, 0)
            .success(false)
            .message("events_dropped")
            .field("count", fmt_dec_u64(count, &mut buf1)),
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
