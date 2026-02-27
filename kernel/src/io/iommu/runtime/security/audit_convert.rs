use super::*;


/// Convert a SecurityEvent to an AuditEvent using stack-allocated formatting.
///
/// # ISR Safety
///
/// This function uses stack-allocated buffers for all numeric formatting,
/// completely avoiding heap allocation. Safe to call from any context
/// including interrupt handlers and high-priority executor threads.
pub(crate) fn security_event_to_audit(event: SecurityEvent) -> AuditEvent {
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
