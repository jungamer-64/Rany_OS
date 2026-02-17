use super::*;


// ============================================================================
// Isolation Helpers (extracted from isolate_faulting_device for CC reduction)
// ============================================================================

impl IommuController {
    /// Evaluate security policy for a fault and return the isolation reason.
    ///
    /// Returns `Some(reason)` if device should be isolated, `None` to skip.
    fn check_isolation_policy(
        &self,
        fault: &FaultRecord,
        bus: u8,
        dev: u8,
        func: u8,
    ) -> Option<crate::io::iommu::security::IsolationReason> {
        use crate::io::iommu::security::{FaultSummary, IsolationDecision};

        let summary = FaultSummary::from(fault);
        let decision = if let Some(notifier) = self.security_notifier.get() {
            notifier.decide(&summary)
        } else {
            IsolationDecision::default()
        };

        match decision {
            IsolationDecision::Ignore => {
                log::debug!(
                    "[SECURITY] Fault from {}:{}.{} ignored by policy",
                    bus,
                    dev,
                    func
                );
                None
            }
            IsolationDecision::LogOnly => {
                log::warn!(
                    "[SECURITY] Fault from {}:{}.{} logged (no isolation)",
                    bus,
                    dev,
                    func
                );
                None
            }
            IsolationDecision::Isolate(reason) => Some(reason),
        }
    }

    /// Disable the context entry for a device in hardware tables.
    ///
    /// Handles both normal and poisoned lock states.
    /// Returns `(need_invalidation, isolated_domain_id)`.
    fn disable_device_context_entry(
        &self,
        bus: u8,
        dev: u8,
        func: u8,
    ) -> (bool, Option<u16>) {
        let mut hw_guard = match self.hardware.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                log::warn!("[IOMMU] Lock poisoned during isolation, attempting best-effort");
                poisoned.into_inner()
            }
        };

        let idx = ((dev as usize) << 3) | (func as usize);
        if self.is_scalable_mode_enabled() {
            self.disable_scalable_context_entry(&mut hw_guard, bus, idx)
        } else {
            Self::disable_legacy_context_entry(&mut hw_guard, bus, idx)
        }
    }

    /// Disable a scalable-mode context entry for a device.
    fn disable_scalable_context_entry(
        &self,
        hw: &mut HardwareContext,
        bus: u8,
        idx: usize,
    ) -> (bool, Option<u16>) {
        if let Some(table) = hw.scalable_context_tables.get_mut(bus as usize) {
            if let Some(entry) = table.get_mut(idx) {
                if entry.is_present() {
                    let domain_id = self.resolve_scalable_domain_id(bus, idx);
                    *entry = ScalableContextEntry::default();
                    return (true, domain_id);
                }
            }
        }
        (false, None)
    }

    /// Disable a legacy-mode context entry for a device.
    fn disable_legacy_context_entry(
        hw: &mut HardwareContext,
        bus: u8,
        idx: usize,
    ) -> (bool, Option<u16>) {
        if let Some(table) = hw.legacy_context_tables.get_mut(bus as usize) {
            if let Some(entry) = table.get_mut(idx) {
                unsafe {
                    let entry_ptr = entry as *mut ContextEntry;
                    let val = core::ptr::read_volatile(entry_ptr);
                    if val.is_present() {
                        // Capture domain_id BEFORE clearing Present bit
                        let domain_id = Some(val.domain_id());
                        let mut new_val = val;
                        new_val.lo &= !1;
                        core::ptr::write_volatile(entry_ptr, new_val);
                        return (true, domain_id);
                    }
                }
            }
        }
        (false, None)
    }

    /// Resolve domain_id for a device via PASID tables (scalable mode).
    fn resolve_scalable_domain_id(&self, bus: u8, idx: usize) -> Option<u16> {
        let dev = ((idx >> 3) & 0x1F) as u8;
        let func = (idx & 0x07) as u8;
        if let Ok(pasid_tables) = self.device_pasid_tables.lock() {
            let device_id = DeviceId::new(self.segment, bus, dev, func);
            pasid_tables.get(&device_id).and_then(|t| t.domain_id(0))
        } else {
            None
        }
    }

    /// Perform cache invalidation and security notification after device isolation.
    fn perform_isolation_invalidation(
        &self,
        sid: u16,
        isolated_domain_id: Option<u16>,
        isolation_reason: crate::io::iommu::security::IsolationReason,
    ) {
        use crate::io::iommu::security::SecurityEvent;

        // Intel VT-d: After modifying context entry, must invalidate caches
        // 1. Context Cache Invalidation (global - device-specific requires QI descriptor)
        // 2. IOTLB Invalidation (domain-specific or global)
        unsafe {
            let use_device_scope = self.is_queued_invalidation_enabled()
                && (self.ecap & ecap_bits::ECAP_DT != 0)
                && isolated_domain_id.is_some();

            if use_device_scope {
                let did = isolated_domain_id.unwrap();
                self.qi_invalidate_context_device(sid, did).unwrap_or_else(|e| {
                    log::warn!(
                        "[IOMMU] Device context invalidation failed: {:?}; falling back to global",
                        e
                    );
                    let _ = self.qi_invalidate_context_global();
                });
            } else {
                // Global context cache invalidation
                self.qi_invalidate_context_global().unwrap_or_else(|e| {
                    log::warn!("[IOMMU] Context invalidation failed: {:?}", e)
                });
            }

            // IOTLB invalidation: prefer domain-specific if we have domain_id
            if let Some(did) = isolated_domain_id {
                self.invalidate_iotlb(did);
            } else {
                self.invalidate_iotlb_global();
            }
        }

        // Phase 7: Notify security event AFTER lock is released and invalidation done
        self.notify_security(SecurityEvent::DeviceIsolated {
            source_id: sid,
            reason: isolation_reason,
        });
    }
}
