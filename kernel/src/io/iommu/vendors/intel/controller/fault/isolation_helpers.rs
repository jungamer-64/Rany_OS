// ============================================================================
// kernel/src/io/iommu/vendors/intel/controller/fault/isolation_helpers.rs
// ============================================================================

use super::*;

// ============================================================================
// Isolation Helpers (extracted from isolate_faulting_device for CC reduction)
// ============================================================================

impl IommuController {
    /// Evaluate security policy for a fault and return the isolation reason.
    ///
    /// Returns `Some(reason)` if device should be isolated, `None` to skip.
    pub(super) fn check_isolation_policy(
        &self,
        fault: &FaultRecord,
        bus: u8,
        dev: u8,
        func: u8,
    ) -> Option<crate::io::iommu::runtime::security::IsolationReason> {
        use crate::io::iommu::runtime::security::{FaultSummary, IsolationDecision};

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
}
