// ============================================================================
// kernel/src/io/iommu/api/security.rs
// ============================================================================

pub use alloc::sync::Arc;

pub use crate::io::iommu::runtime::security::{
    FaultSummary, IsolationDecision, IsolationReason, SecurityEvent, SecurityNotifier,
    default_security_notifier, set_security_notifier, validate_critical_dma_region,
    validate_dma_region,
};
