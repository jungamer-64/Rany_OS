// ============================================================================
// kernel/src/io/iommu/api/security.rs
// ============================================================================

pub use alloc::sync::Arc;

pub use crate::io::iommu::runtime::security::{
    FaultSummary,
    IsolationDecision,
    IsolationReason,
    SecurityEvent,
    SecurityNotifier,
    default_security_notifier,
    is_global_dma_mapping_allowed,
    is_unsafe_identity_mapping_allowed,
    set_global_dma_mapping_allowed,
    set_security_notifier,
    spawn_security_monitor_task,
    validate_critical_dma_region,
    validate_dma_region,
};

