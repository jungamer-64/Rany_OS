// ============================================================================
// kernel/src/io/iommu/runtime/security/mod.rs
// ============================================================================

//! Security monitor and policy integration for the IOMMU subsystem.

pub(crate) use crate::security::dma::{
    range_overlaps_protected,
    register_protected_page,
    unregister_protected_page,
};

mod audit_convert;
mod emergency;
mod fault_storm;
mod format;
mod monitor_task;
mod notifier;
mod protection;
mod types;
mod validation;

pub use emergency::*;
pub use fault_storm::*;
pub use monitor_task::*;
pub use notifier::*;
pub use protection::*;
pub use types::*;
pub use validation::*;

pub(crate) use audit_convert::{log_aggregated_event_summary, security_event_to_audit};
pub(crate) use format::{fmt_dec_u64, fmt_hex_u64, FMT_BUF_SIZE};
