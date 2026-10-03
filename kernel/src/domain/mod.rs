//! Canonical domain namespace.

pub mod api;
pub mod lifecycle;
pub mod policy;
pub mod quota;
pub mod registry;
pub mod types;

pub use api::*;
pub use policy::{DomainPolicyError, DomainTerminationError};
pub use quota::{DomainPriority, DomainQuota, QuotaError, quota_manager};
pub(crate) use registry::with_resource_admission;
pub use types::*;

#[cfg(test)]
pub(crate) use registry::REGISTRY;

#[cfg(test)]
mod tests;
