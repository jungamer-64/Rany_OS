// ============================================================================
// kernel/src/io/iommu/mod.rs
// ============================================================================
//!
//! IOMMU Support (Intel VT-d / AMD-Vi)
//!

#![allow(dead_code)]

use ::core::sync::atomic::AtomicBool;

// Public API surface
pub mod api;
pub mod types {
    pub use super::core::types::*;
}

// Layered module namespaces
pub(crate) mod backends;
pub(crate) mod core;
pub(crate) mod runtime;

#[cfg(any(test, feature = "qemu-test-export"))]
pub(crate) mod tests;

#[cfg(feature = "qemu-test-export")]
pub(crate) mod qemu_tests {
    pub use super::tests::qemu::*;
}

// ============================================================================
// Configuration
// ============================================================================

/// IOMMU Check Required
pub(crate) static IOMMU_REQUIRED: AtomicBool = AtomicBool::new(false);

// End of file
