// ============================================================================
// kernel/src/io/iommu/mod.rs
// ============================================================================

//!
//! IOMMU Support (Intel VT-d / AMD-Vi)
//!

#![allow(dead_code)]

// Public API surface
pub mod api;
pub mod types;

// Layered module namespaces
pub(crate) mod common;
pub(crate) mod runtime;
pub(crate) mod vendors;

#[cfg(any(test, feature = "qemu-test-export"))]
pub(crate) mod testkit;

#[cfg(feature = "qemu-test-export")]
pub(crate) mod qemu_tests {
    pub use super::testkit::qemu::*;
}

// End of file
