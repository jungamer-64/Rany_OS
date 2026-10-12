// ============================================================================
// kernel/src/io/iommu/mod.rs
// ============================================================================

//!
//! IOMMU Support (Intel VT-d / AMD-Vi)
//!
pub mod api;
pub mod types;

// Layered module namespaces
pub(crate) mod common;
pub(crate) mod runtime;
pub(crate) mod vendors;

#[cfg(test)]
pub(crate) mod testkit;

#[cfg(feature = "qemu-test-export")]
pub(crate) mod qemu_tests;

// End of file
