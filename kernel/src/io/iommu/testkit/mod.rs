// ============================================================================
// kernel/src/io/iommu/testkit/mod.rs
// ============================================================================

pub mod fixtures;
pub mod unit;

#[cfg(feature = "qemu-test-export")]
pub mod qemu;

#[cfg(feature = "qemu-test-export")]
pub use fixtures::MockSecurityNotifier;
