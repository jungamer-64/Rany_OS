// ============================================================================
// kernel/src/io/iommu/testkit/mod.rs
// ============================================================================

mod unit;

#[cfg(feature = "qemu-test-export")]
pub mod qemu;

#[cfg(feature = "qemu-test-export")]
pub use qemu::wave2::MockSecurityNotifier;
