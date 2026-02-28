// ============================================================================
// kernel/src/io/iommu/testkit/fixtures/mod.rs
// ============================================================================

#[cfg(feature = "qemu-test-export")]
pub use crate::io::iommu::testkit::qemu::wave2::{MockPciTopology, MockSecurityNotifier};
