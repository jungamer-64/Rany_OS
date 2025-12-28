// ============================================================================
// kernel/src/io/iommu/registry.rs
// ============================================================================

//! Global IOMMU Driver Registration
//!
//! This module manages the active IOMMU backend (Intel VT-d or AMD-Vi).
//! It provides a singleton accessor for the enum-dispatch backend.

use alloc::sync::Arc;
use spin::Once;

use super::IommuBackend;
pub use super::intel::registry::{get_iommu_registry, init_registry, IommuRegistry};

/// Global IOMMU Driver (backend abstraction, initialized once during boot)
static IOMMU_DRIVER: Once<Arc<IommuBackend>> = Once::new();

/// Get reference to the registered IOMMU driver (backend abstraction)
pub fn get_iommu_driver() -> Option<&'static Arc<IommuBackend>> {
    IOMMU_DRIVER.get()
}

/// Check if IOMMU is enabled (driver registered and backend available)
pub fn is_iommu_enabled() -> bool {
    IOMMU_DRIVER.get().map_or(false, |d| d.is_enabled())
}

/// Initialize the global driver (call once during boot)
///
/// # Panics
/// Panics if called more than once.
pub fn init_driver(driver: Arc<IommuBackend>) {
    IOMMU_DRIVER.call_once(|| driver);
}
