// ============================================================================
// kernel/src/io/iommu/api/driver.rs
// ============================================================================

use alloc::boxed::Box;
use alloc::sync::Arc;
use kernel_api::driver::Driver;

use crate::io::iommu::runtime::config::IommuConfig;

/// Create an Intel VT-d driver instance behind the stable API surface.
pub fn create_intel_vtd_driver(dmar: Arc<[u8]>, config: IommuConfig) -> Box<dyn Driver> {
    Box::new(crate::io::iommu::vendors::intel::driver::IntelVtDDriver::new(dmar, config))
}

/// Create an AMD-Vi driver instance behind the stable API surface.
pub fn create_amd_vi_driver(ivrs: Arc<[u8]>, config: IommuConfig) -> Box<dyn Driver> {
    Box::new(crate::io::iommu::vendors::amd::driver::AmdViDriver::new(
        ivrs, config,
    ))
}
