// ============================================================================
// kernel/src/io/iommu/api/driver.rs
// ============================================================================

use alloc::boxed::Box;
use kernel_api::driver::Driver;

use crate::io::iommu::runtime::config::IommuConfig;

/// Create an Intel VT-d driver instance behind the stable API surface.
pub fn create_intel_vtd_driver(dmar_addr: usize, config: IommuConfig) -> Box<dyn Driver> {
    Box::new(crate::io::iommu::vendors::intel::driver::IntelVtDDriver::new(dmar_addr, config))
}

/// Create an AMD-Vi driver instance behind the stable API surface.
pub fn create_amd_vi_driver(ivrs_addr: usize, config: IommuConfig) -> Box<dyn Driver> {
    Box::new(crate::io::iommu::vendors::amd::driver::AmdViDriver::new(
        ivrs_addr, config,
    ))
}
