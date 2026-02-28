// ============================================================================
// kernel/src/io/iommu/backends/amd/driver.rs
// ============================================================================

//! Driver trait implementation for AMD-Vi IOMMU

use kernel_api::driver::{DeviceId, Driver, DriverType, DriverVersion};
use kernel_api::error::{KapiError, KapiResult};

use crate::io::iommu::runtime::config::IommuConfig;
use crate::io::iommu::backends::amd::init_iommu_from_ivrs;

/// AMD-Vi Driver Wrapper
pub struct AmdViDriver {
    ivrs_addr: usize,
    config: IommuConfig,
    initialized: bool,
}

impl AmdViDriver {
    pub fn new(ivrs_addr: usize, config: IommuConfig) -> Self {
        Self {
            ivrs_addr,
            config,
            initialized: false,
        }
    }
}

impl Driver for AmdViDriver {
    fn name(&self) -> &str {
        "amd-vi"
    }

    fn version(&self) -> DriverVersion {
        DriverVersion::new(1, 0, 0)
    }

    fn driver_type(&self) -> DriverType {
        DriverType::Other // IOMMU type
    }

    fn probe(&mut self) -> KapiResult<()> {
        log::info!(target: "amdvi", "Probing AMD-Vi IOMMU at {:#x}", self.ivrs_addr);
        
        // Call existing unsafe initialization
        match unsafe { init_iommu_from_ivrs(self.ivrs_addr, self.config.clone()) } {
            Ok(_) => {
                self.initialized = true;
                log::info!(target: "amdvi", "AMD-Vi initialized successfully");
                Ok(())
            }
            Err(e) => {
                log::error!(target: "amdvi", "Initialization failed: {:?}", e);
                Err(KapiError::IoError)
            }
        }
    }

    fn supported_devices(&self) -> &[DeviceId] {
        &[]
    }
}
