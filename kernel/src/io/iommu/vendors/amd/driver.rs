// ============================================================================
// kernel/src/io/iommu/vendors/amd/driver.rs
// ============================================================================

//! Driver trait implementation for AMD-Vi IOMMU

use kernel_api::driver::{DeviceId, Driver, DriverType, DriverVersion};
use kernel_api::error::{KapiError, KapiResult};

use crate::io::iommu::runtime::config::IommuConfig;
use crate::io::iommu::vendors::amd::init_iommu_from_ivrs;

/// AMD-Vi Driver Wrapper
pub struct AmdViDriver {
    ivrs: Arc<[u8]>,
    config: IommuConfig,
    initialized: bool,
}

impl AmdViDriver {
    pub fn new(ivrs: Arc<[u8]>, config: IommuConfig) -> Self {
        Self {
            ivrs,
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
        log::info!(target: "amdvi", "Probing AMD-Vi from owned IVRS catalog bytes");

        // Call existing unsafe initialization
        match init_iommu_from_ivrs(&self.ivrs, self.config.clone()) {
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
use alloc::sync::Arc;
