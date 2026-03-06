// ============================================================================
// kernel/src/io/iommu/vendors/intel/driver.rs
// ============================================================================

//! Driver trait implementation for Intel VT-d IOMMU

use kernel_api::driver::{DeviceId, Driver, DriverType, DriverVersion};
use kernel_api::error::{KapiError, KapiResult};

use crate::io::iommu::runtime::config::IommuConfig;
use crate::io::iommu::vendors::intel::controller::init_global::init_iommu_from_acpi;

/// Intel VT-d Driver Wrapper
pub struct IntelVtDDriver {
    dmar_addr: usize,
    config: IommuConfig,
    initialized: bool,
}

impl IntelVtDDriver {
    pub fn new(dmar_addr: usize, config: IommuConfig) -> Self {
        Self {
            dmar_addr,
            config,
            initialized: false,
        }
    }
}

impl Driver for IntelVtDDriver {
    fn name(&self) -> &str {
        "intel-vtd"
    }

    fn version(&self) -> DriverVersion {
        DriverVersion::new(1, 0, 0)
    }

    fn driver_type(&self) -> DriverType {
        DriverType::Other // IOMMU type
    }

    fn probe(&mut self) -> KapiResult<()> {
        log::info!(target: "vtd", "Probing Intel VT-d IOMMU at {:#x}", self.dmar_addr);

        // Call existing unsafe initialization
        match unsafe { init_iommu_from_acpi(self.dmar_addr, self.config.clone()) } {
            Ok(_) => {
                self.initialized = true;
                log::info!(target: "vtd", "Intel VT-d initialized successfully");
                Ok(())
            }
            Err(e) => {
                log::error!(target: "vtd", "Initialization failed: {:?}", e);
                // Map IommuError to KapiError
                Err(KapiError::IoError)
            }
        }
    }

    fn supported_devices(&self) -> &[DeviceId] {
        // IOMMU is a system device, not matched by PCI ID usually (though it appears as one).
        // DriverRegistry loads this manually, so this list can be empty.
        &[]
    }
}
