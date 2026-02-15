// ============================================================================
// src/io/virtio/console_driver.rs - VirtIO Console Driver
// ============================================================================
//!
//! Driver trait implementation for VirtIO Console Device.
//! This wrapper allows the driver to be managed by the DriverRegistry.

use alloc::sync::Arc;

use kernel_api::driver::{DeviceId, Driver, DriverType, DriverVersion};
use kernel_api::error::{KapiError, KapiResult};

use crate::io::iommu::types::DeviceId as IommuDeviceId;
use crate::io::virtio::console::{VirtioConsoleDevice, init_virtio_console_for_device};

/// VirtIO Console Driver
pub struct VirtioConsoleDriver {
    mmio_base: u64,
    iommu_id: IommuDeviceId,
    initialized: bool,
    device: Option<Arc<VirtioConsoleDevice>>,
}

impl VirtioConsoleDriver {
    /// Create a new VirtIO Console Driver instance
    pub fn new(mmio_base: u64, iommu_id: IommuDeviceId) -> Self {
        Self {
            mmio_base,
            iommu_id,
            initialized: false,
            device: None,
        }
    }
}

impl Driver for VirtioConsoleDriver {
    fn name(&self) -> &str {
        "virtio-console"
    }

    fn version(&self) -> DriverVersion {
        DriverVersion::new(0, 1, 0)
    }

    fn driver_type(&self) -> DriverType {
        DriverType::Serial
    }

    fn probe(&mut self) -> KapiResult<()> {
        log::info!(target: "virtio_console", "Probing VirtIO-Console at {:#x}", self.mmio_base);

        let res = unsafe { init_virtio_console_for_device(self.mmio_base, self.iommu_id) };

        match res {
            Ok(_) => {
                self.initialized = true;
                Ok(())
            }
            Err(e) => {
                log::error!(target: "virtio_console", "Failed to initialize device: {:?}", e);
                Err(KapiError::IoError)
            }
        }
    }

    fn start(&mut self) -> KapiResult<()> {
        if !self.initialized {
            return Err(KapiError::Internal(-1));
        }
        log::info!(target: "virtio_console", "Driver started");
        Ok(())
    }

    fn stop(&mut self) -> KapiResult<()> {
        Ok(())
    }

    fn supported_devices(&self) -> &[DeviceId] {
        static DEVICES: [DeviceId; 2] = [
            DeviceId {
                vendor: 0x1AF4,
                device: 0x1003, // Console Device (Transitional)
                subsystem_vendor: None,
                subsystem_device: None,
            },
            DeviceId {
                vendor: 0x1AF4,
                device: 0x1043, // Console Device (Modern)
                subsystem_vendor: None,
                subsystem_device: None,
            },
        ];
        &DEVICES
    }
}
