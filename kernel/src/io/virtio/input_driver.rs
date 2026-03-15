// ============================================================================
// src/io/virtio/input_driver.rs - VirtIO Input Driver
// ============================================================================
//!
//! Driver trait implementation for VirtIO Input Device.
//! This wrapper allows the driver to be managed by the DriverRegistry.

use alloc::sync::Arc;

use kernel_api::driver::{DeviceId, Driver, DriverType, DriverVersion};
use kernel_api::error::{KapiError, KapiResult};

use crate::io::iommu::types::DeviceId as IommuDeviceId;
use crate::io::virtio::input::{VirtioInputDevice, init_virtio_input_for_device_at_index};

/// VirtIO Input Driver
pub struct VirtioInputDriver {
    mmio_base: u64,
    iommu_id: IommuDeviceId,
    initialized: bool,
    device: Option<Arc<VirtioInputDevice>>,
}

impl VirtioInputDriver {
    /// Create a new VirtIO Input Driver instance
    pub fn new(mmio_base: u64, iommu_id: IommuDeviceId) -> Self {
        Self {
            mmio_base,
            iommu_id,
            initialized: false,
            device: None,
        }
    }
}

impl Driver for VirtioInputDriver {
    fn name(&self) -> &str {
        "virtio-input"
    }

    fn version(&self) -> DriverVersion {
        DriverVersion::new(0, 1, 0)
    }

    fn driver_type(&self) -> DriverType {
        DriverType::Hid
    }

    fn probe(&mut self) -> KapiResult<()> {
        log::info!(target: "virtio_input", "Probing VirtIO-Input at {:#x}", self.mmio_base);

        let res =
            unsafe { init_virtio_input_for_device_at_index(0, self.mmio_base, self.iommu_id) };

        match res {
            Ok(_) => {
                self.initialized = true;
                Ok(())
            }
            Err(e) => {
                log::error!(target: "virtio_input", "Failed to initialize device: {:?}", e);
                Err(KapiError::IoError)
            }
        }
    }

    fn start(&mut self) -> KapiResult<()> {
        if !self.initialized {
            return Err(KapiError::Internal(-1));
        }
        log::info!(target: "virtio_input", "Driver started");
        Ok(())
    }

    fn stop(&mut self) -> KapiResult<()> {
        Ok(())
    }

    fn supported_devices(&self) -> &[DeviceId] {
        static DEVICES: [DeviceId; 1] = [DeviceId {
            vendor: 0x1AF4,
            device: 0x1052, // Input Device (Modern)
            subsystem_vendor: None,
            subsystem_device: None,
        }];
        &DEVICES
    }
}
