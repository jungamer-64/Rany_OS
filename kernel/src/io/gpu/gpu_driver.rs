// ============================================================================
// src/gpu/gpu_driver.rs - VirtIO GPU Driver (DriverRegistry wrapper)
// ============================================================================
//!
//! Driver trait implementation for VirtIO GPU Device.
//! This wrapper allows the GPU driver to be managed by the DriverRegistry.

use kernel_api::driver::{DeviceId, Driver, DriverType, DriverVersion};
use kernel_api::error::{KapiError, KapiResult};

use super::gpu_impl::init;
use crate::io::iommu::types::DeviceId as IommuDeviceId;

/// VirtIO GPU Driver
pub struct VirtioGpuDriver {
    mmio_base: u64,
    iommu_id: IommuDeviceId,
    initialized: bool,
}

impl VirtioGpuDriver {
    /// Create a new VirtIO GPU Driver instance
    pub fn new(mmio_base: u64, iommu_id: IommuDeviceId) -> Self {
        Self {
            mmio_base,
            iommu_id,
            initialized: false,
        }
    }
}

impl Driver for VirtioGpuDriver {
    fn name(&self) -> &str {
        "virtio-gpu"
    }

    fn version(&self) -> DriverVersion {
        DriverVersion::new(0, 1, 0)
    }

    fn driver_type(&self) -> DriverType {
        DriverType::Graphics
    }

    fn probe(&mut self) -> KapiResult<()> {
        log::info!(target: "virtio_gpu", "Probing VirtIO-GPU at {:#x}", self.mmio_base);

        let transport = unsafe {
            crate::io::virtio::transport::VirtioMmioTransport::new(self.mmio_base as usize)
                .map_err(|_| KapiError::IoError)?
        };

        let res = init(alloc::boxed::Box::new(transport), self.iommu_id);

        match res {
            Ok(_) => {
                self.initialized = true;
                Ok(())
            }
            Err(e) => {
                log::error!(target: "virtio_gpu", "Failed to initialize device: {:?}", e);
                Err(KapiError::IoError)
            }
        }
    }

    fn start(&mut self) -> KapiResult<()> {
        if !self.initialized {
            return Err(KapiError::Internal(-1));
        }
        log::info!(target: "virtio_gpu", "Driver started");
        Ok(())
    }

    fn stop(&mut self) -> KapiResult<()> {
        Ok(())
    }

    fn supported_devices(&self) -> &[DeviceId] {
        static DEVICES: [DeviceId; 1] = [DeviceId {
            vendor: 0x1AF4,
            device: 0x1050, // VirtIO GPU (Modern)
            subsystem_vendor: None,
            subsystem_device: None,
        }];
        &DEVICES
    }
}
