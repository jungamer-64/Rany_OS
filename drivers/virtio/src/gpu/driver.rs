// ============================================================================
// drivers/virtio/src/gpu/driver.rs - VirtIO GPU DriverRegistry wrapper
// ============================================================================

use alloc::boxed::Box;
use kernel_api::abi::driver::PackedPciLocation;
use kernel_api::driver::{DeviceId, Driver, DriverType, DriverVersion};
use kernel_api::error::{KapiError, KapiResult};

use crate::gpu::init;
use crate::transport::VirtioMmioTransport;

/// VirtIO GPU Driver
pub struct VirtioGpuDriver {
    mmio_base: u64,
    pci_locator: PackedPciLocation,
    initialized: bool,
}

impl VirtioGpuDriver {
    pub fn new(mmio_base: u64, pci_locator: PackedPciLocation) -> Self {
        Self {
            mmio_base,
            pci_locator,
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
            VirtioMmioTransport::new(self.mmio_base as usize).map_err(|_| KapiError::IoError)?
        };

        match init(Box::new(transport), self.pci_locator) {
            Ok(()) => {
                self.initialized = true;
                Ok(())
            }
            Err(err) => {
                log::error!(target: "virtio_gpu", "Failed to initialize device: {:?}", err);
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
            device: 0x1050,
            subsystem_vendor: None,
            subsystem_device: None,
        }];
        &DEVICES
    }
}
