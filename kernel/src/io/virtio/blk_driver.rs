// ============================================================================
// src/io/virtio/blk_driver.rs - VirtIO Block Driver
// ============================================================================
//!
//! Driver trait implementation for VirtIO Block Device.
//! This wrapper allows the driver to be managed by the DriverRegistry.

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::any::Any;

use kernel_api::driver::{DeviceId, Driver, DriverType, DriverVersion};
use kernel_api::error::{KapiError, KapiResult};

use crate::io::iommu::types::DeviceId as IommuDeviceId;
use crate::io::virtio::{VirtioBlkDevice, init_virtio_blk_for_device};

/// VirtIO Block Driver
pub struct VirtioBlkDriver {
    mmio_base: u64,
    iommu_id: IommuDeviceId,
    initialized: bool,
    device: Option<Arc<VirtioBlkDevice>>,
}

impl VirtioBlkDriver {
    /// Create a new VirtIO Block Driver instance
    pub fn new(mmio_base: u64, iommu_id: IommuDeviceId) -> Self {
        Self {
            mmio_base,
            iommu_id,
            initialized: false,
            device: None,
        }
    }
}

impl Driver for VirtioBlkDriver {
    fn name(&self) -> &str {
        "virtio-blk"
    }

    fn version(&self) -> DriverVersion {
        DriverVersion::new(0, 1, 0)
    }

    fn driver_type(&self) -> DriverType {
        DriverType::Block
    }

    fn probe(&mut self) -> KapiResult<()> {
        log::info!(target: "virtio_blk", "Probing VirtIO-Blk at {:#x}", self.mmio_base);

        // Initialize the device
        // Note: This relies on the unsafe init function from blk.rs for now.
        // In the future, we should move the initialization logic here or make it safer.
        let res = unsafe {
            init_virtio_blk_for_device(self.mmio_base, self.iommu_id)
        };

        match res {
            Ok(_) => {
                self.initialized = true;
                // Get the global instance if needed, but for now init_virtio_blk populates the global.
                // Ideally we should own the device here.
                // For compatibility, we assume the global static is set by the init function.
                Ok(())
            }
            Err(e) => {
                log::error!(target: "virtio_blk", "Failed to initialize device: {:?}", e);
                Err(KapiError::IoError)
            }
        }
    }

    fn start(&mut self) -> KapiResult<()> {
        if !self.initialized {
            return Err(KapiError::Internal(-1));
        }
        log::info!(target: "virtio_blk", "Driver started");
        Ok(())
    }

    fn stop(&mut self) -> KapiResult<()> {
        // Implement stop/cleanup logic if needed
        Ok(())
    }

    fn supported_devices(&self) -> &[DeviceId] {
        static DEVICES: [DeviceId; 2] = [
            DeviceId {
                vendor: 0x1AF4,
                device: 0x1001, // Block Device
                subsystem_vendor: None,
                subsystem_device: None,
            },
            DeviceId {
                vendor: 0x1AF4,
                device: 0x1042, // Block Device (Modern)
                subsystem_vendor: None,
                subsystem_device: None,
            },
        ];
        &DEVICES
    }
    
    // fn as_any removed - not in trait
}
