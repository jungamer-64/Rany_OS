// ============================================================================
// drivers/virtio/src/balloon/driver.rs - VirtIO Balloon Driver
// ============================================================================
//!
//! Driver trait implementation for VirtIO Balloon Device.
//! This wrapper allows the driver to be managed by the DriverRegistry.

use kernel_api::driver::{DeviceId, Driver, DriverType, DriverVersion};
use kernel_api::error::{KapiError, KapiResult};
use kernel_api::abi::driver::PackedPciLocation;

use super::init_virtio_balloon_for_device_at_index;

/// VirtIO Balloon Driver
pub struct VirtioBalloonDriver {
    mmio_base: u64,
    pci_locator: PackedPciLocation,
    initialized: bool,
}

impl VirtioBalloonDriver {
    /// Create a new VirtIO Balloon Driver instance
    pub fn new(mmio_base: u64, pci_locator: PackedPciLocation) -> Self {
        Self {
            mmio_base,
            pci_locator,
            initialized: false,
        }
    }
}

impl Driver for VirtioBalloonDriver {
    fn name(&self) -> &str {
        "virtio-balloon"
    }

    fn version(&self) -> DriverVersion {
        DriverVersion::new(0, 1, 0)
    }

    fn driver_type(&self) -> DriverType {
        DriverType::Other
    }

    fn probe(&mut self) -> KapiResult<()> {
        log::info!(target: "virtio_balloon", "Probing VirtIO-Balloon at {:#x}", self.mmio_base);

        let res =
            unsafe { init_virtio_balloon_for_device_at_index(0, self.mmio_base, self.pci_locator) };

        match res {
            Ok(_) => {
                self.initialized = true;
                Ok(())
            }
            Err(e) => {
                log::error!(target: "virtio_balloon", "Failed to initialize device: {:?}", e);
                Err(KapiError::IoError)
            }
        }
    }

    fn start(&mut self) -> KapiResult<()> {
        if !self.initialized {
            return Err(KapiError::Internal(-1));
        }
        log::info!(target: "virtio_balloon", "Driver started");
        Ok(())
    }

    fn stop(&mut self) -> KapiResult<()> {
        Ok(())
    }

    fn supported_devices(&self) -> &[DeviceId] {
        static DEVICES: [DeviceId; 2] = [
            DeviceId {
                vendor: 0x1AF4,
                device: 0x1005, // Balloon Device (Transitional)
                subsystem_vendor: None,
                subsystem_device: None,
            },
            DeviceId {
                vendor: 0x1AF4,
                device: 0x1045, // Balloon Device (Modern)
                subsystem_vendor: None,
                subsystem_device: None,
            },
        ];
        &DEVICES
    }
}
