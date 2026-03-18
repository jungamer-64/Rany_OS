// ============================================================================
// drivers/virtio/src/input/driver.rs - VirtIO Input Driver
// ============================================================================
//!
//! Driver trait implementation for VirtIO Input Device.
//! This wrapper allows the driver to be managed by the DriverRegistry.

use kernel_api::abi::driver::PackedPciLocation;
use kernel_api::driver::{DeviceId, Driver, DriverType, DriverVersion};
use kernel_api::error::{KapiError, KapiResult};

use crate::input::init_virtio_input_for_device_at_index;

/// VirtIO Input Driver
pub struct VirtioInputDriver {
    mmio_base: u64,
    pci_locator: PackedPciLocation,
    initialized: bool,
}

impl VirtioInputDriver {
    /// Create a new VirtIO Input Driver instance
    pub fn new(mmio_base: u64, pci_locator: PackedPciLocation) -> Self {
        Self {
            mmio_base,
            pci_locator,
            initialized: false,
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
            unsafe { init_virtio_input_for_device_at_index(0, self.mmio_base, self.pci_locator) };

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
