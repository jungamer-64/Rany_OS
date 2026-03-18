use kernel_api::abi::driver::PackedPciLocation;
use kernel_api::driver::{DeviceId, Driver, DriverType, DriverVersion};
use kernel_api::error::{KapiError, KapiResult};

use crate::blk::init_virtio_blk_for_device_at_index;

/// VirtIO Block Driver
pub struct VirtioBlkDriver {
    mmio_base: u64,
    pci_locator: PackedPciLocation,
    initialized: bool,
}

impl VirtioBlkDriver {
    pub fn new(mmio_base: u64, pci_locator: PackedPciLocation) -> Self {
        Self {
            mmio_base,
            pci_locator,
            initialized: false,
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
        let res =
            unsafe { init_virtio_blk_for_device_at_index(0, self.mmio_base, self.pci_locator) };

        match res {
            Ok(()) => {
                self.initialized = true;
                Ok(())
            }
            Err(err) => {
                log::error!(target: "virtio_blk", "Failed to initialize device: {:?}", err);
                Err(KapiError::IoError)
            }
        }
    }

    fn start(&mut self) -> KapiResult<()> {
        if !self.initialized {
            return Err(KapiError::Internal(-1));
        }
        Ok(())
    }

    fn stop(&mut self) -> KapiResult<()> {
        Ok(())
    }

    fn supported_devices(&self) -> &[DeviceId] {
        static DEVICES: [DeviceId; 2] = [
            DeviceId {
                vendor: 0x1AF4,
                device: 0x1001,
                subsystem_vendor: None,
                subsystem_device: None,
            },
            DeviceId {
                vendor: 0x1AF4,
                device: 0x1042,
                subsystem_vendor: None,
                subsystem_device: None,
            },
        ];
        &DEVICES
    }
}
