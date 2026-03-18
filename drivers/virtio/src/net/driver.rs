use alloc::sync::Arc;
use kernel_api::abi::driver::PackedPciLocation;
use kernel_api::driver::{DeviceId, Driver, DriverType, DriverVersion};
use kernel_api::error::{KapiError, KapiResult};
use kernel_api::netdev::NetDevicePort;

use super::{NetRuntime, init_virtio_net_for_device_at_index, virtio_net_driver_adapter};

pub type VirtioNetRuntimeFactory = fn(u8, PackedPciLocation) -> KapiResult<Arc<dyn NetRuntime>>;
pub type VirtioNetPostProbe = fn(u8, Arc<dyn NetDevicePort>) -> KapiResult<()>;

#[derive(Clone, Copy)]
pub struct VirtioNetDriverHooks {
    pub runtime_factory: VirtioNetRuntimeFactory,
    pub post_probe: VirtioNetPostProbe,
}

impl VirtioNetDriverHooks {
    pub const fn new(runtime_factory: VirtioNetRuntimeFactory, post_probe: VirtioNetPostProbe) -> Self {
        Self {
            runtime_factory,
            post_probe,
        }
    }
}

#[derive(Clone, Copy)]
enum ProbeSource {
    Existing,
    Mmio {
        mmio_base: u64,
        pci_locator: PackedPciLocation,
    },
}

/// DriverRegistry wrapper for VirtIO-Net.
///
/// The portable driver core stays in `virtio_driver`, while the kernel injects
/// runtime allocation and post-probe registration hooks.
pub struct VirtioNetDriver {
    index: u8,
    hooks: VirtioNetDriverHooks,
    probe_source: ProbeSource,
    initialized: bool,
}

impl VirtioNetDriver {
    pub fn new(index: u8, hooks: VirtioNetDriverHooks) -> Self {
        Self {
            index,
            hooks,
            probe_source: ProbeSource::Existing,
            initialized: false,
        }
    }

    pub fn new_with_device(
        index: u8,
        mmio_base: u64,
        pci_locator: PackedPciLocation,
        hooks: VirtioNetDriverHooks,
    ) -> Self {
        Self {
            index,
            hooks,
            probe_source: ProbeSource::Mmio {
                mmio_base,
                pci_locator,
            },
            initialized: false,
        }
    }

    fn initialize_if_needed(&self) -> KapiResult<()> {
        let ProbeSource::Mmio {
            mmio_base,
            pci_locator,
        } = self.probe_source
        else {
            return Ok(());
        };

        let runtime = (self.hooks.runtime_factory)(self.index, pci_locator)?;
        unsafe { init_virtio_net_for_device_at_index(self.index, mmio_base as usize, runtime) }
            .map_err(|err| {
                log::error!(
                    target: "virtio_net",
                    "Failed to initialize VirtIO-Net index {}: {:?}",
                    self.index,
                    err
                );
                KapiError::IoError
            })
    }
}

impl Driver for VirtioNetDriver {
    fn name(&self) -> &str {
        "virtio-net"
    }

    fn version(&self) -> DriverVersion {
        DriverVersion::new(0, 1, 0)
    }

    fn driver_type(&self) -> DriverType {
        DriverType::Network
    }

    fn probe(&mut self) -> KapiResult<()> {
        self.initialize_if_needed()?;

        let adapter = virtio_net_driver_adapter(self.index);
        if adapter.info().flags == 0 {
            return Err(KapiError::NotFound);
        }

        (self.hooks.post_probe)(self.index, adapter)?;
        self.initialized = true;
        Ok(())
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
                device: 0x1000,
                subsystem_vendor: None,
                subsystem_device: None,
            },
            DeviceId {
                vendor: 0x1AF4,
                device: 0x1041,
                subsystem_vendor: None,
                subsystem_device: None,
            },
        ];
        &DEVICES
    }
}
