// ============================================================================
// kernel/src/net/drivers/virtio_registry.rs - VirtIO-Net Driver Registry
// ============================================================================
//!
//! VirtIO-Net driver implementing the Driver trait for DriverRegistry integration.
//!
//! This wraps the existing driver_bridge functionality to work with the
//! unified DriverRegistry system.

use alloc::boxed::Box;
use kernel_api::abi::driver::DriverContext;
use kernel_api::driver::{AsyncDriver, DeviceId, Driver, DriverFuture, DriverType, DriverVersion};
use kernel_api::error::{KapiError, KapiResult};

use crate::io::iommu::types::DeviceId as IommuDeviceId;
use crate::io::virtio::init_virtio_net_for_device;

/// Async-backed VirtIO-Net driver core.
pub struct VirtioNetAsyncDriver {
    initialized: bool,
    mmio_base: Option<u64>,
    iommu_id: Option<IommuDeviceId>,
}

impl VirtioNetAsyncDriver {
    /// Create a new VirtIO-Net driver (legacy default)
    pub fn new() -> Self {
        Self {
            initialized: false,
            mmio_base: None,
            iommu_id: None,
        }
    }

    /// Create a new VirtIO-Net driver with specific device configuration
    pub fn new_with_device(mmio_base: u64, iommu_id: IommuDeviceId) -> Self {
        Self {
            initialized: false,
            mmio_base: Some(mmio_base),
            iommu_id: Some(iommu_id),
        }
    }
}

impl AsyncDriver for VirtioNetAsyncDriver {
    fn name(&self) -> &str {
        "virtio-net"
    }

    fn version(&self) -> DriverVersion {
        DriverVersion::new(0, 1, 0)
    }

    fn driver_type(&self) -> DriverType {
        DriverType::Network
    }

    fn probe(&mut self, _ctx: &mut DriverContext) -> DriverFuture<'_, KapiResult<()>> {
        Box::pin(async move {
            crate::io::log::early_print(&alloc::format!(
                "[DEBUG] VirtioNetAsyncDriver::probe mmio_base={:?} iommu_id={:?}\n",
                self.mmio_base,
                self.iommu_id
            ));

            if let (Some(base), Some(id)) = (self.mmio_base, self.iommu_id) {
                log::info!(target: "net", "Probing VirtIO-Net at {:#x}", base);
                match init_virtio_net_for_device(base as usize, id) {
                    Ok(_) => {
                        log::info!(target: "net", "VirtIO-Net device initialized");
                    }
                    Err(e) => {
                        log::error!(target: "net", "Failed to initialize VirtIO-Net device: {:?}", e);
                        return Err(KapiError::IoError);
                    }
                }
            }

            if crate::net::runtime::bridge::is_initialized() {
                self.initialized = true;
                return Ok(());
            }

            match crate::net::runtime::bridge::init_bridge() {
                Ok(()) => {
                    self.initialized = true;
                    Ok(())
                }
                Err(_) => Err(KapiError::NotFound),
            }
        })
    }

    fn start(&mut self) -> DriverFuture<'_, KapiResult<()>> {
        Box::pin(async move {
            if !self.initialized {
                return Err(KapiError::Internal(-1));
            }

            log::info!(target: "net", "VirtIO-Net driver started");
            Ok(())
        })
    }

    fn stop(&mut self) -> DriverFuture<'_, KapiResult<()>> {
        Box::pin(async move {
            log::info!(target: "net", "VirtIO-Net driver stopped");
            Ok(())
        })
    }

    fn supported_devices(&self) -> &[DeviceId] {
        // VirtIO-Net PCI device ID
        static DEVICES: [DeviceId; 1] = [DeviceId {
            vendor: 0x1AF4,
            device: 0x1000, // VirtIO-Net (legacy)
            subsystem_vendor: None,
            subsystem_device: None,
        }];
        &DEVICES
    }
}

impl Default for VirtioNetAsyncDriver {
    fn default() -> Self {
        Self::new()
    }
}

/// Sync DriverRegistry wrapper for the async VirtIO-Net core.
pub struct VirtioNetDriver {
    inner: VirtioNetAsyncDriver,
}

impl VirtioNetDriver {
    pub fn new() -> Self {
        Self {
            inner: VirtioNetAsyncDriver::new(),
        }
    }

    pub fn new_with_device(mmio_base: u64, iommu_id: IommuDeviceId) -> Self {
        Self {
            inner: VirtioNetAsyncDriver::new_with_device(mmio_base, iommu_id),
        }
    }
}

impl Driver for VirtioNetDriver {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn version(&self) -> DriverVersion {
        self.inner.version()
    }

    fn driver_type(&self) -> DriverType {
        self.inner.driver_type()
    }

    fn probe(&mut self) -> KapiResult<()> {
        let mut ctx = DriverContext::default();
        crate::task::block_on(self.inner.probe(&mut ctx))
    }

    fn start(&mut self) -> KapiResult<()> {
        crate::task::block_on(self.inner.start())
    }

    fn stop(&mut self) -> KapiResult<()> {
        crate::task::block_on(self.inner.stop())
    }

    fn remove(&mut self) -> KapiResult<()> {
        crate::task::block_on(self.inner.remove())
    }

    fn supported_devices(&self) -> &[DeviceId] {
        self.inner.supported_devices()
    }
}

impl Default for VirtioNetDriver {
    fn default() -> Self {
        Self::new()
    }
}
