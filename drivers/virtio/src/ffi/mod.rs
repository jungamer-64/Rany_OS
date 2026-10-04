//! The service host retains each cell instance and its registered callback
//! runtimes through acknowledged removal. Lifecycle waits run as host-owned
//! futures; cancellation leaves device and DMA resources in that instance.
#![deny(unsafe_code)]

use kernel_api::abi::driver::DriverContext;
use kernel_api::driver::{AsyncDriver, DriverType};
use kernel_api::{KapiError, KapiResult};

mod block;
mod net;

enum Device {
    Unprobed,
    Block(block::BlockCell),
    Network(net::NetCell),
}

struct VirtioCell {
    device: Device,
}

impl VirtioCell {
    const fn new() -> Self {
        Self { device: Device::Unprobed }
    }
}

impl AsyncDriver for VirtioCell {
    fn name(&self) -> &str {
        "virtio"
    }
    fn driver_type(&self) -> DriverType {
        match self.device {
            Device::Block(_) => DriverType::Block,
            Device::Network(_) => DriverType::Network,
            Device::Unprobed => DriverType::Other,
        }
    }
    async fn probe(&mut self, context: &mut DriverContext) -> KapiResult<()> {
        if !matches!(self.device, Device::Unprobed) {
            return Err(KapiError::AlreadyExists);
        }
        if context.vendor_id != 0x1af4 || context.pci_location().is_null() {
            return Err(KapiError::NotFound);
        }
        self.device = match context.device_id {
            0x1000 | 0x1041 => Device::Network(net::NetCell::new()),
            0x1001 | 0x1042 => Device::Block(block::BlockCell::new()),
            _ => return Err(KapiError::NotSupported),
        };
        match &mut self.device {
            Device::Block(cell) => cell.probe(context).await,
            Device::Network(cell) => cell.probe(context).await,
            Device::Unprobed => Err(KapiError::NotFound),
        }
    }
    async fn start(&mut self) -> KapiResult<()> {
        match &mut self.device {
            Device::Block(cell) => cell.start().await,
            Device::Network(cell) => cell.start().await,
            Device::Unprobed => Err(KapiError::NotFound),
        }
    }
    async fn stop(&mut self) -> KapiResult<()> {
        match &mut self.device {
            Device::Block(cell) => cell.stop().await,
            Device::Network(cell) => cell.stop().await,
            Device::Unprobed => Ok(()),
        }
    }
    async fn remove(&mut self) -> KapiResult<()> {
        match &mut self.device {
            Device::Block(cell) => cell.remove().await?,
            Device::Network(cell) => cell.remove().await?,
            Device::Unprobed => {}
        }
        self.device = Device::Unprobed;
        Ok(())
    }
}

#[allow(unsafe_code, reason = "export_async_driver owns the permanent foreign lifecycle callbacks and retained host vtable")]
mod exports {
    use super::*;
    kernel_api::export_async_driver! {
        type: VirtioCell,
        constructor: VirtioCell::new(),
        name: || b"virtio",
        driver_type: DriverType::Other,
        version: kernel_api::abi::driver::pack_version(0, 1, 0)
    }
}
pub use exports::standalone_driver_vtable;
