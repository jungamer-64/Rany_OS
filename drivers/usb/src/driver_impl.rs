//! USB Driver Wrapper for Driver Trait
//!
//! Implements the kernel_api::Driver trait for xHCI USB controller.

extern crate alloc;

use alloc::sync::Arc;
use kernel_api::driver::{Driver, DriverType};
use kernel_api::{KapiError, KapiResult};

use crate::xhci::{XhciController, init_from_pci};

/// USB driver wrapper implementing the Driver trait
pub struct UsbDriverWrapper {
    base_addr: u64,
    controller: Option<Arc<XhciController>>,
}

impl UsbDriverWrapper {
    /// Create a new USB driver wrapper
    pub fn new(base_addr: u64) -> Self {
        Self {
            base_addr,
            controller: None,
        }
    }
}

impl Driver for UsbDriverWrapper {
    fn name(&self) -> &str {
        "usb_xhci"
    }

    fn driver_type(&self) -> DriverType {
        DriverType::Usb
    }

    fn probe(&mut self) -> KapiResult<()> {
        let controller = init_from_pci(self.base_addr).map_err(|_| KapiError::Internal(-1))?;

        self.controller = Some(controller);
        Ok(())
    }

    fn start(&mut self) -> KapiResult<()> {
        // Controller is already started in probe via init_from_pci
        Ok(())
    }

    fn stop(&mut self) -> KapiResult<()> {
        // USB controller doesn't have explicit stop
        Ok(())
    }
}
