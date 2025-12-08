// use alloc::boxed::Box;
use alloc::sync::Arc;
use spin::Mutex;

use kernel_api::driver::{Driver, DriverType};
use kernel_api::KapiResult;

use super::controller::{AhciController, init_from_pci};

pub struct AhciDriverWrapper {
    base_addr: u64,
    irq: u8,
    controller: Option<Arc<Mutex<AhciController>>>,
}

impl AhciDriverWrapper {
    pub fn new(base_addr: u64, irq: u8) -> Self {
        Self {
            base_addr,
            irq,
            controller: None,
        }
    }
}

impl Driver for AhciDriverWrapper {
    fn name(&self) -> &str {
        "ahci"
    }

    fn driver_type(&self) -> DriverType {
        DriverType::Block // AHCI is primary storage
    }

    fn probe(&mut self) -> KapiResult<()> {
        let controller = init_from_pci(self.base_addr)
            .map_err(|_| kernel_api::KapiError::Internal(-1))?;
        
        self.controller = Some(controller);
        Ok(())
    }

    fn start(&mut self) -> KapiResult<()> {
        if let Some(_ctrl) = &self.controller {
             // Example: registering interrupt handler would go here
        }
        Ok(())
    }

    fn stop(&mut self) -> KapiResult<()> {
        Ok(())
    }
}
