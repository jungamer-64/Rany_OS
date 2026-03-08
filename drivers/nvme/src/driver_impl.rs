use crate::polling_driver::NvmePollingDriver;
use kernel_api::KapiResult;
use kernel_api::abi::driver::DriverContext;
use kernel_api::driver::{Driver, DriverType};

use exorust_sync::PoisonLock;

pub struct NvmeDriverWrapper {
    inner: PoisonLock<NvmePollingDriver>,
}

impl NvmeDriverWrapper {
    pub fn new(bar0: u64, cores: u32) -> Self {
        Self {
            inner: PoisonLock::new(NvmePollingDriver::new(bar0, cores, None)),
        }
    }
}

impl Driver for NvmeDriverWrapper {
    fn name(&self) -> &str {
        "NVMe Polling Driver"
    }

    fn driver_type(&self) -> DriverType {
        DriverType::Block
    }

    fn probe(&mut self) -> KapiResult<()> {
        let mut driver = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        driver.init().map_err(|_| kernel_api::KapiError::IoError)
    }
}

// ============================================================================
// ABI Export for Dynamic Cell Loading
// ============================================================================

fn abi_probe(ctx: &mut DriverContext) -> i32 {
    static mut DRIVER: Option<NvmePollingDriver> = None;
    unsafe {
        DRIVER = Some(NvmePollingDriver::new(ctx.device_address, 1, None));
        if let Some(ref mut driver) = DRIVER {
            if driver.init().is_err() { return -1; }
        }
    }
    0
}

fn abi_remove(_ctx: &mut DriverContext) -> i32 { 0 }
fn abi_start(_ctx: &mut DriverContext) -> i32 { 0 }
fn abi_stop(_ctx: &mut DriverContext) -> i32 { 0 }
fn driver_name() -> &'static str { "nvme" }

kernel_api::export_driver!(
    probe: abi_probe,
    remove: abi_remove,
    name: driver_name,
    driver_type: (kernel_api::abi::driver::AbiDriverType::Block as u32),
    version: 0x00010000_u64,
    start: abi_start,
    stop: abi_stop,
);
