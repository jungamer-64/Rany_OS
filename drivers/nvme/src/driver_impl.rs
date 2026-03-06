use crate::polling_driver::NvmePollingDriver;
use kernel_api::KapiResult;
use kernel_api::driver::{Driver, DriverType};
use kernel_api::abi::driver::DriverContext;

use spin::Mutex;

pub struct NvmeDriverWrapper {
    inner: Mutex<NvmePollingDriver>,
}

impl NvmeDriverWrapper {
    pub fn new(bar0: u64, cores: u32) -> Self {
        Self {
            inner: Mutex::new(NvmePollingDriver::new(bar0, cores, None)),
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
        let mut driver = self.inner.lock();
        driver.init().map_err(|_| kernel_api::KapiError::IoError)
    }
}

// ============================================================================
// ABI Export for Dynamic Cell Loading
// ============================================================================
//
// Note: Full standalone Cell build requires:
// - #[global_allocator] - provided by kernel when statically linked
// - #[panic_handler] - provided by kernel when statically linked
//
// For now, ABI export is enabled when building with kernel (export_driver_entry feature)
// The Cell loader can resolve the _exorust_driver_entry symbol from the loaded ELF.

/// ABI-compatible probe function for dynamic loading
fn abi_probe(ctx: &mut DriverContext) -> i32 {
    // In Cell mode, this will use the kernel's allocator via kernel_api
    // For now, just initialize the driver using the provided context address
    static mut DRIVER: Option<NvmePollingDriver> = None;

    unsafe {
        DRIVER = Some(NvmePollingDriver::new(ctx.device_address, 1, None));
        if let Some(ref mut driver) = DRIVER {
            if driver.init().is_err() {
                return -1;
            }
        }
    }
    0
}

/// ABI-compatible remove function for dynamic loading
fn abi_remove(_ctx: &mut DriverContext) -> i32 {
    0
}

/// ABI-compatible start function
fn abi_start(_ctx: &mut DriverContext) -> i32 {
    0
}

/// ABI-compatible stop function
fn abi_stop(_ctx: &mut DriverContext) -> i32 {
    0
}

/// Driver name for ABI
fn driver_name() -> &'static str {
    "nvme"
}

// Export the driver entry point
// Only when export_driver_entry feature is enabled
kernel_api::export_driver!(
    probe: abi_probe,
    remove: abi_remove,
    name: driver_name,
    driver_type: (kernel_api::abi::driver::AbiDriverType::Block as u32),
    version: 0x00010000_u64,
    start: abi_start,
    stop: abi_stop,
);
