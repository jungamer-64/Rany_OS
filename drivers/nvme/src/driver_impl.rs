use crate::polling_driver::NvmePollingDriver;
use kernel_api::KapiResult;
use kernel_api::driver::{Driver, DriverType};
use spin::Mutex;

pub struct NvmeDriverWrapper {
    inner: Mutex<NvmePollingDriver>,
}

impl NvmeDriverWrapper {
    pub fn new(bar0: u64, cores: u32) -> Self {
        Self {
            inner: Mutex::new(NvmePollingDriver::new(bar0, cores)),
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
