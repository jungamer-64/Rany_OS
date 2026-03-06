// ============================================================================
// drivers/gpu/src/ffi.rs - ABI-Stable Driver Export
// ============================================================================
//!
//! FFI adapter for the GPU driver.

use kernel_api::driver::DriverType;
use kernel_api::abi::driver::{
    DRIVER_ABI_VERSION, DriverCapabilities, DriverContext, DriverVTable, pack_version,
};

extern "C" fn gpu_probe(_ctx: *mut DriverContext) -> i32 {
    0
}
extern "C" fn gpu_start(_ctx: *mut DriverContext) -> i32 {
    0
}
extern "C" fn gpu_stop(_ctx: *mut DriverContext) -> i32 {
    0
}
extern "C" fn gpu_remove(_ctx: *mut DriverContext) -> i32 {
    0
}
extern "C" fn gpu_name() -> *const u8 {
    b"gpu\0".as_ptr()
}
extern "C" fn gpu_name_len() -> usize {
    3
}
extern "C" fn gpu_driver_type() -> u32 {
    DriverType::Graphics as u32
}
extern "C" fn gpu_version() -> u64 {
    pack_version(0, 1, 0)
}

extern "C" fn gpu_request_capabilities(caps: *mut DriverCapabilities) {
    if !caps.is_null() {
        unsafe {
            (*caps).needs_dma = true;
            (*caps).needs_mmio = true;
        }
    }
}

#[cfg(feature = "export_driver_entry")]
#[export_name = "_exorust_driver_entry"]
pub extern "C" fn _exorust_driver_entry() -> *const DriverVTable {
    static VTABLE: DriverVTable = DriverVTable::new(
        DRIVER_ABI_VERSION,
        gpu_probe,
        gpu_start,
        gpu_stop,
        gpu_remove,
        gpu_name,
        gpu_name_len,
        gpu_driver_type,
        gpu_version,
        Some(gpu_request_capabilities),
        None,
    );
    &VTABLE
}
fn gpu_driver_vtable() -> *const DriverVTable {
    static VTABLE: DriverVTable = DriverVTable::new(
        DRIVER_ABI_VERSION,
        gpu_probe,
        gpu_start,
        gpu_stop,
        gpu_remove,
        gpu_name,
        gpu_name_len,
        gpu_driver_type,
        gpu_version,
        None,
        None,
    );

    &VTABLE
}

#[cfg(not(feature = "export_driver_entry"))]
#[allow(non_snake_case)]
pub(crate) fn _exorust_driver_entry_unique() -> *const DriverVTable {
    gpu_driver_vtable()
}
