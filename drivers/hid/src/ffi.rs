// ============================================================================
// drivers/hid/src/ffi.rs - ABI-Stable Driver Export
// ============================================================================
//!
//! FFI adapter for the HID (Human Interface Device) driver.

use kernel_api::driver_abi::{DriverContext, DriverVTable, DriverCapabilities, DRIVER_ABI_VERSION, pack_version};
use kernel_api::driver::DriverType;

extern "C" fn hid_probe(_ctx: *mut DriverContext) -> i32 { 0 }
extern "C" fn hid_start(_ctx: *mut DriverContext) -> i32 { 0 }
extern "C" fn hid_stop(_ctx: *mut DriverContext) -> i32 { 0 }
extern "C" fn hid_remove(_ctx: *mut DriverContext) -> i32 { 0 }
extern "C" fn hid_name() -> *const u8 { b"hid\0".as_ptr() }
extern "C" fn hid_name_len() -> usize { 3 }
extern "C" fn hid_driver_type() -> u32 { DriverType::Hid as u32 }
extern "C" fn hid_version() -> u64 { pack_version(0, 1, 0) }

extern "C" fn hid_request_capabilities(caps: *mut DriverCapabilities) {
    if !caps.is_null() {
        unsafe {
            (*caps).needs_irq = true;
            (*caps).needs_io_ports = true;
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _exorust_driver_entry() -> *const DriverVTable {
    static VTABLE: DriverVTable = DriverVTable::new(
        DRIVER_ABI_VERSION,
        hid_probe, hid_start, hid_stop, hid_remove,
        hid_name, hid_name_len, hid_driver_type, hid_version,
        Some(hid_request_capabilities), None,
    );
    &VTABLE
}
