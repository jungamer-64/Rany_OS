// ============================================================================
// drivers/hid/src/ffi.rs - ABI-Stable Driver Export
// ============================================================================
//!
//! FFI adapter for the HID (Human Interface Device) driver.

use kernel_api::abi::driver::{
    DRIVER_ABI_VERSION, DriverCapabilities, DriverContext, DriverVTable, DriverVTableFns,
    pack_version,
};
use kernel_api::driver::DriverType;

extern "C" fn hid_probe(_ctx: *mut DriverContext) -> i32 {
    0
}
extern "C" fn hid_start(_ctx: *mut DriverContext) -> i32 {
    0
}
extern "C" fn hid_stop(_ctx: *mut DriverContext) -> i32 {
    0
}
extern "C" fn hid_remove(_ctx: *mut DriverContext) -> i32 {
    0
}
extern "C" fn hid_name() -> *const u8 {
    b"hid\0".as_ptr()
}
extern "C" fn hid_name_len() -> usize {
    3
}
extern "C" fn hid_driver_type() -> u32 {
    DriverType::Hid as u32
}
extern "C" fn hid_version() -> u64 {
    pack_version(0, 1, 0)
}

extern "C" fn hid_request_capabilities(caps: *mut DriverCapabilities) {
    if !caps.is_null() {
        unsafe {
            (*caps).needs_irq = true;
            (*caps).needs_io_ports = true;
        }
    }
}

fn hid_driver_vtable() -> *const DriverVTable {
    static VTABLE: DriverVTable = DriverVTable::new(
        DRIVER_ABI_VERSION,
        DriverVTableFns {
            probe: hid_probe,
            start: hid_start,
            stop: hid_stop,
            remove: hid_remove,
            name: hid_name,
            name_len: hid_name_len,
            driver_type: hid_driver_type,
            version: hid_version,
            request_capabilities: Some(hid_request_capabilities),
            handle_irq: None,
        },
    );
    &VTABLE
}

#[cfg(feature = "export_driver_entry")]
#[unsafe(export_name = "_exorust_driver_entry")]
pub extern "C" fn _exorust_driver_entry() -> *const DriverVTable {
    hid_driver_vtable()
}

#[cfg(not(feature = "export_driver_entry"))]
pub(crate) fn exorust_driver_entry_unique() -> *const DriverVTable {
    hid_driver_vtable()
}
