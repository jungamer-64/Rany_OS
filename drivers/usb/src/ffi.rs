// ============================================================================
// drivers/usb/src/ffi.rs - ABI-Stable Driver Export
// ============================================================================
//!
//! FFI adapter for the USB xHCI driver.
//!
//! Exports a C-compatible `DriverVTable` for dynamic loading.

use kernel_api::driver_abi::{DriverContext, DriverVTable, DriverCapabilities, DRIVER_ABI_VERSION, pack_version};
use kernel_api::driver::DriverType;

// ============================================================================
// Driver Lifecycle Functions
// ============================================================================

/// Probe function for USB xHCI controller.
extern "C" fn usb_probe(_ctx: *mut DriverContext) -> i32 {
    // TODO: Initialize xHCI controller using ctx.device_address (BAR0)
    // For now, return success
    0
}

/// Start function for USB driver.
extern "C" fn usb_start(_ctx: *mut DriverContext) -> i32 {
    // TODO: Start controller, enable ports
    0
}

/// Stop function for USB driver.
extern "C" fn usb_stop(_ctx: *mut DriverContext) -> i32 {
    // TODO: Stop controller, disable ports
    0
}

/// Remove/cleanup function for USB driver.
extern "C" fn usb_remove(_ctx: *mut DriverContext) -> i32 {
    // TODO: Clean up resources
    0
}

// ============================================================================
// Driver Metadata Functions
// ============================================================================

extern "C" fn usb_name() -> *const u8 {
    b"usb_xhci\0".as_ptr()
}

extern "C" fn usb_name_len() -> usize {
    8
}

extern "C" fn usb_driver_type() -> u32 {
    DriverType::Usb as u32
}

extern "C" fn usb_version() -> u64 {
    pack_version(0, 1, 0)
}

extern "C" fn usb_request_capabilities(caps: *mut DriverCapabilities) {
    if !caps.is_null() {
        unsafe {
            (*caps).needs_dma = true;
            (*caps).needs_irq = true;
            (*caps).needs_mmio = true;
        }
    }
}

// ============================================================================
// Driver Entry Point
// ============================================================================

/// The ABI-stable driver entry point.
#[unsafe(no_mangle)]
pub extern "C" fn _exorust_driver_entry() -> *const DriverVTable {
    static VTABLE: DriverVTable = DriverVTable::new(
        DRIVER_ABI_VERSION,
        usb_probe,
        usb_start,
        usb_stop,
        usb_remove,
        usb_name,
        usb_name_len,
        usb_driver_type,
        usb_version,
        Some(usb_request_capabilities),
        None, // handle_irq - TODO: implement interrupt handler
    );

    &VTABLE
}
