// ============================================================================
// drivers/usb/src/ffi.rs - ABI-Stable Driver Export
// ============================================================================
//!
//! FFI adapter for the USB xHCI driver.
//!
//! Exports a C-compatible `DriverVTable` for dynamic loading.

use kernel_api::abi::driver::{
    DRIVER_ABI_VERSION, DriverCapabilities, DriverContext, DriverVTable, pack_version,
};
use kernel_api::driver::Driver;
use kernel_api::driver::DriverType;

use crate::driver_impl::UsbDriverWrapper;

static mut USB_DRIVER: Option<UsbDriverWrapper> = None;

unsafe fn with_usb_driver<R>(f: impl FnOnce(&mut UsbDriverWrapper) -> R) -> Option<R> {
    let slot = core::ptr::addr_of_mut!(USB_DRIVER);
    unsafe { (*slot).as_mut().map(f) }
}

// ============================================================================
// Driver Lifecycle Functions
// ============================================================================

/// Probe function for USB xHCI controller.
extern "C" fn usb_probe(ctx: *mut DriverContext) -> i32 {
    if ctx.is_null() {
        return -1;
    }

    let ctx = unsafe { &mut *ctx };
    unsafe {
        core::ptr::write(
            core::ptr::addr_of_mut!(USB_DRIVER),
            Some(UsbDriverWrapper::new(
                ctx.device_address,
                ctx.pci_location(),
            )),
        );
        match with_usb_driver(|driver| driver.probe()) {
            Some(Ok(())) => 0,
            _ => -1,
        }
    }
}

/// Start function for USB driver.
extern "C" fn usb_start(_ctx: *mut DriverContext) -> i32 {
    unsafe {
        match with_usb_driver(|driver| driver.start()) {
            Some(Ok(())) => 0,
            _ => -1,
        }
    }
}

/// Stop function for USB driver.
extern "C" fn usb_stop(_ctx: *mut DriverContext) -> i32 {
    unsafe {
        match with_usb_driver(|driver| driver.stop()) {
            Some(Ok(())) => 0,
            _ => -1,
        }
    }
}

/// Remove/cleanup function for USB driver.
extern "C" fn usb_remove(_ctx: *mut DriverContext) -> i32 {
    unsafe {
        let slot = core::ptr::addr_of_mut!(USB_DRIVER);
        let _ = core::ptr::replace(slot, None);
    }
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
        // SAFETY: We checked that caps is not null. Caller guarantees it points to valid memory.
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

/// Inner implementation returning pointer to the VTABLE.
fn usb_driver_vtable() -> *const DriverVTable {
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

// Export canonical symbol only when the export_driver_entry feature is enabled
#[cfg(feature = "export_driver_entry")]
#[unsafe(export_name = "_exorust_driver_entry")]
pub extern "C" fn _exorust_driver_entry() -> *const DriverVTable {
    usb_driver_vtable()
}

// When compiled as part of the kernel (not exporting the canonical symbol),
// emit a unique name to avoid collisions across multiple statically linked
// drivers. We use unsafe(concat!(...)) for the compile-time concatenation.
#[cfg(not(feature = "export_driver_entry"))]
#[allow(non_snake_case)]
#[allow(clippy::missing_safety_doc)]
pub(crate) fn _exorust_driver_entry_unique() -> *const DriverVTable {
    usb_driver_vtable()
}
