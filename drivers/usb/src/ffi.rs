// ============================================================================
// drivers/usb/src/ffi.rs - ABI-Stable Driver Export
// ============================================================================
//!
//! FFI adapter for the USB xHCI driver.
//!
//! Exports a C-compatible `DriverVTable` for dynamic loading.

use exorust_sync::Mutex;
use kernel_api::abi::driver::{
    DRIVER_ABI_VERSION, DriverCapabilities, DriverContext, DriverVTable, DriverVTableFns,
    pack_version,
};
use kernel_api::driver::Driver;
use kernel_api::driver::DriverType;

use crate::driver_impl::UsbDriverWrapper;

static USB_DRIVER: Mutex<Option<UsbDriverWrapper>> = Mutex::new(None);

fn with_usb_driver<R>(f: impl FnOnce(&mut UsbDriverWrapper) -> R) -> Option<R> {
    USB_DRIVER.lock().as_mut().map(f)
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
    let mut slot = USB_DRIVER.lock();
    if slot.is_some() {
        return -1;
    }
    *slot = Some(UsbDriverWrapper::new(ctx.pci_location()));
    match slot.as_mut().map(Driver::probe) {
        Some(Ok(())) => 0,
        _ => -1,
    }
}

/// Start function for USB driver.
extern "C" fn usb_start(_ctx: *mut DriverContext) -> i32 {
    match with_usb_driver(|driver| driver.start()) {
        Some(Ok(())) => 0,
        _ => -1,
    }
}

/// Stop function for USB driver.
extern "C" fn usb_stop(_ctx: *mut DriverContext) -> i32 {
    match with_usb_driver(|driver| driver.stop()) {
        Some(Ok(())) => 0,
        _ => -1,
    }
}

/// Remove/cleanup function for USB driver.
extern "C" fn usb_remove(_ctx: *mut DriverContext) -> i32 {
    let mut slot = USB_DRIVER.lock();
    match slot.as_mut().map(Driver::remove) {
        Some(Ok(())) => {
            drop(slot.take());
            0
        }
        None => 0,
        Some(Err(_)) => -1,
    }
}

extern "C" fn usb_handle_irq(ctx: *mut DriverContext) -> bool {
    if ctx.is_null() {
        return false;
    }
    // SAFETY: the relay framework retains the initialized DriverContext for
    // this synchronous callback. Only the observed vector is copied here.
    let irq = unsafe { (*ctx).irq };
    with_usb_driver(|driver| driver.handle_irq(irq)).unwrap_or(false)
}

// ============================================================================
// Driver Metadata Functions
// ============================================================================

extern "C" fn usb_name() -> *const u8 {
    c"usb_xhci".as_ptr().cast()
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

/// Public vtable helper used by standalone wrapper cells.
pub fn standalone_driver_vtable() -> *const DriverVTable {
    static VTABLE: DriverVTable = DriverVTable::new(
        DRIVER_ABI_VERSION,
        DriverVTableFns {
            probe: usb_probe,
            start: usb_start,
            stop: usb_stop,
            remove: usb_remove,
            name: usb_name,
            name_len: usb_name_len,
            driver_type: usb_driver_type,
            version: usb_version,
            request_capabilities: Some(usb_request_capabilities),
            handle_irq: Some(usb_handle_irq),
        },
    );

    &VTABLE
}

// Export canonical symbol only when the export_driver_entry feature is enabled
#[cfg(feature = "export_driver_entry")]
#[unsafe(export_name = "_exorust_driver_entry")]
pub extern "C" fn _exorust_driver_entry() -> *const DriverVTable {
    standalone_driver_vtable()
}
