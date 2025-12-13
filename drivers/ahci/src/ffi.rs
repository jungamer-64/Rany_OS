// ============================================================================
// drivers/ahci/src/ffi.rs - ABI-Stable Driver Export
// ============================================================================
//!
//! FFI adapter for the AHCI driver.
//!
//! Exports a C-compatible `DriverVTable` for dynamic loading.

use kernel_api::driver::DriverType;
use kernel_api::driver_abi::{
    DRIVER_ABI_VERSION, DriverCapabilities, DriverContext, DriverVTable, pack_version,
};

// ============================================================================
// Driver Probe/Remove Functions
// ============================================================================

/// Probe function for AHCI controller.
extern "C" fn ahci_probe(_ctx: *mut DriverContext) -> i32 {
    // TODO: Initialize AHCI controller using ctx.device_address (BAR5)
    // For now, return success
    0
}

/// Start function for AHCI driver.
extern "C" fn ahci_start(_ctx: *mut DriverContext) -> i32 {
    // TODO: Start port scanning and device detection
    0
}

/// Stop function for AHCI driver.
extern "C" fn ahci_stop(_ctx: *mut DriverContext) -> i32 {
    // TODO: Stop all ports, flush caches
    0
}

/// Remove/cleanup function for AHCI driver.
extern "C" fn ahci_remove(_ctx: *mut DriverContext) -> i32 {
    // TODO: Clean up resources
    0
}

// ============================================================================
// Driver Metadata Functions
// ============================================================================

extern "C" fn ahci_name() -> *const u8 {
    b"ahci\0".as_ptr()
}

extern "C" fn ahci_name_len() -> usize {
    4
}

extern "C" fn ahci_driver_type() -> u32 {
    DriverType::Block as u32
}

extern "C" fn ahci_version() -> u64 {
    pack_version(0, 1, 0)
}

extern "C" fn ahci_request_capabilities(caps: *mut DriverCapabilities) {
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
///
/// The kernel calls this to get the driver's vtable.
#[unsafe(no_mangle)]
pub extern "C" fn _exorust_driver_entry() -> *const DriverVTable {
    static VTABLE: DriverVTable = DriverVTable::new(
        DRIVER_ABI_VERSION,
        ahci_probe,
        ahci_start,
        ahci_stop,
        ahci_remove,
        ahci_name,
        ahci_name_len,
        ahci_driver_type,
        ahci_version,
        Some(ahci_request_capabilities),
        None, // handle_irq - TODO: implement interrupt handler
    );

    &VTABLE
}
