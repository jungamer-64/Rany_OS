// ============================================================================
// drivers/ahci/src/ffi.rs - ABI-Stable Driver Export
// ============================================================================
//!
//! FFI adapter for the AHCI driver.
//!
//! Exports a C-compatible `DriverVTable` for dynamic loading.

use kernel_api::abi::driver::{
    DRIVER_ABI_VERSION, DriverCapabilities, DriverContext, DriverVTable, pack_version,
};
use kernel_api::driver::DriverType;

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

/// Inner implementation returning pointer to the VTABLE.
fn ahci_driver_vtable() -> *const DriverVTable {
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

// Export canonical symbol only when explicitly requested by the feature
// `export_driver_entry` (enabled for standalone builds). This avoids
// emitting the same symbol from multiple drivers when they are statically
// linked into the kernel.
#[cfg(feature = "export_driver_entry")]
#[unsafe(export_name = "_exorust_driver_entry")]
pub extern "C" fn _exorust_driver_entry() -> *const DriverVTable {
    ahci_driver_vtable()
}

// When not exporting the canonical symbol, emit a crate-unique name so
// multiple drivers can coexist in a single static link without symbol
// collisions. `unsafe(concat!(...))` is required for compile-time
// concatenation in the attribute expression.
#[cfg(not(feature = "export_driver_entry"))]
#[allow(non_snake_case)]
pub(crate) fn _exorust_driver_entry_unique() -> *const DriverVTable {
    ahci_driver_vtable()
}
