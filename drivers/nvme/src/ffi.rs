use kernel_api::driver_abi::{DriverContext};
use kernel_api::driver::DriverType;

// Minimal probe function for the ABI export. In a real driver this
// would construct and register the driver instance using the provided
// `DriverContext` (e.g. base address, IRQ, PCI ids).
extern "C" fn nvme_probe(_ctx: *mut DriverContext) -> i32 {
    // For now, simply return success
    0
}

extern "C" fn nvme_remove(_ctx: *mut DriverContext) -> i32 {
    // Driver removal cleanup (nothing to do for this minimal adapter)
    0
}

fn nvme_name() -> &'static str { "nvme" }

// Export the ABI vtable using the provided macro.
// The driver type is Block (storage), and we pack a trivial version.
// Provide the vtable; export canonical symbol for standalone builds and
// a crate-unique symbol when compiled into the kernel to avoid collisions.
fn nvme_driver_vtable() -> *const kernel_api::driver_abi::DriverVTable {
    extern "C" fn probe_adapter(_ctx: *mut kernel_api::driver_abi::DriverContext) -> i32 { 0 }
    extern "C" fn start_adapter(_ctx: *mut kernel_api::driver_abi::DriverContext) -> i32 { 0 }
    extern "C" fn stop_adapter(_ctx: *mut kernel_api::driver_abi::DriverContext) -> i32 { 0 }
    extern "C" fn remove_adapter(_ctx: *mut kernel_api::driver_abi::DriverContext) -> i32 { 0 }
    extern "C" fn name_adapter() -> *const u8 { b"nvme\0".as_ptr() }
    extern "C" fn name_len_adapter() -> usize { 4 }
    extern "C" fn type_adapter() -> u32 { kernel_api::driver::DriverType::Block as u32 }
    extern "C" fn version_adapter() -> u64 { kernel_api::driver_abi::pack_version(0, 1, 0) }

    static VTABLE: kernel_api::driver_abi::DriverVTable = kernel_api::driver_abi::DriverVTable {
        abi_version: kernel_api::driver_abi::DRIVER_ABI_VERSION,
        probe: probe_adapter,
        start: start_adapter,
        stop: stop_adapter,
        remove: remove_adapter,
        name: name_adapter,
        name_len: name_len_adapter,
        driver_type: type_adapter,
        version: version_adapter,
        request_capabilities: None,
        handle_irq: None,
        _reserved: [0usize; 8],
    };

    &VTABLE
}

#[cfg(feature = "export_driver_entry")]
#[unsafe(export_name = "_exorust_driver_entry")]
pub extern "C" fn _exorust_driver_entry() -> *const kernel_api::driver_abi::DriverVTable {
    nvme_driver_vtable()
}

#[cfg(not(feature = "export_driver_entry"))]
#[unsafe(export_name = concat!("_exorust_driver_entry_", env!("CARGO_PKG_NAME")))]
pub extern "C" fn _exorust_driver_entry_unique() -> *const kernel_api::driver_abi::DriverVTable {
    nvme_driver_vtable()
}
