#![cfg_attr(target_os = "none", no_std)]

// Register Cell runtime stubs (allocator, panic handler) for standalone builds
#[cfg(feature = "standalone")]
kernel_api::register_cell_runtime!();

use kernel_api::driver_abi::DriverContext;

pub extern "C" fn probe_fn(_ctx: *mut DriverContext) -> i32 {
    0
}

pub extern "C" fn remove_fn(_ctx: *mut DriverContext) -> i32 {
    0
}

pub extern "C" fn start_fn(_ctx: *mut DriverContext) -> i32 {
    // Example start implementation: enable device, allocate resources, etc.
    0
}

pub extern "C" fn irq_handler(_ctx: *mut DriverContext) -> bool {
    // Example IRQ handler: return true to indicate IRQ handled
    true
}

pub fn driver_name() -> &'static str {
    "example_abi\0"
}

kernel_api::export_driver!(
    probe: crate::probe_fn,
    remove: crate::remove_fn,
    name: crate::driver_name,
    driver_type: (kernel_api::driver_abi::AbiDriverType::Block as u32),
    version: 0,
    start: crate::start_fn,
    irq: crate::irq_handler
);
