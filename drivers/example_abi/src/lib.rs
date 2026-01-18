#![cfg_attr(target_os = "none", no_std)]

// Register Cell runtime stubs (allocator, panic handler) for standalone builds
#[cfg(feature = "standalone")]
kernel_api::register_cell_runtime!();

use kernel_api::driver_abi::DriverContext;
#[cfg(feature = "export_driver_entry")]
use kernel_api::driver_abi::{
    AbiError, DriverExportsV1, KernelApiV1, DRIVER_EXPORTS_ABI_VERSION, KERNEL_API_ABI_VERSION,
};

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

#[cfg(feature = "export_driver_entry")]
extern "C" fn driver_init(api: *const KernelApiV1) -> i32 {
    if api.is_null() {
        return AbiError::InvalidParam as i32;
    }

    let api_ref = unsafe { &*api };
    if api_ref.abi_version != KERNEL_API_ABI_VERSION {
        return AbiError::NotSupported as i32;
    }

    let msg = b"example_abi init";
    (api_ref.log)(0, msg.as_ptr(), msg.len());
    AbiError::Success as i32
}

#[cfg(feature = "export_driver_entry")]
extern "C" fn driver_fini() -> i32 {
    AbiError::Success as i32
}

/// New ABI entrypoint: `DRIVER_EXPORTS` (preferred by loader).
#[cfg(feature = "export_driver_entry")]
#[unsafe(no_mangle)]
pub static DRIVER_EXPORTS: DriverExportsV1 = DriverExportsV1 {
    abi_version: DRIVER_EXPORTS_ABI_VERSION,
    abi_size: core::mem::size_of::<DriverExportsV1>() as u32,
    name_ptr: driver_name().as_ptr(),
    name_len: driver_name().len(),
    entry: _exorust_driver_entry,
    init: Some(driver_init),
    fini: Some(driver_fini),
    _reserved: [0; 8],
};
