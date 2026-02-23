#![cfg_attr(target_os = "none", no_std)]

#[cfg(all(feature = "variant_v1", feature = "variant_v2"))]
compile_error!("driver_cell_probe: enable at most one of variant_v1/variant_v2");

#[cfg(feature = "standalone")]
kernel_api::register_cell_runtime!();

use kernel_api::driver_abi::DriverContext;
#[cfg(feature = "export_driver_entry")]
use kernel_api::driver_abi::{
    AbiError, DRIVER_EXPORTS_ABI_VERSION, DriverExportsV1, KERNEL_API_ABI_VERSION, KernelApiV1,
};

pub extern "C" fn probe_fn(_ctx: *mut DriverContext) -> i32 {
    0
}

pub extern "C" fn remove_fn(_ctx: *mut DriverContext) -> i32 {
    0
}

pub extern "C" fn start_fn(_ctx: *mut DriverContext) -> i32 {
    0
}

pub extern "C" fn irq_handler(_ctx: *mut DriverContext) -> bool {
    true
}

pub const fn driver_name() -> &'static str {
    "driver_cell_probe\0"
}

#[cfg(feature = "variant_v2")]
const INIT_LOG_MSG: &[u8] = b"driver_cell_probe init v2";
#[cfg(not(feature = "variant_v2"))]
const INIT_LOG_MSG: &[u8] = b"driver_cell_probe init v1";

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

    (api_ref.log)(0, INIT_LOG_MSG.as_ptr(), INIT_LOG_MSG.len());
    AbiError::Success as i32
}

#[cfg(feature = "export_driver_entry")]
extern "C" fn driver_fini() -> i32 {
    AbiError::Success as i32
}

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
    reserved: [0; 8],
};
