#![cfg_attr(target_os = "none", no_std)]

#[cfg(feature = "standalone")]
kernel_api::register_cell_runtime!();

use kernel_api::abi::driver::DriverContext;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ObservedDriverContext {
    pub probe_count: u32,
    pub start_count: u32,
    pub reserved: [u32; 2],
    pub ctx: DriverContext,
}

#[unsafe(no_mangle)]
pub static mut __exorust_driver_cell_probe_observed_context: ObservedDriverContext =
    ObservedDriverContext {
        probe_count: 0,
        start_count: 0,
        reserved: [0; 2],
        ctx: DriverContext::new(),
    };

fn variant_label() -> &'static str {
    #[cfg(feature = "variant_v2")]
    {
        return "driver_cell_probe_v2";
    }

    #[cfg(not(feature = "variant_v2"))]
    {
        "driver_cell_probe_v1"
    }
}

fn driver_name() -> &'static str {
    "driver_cell_probe"
}

fn log_variant(prefix: &str) {
    let mut message = [0u8; 64];
    let mut len = 0usize;

    for part in [prefix.as_bytes(), b": ", variant_label().as_bytes()] {
        let copy_len = core::cmp::min(part.len(), message.len().saturating_sub(len));
        if copy_len == 0 {
            break;
        }
        message[len..len + copy_len].copy_from_slice(&part[..copy_len]);
        len += copy_len;
    }

    if let Ok(text) = core::str::from_utf8(&message[..len]) {
        kernel_api::service::kernel::instance().log(text);
    }
}

fn probe(_ctx: &mut DriverContext) -> i32 {
    unsafe {
        __exorust_driver_cell_probe_observed_context.probe_count =
            __exorust_driver_cell_probe_observed_context
                .probe_count
                .saturating_add(1);
        __exorust_driver_cell_probe_observed_context.ctx = *_ctx;
    }
    log_variant("driver_cell_probe probe");
    0
}

fn remove(_ctx: &mut DriverContext) -> i32 {
    0
}

fn start(_ctx: &mut DriverContext) -> i32 {
    unsafe {
        __exorust_driver_cell_probe_observed_context.start_count =
            __exorust_driver_cell_probe_observed_context
                .start_count
                .saturating_add(1);
        __exorust_driver_cell_probe_observed_context.ctx = *_ctx;
    }
    log_variant("driver_cell_probe start");
    0
}

fn stop(_ctx: &mut DriverContext) -> i32 {
    0
}

kernel_api::export_driver!(
    probe: crate::probe,
    remove: crate::remove,
    name: crate::driver_name,
    driver_type: (kernel_api::abi::driver::AbiDriverType::Network as u32),
    version: 0x0001_0000_u64,
    start: crate::start,
    stop: crate::stop,
);
