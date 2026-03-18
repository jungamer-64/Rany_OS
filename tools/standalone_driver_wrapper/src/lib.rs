#![cfg_attr(target_os = "none", no_std)]

#[cfg(feature = "standalone")]
kernel_api::register_cell_runtime!();

use kernel_api::abi::driver::DriverVTable;

const SELECTED_DRIVER_COUNT: usize = (cfg!(feature = "driver-ahci") as usize)
    + (cfg!(feature = "driver-usb") as usize)
    + (cfg!(feature = "driver-nvme") as usize)
    + (cfg!(feature = "driver-mlx5") as usize);

#[cfg(target_os = "none")]
const _: [(); 1] = [(); SELECTED_DRIVER_COUNT];

#[cfg(feature = "driver-ahci")]
fn selected_driver_vtable() -> *const DriverVTable {
    ahci_driver::ffi::standalone_driver_vtable()
}

#[cfg(feature = "driver-usb")]
fn selected_driver_vtable() -> *const DriverVTable {
    usb_driver::ffi::standalone_driver_vtable()
}

#[cfg(feature = "driver-nvme")]
fn selected_driver_vtable() -> *const DriverVTable {
    nvme_driver::standalone_driver_vtable()
}

#[cfg(feature = "driver-mlx5")]
fn selected_driver_vtable() -> *const DriverVTable {
    mlx5_driver::standalone_driver_vtable()
}

#[cfg(all(
    not(target_os = "none"),
    not(feature = "driver-ahci"),
    not(feature = "driver-usb"),
    not(feature = "driver-nvme"),
    not(feature = "driver-mlx5"),
))]
fn selected_driver_vtable() -> *const DriverVTable {
    core::ptr::null()
}

#[unsafe(export_name = "_exorust_driver_entry")]
pub extern "C" fn _exorust_driver_entry() -> *const DriverVTable {
    selected_driver_vtable()
}
