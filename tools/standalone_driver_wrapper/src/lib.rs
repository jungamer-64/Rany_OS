#![cfg_attr(target_os = "none", no_std)]

#[cfg(feature = "standalone")]
kernel_api::register_cell_runtime!();

use kernel_api::abi::driver::DriverVTable;

const SELECTED_DRIVER_COUNT: usize = (cfg!(feature = "driver-ahci") as usize)
    + (cfg!(feature = "driver-usb") as usize)
    + (cfg!(feature = "driver-hda") as usize)
    + (cfg!(feature = "driver-nvme") as usize)
    + (cfg!(feature = "driver-mlx5") as usize);

const _: [(); 1] = [(); SELECTED_DRIVER_COUNT];

#[cfg(feature = "driver-ahci")]
fn selected_driver_vtable() -> *const DriverVTable {
    ahci_driver::ffi::standalone_driver_vtable()
}

#[cfg(feature = "driver-usb")]
fn selected_driver_vtable() -> *const DriverVTable {
    usb_driver::ffi::standalone_driver_vtable()
}

#[cfg(feature = "driver-hda")]
fn selected_driver_vtable() -> *const DriverVTable {
    hda_driver::ffi::standalone_driver_vtable()
}

#[cfg(feature = "driver-nvme")]
fn selected_driver_vtable() -> *const DriverVTable {
    nvme_driver::standalone_driver_vtable()
}

#[cfg(feature = "driver-mlx5")]
fn selected_driver_vtable() -> *const DriverVTable {
    mlx5_driver::standalone_driver_vtable()
}

#[unsafe(export_name = "_exorust_driver_entry")]
pub extern "C" fn _exorust_driver_entry() -> *const DriverVTable {
    selected_driver_vtable()
}
