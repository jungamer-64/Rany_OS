use kernel_api::abi::driver::{
    DRIVER_ABI_VERSION, DriverCapabilities, DriverContext, DriverVTable, pack_version,
};
use kernel_api::driver::DriverType;

use crate::hda::HdaController;

static mut HDA_CONTROLLER: Option<HdaController> = None;

unsafe fn hda_controller_present() -> bool {
    let slot = core::ptr::addr_of_mut!(HDA_CONTROLLER);
    unsafe { (*slot).is_some() }
}

extern "C" fn hda_probe(ctx: *mut DriverContext) -> i32 {
    if ctx.is_null() {
        return -1;
    }

    let ctx = unsafe { &mut *ctx };
    let mut controller = HdaController::new(ctx.device_address, ctx.pci_location());
    match controller.init() {
        Ok(()) => unsafe {
            core::ptr::write(core::ptr::addr_of_mut!(HDA_CONTROLLER), Some(controller));
            0
        },
        Err(_) => -1,
    }
}

extern "C" fn hda_start(_ctx: *mut DriverContext) -> i32 {
    unsafe { if hda_controller_present() { 0 } else { -1 } }
}

extern "C" fn hda_stop(_ctx: *mut DriverContext) -> i32 {
    unsafe { if hda_controller_present() { 0 } else { -1 } }
}

extern "C" fn hda_remove(_ctx: *mut DriverContext) -> i32 {
    unsafe {
        let slot = core::ptr::addr_of_mut!(HDA_CONTROLLER);
        let _ = core::ptr::replace(slot, None);
    }
    0
}

extern "C" fn hda_name() -> *const u8 {
    b"intel-hda\0".as_ptr()
}

extern "C" fn hda_name_len() -> usize {
    9
}

extern "C" fn hda_driver_type() -> u32 {
    DriverType::Other as u32
}

extern "C" fn hda_version() -> u64 {
    pack_version(0, 1, 0)
}

extern "C" fn hda_request_capabilities(caps: *mut DriverCapabilities) {
    if caps.is_null() {
        return;
    }

    unsafe {
        (*caps).needs_dma = true;
        (*caps).needs_irq = true;
        (*caps).needs_mmio = true;
    }
}

fn hda_driver_vtable() -> *const DriverVTable {
    static VTABLE: DriverVTable = DriverVTable::new(
        DRIVER_ABI_VERSION,
        hda_probe,
        hda_start,
        hda_stop,
        hda_remove,
        hda_name,
        hda_name_len,
        hda_driver_type,
        hda_version,
        Some(hda_request_capabilities),
        None,
    );

    &VTABLE
}

#[cfg(feature = "export_driver_entry")]
#[unsafe(export_name = "_exorust_driver_entry")]
pub extern "C" fn _exorust_driver_entry() -> *const DriverVTable {
    hda_driver_vtable()
}

#[cfg(not(feature = "export_driver_entry"))]
#[allow(non_snake_case)]
pub(crate) fn _exorust_driver_entry_unique() -> *const DriverVTable {
    hda_driver_vtable()
}
