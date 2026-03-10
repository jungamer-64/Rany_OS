use kernel_api::abi::driver::{
    AbiAudioControllerRegistration, AbiAudioDeviceInfo, AbiError, DRIVER_ABI_VERSION,
    DriverCapabilities, DriverContext, DriverVTable, pack_version,
};
use kernel_api::driver::DriverType;

use crate::hda::HdaController;

static mut HDA_CONTROLLER: Option<HdaController> = None;
static mut AUDIO_HANDLE: Option<u64> = None;
static mut HDA_IRQ: u32 = 0;

unsafe fn audio_handle_present() -> bool {
    let slot = core::ptr::addr_of!(AUDIO_HANDLE);
    unsafe { (*slot).is_some() }
}

unsafe fn take_audio_handle() -> Option<u64> {
    let slot = core::ptr::addr_of_mut!(AUDIO_HANDLE);
    unsafe { core::ptr::replace(slot, None) }
}

unsafe fn hda_controller_present() -> bool {
    let slot = core::ptr::addr_of_mut!(HDA_CONTROLLER);
    unsafe { (*slot).is_some() }
}

extern "C" fn hda_probe(ctx: *mut DriverContext) -> i32 {
    if ctx.is_null() {
        return -1;
    }

    let ctx = unsafe { &mut *ctx };
    unsafe {
        HDA_IRQ = ctx.irq;
    }
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
    unsafe {
        if !hda_controller_present() {
            return -1;
        }
        if audio_handle_present() {
            return 0;
        }

        let registration = AbiAudioControllerRegistration::new(
            0,
            HDA_IRQ,
            hda_is_initialized,
            hda_device_count,
            hda_device_info,
            hda_enable_irq,
            hda_disable_irq,
        );
        match kernel_api::service::kernel::instance().register_audio_controller(&registration) {
            Ok(handle) => {
                core::ptr::write(core::ptr::addr_of_mut!(AUDIO_HANDLE), Some(handle));
                0
            }
            Err(_) => -1,
        }
    }
}

extern "C" fn hda_stop(_ctx: *mut DriverContext) -> i32 {
    unsafe {
        if let Some(handle) = take_audio_handle() {
            let _ = kernel_api::service::kernel::instance().unregister_audio_controller(handle);
        }
        if hda_controller_present() { 0 } else { -1 }
    }
}

extern "C" fn hda_remove(_ctx: *mut DriverContext) -> i32 {
    unsafe {
        if let Some(handle) = take_audio_handle() {
            let _ = kernel_api::service::kernel::instance().unregister_audio_controller(handle);
        }
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

extern "C" fn hda_is_initialized(_opaque: u64) -> bool {
    unsafe {
        let slot = core::ptr::addr_of!(HDA_CONTROLLER);
        (*slot)
            .as_ref()
            .map(|controller| controller.is_initialized())
            .unwrap_or(false)
    }
}

extern "C" fn hda_device_count(_opaque: u64) -> u32 {
    unsafe {
        let slot = core::ptr::addr_of!(HDA_CONTROLLER);
        (*slot)
            .as_ref()
            .map(|controller| controller.codecs().len() as u32)
            .unwrap_or(0)
    }
}

extern "C" fn hda_device_info(_opaque: u64, index: u32, out: *mut AbiAudioDeviceInfo) -> i32 {
    if out.is_null() {
        return AbiError::InvalidParam as i32;
    }

    unsafe {
        let slot = core::ptr::addr_of!(HDA_CONTROLLER);
        let Some(controller) = (*slot).as_ref() else {
            return AbiError::NotInitialized as i32;
        };
        let Some(codec) = controller.codecs().get(index as usize) else {
            return AbiError::DeviceNotFound as i32;
        };
        *out = AbiAudioDeviceInfo {
            device_id: ((codec.vendor_id as u64) << 32)
                | ((codec.device_id as u64) << 16)
                | codec.address as u64,
            output_channels: if codec.output_nodes.is_empty() { 0 } else { 2 },
            input_channels: if codec.input_nodes.is_empty() { 0 } else { 2 },
            _padding0: 0,
            sample_rate_hz: 48_000,
            flags: 1 | ((codec.beep_node.is_some() as u32) << 1),
        };
    }
    AbiError::Success as i32
}

extern "C" fn hda_enable_irq(_opaque: u64) -> i32 {
    AbiError::Success as i32
}

extern "C" fn hda_disable_irq(_opaque: u64) -> i32 {
    AbiError::Success as i32
}

/// Public vtable helper used by standalone wrapper cells.
pub fn standalone_driver_vtable() -> *const DriverVTable {
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
    standalone_driver_vtable()
}

#[cfg(not(feature = "export_driver_entry"))]
#[allow(non_snake_case)]
pub(crate) fn _exorust_driver_entry_unique() -> *const DriverVTable {
    standalone_driver_vtable()
}
