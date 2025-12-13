#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(feature = "standalone", feature(alloc_error_handler))]

use core::alloc::{GlobalAlloc, Layout};
use kernel_api::driver_abi::{AbiDriverType, DriverContext};

#[cfg(all(feature = "standalone", target_os = "none"))]
struct DummyAllocator;

#[cfg(all(feature = "standalone", target_os = "none"))]
unsafe impl GlobalAlloc for DummyAllocator {
    unsafe fn alloc(&self, _layout: Layout) -> *mut u8 {
        core::ptr::null_mut()
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}

#[cfg(all(feature = "standalone", target_os = "none"))]
#[global_allocator]
static DUMMY_ALLOC: DummyAllocator = DummyAllocator;

use core::panic::PanicInfo;

#[cfg(all(feature = "standalone", target_os = "none"))]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

#[cfg(all(feature = "standalone", target_os = "none"))]
#[alloc_error_handler]
fn oom(_layout: Layout) -> ! {
    loop {}
}

pub extern "C" fn probe_fn(_ctx: *mut DriverContext) -> i32 {
    0
}

pub extern "C" fn remove_fn(_ctx: *mut DriverContext) -> i32 {
    0
}

pub fn driver_name() -> &'static str {
    "example_abi\0"
}

kernel_api::export_driver!(
    probe = crate::probe_fn,
    remove = crate::remove_fn,
    name = crate::driver_name,
    driver_type = (kernel_api::driver_abi::AbiDriverType::Block as u32),
    version = 0
);
