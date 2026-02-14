#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

extern crate alloc;

use core::alloc::{GlobalAlloc, Layout};
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicUsize, Ordering};

const HEAP_SIZE: usize = 1024 * 1024;

#[repr(align(16))]
struct Heap([u8; HEAP_SIZE]);

static mut HEAP: Heap = Heap([0; HEAP_SIZE]);
static NEXT: AtomicUsize = AtomicUsize::new(0);

struct BumpAlloc;

#[global_allocator]
static ALLOCATOR: BumpAlloc = BumpAlloc;

unsafe impl GlobalAlloc for BumpAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let align_mask = layout.align().saturating_sub(1);
        let size = layout.size();
        if size == 0 {
            return layout.align() as *mut u8;
        }

        let base = unsafe { core::ptr::addr_of_mut!(HEAP.0) as usize };
        loop {
            let cur = NEXT.load(Ordering::Relaxed);
            let aligned = (cur + align_mask) & !align_mask;
            let end = aligned.saturating_add(size);
            if end > HEAP_SIZE {
                return core::ptr::null_mut();
            }
            if NEXT
                .compare_exchange(cur, end, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                return (base + aligned) as *mut u8;
            }
        }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}

#[alloc_error_handler]
fn alloc_error(_layout: Layout) -> ! {
    serial_write_str("[qemu-suite] graphics fail\n");
    suite_fail_trap()
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    serial_write_str("[qemu-suite] graphics fail\n");
    suite_fail_trap()
}

fn run_suite() -> bool {
    test_types() && test_images() && test_browser()
}

#[cfg(not(target_os = "uefi"))]
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    serial_write_str("[qemu-suite] graphics start\n");

    if run_suite() {
        serial_write_str("[qemu-suite] graphics pass\n");
        exit_qemu(0x10);
    }

    serial_write_str("[qemu-suite] graphics fail\n");
    suite_fail_trap()
}

#[cfg(target_os = "uefi")]
#[unsafe(no_mangle)]
pub extern "efiapi" fn efi_main(_image_handle: usize, _system_table: usize) -> usize {
    serial_write_str("[qemu-suite] graphics start\n");

    if run_suite() {
        serial_write_str("[qemu-suite] graphics pass\n");
        return 0;
    }

    serial_write_str("[qemu-suite] graphics fail\n");
    1
}

fn test_types() -> bool {
    graphic_types::qemu_tests::color_ctor_smoke()
        && graphic_types::qemu_tests::color_roundtrip_smoke()
        && graphic_types::qemu_tests::rect_intersection_smoke()
        && graphic_types::qemu_tests::rect_contains_smoke()
        && graphic_types::qemu_tests::pixel_format_bytes_smoke()
        && graphic_types::qemu_tests::encode_decode_roundtrip_smoke()
        && graphic_types::qemu_tests::point_layout_smoke()
        && graphic_types::qemu_tests::rect_layout_smoke()
        && graphic_types::qemu_tests::color_layout_smoke()
        && graphic_types::qemu_tests::pixel_format_layout_smoke()
}

fn test_images() -> bool {
    graphic_types::qemu_tests::image_try_new_overflow_smoke()
        && graphic_types::qemu_tests::image_try_new_max_size_smoke()
        && graphic_types::qemu_tests::image_try_new_valid_smoke()
        && graphic_types::qemu_tests::image_try_filled_overflow_smoke()
        && graphic_types::qemu_tests::image_view_basic_smoke()
        && graphic_types::qemu_tests::image_view_mut_set_pixel_smoke()
        && graphic_types::qemu_tests::image_view_mut_fill_rect_smoke()
        && graphic_types::qemu_tests::image_view_out_of_bounds_smoke()
        && graphic_types::qemu_tests::image_view_external_buffer_smoke()
        && graphic_types::qemu_tests::image_view_stride_smoke()
        && graphic_types::qemu_tests::max_image_size_constant_smoke()
}

fn test_browser() -> bool {
    exorust_apps::browser::browser::qemu_tests::browser_creation_smoke()
        && exorust_apps::browser::browser::qemu_tests::history_smoke()
}

fn serial_write_str(s: &str) {
    for b in s.bytes() {
        serial_write_byte(b);
    }
}

fn serial_write_byte(byte: u8) {
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") 0x3f8u16,
            in("al") byte,
            options(nostack, nomem, preserves_flags)
        );
    }
}

fn suite_fail_trap() -> ! {
    #[cfg(not(target_os = "uefi"))]
    {
        exit_qemu(0x11)
    }
    #[cfg(target_os = "uefi")]
    {
        loop {
            core::hint::spin_loop();
        }
    }
}

#[cfg(not(target_os = "uefi"))]
fn exit_qemu(code: u32) -> ! {
    unsafe {
        core::arch::asm!(
            "out dx, eax",
            in("dx") 0xf4u16,
            in("eax") code,
            options(nostack, nomem, preserves_flags)
        );
    }
    loop {
        core::hint::spin_loop();
    }
}
