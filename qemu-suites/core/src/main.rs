#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

extern crate alloc;

use core::alloc::{GlobalAlloc, Layout};
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicUsize, Ordering};
#[path = "../../../bootloader/src/config.rs"]
mod bootloader_config;

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
    serial_write_str("[qemu-suite] core fail\n");
    suite_fail_trap()
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    serial_write_str("[qemu-suite] core fail\n");
    suite_fail_trap()
}

fn run_suite() -> bool {
    test_capability_set()
        && test_version_pack_unpack()
        && test_sync_lock_compiles()
        && test_bootloader_config_parse()
}

#[cfg(not(target_os = "uefi"))]
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    serial_write_str("[qemu-suite] core start\n");

    if run_suite() {
        serial_write_str("[qemu-suite] core pass\n");
        exit_qemu(0x10);
    }

    serial_write_str("[qemu-suite] core fail\n");
    suite_fail_trap()
}

#[cfg(target_os = "uefi")]
#[unsafe(no_mangle)]
pub extern "efiapi" fn efi_main(_image_handle: usize, _system_table: usize) -> usize {
    serial_write_str("[qemu-suite] core start\n");

    if run_suite() {
        serial_write_str("[qemu-suite] core pass\n");
        return 0;
    }

    serial_write_str("[qemu-suite] core fail\n");
    1
}

fn test_capability_set() -> bool {
    security::qemu_tests::capability_set_smoke() && security::qemu_tests::grant_flow_smoke()
}

fn test_version_pack_unpack() -> bool {
    kernel_api::qemu_tests::version_pack_unpack_smoke()
        && kernel_api::qemu_tests::abi_error_decode_smoke()
        && kernel_api::qemu_tests::driver_context_default_smoke()
}

fn test_sync_lock_compiles() -> bool {
    exorust_sync::qemu_tests::basic_lock_smoke()
        && exorust_sync::qemu_tests::try_lock_smoke()
        && exorust_sync::qemu_tests::initial_poison_state_smoke()
        && exorust_sync::qemu_tests::clear_poison_smoke()
        && exorust_sync::qemu_tests::default_lock_smoke()
}

fn test_bootloader_config_parse() -> bool {
    let cfg = bootloader_config::parse_config("timeout=5\n[Default]\nkernel=rany_os\n");
    cfg.timeout == 5 && cfg.entries.len() == 1 && cfg.entries[0].kernel == "rany_os"
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
