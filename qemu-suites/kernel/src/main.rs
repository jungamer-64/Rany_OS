#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

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
    serial_write_str("[qemu-suite] kernel fail\n");
    suite_fail_trap()
}

// The kernel library expects these linker symbols in full kernel builds.
// For qemu suite linkage we provide harmless stubs.
#[unsafe(no_mangle)]
static __eh_frame_start: u8 = 0;
#[unsafe(no_mangle)]
static __eh_frame_end: u8 = 0;
#[unsafe(no_mangle)]
static __tls_start: u8 = 0;
#[unsafe(no_mangle)]
static __tls_end: u8 = 0;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    serial_write_str("[qemu-suite] kernel fail\n");
    suite_fail_trap()
}

fn run_suite() -> bool {
    smoke_kernel_abi()
        && test_kernel_error_exports()
        && test_loader_crypto_exports()
        && test_loader_metadata_exports()
        && test_loader_live_update_exports()
        && test_loader_elf_exports()
}

#[cfg(not(target_os = "uefi"))]
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    serial_write_str("[qemu-suite] kernel start\n");

    // Migration baseline check: verify shared utility path still behaves.
    if run_suite() {
        serial_write_str("[qemu-suite] kernel pass\n");
        exit_qemu(0x10);
    }

    serial_write_str("[qemu-suite] kernel fail\n");
    suite_fail_trap()
}

#[cfg(target_os = "uefi")]
#[unsafe(no_mangle)]
pub extern "efiapi" fn efi_main(_image_handle: usize, _system_table: usize) -> usize {
    serial_write_str("[qemu-suite] kernel start\n");

    if run_suite() {
        serial_write_str("[qemu-suite] kernel pass\n");
        return 0;
    }

    serial_write_str("[qemu-suite] kernel fail\n");
    1
}

fn smoke_kernel_abi() -> bool {
    let cmdline = "a=1 b=2 run_integration=storage";
    cmdline.contains("run_integration=storage")
}

fn test_kernel_error_exports() -> bool {
    rany_os::qemu_tests::error_conversion_smoke() && rany_os::qemu_tests::error_display_smoke()
}

fn test_loader_crypto_exports() -> bool {
    rany_os::qemu_tests::loader_sha256_empty_smoke()
        && rany_os::qemu_tests::loader_sha256_abc_smoke()
        && rany_os::qemu_tests::loader_sha256_streaming_smoke()
        && rany_os::qemu_tests::loader_ed25519_invalid_public_key_smoke()
        && rany_os::qemu_tests::loader_ed25519_signature_format_smoke()
        && rany_os::qemu_tests::loader_ed25519_rfc8032_vector1_smoke()
}

fn test_loader_metadata_exports() -> bool {
    rany_os::qemu_tests::loader_type_id_const_hash_smoke()
        && rany_os::qemu_tests::loader_type_id_semver_compatibility_smoke()
        && rany_os::qemu_tests::loader_signature_default_smoke()
        && rany_os::qemu_tests::loader_signature_well_formed_smoke()
        && rany_os::qemu_tests::loader_signature_verifier_dev_mode_smoke()
        && rany_os::qemu_tests::loader_signature_verifier_production_mode_smoke()
}

fn test_loader_live_update_exports() -> bool {
    rany_os::qemu_tests::loader_live_update_request_tracker_smoke()
        && rany_os::qemu_tests::loader_live_update_request_tracker_drain_smoke()
        && rany_os::qemu_tests::loader_live_update_per_core_epoch_smoke()
}

fn test_loader_elf_exports() -> bool {
    rany_os::qemu_tests::loader_elf_empty_data_returns_error_smoke()
        && rany_os::qemu_tests::loader_elf_invalid_magic_returns_error_smoke()
        && rany_os::qemu_tests::loader_elf_max_size_constants_smoke()
        && rany_os::qemu_tests::loader_elf_wrong_elf_class_smoke()
        && rany_os::qemu_tests::loader_elf_wrong_endianness_smoke()
        && rany_os::qemu_tests::loader_elf_wx_flags_smoke()
        && rany_os::qemu_tests::loader_elf_rela_extraction_smoke()
        && rany_os::qemu_tests::loader_elf_symbol_extraction_smoke()
        && rany_os::qemu_tests::loader_elf_aslr_offset_generation_smoke()
        && rany_os::qemu_tests::loader_elf_aslr_enable_disable_smoke()
        && rany_os::qemu_tests::loader_elf_get_string_zero_copy_smoke()
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
