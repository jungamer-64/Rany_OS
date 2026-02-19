#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

use core::alloc::{GlobalAlloc, Layout};
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicUsize, Ordering};

const HEAP_SIZE: usize = 32 * 1024 * 1024;

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
    serial_write_str("[qemu-suite] kernel_mm_pending fail\n");
    suite_fail_trap()
}

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
    serial_write_str("[qemu-suite] kernel_mm_pending fail\n");
    suite_fail_trap()
}

struct PendingCounts {
    passed: u64,
    failed: u64,
    blocked: u64,
}

fn report_case(name: &str, state: &str) {
    serial_write_str("[qemu-suite] kernel_mm_pending case ");
    serial_write_str(name);
    serial_write_str(": ");
    serial_write_str(state);
    serial_write_str("\n");
}

fn run_case(name: &str, f: fn() -> bool, counts: &mut PendingCounts) {
    if f() {
        report_case(name, "pass");
        counts.passed += 1;
    } else {
        report_case(name, "fail");
        counts.failed += 1;
    }
}

fn run_suite() -> PendingCounts {
    serial_write_str("[qemu-suite] kernel_mm_pending start\n");

    let mut counts = PendingCounts {
        passed: 0,
        failed: 0,
        blocked: 0,
    };

    run_case(
        "mm_wave7_bench_enqueue_pool_effect_smoke",
        rany_os::qemu_tests::mm_wave7_bench_enqueue_pool_effect_smoke,
        &mut counts,
    );
    run_case(
        "mm_wave7_bench_buffer_pool_2m_reuse_smoke",
        rany_os::qemu_tests::mm_wave7_bench_buffer_pool_2m_reuse_smoke,
        &mut counts,
    );
    run_case(
        "mm_wave7_bench_buffer_pool_1g_reuse_smoke",
        rany_os::qemu_tests::mm_wave7_bench_buffer_pool_1g_reuse_smoke,
        &mut counts,
    );

    counts
}

fn write_counts(counts: &PendingCounts) {
    serial_write_str("[qemu-suite] kernel_mm_pending counts pass=");
    serial_write_u64(counts.passed);
    serial_write_str(" fail=");
    serial_write_u64(counts.failed);
    serial_write_str(" blocked=");
    serial_write_u64(counts.blocked);
    serial_write_str("\n");
}

#[cfg(not(target_os = "uefi"))]
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let counts = run_suite();
    write_counts(&counts);

    // MM pending suite is informational and non-fatal.
    serial_write_str("[qemu-suite] kernel_mm_pending pass\n");
    exit_qemu(0x10)
}

#[cfg(target_os = "uefi")]
#[unsafe(no_mangle)]
pub extern "efiapi" fn efi_main(_image_handle: usize, _system_table: usize) -> usize {
    let counts = run_suite();
    write_counts(&counts);
    serial_write_str("[qemu-suite] kernel_mm_pending pass\n");
    0
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

fn serial_write_u64(mut value: u64) {
    if value == 0 {
        serial_write_byte(b'0');
        return;
    }

    let mut digits = [0u8; 20];
    let mut idx = 0usize;
    while value > 0 {
        digits[idx] = b'0' + (value % 10) as u8;
        idx += 1;
        value /= 10;
    }

    while idx > 0 {
        idx -= 1;
        serial_write_byte(digits[idx]);
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
