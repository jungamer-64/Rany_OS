// When not running tests or benches, compile as `no_std`. For benches we
// enable the standard library so benchmark harnesses (Criterion) and
// alloc-dependent graphics helpers can build and run under the host test
// runner.
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(all(test, not(feature = "std")), no_main)]
#![feature(custom_test_frameworks)]
#![cfg_attr(test, test_runner(crate::test_runner))]
#![reexport_test_harness_main = "test_main"]
#![cfg_attr(any(not(test), feature = "full_mm_tests"), allow(unsafe_op_in_unsafe_fn))]
#![cfg_attr(any(not(test), feature = "full_mm_tests"), feature(abi_x86_interrupt))]
#![cfg_attr(any(not(test), feature = "full_mm_tests"), feature(alloc_error_handler))]
#![feature(format_args_nl)]

mod _split_1;
use _split_1::*;
mod _split_2;
use _split_2::*;
#[macro_use]
extern crate alloc;


// Interrupt helper macro moved to a shared module so it's visible in both the
// library and binary crate (define_interrupt! is used by modules included by
// `main.rs`). See `interrupt_macros.rs` for the implementation.
#[macro_use]
mod interrupt_macros;




// ========== Test Runner & Entry Point ==========

// Global Allocator for tests (requires full_mm_tests)
#[cfg(all(feature = "full_mm_tests", not(feature = "std")))]
#[global_allocator]
pub static ALLOCATOR: DummyGlobalAlloc = DummyGlobalAlloc;

// Dummy allocator for tests if not found or problematic
#[cfg(all(feature = "full_mm_tests", not(feature = "std")))]
pub struct DummyGlobalAlloc;

#[cfg(all(feature = "full_mm_tests", not(feature = "std")))]
impl DummyGlobalAlloc {
    /// full_mm_tests のダミー実装ではヒープ未初期化扱い。
    pub fn is_initialized(&self) -> Option<bool> {
        Some(false)
    }
}

#[cfg(all(feature = "full_mm_tests", not(feature = "std")))]
unsafe impl core::alloc::GlobalAlloc for DummyGlobalAlloc {
    unsafe fn alloc(&self, _layout: core::alloc::Layout) -> *mut u8 {
        core::ptr::null_mut()
    }
    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: core::alloc::Layout) {}
}

// Bump allocator for unit tests. Provides a working 64MB heap so tests that
// use `alloc::vec::Vec`, `alloc::boxed::Box`, etc. succeed in the no_std QEMU
// test environment (the previous `LockedBuddyHeap::empty()` returned null for
// every allocation).
#[cfg(all(test, not(feature = "full_mm_tests"), not(feature = "std")))]
mod test_bump_alloc {
    use core::alloc::{GlobalAlloc, Layout};
    use core::sync::atomic::{AtomicUsize, Ordering};

    const HEAP_SIZE: usize = 64 * 1024 * 1024; // 64 MB

    #[repr(C, align(4096))]
    struct HeapMem([u8; HEAP_SIZE]);

    static mut HEAP: HeapMem = HeapMem([0; HEAP_SIZE]);
    static OFFSET: AtomicUsize = AtomicUsize::new(0);

    pub struct BumpAlloc;

    impl BumpAlloc {
        pub const fn new() -> Self { Self }

        /// Compatibility shim: the kernel sometimes checks `ALLOCATOR.is_initialized()`.
        pub fn is_initialized(&self) -> Option<bool> { Some(true) }
    }

    unsafe impl GlobalAlloc for BumpAlloc {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            loop {
                let current = OFFSET.load(Ordering::Relaxed);
                let aligned = (current + layout.align() - 1) & !(layout.align() - 1);
                let new_off = aligned + layout.size();
                if new_off > HEAP_SIZE {
                    return core::ptr::null_mut();
                }
                if OFFSET
                    .compare_exchange_weak(current, new_off, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
                {
                    return unsafe { HEAP.0.as_mut_ptr().add(aligned) };
                }
            }
        }

        unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
            // Bump allocator: no individual deallocation.
        }
    }
}

#[cfg(all(test, not(feature = "full_mm_tests"), not(feature = "std")))]
#[global_allocator]
pub static ALLOCATOR: test_bump_alloc::BumpAlloc = test_bump_alloc::BumpAlloc::new();

#[cfg(all(test, not(feature = "std")))]
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    // Minimal serial init for test output
    unsafe {
        let port = 0x3F8u16;
        core::arch::asm!("out dx, al", in("dx") port + 1, in("al") 0u8); // INT disable
        core::arch::asm!("out dx, al", in("dx") port + 3, in("al") 0x80u8); // DLAB on
        core::arch::asm!("out dx, al", in("dx") port + 0, in("al") 0x03u8); // Divisor low
        core::arch::asm!("out dx, al", in("dx") port + 1, in("al") 0x00u8); // Divisor high
        core::arch::asm!("out dx, al", in("dx") port + 3, in("al") 0x03u8); // 8N1
        core::arch::asm!("out dx, al", in("dx") port + 2, in("al") 0xC7u8); // FIFO
        core::arch::asm!("out dx, al", in("dx") port + 4, in("al") 0x0Bu8); // RTS/DSR
    }

    test_main();

    exit_qemu(QemuExitCode::Success);
}

#[cfg(all(test, not(feature = "full_mm_tests"), not(feature = "std")))]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    unsafe {
        for byte in b"[test] FAILED\n" {
            core::arch::asm!("out dx, al", in("dx") 0x3F8u16, in("al") *byte);
        }
        for byte in b"[qemu-suite] kernel-unit fail\n" {
            core::arch::asm!("out dx, al", in("dx") 0x3F8u16, in("al") *byte);
        }
    }
    exit_qemu(QemuExitCode::Failed);
}

#[cfg(all(test, feature = "full_mm_tests", not(feature = "std")))]
#[panic_handler]
pub fn panic(info: &core::panic::PanicInfo) -> ! {
    crate::panic_handler::panic(info)
}

// Macro helpers
#[macro_export]
macro_rules! println {
    () => (print!("\n"));
    ($($arg:tt)*) => ({
        if cfg!(feature = "std") {
            // In std-based tests, use std::println
            #[cfg(feature = "std")]
            std::println!($($arg)*);
        } else {
             // In no_std, use kernel logger
             $crate::io::log::print(format_args!("{}\n", format_args!($($arg)*)));
        }
    });
}

#[macro_export]
macro_rules! eprintln {
    () => (eprint!("\n"));
    ($($arg:tt)*) => ({
        if cfg!(feature = "std") {
            // In std-based tests, use std::eprintln
            #[cfg(feature = "std")]
            std::eprintln!($($arg)*);
        } else {
             // In no_std, use kernel logger w/ error level or just print
             $crate::io::log::print(format_args!("{}\n", format_args!($($arg)*)));
        }
    });
}

#[cfg(test)]
pub fn test_runner(tests: &[&dyn Fn()]) {
    crate::io::log::early_print("[qemu-suite] kernel-unit start\n");
    crate::io::log::early_print("[test] running ");
    crate::io::log::early_print_dec(tests.len() as u64);
    crate::io::log::early_print(" tests...\n");

    for t in tests {
        t();
        crate::io::log::early_print("[test] ok\n");
    }

    crate::io::log::early_print("[qemu-suite] kernel-unit pass\n");
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum QemuExitCode {
    Success = 0x10,
    Failed = 0x11,
}

pub fn exit_qemu(code: QemuExitCode) -> ! {
    unsafe {
        core::arch::asm!(
            "out dx, eax",
            in("dx") 0xf4u16,
            in("eax") code as u32,
            options(nomem, nostack, preserves_flags)
        );
    }
    loop {}
}
