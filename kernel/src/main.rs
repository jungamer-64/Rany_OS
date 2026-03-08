#![feature(custom_test_frameworks)]
#![cfg_attr(
    all(
        not(any(test, feature = "std", feature = "bench")),
        target_os = "none"
    ),
    no_std
)]
#![cfg_attr(
    all(
        not(any(test, feature = "std", feature = "bench")),
        target_os = "none"
    ),
    no_main
)]
#![feature(abi_x86_interrupt)]
#![feature(thread_local)]
#![feature(ptr_metadata)]
#![feature(alloc_error_handler)]
#![allow(unsafe_op_in_unsafe_fn)] // Transitional: allows unsafe calls in unsafe fn without block

#[cfg(not(feature = "bench"))]
macro_rules! println {
    () => (print!("\n"));
    ($($arg:tt)*) => ({
        crate::io::log::print(format_args!("{}\n", format_args!($($arg)*)));
    });
}

#[cfg(not(feature = "bench"))]
macro_rules! eprintln {
    () => (eprint!("\n"));
    ($($arg:tt)*) => ({
        crate::io::log::print(format_args!("{}\n", format_args!($($arg)*)));
    });
}

// Include the actual kernel logic only when NOT benchmarking
#[cfg(not(feature = "bench"))]
include!("kernel_content.rs");

// Provide fallback TLS symbols for binary builds on Windows hosts
// when the kernel linker script is not applied (test runner builds).
#[cfg(all(target_os = "windows", not(feature = "bench")))]
#[unsafe(no_mangle)]
pub static __tls_start: u8 = 0;
#[cfg(all(target_os = "windows", not(feature = "bench")))]
#[unsafe(no_mangle)]
pub static __tls_end: u8 = 0;

// Explicit _start entry point for the linker
// This references kmain to prevent the linker from stripping it
#[cfg(all(
    not(any(test, feature = "std", feature = "bench")),
    target_os = "none"
))]
#[unsafe(no_mangle)]
#[unsafe(naked)]
pub unsafe extern "C" fn _start() -> ! {
    // Output 'K!' to COM1 (0x3F8) to verify kernel entry, then jump to kmain
    // RDI already contains boot_info pointer from bootloader
    core::arch::naked_asm!(
        // Output 'K' to COM1 serial port to verify we reached kernel
        "mov dx, 0x3F8", // COM1 port
        "mov al, 0x4B",  // 'K' character
        "out dx, al",    // Send to serial
        "mov al, 0x21",  // '!' character
        "out dx, al",    // Send to serial
        "jmp kmain"      // Jump to main kernel entry
    )
}

#[cfg(all(
    not(any(test, feature = "std", feature = "bench")),
    not(target_os = "none")
))]
fn main() {}

// Dummy main for benchmarking (std mode)
#[cfg(feature = "bench")]
fn main() {}

// Provide a no-op main when building with std (e.g., for tests)
// Avoid defining multiple `main` entries when `bench` and `std` are both enabled
#[cfg(all(feature = "std", not(feature = "bench")))]
fn main() {}

// Provide a no-op main when running `cargo test` on Windows hosts.
// This ensures the test build has an entry point and avoids linker errors (LNK1561).
// Keep the symbol available across std/non-std configurations on Windows builds.
#[cfg(target_os = "windows")]
#[unsafe(no_mangle)]
pub extern "C" fn mainCRTStartup() {}

// Fallback for test configurations that do set `test` (e.g. library builds)
#[cfg(all(test, not(feature = "std")))]
fn main() {}

// Time helpers are implemented in `kernel/src/time.rs`.
// Test/bench shims and production fallbacks live there;
// keep this file minimal to avoid duplicate module definitions.
