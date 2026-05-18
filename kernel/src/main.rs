#![cfg_attr(
    all(not(any(test, feature = "std", feature = "bench")), target_os = "none"),
    no_std
)]
#![cfg_attr(
    all(not(any(test, feature = "std", feature = "bench")), target_os = "none"),
    no_main
)]
#![feature(abi_x86_interrupt)]
#![feature(custom_test_frameworks)]
#![feature(thread_local)]
#![feature(ptr_metadata)]
#![feature(alloc_error_handler)]

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
#[cfg(all(not(any(test, feature = "std", feature = "bench")), target_os = "none"))]
#[unsafe(no_mangle)]
#[unsafe(naked)]
pub unsafe extern "C" fn _start() -> ! {
    // Output 'K!' to COM1 (0x3F8) to verify kernel entry, then jump into the
    // canonical library-side boot entry.
    // RDI already contains boot_info pointer from bootloader
    core::arch::naked_asm!(
        "mov dx, 0x3F8",
        "mov al, 0x4B",
        "out dx, al",
        "mov al, 0x21",
        "out dx, al",
        "jmp {entry}",
        entry = sym kernel_boot_entry,
    )
}

#[cfg(all(not(any(test, feature = "std", feature = "bench")), target_os = "none"))]
#[unsafe(no_mangle)]
pub extern "C" fn kernel_boot_entry(boot_info: &'static boot_proto::ExoBootInfo) -> ! {
    rany_os::boot::kmain(boot_info)
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

// Keep this file limited to binary entry glue; the library owns the kernel
// module graph and runtime boot implementation.
