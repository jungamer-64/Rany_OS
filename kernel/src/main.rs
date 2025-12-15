#![cfg_attr(not(any(test, feature = "std", feature = "bench")), no_std)]
#![cfg_attr(not(any(test, feature = "std", feature = "bench")), no_main)]
#![feature(abi_x86_interrupt)]
#![feature(thread_local)]

// Include the actual kernel logic only when NOT benchmarking
#[cfg(not(feature = "bench"))]
include!("kernel_content.rs");

// Dummy main for benchmarking (std mode)
#[cfg(feature = "bench")]
fn main() {}

// Provide a no-op main when building with std (e.g., for tests)
#[cfg(feature = "std")]
fn main() {}
