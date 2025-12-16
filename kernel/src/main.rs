#![cfg_attr(not(any(test, feature = "std", feature = "bench")), no_std)]
#![cfg_attr(not(any(test, feature = "std", feature = "bench")), no_main)]
#![feature(abi_x86_interrupt)]
#![feature(thread_local)]
#![allow(unsafe_op_in_unsafe_fn)] // Transitional: allows unsafe calls in unsafe fn without block

// Include the actual kernel logic only when NOT benchmarking
#[cfg(not(feature = "bench"))]
include!("kernel_content.rs");

// Dummy main for benchmarking (std mode)
#[cfg(feature = "bench")]
fn main() {}

// Provide a no-op main when building with std (e.g., for tests)
// Avoid defining multiple `main` entries when `bench` and `std` are both enabled
#[cfg(all(feature = "std", not(feature = "bench")))]
fn main() {}
