#![cfg_attr(not(feature = "bench"), no_std)]
#![cfg_attr(not(feature = "bench"), no_main)]
#![feature(abi_x86_interrupt)]
#![feature(thread_local)]
#![allow(macro_expanded_macro_exports_accessed_by_absolute_paths)]

// Include the actual kernel logic only when NOT benchmarking
#[cfg(not(feature = "bench"))]
include!("kernel_content.rs");

// Dummy main for benchmarking (std mode)
#[cfg(feature = "bench")]
fn main() {}
