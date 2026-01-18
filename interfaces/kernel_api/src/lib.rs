// ============================================================================
// kernel_api/src/lib.rs - Pure Interface Definitions for ExoRust OS
// ============================================================================
//!
//! # Kernel API Interface Crate
//!
//! Shared types and traits for the ExoRust OS kernel.

#![no_std]
#![allow(dead_code)]
#![allow(clippy::cargo_common_metadata)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::use_self)]
#![allow(clippy::inline_always)]
#![allow(clippy::wildcard_imports)]
#![allow(clippy::manual_let_else)]
#![allow(clippy::assign_op_pattern)]
#![allow(clippy::unnecessary_literal_bound)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::semicolon_if_nothing_returned)]
#![allow(unused_variables)] // API consistency - capability parameters are used for type safety
#![allow(clippy::derivable_impls)] // Explicit Default impls for clarity
#![allow(clippy::must_use_candidate)] // Setter methods in security module

extern crate alloc;

pub mod application;
pub mod driver;
pub mod driver_abi;
pub mod error;
pub mod gui;
pub mod kapi;
pub mod security;
pub mod services;
pub mod shell;
pub mod types;

// Standalone Cell runtime stubs (allocator, panic handler)
#[cfg(feature = "cell_runtime")]
pub mod cell_runtime;

// Re-export commonly used types
pub use application::{AppContext, Application};
pub use driver::{DeviceId, Driver, DriverInfo, DriverState, DriverType, DriverVersion};
pub use driver_abi::{
    AbiDmaBuffer, AbiDriverType, AbiError, AbiMmioHandle, DRIVER_ABI_VERSION,
    DRIVER_ENTRY_SYMBOL, DRIVER_EXPORTS_ABI_VERSION, DRIVER_EXPORTS_SYMBOL, DriverCapabilities,
    DriverContext, DriverEntryFn, DriverExportsV1, DriverVTable, KERNEL_API_ABI_VERSION,
    KernelApiV1, pack_version, unpack_version,
};
pub use error::{KapiError, KapiResult};
pub use security::{
    DmaCapability, DomainCapabilities, FsCapability, InterruptCapability, IoCapability,
    IpcCapability, MemoryCapability, NetCapability, TaskCapability,
};
pub use services::{KernelServices, is_kernel_registered, kernel, register_kernel};
pub use types::{
    ChannelHandle, DirectBlockHandle, DmaBuffer, FileHandle, NvmeDmaHandle,
    NvmeIoHandle, NvmeIoPriority, NvmeIoResult, NvmeIoType, NvmeRwRequest,
    OpenMode, Packet, RawSocketHandle, SystemInfo, TaskHandle, TcpEndpoint,
};
