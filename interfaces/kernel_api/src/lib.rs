// ============================================================================
// kernel_api/src/lib.rs - Pure Interface Definitions for ExoRust OS
// ============================================================================
//!
//! # Kernel API Interface Crate
//!
//! Shared types and traits for the ExoRust OS kernel.

#![no_std]
#![allow(dead_code)]
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

// Re-export commonly used types
pub use application::{AppContext, Application};
pub use driver::{DeviceId, Driver, DriverInfo, DriverState, DriverType, DriverVersion};
pub use driver_abi::{
    AbiDriverType, AbiError, DRIVER_ABI_VERSION, DRIVER_ENTRY_SYMBOL, DriverCapabilities,
    DriverContext, DriverEntryFn, DriverVTable, pack_version, unpack_version,
};
pub use error::{KapiError, KapiResult};
pub use security::{
    DmaCapability, DomainCapabilities, FsCapability, InterruptCapability, IoCapability,
    IpcCapability, MemoryCapability, NetCapability, TaskCapability,
};
pub use services::{KernelServices, is_kernel_registered, kernel, register_kernel};
pub use types::{
    ChannelHandle, DmaBuffer, FileHandle, OpenMode, Packet, SystemInfo, TaskHandle, TcpEndpoint,
};
