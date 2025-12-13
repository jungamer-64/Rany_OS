// ============================================================================
// kernel_api/src/lib.rs - Pure Interface Definitions for ExoRust OS
// ============================================================================
//!
//! # Kernel API Interface Crate
//!
//! Shared types and traits for the ExoRust OS kernel.

#![no_std]
#![allow(dead_code)]

extern crate alloc;

pub mod application;
pub mod driver;
pub mod driver_abi;
pub mod error;
pub mod kapi;
pub mod security;
pub mod services;
pub mod types;

// Re-export commonly used types
pub use application::{AppContext, Application};
pub use driver::{DeviceId, Driver, DriverInfo, DriverState, DriverType, DriverVersion};
pub use driver_abi::{
    pack_version, unpack_version, AbiDriverType, AbiError, DriverCapabilities, DriverContext,
    DriverEntryFn, DriverVTable, DRIVER_ABI_VERSION, DRIVER_ENTRY_SYMBOL,
};
pub use error::{KapiError, KapiResult};
pub use security::{
    DmaCapability, DomainCapabilities, FsCapability, InterruptCapability, IoCapability,
    IpcCapability, MemoryCapability, NetCapability, TaskCapability,
};
pub use services::{is_kernel_registered, kernel, register_kernel, KernelServices};
pub use types::{
    ChannelHandle, DmaBuffer, FileHandle, OpenMode, Packet, SystemInfo, TaskHandle, TcpEndpoint,
};
