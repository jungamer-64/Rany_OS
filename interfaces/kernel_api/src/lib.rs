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

pub mod error;
pub mod services;
pub mod types;
pub mod security;
pub mod kapi;
pub mod application;
pub mod driver;
pub mod driver_abi;

// Re-export commonly used types
pub use error::{KapiError, KapiResult};
pub use services::{KernelServices, kernel, register_kernel, is_kernel_registered};
pub use types::{TaskHandle, DmaBuffer, Packet, SystemInfo, OpenMode, FileHandle, ChannelHandle, TcpEndpoint};
pub use security::{DomainCapabilities, MemoryCapability, NetCapability, IoCapability, DmaCapability, FsCapability, IpcCapability, TaskCapability, InterruptCapability};
pub use application::{Application, AppContext};
pub use driver::{Driver, DriverVersion, DriverType, DeviceId, DriverInfo, DriverState};
pub use driver_abi::{
    DRIVER_ABI_VERSION, DRIVER_ENTRY_SYMBOL,
    DriverVTable, DriverContext, DriverCapabilities, DriverEntryFn,
    AbiError, AbiDriverType, pack_version, unpack_version,
};
