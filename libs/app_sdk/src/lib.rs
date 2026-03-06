// ============================================================================
// libs/app_sdk/src/lib.rs - Application SDK for ExoRust OS
// ============================================================================
//!
//! # ExoRust Application SDK
//!
//! This crate provides the "standard library" for ExoRust applications.
//! Applications depend only on this crate and kernel_api.
//!
//! ## Features
//!
//! - `Application` trait: Entry point for all apps
//! - `AppContext`: Runtime context with capability access
//! - SDK functions: `sleep()`, `print()`, `now()`, etc.

#![no_std]
#![allow(dead_code)]

extern crate alloc;

mod sdk;

// Re-export Application and AppContext from kernel_api (canonical source)
pub use kernel_api::app::{AppContext, Application};
pub use sdk::{now, now_nanos, print, sleep, yield_now};

// Re-export kernel_api types for convenience
pub use kernel_api::capability::{
    DmaCapability, DomainCapabilities, FsCapability, IoCapability, IpcCapability, MemoryCapability,
    NetCapability, TaskCapability,
};
pub use kernel_api::{KapiError, KapiResult};
