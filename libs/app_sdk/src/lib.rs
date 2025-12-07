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

mod application;
mod context;
mod sdk;

// Re-export public API
pub use application::Application;
pub use context::AppContext;
pub use sdk::{sleep, yield_now, print, now, now_nanos};

// Re-export kernel_api types for convenience
pub use kernel_api::{
    DomainCapabilities, NetCapability, FsCapability, IoCapability, 
    DmaCapability, IpcCapability, TaskCapability, MemoryCapability,
    KapiError, KapiResult,
};
