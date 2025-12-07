// ============================================================================
// kernel_api/src/lib.rs - Pure Interface Definitions for ExoRust OS
// ============================================================================
//!
//! # Kernel API Interface Crate
//!
//! This crate defines the shared types and traits that form the contract
//! between the kernel and all other components (drivers, applications, etc.).
//!
//! ## Design Philosophy
//!
//! - **No kernel dependencies**: This crate has zero dependencies on kernel internals
//! - **Pure interfaces**: Only trait definitions, error types, and type aliases
//! - **no_std compatible**: Works in any no_std environment
//!
//! ## Modules
//!
//! - `error`: Common error types (`KapiError`, `KapiResult`)
//! - `capability`: Static capability marker types

#![no_std]
#![allow(dead_code)]

extern crate alloc;

pub mod error;
pub mod capability;

// Re-export commonly used types
pub use error::{KapiError, KapiResult};
