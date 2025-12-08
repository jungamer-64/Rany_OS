// ============================================================================
// apps/src/lib.rs - ExoRust System Applications (Stub Version)
// ============================================================================
//!
//! # ExoRust System Applications
//!
//! This crate contains stub declarations for system applications.
//! Full implementation will be migrated incrementally from kernel.

#![no_std]
#![allow(dead_code)]
#![allow(unused_variables)]

extern crate alloc;

// Stub modules - TODO: migrate full implementations
pub mod browser;
pub mod editor;
pub mod games;
pub mod terminal;
pub mod system_monitor;

// Re-export main application types
pub use kernel_api::{Application, AppContext};
