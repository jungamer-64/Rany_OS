// ============================================================================
// apps/src/lib.rs - ExoRust System Applications
// ============================================================================
//!
//! # ExoRust System Applications
//!
//! This crate contains system applications that implement the `Application` trait.
//! Each application can be spawned as a separate task with capability-based access.
//!
//! ## Available Applications
//!
//! - **Terminal**: Command-line interface
//! - **Browser**: Web browser
//! - **Editor**: Text editor
//! - **Games**: Games collection
//! - **SystemMonitor**: System resource monitoring

#![no_std]
#![allow(dead_code)]
#![allow(unused_variables)]

#[macro_use]
extern crate alloc;

pub mod browser;
pub mod editor;
pub mod games;
pub mod system_monitor;
pub mod terminal;

// Re-export main application types
pub use app_sdk::{AppContext, Application};

// Re-export specific applications
pub use browser::Browser;
pub use editor::Editor;
pub use games::Games;
pub use system_monitor::SystemMonitor;
pub use terminal::Terminal;
