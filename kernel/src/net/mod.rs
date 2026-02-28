// ============================================================================
// src/net/mod.rs - Network Subsystem
// ============================================================================

#![allow(dead_code)]

pub mod api;
pub mod obs;
pub mod types;

pub mod l2;
pub mod l3;
pub mod l4;
pub mod services;
pub mod security;
pub mod datapath;
pub mod runtime;
pub mod drivers;
pub mod tests;

#[cfg(feature = "qemu-test-export")]
pub mod qemu_tests {
    pub use crate::net::tests::qemu::*;
}
