// ============================================================================
// src/net/mod.rs - Network Subsystem
// ============================================================================

#![allow(dead_code)]

/// Common Network Errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkError {
    PermissionDenied,
    PortInUse,
    InvalidAddress,
    Timeout,
    Unknown,
    /// Connection was closed
    ConnectionClosed,
    /// Internal lock was poisoned
    LockPoisoned,
    /// ARP resolution is pending (retry later)
    ArpResolutionPending,
    /// Buffer too small for operation
    BufferTooSmall,
    /// Transmit operation failed
    TransmitFailed,
}

pub mod api;
pub mod obs;

pub mod l2;
pub mod l3;
pub mod l4;
pub mod services;
pub mod security;
pub mod datapath;
pub mod runtime;
pub mod drivers;
pub mod tests;
