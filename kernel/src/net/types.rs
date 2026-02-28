// ============================================================================
// src/net/types.rs - Network shared types
// ============================================================================

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
