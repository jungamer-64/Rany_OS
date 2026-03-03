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

// ============================================================================
// IPv4 アドレス（軽量ラッパー）
// ============================================================================

/// IPv4アドレス
///
/// `l3::ipv4::Ipv4Address` がプロトコルスタック向けの詳細実装を提供するのに対し、
/// こちらは汎用的な軽量 IPv4 アドレス型として上位層（TCP/UDP/API等）で使用する。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Ipv4Addr(pub [u8; 4]);

impl Ipv4Addr {
    pub const fn new(a: u8, b: u8, c: u8, d: u8) -> Self {
        Self([a, b, c, d])
    }

    pub const UNSPECIFIED: Self = Self([0, 0, 0, 0]);
    pub const LOCALHOST: Self = Self([127, 0, 0, 1]);
    pub const BROADCAST: Self = Self([255, 255, 255, 255]);

    pub fn octets(&self) -> [u8; 4] {
        self.0
    }

    pub fn to_u32(&self) -> u32 {
        u32::from_be_bytes(self.0)
    }

    pub fn from_u32(val: u32) -> Self {
        Self(val.to_be_bytes())
    }
}

impl core::fmt::Display for Ipv4Addr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}.{}.{}.{}", self.0[0], self.0[1], self.0[2], self.0[3])
    }
}
