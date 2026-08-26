// ============================================================================
// kernel/src/net/types.rs - Network shared types
// ============================================================================
//! ネットワークサブシステム全体で共有される基本型。
//!
//! ## IPv4アドレス型について
//!
//! - [`Ipv4Addr`] — 上位層（TCP/UDP/API等）向けの軽量ラッパー
//! - [`crate::net::l3::ipv4::Ipv4Address`] — プロトコルスタック内部向けのフル機能版
//!   (`is_private()`, `same_subnet()`, `apply_mask()` 等)
//!
//! 両者間の変換は `From`/`Into` トレイトで提供される。

use crate::net::runtime::manager::NetIfId;
use kernel_api::resource::net::PacketPayload;

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
    /// Runtime-owned network resources were exhausted
    ResourceExhausted,
    /// No usable route or interface was found for the requested operation
    NetworkUnreachable,
    /// Transmit operation failed
    TransmitFailed,
}

#[derive(Debug)]
pub struct NetworkPayloadError {
    cause: NetworkError,
    payload: PacketPayload,
}

impl NetworkPayloadError {
    pub const fn new(cause: NetworkError, payload: PacketPayload) -> Self {
        Self { cause, payload }
    }

    pub const fn cause(&self) -> NetworkError {
        self.cause
    }

    pub fn into_parts(self) -> (NetworkError, PacketPayload) {
        (self.cause, self.payload)
    }
}

/// Interface selection policy for socket and raw network operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum InterfaceScope {
    /// Allow the stack to select the egress interface using socket affinity,
    /// source address matching, and the routing table.
    Any,
    /// Restrict the operation to a specific interface id.
    Pinned(NetIfId),
}

impl Default for InterfaceScope {
    fn default() -> Self {
        Self::Any
    }
}

impl InterfaceScope {
    #[inline]
    pub const fn pinned(if_id: NetIfId) -> Self {
        Self::Pinned(if_id)
    }

    #[inline]
    pub fn matches_if(self, if_id: NetIfId) -> bool {
        match self {
            Self::Any => true,
            Self::Pinned(pinned) => pinned == if_id,
        }
    }
}

// ============================================================================
// IPv4 アドレス（軽量ラッパー）
// ============================================================================

/// 上位層向け軽量 IPv4 アドレス型
///
/// プロトコルスタック内部では [`crate::net::l3::ipv4::Ipv4Address`] を使用し、
/// 上位層（TCP/UDP/APIなど）ではこちらを使用する。
/// `From<Ipv4Address>` / `Into<Ipv4Address>` による相互変換が可能。
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

    /// `[u8; 4]` バイト列から生成
    pub const fn from_bytes(bytes: [u8; 4]) -> Self {
        Self(bytes)
    }
}

impl core::fmt::Display for Ipv4Addr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}.{}.{}.{}", self.0[0], self.0[1], self.0[2], self.0[3])
    }
}

// ============================================================================
// Ipv4Addr <-> l3::ipv4::Ipv4Address 相互変換
// ============================================================================

impl From<crate::net::l3::ipv4::Ipv4Address> for Ipv4Addr {
    fn from(addr: crate::net::l3::ipv4::Ipv4Address) -> Self {
        Self(addr.octets())
    }
}

impl From<Ipv4Addr> for crate::net::l3::ipv4::Ipv4Address {
    fn from(addr: Ipv4Addr) -> Self {
        crate::net::l3::ipv4::Ipv4Address::new(addr.0)
    }
}

impl From<[u8; 4]> for Ipv4Addr {
    fn from(bytes: [u8; 4]) -> Self {
        Self(bytes)
    }
}
