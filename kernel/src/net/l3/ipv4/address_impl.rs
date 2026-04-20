// ============================================================================
// kernel/src/net/l3/ipv4/address_impl.rs - L3 / IPv4 / アドレス実装
// ============================================================================

use super::*;
use core::fmt;

impl Ipv4Address {
    /// Any address (0.0.0.0)
    pub const ANY: Ipv4Address = Ipv4Address([0, 0, 0, 0]);

    /// Broadcast address (255.255.255.255)
    pub const BROADCAST: Ipv4Address = Ipv4Address([255, 255, 255, 255]);

    /// Loopback address (127.0.0.1)
    pub const LOOPBACK: Ipv4Address = Ipv4Address([127, 0, 0, 1]);

    /// Create from bytes
    pub const fn new(bytes: [u8; 4]) -> Self {
        Ipv4Address(bytes)
    }

    /// Create from individual octets
    pub const fn from_octets(a: u8, b: u8, c: u8, d: u8) -> Self {
        Ipv4Address([a, b, c, d])
    }

    /// Get the underlying bytes
    pub const fn as_bytes(&self) -> &[u8; 4] {
        &self.0
    }

    /// Get the underlying bytes as octets (alias for as_bytes)
    pub const fn octets(&self) -> [u8; 4] {
        self.0
    }

    /// Convert to u32 (network byte order)
    pub const fn to_u32(&self) -> u32 {
        ((self.0[0] as u32) << 24)
            | ((self.0[1] as u32) << 16)
            | ((self.0[2] as u32) << 8)
            | (self.0[3] as u32)
    }

    /// Create from u32 (network byte order)
    pub const fn from_u32(value: u32) -> Self {
        Ipv4Address([
            (value >> 24) as u8,
            (value >> 16) as u8,
            (value >> 8) as u8,
            value as u8,
        ])
    }

    /// Check if this is a broadcast address
    pub const fn is_broadcast(&self) -> bool {
        self.0[0] == 255 && self.0[1] == 255 && self.0[2] == 255 && self.0[3] == 255
    }

    /// Check if this is the any address
    pub const fn is_any(&self) -> bool {
        self.0[0] == 0 && self.0[1] == 0 && self.0[2] == 0 && self.0[3] == 0
    }

    /// Check if this is a loopback address (127.x.x.x)
    pub const fn is_loopback(&self) -> bool {
        self.0[0] == 127
    }

    /// Check if this is a multicast address (224.0.0.0 - 239.255.255.255)
    pub const fn is_multicast(&self) -> bool {
        self.0[0] >= 224 && self.0[0] <= 239
    }

    /// Check if this is a link-local address (169.254.x.x)
    pub const fn is_link_local(&self) -> bool {
        self.0[0] == 169 && self.0[1] == 254
    }

    /// Check if this is a private address
    pub const fn is_private(&self) -> bool {
        // 10.0.0.0/8
        self.0[0] == 10 ||
        // 172.16.0.0/12
        (self.0[0] == 172 && (self.0[1] & 0xf0) == 16) ||
        // 192.168.0.0/16
        (self.0[0] == 192 && self.0[1] == 168)
    }

    /// Check if this is a shared address space (CGNAT, 100.64.0.0/10)
    pub const fn is_shared_address(&self) -> bool {
        self.0[0] == 100 && (self.0[1] & 0xc0) == 64
    }

    /// Check if this is a Martian/Reserved address that should not appear on the public internet
    /// as a source address (RFC 1812, RFC 6890)
    pub const fn is_martian(&self) -> bool {
        // 0.0.0.0/8 (Current network)
        if self.0[0] == 0 {
            return true;
        }
        // 127.0.0.0/8 (Loopback)
        if self.is_loopback() {
            return true;
        }
        // 169.254.0.0/16 (Link Local)
        if self.is_link_local() {
            return true;
        }
        // 192.0.0.0/24 (IETF Protocol Assignments)
        if self.0[0] == 192 && self.0[1] == 0 && self.0[2] == 0 {
            return true;
        }
        // 192.0.2.0/24 (TEST-NET-1)
        if self.0[0] == 192 && self.0[1] == 0 && self.0[2] == 2 {
            return true;
        }
        // 198.51.100.0/24 (TEST-NET-2)
        if self.0[0] == 198 && self.0[1] == 51 && self.0[2] == 100 {
            return true;
        }
        // 203.0.113.0/24 (TEST-NET-3)
        if self.0[0] == 203 && self.0[1] == 0 && self.0[2] == 113 {
            return true;
        }
        // 240.0.0.0/4 (Reserved / Future Use)
        if (self.0[0] & 0xf0) == 240 {
            // 255.255.255.255 is handled separately as broadcast
            return !self.is_broadcast();
        }
        false
    }

    /// Apply a subnet mask
    pub const fn apply_mask(&self, mask: Ipv4Address) -> Ipv4Address {
        Ipv4Address([
            self.0[0] & mask.0[0],
            self.0[1] & mask.0[1],
            self.0[2] & mask.0[2],
            self.0[3] & mask.0[3],
        ])
    }

    /// Check if two addresses are in the same subnet
    pub const fn same_subnet(&self, other: &Ipv4Address, mask: Ipv4Address) -> bool {
        (self.0[0] & mask.0[0]) == (other.0[0] & mask.0[0])
            && (self.0[1] & mask.0[1]) == (other.0[1] & mask.0[1])
            && (self.0[2] & mask.0[2]) == (other.0[2] & mask.0[2])
            && (self.0[3] & mask.0[3]) == (other.0[3] & mask.0[3])
    }
}

impl fmt::Debug for Ipv4Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}.{}", self.0[0], self.0[1], self.0[2], self.0[3])
    }
}

impl fmt::Display for Ipv4Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}
