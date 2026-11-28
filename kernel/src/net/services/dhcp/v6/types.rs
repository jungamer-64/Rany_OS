// ============================================================================
// kernel/src/net/services/dhcp/v6/types.rs - サービス / DHCP / v6 / 型定義
// ============================================================================

use crate::net::l3::ipv6::Ipv6Address;

pub const DHCPV6_CLIENT_PORT: u16 = 546;
pub const DHCPV6_SERVER_PORT: u16 = 547;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhcpV6MessageType {
    Solicit = 1,
    Advertise = 2,
    Request = 3,
    Renew = 5,
    Rebind = 6,
    Reply = 7,
    Release = 8,
}

#[derive(Debug, Clone, Copy)]
pub struct DhcpV6Lease {
    pub addr: Ipv6Address,
    pub preferred_lifetime: u32,
    pub valid_lifetime: u32,
    pub t1: u32,
    pub t2: u32,
    pub obtained_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhcpV6State {
    Init,
    SolicitSent,
    Requesting,
    Bound,
    Renewing,
    Rebinding,
}
