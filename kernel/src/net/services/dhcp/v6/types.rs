// ============================================================================
// kernel/src/net/services/dhcp/v6/types.rs - サービス / DHCP / v6 / 型定義
// ============================================================================

use crate::net::l2::ethernet::MacAddress;
use crate::net::l3::ipv6::Ipv6Address;
use crate::net::runtime::NetRuntimeHandle;
use crate::sync::PoisonLock;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64};
use kernel_api::resource::net::PacketPayload;

pub const DHCPV6_CLIENT_PORT: u16 = 546;
pub const DHCPV6_SERVER_PORT: u16 = 547;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhcpV6MessageType {
    Solicit = 1,
    Advertise = 2,
    Request = 3,
    Confirm = 4,
    Renew = 5,
    Rebind = 6,
    Reply = 7,
    Release = 8,
    Decline = 9,
    InformationRequest = 11,
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

#[derive(Debug)]
pub struct DhcpV6AppliedConfig {
    pub addr: Ipv6Address,
    pub dns_servers: Vec<Ipv6Address>,
    pub domain_search: Vec<crate::net::services::dns::DnsNameOwned>,
}

impl DhcpV6AppliedConfig {
    pub fn new(
        addr: Ipv6Address,
        dns_servers: Vec<Ipv6Address>,
        domain_search: Vec<crate::net::services::dns::DnsNameOwned>,
    ) -> Self {
        Self {
            addr,
            dns_servers,
            domain_search,
        }
    }
}

#[derive(Debug)]
pub struct DhcpV6ReplyOutcome {
    pub lease: DhcpV6Lease,
    pub applied: DhcpV6AppliedConfig,
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

pub struct DhcpV6Client {
    pub(crate) runtime: NetRuntimeHandle,
    pub(crate) mac: MacAddress,
    pub(crate) duid: [u8; 10],
    pub(crate) state: PoisonLock<DhcpV6State>,
    pub(crate) xid: AtomicU32,
    pub(crate) iaid: u32,
    pub(crate) lease: PoisonLock<Option<DhcpV6Lease>>,
    pub(crate) server_duid: PoisonLock<Option<PacketPayload>>,
    pub(crate) server_addr: PoisonLock<Option<Ipv6Address>>,
    pub(crate) state_time: AtomicU64,
    pub(crate) retry_count: AtomicU32,
    pub(crate) cached_link_local: PoisonLock<Option<Ipv6Address>>,
}
