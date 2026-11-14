// ============================================================================
// kernel/src/net/services/dhcp/v4/types.rs - サービス / DHCP / v4 / 型定義
// ============================================================================

use crate::net::l2::ethernet::MacAddress;
use crate::net::l3::ipv4::Ipv4Address;
use crate::net::runtime::NetRuntimeHandle;
use crate::sync::PoisonLock;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64};

pub const DHCP_CLIENT_PORT: u16 = 68;
pub const DHCP_SERVER_PORT: u16 = 67;
pub const DHCP_MAX_MESSAGE_SIZE: usize = 576;
pub const DHCP_MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DhcpOperation {
    Request = 1,
    Reply = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DhcpMessageType {
    Discover = 1,
    Offer = 2,
    Request = 3,
    Decline = 4,
    Ack = 5,
    Nak = 6,
    Release = 7,
    Inform = 8,
}

impl DhcpMessageType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Discover),
            2 => Some(Self::Offer),
            3 => Some(Self::Request),
            4 => Some(Self::Decline),
            5 => Some(Self::Ack),
            6 => Some(Self::Nak),
            7 => Some(Self::Release),
            8 => Some(Self::Inform),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DhcpOption {
    Pad = 0,
    SubnetMask = 1,
    Router = 3,
    DnsServer = 6,
    Hostname = 12,
    DomainName = 15,
    RequestedIp = 50,
    LeaseTime = 51,
    RenewalTime = 58,
    RebindingTime = 59,
    MessageType = 53,
    ServerIdentifier = 54,
    ParameterRequestList = 55,
    MaximumMessageSize = 57,
    ClientIdentifier = 61,
    End = 255,
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct DhcpHeader {
    pub op: u8,
    pub htype: u8,
    pub hlen: u8,
    pub hops: u8,
    pub xid: [u8; 4],
    pub secs: [u8; 2],
    pub flags: [u8; 2],
    pub ciaddr: [u8; 4],
    pub yiaddr: [u8; 4],
    pub siaddr: [u8; 4],
    pub giaddr: [u8; 4],
    pub chaddr: [u8; 16],
    pub sname: [u8; 64],
    pub file: [u8; 128],
}

impl DhcpHeader {
    pub const SIZE: usize = 236;

    pub fn decode_from(src: &[u8]) -> Option<Self> {
        if src.len() < Self::SIZE {
            return None;
        }

        let mut off = 0usize;
        let op = src[off];
        off += 1;
        let htype = src[off];
        off += 1;
        let hlen = src[off];
        off += 1;
        let hops = src[off];
        off += 1;

        let mut xid = [0u8; 4];
        xid.copy_from_slice(&src[off..off + 4]);
        off += 4;
        let mut secs = [0u8; 2];
        secs.copy_from_slice(&src[off..off + 2]);
        off += 2;
        let mut flags = [0u8; 2];
        flags.copy_from_slice(&src[off..off + 2]);
        off += 2;
        let mut ciaddr = [0u8; 4];
        ciaddr.copy_from_slice(&src[off..off + 4]);
        off += 4;
        let mut yiaddr = [0u8; 4];
        yiaddr.copy_from_slice(&src[off..off + 4]);
        off += 4;
        let mut siaddr = [0u8; 4];
        siaddr.copy_from_slice(&src[off..off + 4]);
        off += 4;
        let mut giaddr = [0u8; 4];
        giaddr.copy_from_slice(&src[off..off + 4]);
        off += 4;
        let mut chaddr = [0u8; 16];
        chaddr.copy_from_slice(&src[off..off + 16]);
        off += 16;
        let mut sname = [0u8; 64];
        sname.copy_from_slice(&src[off..off + 64]);
        off += 64;
        let mut file = [0u8; 128];
        file.copy_from_slice(&src[off..off + 128]);

        Some(Self {
            op,
            htype,
            hlen,
            hops,
            xid,
            secs,
            flags,
            ciaddr,
            yiaddr,
            siaddr,
            giaddr,
            chaddr,
            sname,
            file,
        })
    }

    pub fn xid(&self) -> u32 {
        u32::from_be_bytes(self.xid)
    }

    pub fn yiaddr(&self) -> Ipv4Address {
        Ipv4Address::new(self.yiaddr)
    }

    pub fn siaddr(&self) -> Ipv4Address {
        Ipv4Address::new(self.siaddr)
    }
}

const _: [(); DhcpHeader::SIZE] = [(); core::mem::size_of::<DhcpHeader>()];
const _: [(); core::mem::size_of::<DhcpHeader>()] = [(); DhcpHeader::SIZE];

#[derive(Debug)]
pub struct DhcpV4AppliedConfig {
    pub ip_address: Ipv4Address,
    pub subnet_mask: Ipv4Address,
    pub gateway: Option<Ipv4Address>,
    pub dns_servers: Vec<Ipv4Address>,
    /// Domain Name option (RFC 2132 Section 3.17), used as the DNS search domain.
    pub domain_name: Option<crate::net::services::dns::DnsNormalizedName>,
}

impl DhcpV4AppliedConfig {
    pub fn new(
        ip_address: Ipv4Address,
        subnet_mask: Ipv4Address,
        gateway: Option<Ipv4Address>,
        dns_servers: Vec<Ipv4Address>,
        domain_name: Option<crate::net::services::dns::DnsNormalizedName>,
    ) -> Self {
        Self {
            ip_address,
            subnet_mask,
            gateway,
            dns_servers,
            domain_name,
        }
    }
}

#[derive(Debug)]
pub struct DhcpAckResult {
    pub lease: DhcpLease,
    pub applied: DhcpV4AppliedConfig,
}

#[derive(Debug, Clone, Copy)]
pub struct DhcpLease {
    pub ip_address: Ipv4Address,
    pub subnet_mask: Ipv4Address,
    pub gateway: Option<Ipv4Address>,
    pub server_ip: Ipv4Address,
    pub lease_time: u32,
    pub t1: u32,
    pub t2: u32,
    pub obtained_at: u64,
}

#[derive(Debug)]
pub enum DhcpResponseResult {
    Offer(DhcpLease),
    Ack(DhcpAckResult),
    Nak,
}

impl DhcpLease {
    pub fn is_expired(&self, current_tick: u64, tick_rate: u64) -> bool {
        let elapsed_secs = (current_tick.saturating_sub(self.obtained_at)) / tick_rate;
        elapsed_secs > self.lease_time as u64
    }

    pub fn needs_renewal(&self, current_tick: u64, tick_rate: u64) -> bool {
        let elapsed_secs = (current_tick.saturating_sub(self.obtained_at)) / tick_rate;
        elapsed_secs >= self.t1 as u64
    }

    pub fn needs_rebind(&self, current_tick: u64, tick_rate: u64) -> bool {
        let elapsed_secs = (current_tick.saturating_sub(self.obtained_at)) / tick_rate;
        elapsed_secs >= self.t2 as u64
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhcpState {
    Init,
    Selecting,
    Requesting,
    Bound,
    Informing,
    Renewing,
    Rebinding,
}

pub struct DhcpClient {
    pub(crate) runtime: NetRuntimeHandle,
    pub(crate) if_id: crate::net::runtime::manager::NetIfId,
    pub(crate) mac_address: MacAddress,
    pub(crate) state: PoisonLock<DhcpState>,
    pub(crate) xid: AtomicU32,
    pub(crate) lease: PoisonLock<Option<DhcpLease>>,
    pub(crate) offered_lease: PoisonLock<Option<DhcpLease>>,
    pub(crate) offered_probe_at: AtomicU64,
    pub(crate) last_declined: AtomicU32,
    pub(crate) last_released: AtomicU32,
    pub(crate) state_time: AtomicU64,
    pub(crate) retry_count: AtomicU32,
}

pub(super) struct ParsedOptions {
    pub(super) message_type: Option<DhcpMessageType>,
    pub(super) subnet_mask: Option<Ipv4Address>,
    pub(super) router: Option<Ipv4Address>,
    pub(super) dns_servers: Vec<Ipv4Address>,
    pub(super) lease_time: u32,
    pub(super) renewal_time: Option<u32>,
    pub(super) rebinding_time: Option<u32>,
    pub(super) server_id: Option<Ipv4Address>,
    pub(super) domain_name: Option<crate::net::services::dns::DnsNormalizedName>,
}
