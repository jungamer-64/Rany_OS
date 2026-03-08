use crate::net::l3::ipv4::{IpProtocol, Ipv4Address};
use crate::net::runtime::manager::NetIfId;
use crate::sync::PoisonRwLock;
use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicU64, Ordering};

/// NAT entry for tracking a connection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NatEntry {
    pub protocol: IpProtocol,
    pub internal_ip: Ipv4Address,
    pub internal_port: u16,
    pub external_ip: Ipv4Address,
    pub external_port: u16,
    pub remote_ip: Ipv4Address,
    pub remote_port: u16,
    pub last_used: u64,
    pub if_id: NetIfId,
}

/// Global NAT table
pub struct NatTable {
    /// Mapping of (proto, remote_ip, remote_port, external_port) -> NatEntry
    inbound: BTreeMap<(IpProtocol, Ipv4Address, u16, u16), NatEntry>,
    /// Mapping of (proto, internal_ip, internal_port, remote_ip, remote_port) -> NatEntry
    outbound: BTreeMap<(IpProtocol, Ipv4Address, u16, Ipv4Address, u16), NatEntry>,
    /// Last used port for NAT
    next_port: u16,
}

static NAT_TABLE: PoisonRwLock<NatTable> = PoisonRwLock::new(NatTable {
    inbound: BTreeMap::new(),
    outbound: BTreeMap::new(),
    next_port: 10000,
});

pub fn nat_translate_in(
    proto: IpProtocol,
    src_ip: Ipv4Address,
    src_port: u16,
    dst_ip: &mut Ipv4Address,
    dst_port: &mut u16,
    _tcp_flags: u8,
) -> bool {
    let table = NAT_TABLE.read().unwrap_or_else(|e| e.into_inner());
    if let Some(entry) = table.inbound.get(&(proto, src_ip, src_port, *dst_port)) {
        *dst_ip = entry.internal_ip;
        *dst_port = entry.internal_port;
        return true;
    }
    false
}

pub fn nat_translate_out(
    proto: IpProtocol,
    src_ip: Ipv4Address,
    src_port: u16,
    dst_ip: Ipv4Address,
    dst_port: u16,
    if_id: NetIfId,
    _tcp_flags: u8,
) -> Option<(Ipv4Address, u16)> {
    let mut table = NAT_TABLE.write().unwrap_or_else(|e| e.into_inner());
    
    // Check existing
    if let Some(entry) = table.outbound.get(&(proto, src_ip, src_port, dst_ip, dst_port)) {
        return Some((entry.external_ip, entry.external_port));
    }

    // Create new mapping (simplified)
    let ext_port = table.next_port;
    table.next_port = table.next_port.wrapping_add(1);
    if table.next_port < 10000 { table.next_port = 10000; }

    // In a real system, we'd get the actual external IP of the interface here
    let ext_ip = Ipv4Address::new([192, 168, 1, 100]); 

    let entry = NatEntry {
        protocol: proto,
        internal_ip: src_ip,
        internal_port: src_port,
        external_ip: ext_ip,
        external_port: ext_port,
        remote_ip: dst_ip,
        remote_port: dst_port,
        last_used: 0, // Should be current tick
        if_id,
    };

    table.outbound.insert((proto, src_ip, src_port, dst_ip, dst_port), entry);
    table.inbound.insert((proto, dst_ip, dst_port, ext_port), entry);

    Some((ext_ip, ext_port))
}

pub fn nat_maybe_gc(_rx_count: u64) {
    // GC logic omitted
}

pub fn nat_translate_in_icmp(_src_ip: Ipv4Address, _dst_ip: &mut Ipv4Address, _payload: &mut [u8]) -> Option<Ipv4Address> {
    None
}

pub fn nat_translate_out_icmp(_src_ip: Ipv4Address, _dst_ip: Ipv4Address, _payload: &[u8], _if_id: NetIfId) -> Option<(Ipv4Address, u16)> {
    None
}

pub fn recompute_ipv4_transport_checksum(_payload: &mut [u8], _src: Ipv4Address, _dst: Ipv4Address, _proto: IpProtocol) {
    // Checksum logic omitted
}
