use crate::net::l3::ipv4::{IpProtocol, Ipv4Address};
use crate::net::runtime::manager::{self, NetIfId};
use crate::sync::PoisonRwLock;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

/// Maximum number of NAT entries to prevent DoS
const MAX_NAT_ENTRIES: usize = 1024;

/// NAT entry timeout (5 minutes in ticks, assuming 1000 ticks/sec)
const NAT_ENTRY_TIMEOUT: u64 = 5 * 60 * 1000;

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

/// Global NAT table with security improvements
pub struct NatTable {
    /// Mapping of (proto, remote_ip, remote_port, external_port) -> NatEntry
    inbound: BTreeMap<(IpProtocol, Ipv4Address, u16, u16), NatEntry>,
    /// Mapping of (proto, internal_ip, internal_port, remote_ip, remote_port) -> NatEntry
    outbound: BTreeMap<(IpProtocol, Ipv4Address, u16, Ipv4Address, u16), NatEntry>,
}

static NAT_TABLE: PoisonRwLock<NatTable> = PoisonRwLock::new(NatTable {
    inbound: BTreeMap::new(),
    outbound: BTreeMap::new(),
});

/// Get current system tick for GC
fn get_current_tick() -> u64 {
    crate::task::timer::current_tick()
}

/// Generate a random port for NAT to prevent prediction attacks (RFC 6056)
fn generate_random_port(table: &NatTable) -> u16 {
    let mut random_bytes = [0u8; 2];
    // Ephemeral port range 49152-65535
    const PORT_START: u32 = 49152;
    const PORT_END: u32 = 65535;
    const RANGE: u32 = PORT_END - PORT_START + 1;

    for _ in 0..100 {
        random_bytes.copy_from_slice(&crate::net::security::tls::crypto::random::generate_random()[0..2]);
        let port = (PORT_START + (u16::from_be_bytes(random_bytes) as u32 % RANGE)) as u16;
        
        // Check if port is already used in any entry
        let mut used = false;
        for entry in table.inbound.values() {
            if entry.external_port == port {
                used = true;
                break;
            }
        }
        if !used {
            return port;
        }
    }
    // Fallback if randomization fails (rare)
    49152
}

pub fn nat_translate_in(
    proto: IpProtocol,
    src_ip: Ipv4Address,
    src_port: u16,
    dst_ip: &mut Ipv4Address,
    dst_port: &mut u16,
    _tcp_flags: u8,
) -> bool {
    let mut table = NAT_TABLE.write().unwrap_or_else(|e| e.into_inner());
    let now = get_current_tick();

    if let Some(entry) = table.inbound.get_mut(&(proto, src_ip, src_port, *dst_port)) {
        entry.last_used = now;
        let internal_ip = entry.internal_ip;
        let internal_port = entry.internal_port;
        let remote_ip = entry.remote_ip;
        let remote_port = entry.remote_port;

        *dst_ip = internal_ip;
        *dst_port = internal_port;

        // Also update the outbound mapping last_used
        if let Some(out_entry) =
            table
                .outbound
                .get_mut(&(proto, internal_ip, internal_port, remote_ip, remote_port))
        {
            out_entry.last_used = now;
        }
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
    let now = get_current_tick();
    
    // Check existing mapping
    if let Some(entry) = table.outbound.get_mut(&(proto, src_ip, src_port, dst_ip, dst_port)) {
        entry.last_used = now;
        return Some((entry.external_ip, entry.external_port));
    }

    // Resource limit check and GC
    if table.outbound.len() >= MAX_NAT_ENTRIES {
        drop(table);
        nat_maybe_gc(0); // Force GC
        table = NAT_TABLE.write().unwrap_or_else(|e| e.into_inner());
        
        if table.outbound.len() >= MAX_NAT_ENTRIES {
            log::warn!("[NAT] Table full, dropping connection from {}", src_ip);
            return None;
        }
    }

    // Get actual external IP of the interface
    let ext_ip = if let Ok(mgr_guard) = manager::NETWORK_MANAGER.lock() {
        mgr_guard.as_ref().and_then(|mgr| {
            mgr.get_interface(if_id).and_then(|iface| {
                iface.config.map(|cfg| cfg.ipv4.address)
            })
        }).unwrap_or(Ipv4Address::new([192, 168, 1, 100]))
    } else {
        Ipv4Address::new([192, 168, 1, 100])
    };

    let ext_port = generate_random_port(&table);

    let entry = NatEntry {
        protocol: proto,
        internal_ip: src_ip,
        internal_port: src_port,
        external_ip: ext_ip,
        external_port: ext_port,
        remote_ip: dst_ip,
        remote_port: dst_port,
        last_used: now,
        if_id,
    };

    table.outbound.insert((proto, src_ip, src_port, dst_ip, dst_port), entry);
    table.inbound.insert((proto, dst_ip, dst_port, ext_port), entry);

    Some((ext_ip, ext_port))
}

pub fn nat_maybe_gc(rx_count: u64) {
    // Periodic GC every 1000 packets or when forced (rx_count=0)
    if rx_count != 0 && rx_count % 1000 != 0 {
        return;
    }

    let mut table = NAT_TABLE.write().unwrap_or_else(|e| e.into_inner());
    let now = get_current_tick();
    
    let mut to_remove_out = Vec::new();
    let mut to_remove_in = Vec::new();

    for (key, entry) in table.outbound.iter() {
        if now.saturating_sub(entry.last_used) > NAT_ENTRY_TIMEOUT {
            to_remove_out.push(*key);
            to_remove_in.push((entry.protocol, entry.remote_ip, entry.remote_port, entry.external_port));
        }
    }

    if !to_remove_out.is_empty() {
        log::debug!("[NAT] GC: removing {} expired entries", to_remove_out.len());
        for key in to_remove_out { table.outbound.remove(&key); }
        for key in to_remove_in { table.inbound.remove(&key); }
    }
}

pub fn nat_translate_in_icmp(_src_ip: Ipv4Address, _dst_ip: &mut Ipv4Address, _payload: &mut [u8]) -> Option<Ipv4Address> {
    // ICMP translation is complex as it requires parsing the quoted IP header.
    // For now, return None.
    None
}

pub fn nat_translate_out_icmp(_src_ip: Ipv4Address, _dst_ip: Ipv4Address, _payload: &[u8], _if_id: NetIfId) -> Option<(Ipv4Address, u16)> {
    None
}

/// Recompute transport checksum after NAT translation.
pub fn recompute_ipv4_transport_checksum(payload: &mut [u8], src: Ipv4Address, dst: Ipv4Address, proto: IpProtocol) {
    use crate::net::datapath::checksum_offload;

    let src_bytes = src.octets();
    let dst_bytes = dst.octets();

    match proto {
        IpProtocol::Tcp => {
            if payload.len() >= 20 {
                // Clear old checksum
                payload[16] = 0;
                payload[17] = 0;
                
                // Recalculate checksum: pseudo-header sum + payload sum
                let partial = checksum_offload::pseudo_header_partial_sum(
                    &src_bytes, &dst_bytes, 6, payload.len() as u16
                );
                
                let mut sum = partial as u32;
                let mut i = 0;
                while i + 1 < payload.len() {
                    let word = u16::from_be_bytes([payload[i], payload[i + 1]]);
                    sum += word as u32;
                    i += 2;
                }
                if i < payload.len() {
                    sum += (payload[i] as u32) << 8;
                }
                while sum >> 16 != 0 {
                    sum = (sum & 0xFFFF) + (sum >> 16);
                }
                
                let cksum = !(sum as u16);
                let bytes = cksum.to_be_bytes();
                payload[16] = bytes[0];
                payload[17] = bytes[1];
            }
        }
        IpProtocol::Udp => {
            if payload.len() >= 8 {
                let old_cksum = u16::from_be_bytes([payload[6], payload[7]]);
                if old_cksum != 0 {
                    payload[6] = 0;
                    payload[7] = 0;
                    
                    let partial = checksum_offload::pseudo_header_partial_sum(
                        &src_bytes, &dst_bytes, 17, payload.len() as u16
                    );
                    
                    let mut sum = partial as u32;
                    let mut i = 0;
                    while i + 1 < payload.len() {
                        let word = u16::from_be_bytes([payload[i], payload[i + 1]]);
                        sum += word as u32;
                        i += 2;
                    }
                    if i < payload.len() {
                        sum += (payload[i] as u32) << 8;
                    }
                    while sum >> 16 != 0 {
                        sum = (sum & 0xFFFF) + (sum >> 16);
                    }
                    
                    let mut cksum = !(sum as u16);
                    if cksum == 0 { cksum = 0xFFFF; }
                    let bytes = cksum.to_be_bytes();
                    payload[6] = bytes[0];
                    payload[7] = bytes[1];
                }
            }
        }
        _ => {}
    }
}
