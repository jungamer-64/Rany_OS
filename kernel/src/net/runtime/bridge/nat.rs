// ============================================================================
// NAT (Network Address Translation) for ExoRust Bridge
// ============================================================================
//! Symmetric NAT implementation for outbound/inbound IPv4 port translation.
//!
//! Supports TCP state tracking (SYN/FIN/RST), ICMP echo NAT, ICMP error
//! rewriting, and periodic garbage collection of expired entries.

use crate::net::l3::ipv4::{IpProtocol, Ipv4Address};
use crate::net::runtime::manager::{self, NetIfId};
use alloc::vec::Vec;
use core::sync::atomic::AtomicU16;
use spin::RwLock;

extern crate alloc;

// ============================================================================
// Constants
// ============================================================================

pub(super) const NAT_EPHEMERAL_START: u16 = 40_000;
const NAT_IDLE_TIMEOUT_MS: u64 = 5 * 60_000;
const NAT_TCP_ESTABLISHED_TIMEOUT_MS: u64 = 24 * 60 * 60_000; // 24 hours for established TCP
const NAT_TCP_TRANSIT_TIMEOUT_MS: u64 = 30_000; // 30s for non-established or closing TCP
pub(super) const NAT_GC_EVERY_RX_MASK: u64 = 0xFF;

/// Maximum NAT table entries to prevent memory DoS
const MAX_NAT_ENTRIES: usize = 10000;

// ============================================================================
// Types
// ============================================================================

/// TCP state for NAT session tracking
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum NatTcpState {
    /// Non-TCP protocol
    None,
    /// SYN sent, waiting for SYN-ACK
    SynSent,
    /// Handshake complete
    Established,
    /// FIN seen from one or both sides
    Closing,
}

/// Simple NAT entry for TCP/UDP port translation.
/// External port is key; value stores internal address/port.
#[derive(Clone, Copy)]
pub(super) struct NatEntry {
    pub(super) protocol: IpProtocol,
    pub(super) tcp_state: NatTcpState,
    pub(super) external_addr: Ipv4Address,
    pub(super) remote_addr: Ipv4Address,
    pub(super) remote_port: u16,
    pub(super) egress_if: NetIfId,
    pub(super) internal_addr: Ipv4Address,
    pub(super) internal_port: u16,
    pub(super) last_seen: u64,
}

// ============================================================================
// Global state
// ============================================================================

/// Global NAT mapping: external_port -> NatEntry
pub(super) static NAT_TABLE: RwLock<alloc::collections::BTreeMap<u16, NatEntry>> =
    RwLock::new(alloc::collections::BTreeMap::new());

/// Next ephemeral port to allocate for NAT
pub(super) static NAT_NEXT_PORT: AtomicU16 = AtomicU16::new(NAT_EPHEMERAL_START);

// ============================================================================
// Outbound NAT
// ============================================================================

/// Perform outbound NAT translation for a packet leaving on `out_if_id`.
/// Returns Some((translated_src_ip, translated_src_port)) or None if allocation fails.
pub(super) fn nat_translate_out(
    protocol: IpProtocol,
    internal_ip: Ipv4Address,
    internal_port: u16,
    remote_ip: Ipv4Address,
    remote_port: u16,
    out_if_id: NetIfId,
    tcp_flags: u8,
) -> Option<(Ipv4Address, u16)> {
    // determine external IP from interface config
    let mut ext_ip = internal_ip;
    if let Ok(iface_opt) = manager::get_interface(out_if_id) {
        if let Some(iface) = iface_opt {
            if let Some(cfg) = iface.config {
                ext_ip = cfg.ipv4.address;
            }
        }
    }

    // look for existing mapping (by internal_addr+port + remote_addr+port)
    // This implements Symmetric NAT for better security.
    {
        let table = NAT_TABLE.read();
        for (&ext_port, entry) in table.iter() {
            if entry.protocol == protocol
                && entry.internal_addr == internal_ip
                && entry.internal_port == internal_port
                && entry.remote_addr == remote_ip
                && entry.remote_port == remote_port
            {
                // refresh timestamp and update state
                drop(table);
                let mut tablew = NAT_TABLE.write();
                if let Some(e) = tablew.get_mut(&ext_port) {
                    e.last_seen = crate::time::get_uptime_ms();

                    // TCP state machine
                    if protocol == IpProtocol::Tcp {
                        const FIN: u8 = 0x01;
                        const SYN: u8 = 0x02;
                        const RST: u8 = 0x04;
                        const ACK: u8 = 0x10;

                        if (tcp_flags & RST) != 0 {
                            e.tcp_state = NatTcpState::Closing;
                            e.last_seen -= NAT_TCP_TRANSIT_TIMEOUT_MS; // Expire quickly
                        } else if (tcp_flags & FIN) != 0 {
                            e.tcp_state = NatTcpState::Closing;
                        } else if e.tcp_state == NatTcpState::SynSent && (tcp_flags & ACK) != 0 {
                            e.tcp_state = NatTcpState::Established;
                        }
                    }
                }
                return Some((ext_ip, ext_port));
            }
        }
    }

    // allocate new external port with collision check
    let mut tablew = NAT_TABLE.write();

    // DoS protection: limit NAT table size
    if tablew.len() >= MAX_NAT_ENTRIES {
        // Emergency prune before rejecting
        drop(tablew);
        nat_prune_expired(crate::time::get_uptime_ms());
        tablew = NAT_TABLE.write();
        if tablew.len() >= MAX_NAT_ENTRIES {
            log::error!(
                "[NET BRIDGE] NAT table full, dropping connection (Security: prevent internal IP leak)"
            );
            return None;
        }
    }

    // Use random starting port to prevent port prediction attacks
    let random_bytes = crate::net::security::tls::generate_random();
    let mut ext_port = (u16::from_be_bytes([random_bytes[0], random_bytes[1]])
        % (65535 - NAT_EPHEMERAL_START))
        + NAT_EPHEMERAL_START;

    // Collision detection: skip ports that are already mapped
    let mut attempts = 0;
    while tablew.contains_key(&ext_port) && attempts < 1000 {
        ext_port = (ext_port.wrapping_add(1) % (65535 - NAT_EPHEMERAL_START)) + NAT_EPHEMERAL_START;
        attempts += 1;
    }

    if attempts >= 1000 {
        log::error!("[NET BRIDGE] NAT port allocation failed (exhaustion)");
        return None;
    }

    // Initial state for TCP
    let mut tcp_state = NatTcpState::None;
    if protocol == IpProtocol::Tcp {
        const SYN: u8 = 0x02;
        if (tcp_flags & SYN) != 0 {
            tcp_state = NatTcpState::SynSent;
        } else {
            tcp_state = NatTcpState::Established; // Assume established for mid-stream packets
        }
    }

    tablew.insert(
        ext_port,
        NatEntry {
            protocol,
            tcp_state,
            external_addr: ext_ip,
            remote_addr: remote_ip,
            remote_port,
            egress_if: out_if_id,
            internal_addr: internal_ip,
            internal_port,
            last_seen: crate::time::get_uptime_ms(),
        },
    );

    Some((ext_ip, ext_port))
}

// ============================================================================
// Inbound NAT
// ============================================================================

/// Perform inbound NAT translation on a packet arriving on any interface.
/// If translation exists for `dst_port` AND matches remote address/port,
/// rewrites `dst_ip` and `dst_port` to the internal values and returns true.
/// Caller should recompute checksums.
pub(super) fn nat_translate_in(
    protocol: IpProtocol,
    src_ip: Ipv4Address,
    src_port: u16,
    dst_ip: &mut Ipv4Address,
    dst_port: &mut u16,
    tcp_flags: u8,
) -> bool {
    // Only DNAT packets that are actually addressed to one of our local IPs.
    if !super::is_local_ipv4(*dst_ip) {
        return false;
    }

    let mut tablew = NAT_TABLE.write();
    if let Some(entry) = tablew.get_mut(dst_port) {
        // Security check: Verify protocol, local destination IP, AND the remote source IP/port.
        if entry.protocol != protocol
            || entry.external_addr != *dst_ip
            || entry.remote_addr != src_ip
            || entry.remote_port != src_port
        {
            return false;
        }

        // TCP state machine for inbound packets
        if protocol == IpProtocol::Tcp {
            const FIN: u8 = 0x01;
            const SYN: u8 = 0x02;
            const RST: u8 = 0x04;
            const ACK: u8 = 0x10;

            if (tcp_flags & RST) != 0 {
                entry.tcp_state = NatTcpState::Closing;
                entry.last_seen = entry.last_seen.saturating_sub(NAT_TCP_TRANSIT_TIMEOUT_MS);
            } else if (tcp_flags & FIN) != 0 {
                entry.tcp_state = NatTcpState::Closing;
            } else if entry.tcp_state == NatTcpState::SynSent
                && (tcp_flags & (SYN | ACK)) == (SYN | ACK)
            {
                entry.tcp_state = NatTcpState::Established;
            }
        }

        // rewrite
        *dst_ip = entry.internal_addr;
        *dst_port = entry.internal_port;
        entry.last_seen = crate::time::get_uptime_ms();
        true
    } else {
        false
    }
}

// ============================================================================
// ICMP NAT
// ============================================================================

/// Perform outbound ICMP NAT translation.
pub(super) fn nat_translate_out_icmp(
    internal_ip: Ipv4Address,
    remote_ip: Ipv4Address,
    icmp_payload: &[u8],
    out_if_id: NetIfId,
) -> Option<(Ipv4Address, u16)> {
    if icmp_payload.len() < 8 {
        return None;
    }

    let icmp_type = icmp_payload[0];
    if icmp_type == 8 {
        // Echo Request
        let identifier = u16::from_be_bytes([icmp_payload[4], icmp_payload[5]]);
        nat_translate_out(
            IpProtocol::Icmp,
            internal_ip,
            identifier,
            remote_ip,
            0,
            out_if_id,
            0,
        )
    } else {
        None
    }
}

/// Perform inbound ICMP NAT translation.
pub(super) fn nat_translate_in_icmp(
    src_ip: Ipv4Address,
    dst_ip: &mut Ipv4Address,
    icmp_payload: &mut [u8],
) -> Option<Ipv4Address> {
    if icmp_payload.len() < 8 {
        return None;
    }

    let icmp_type = icmp_payload[0];
    if icmp_type == 0 {
        // Echo Reply
        let identifier = u16::from_be_bytes([icmp_payload[4], icmp_payload[5]]);
        let mut port = identifier;
        if nat_translate_in(IpProtocol::Icmp, src_ip, 0, dst_ip, &mut port, 0) {
            icmp_payload[4..6].copy_from_slice(&port.to_be_bytes());
            return Some(*dst_ip);
        }
    } else if icmp_type == 3 || icmp_type == 11 || icmp_type == 12 {
        // Destination Unreachable, Time Exceeded, Parameter Problem
        if icmp_payload.len() < 8 + 20 {
            return None;
        }

        let inner_ip_header_off = 8;
        let ihl = (icmp_payload[inner_ip_header_off] & 0x0F) as usize;
        let inner_ip_header_len = ihl * 4;

        if inner_ip_header_len < 20
            || icmp_payload.len() < inner_ip_header_off + inner_ip_header_len + 8
        {
            return None;
        }

        let inner_ip_header = &icmp_payload[inner_ip_header_off..inner_ip_header_off + 20];
        let inner_proto = inner_ip_header[9];
        let _inner_src = Ipv4Address::from_octets(
            inner_ip_header[12],
            inner_ip_header[13],
            inner_ip_header[14],
            inner_ip_header[15],
        );
        let inner_dst = Ipv4Address::from_octets(
            inner_ip_header[16],
            inner_ip_header[17],
            inner_ip_header[18],
            inner_ip_header[19],
        );

        let inner_payload_off = inner_ip_header_off + inner_ip_header_len;
        let inner_src_port = u16::from_be_bytes([
            icmp_payload[inner_payload_off],
            icmp_payload[inner_payload_off + 1],
        ]);
        let inner_dst_port = u16::from_be_bytes([
            icmp_payload[inner_payload_off + 2],
            icmp_payload[inner_payload_off + 3],
        ]);

        let table = NAT_TABLE.read();
        if let Some(entry) = table.get(&inner_src_port) {
            if u8::from(entry.protocol) == inner_proto
                && entry.remote_addr == inner_dst
                && entry.remote_port == inner_dst_port
            {
                *dst_ip = entry.internal_addr;

                icmp_payload[inner_ip_header_off + 12..inner_ip_header_off + 16]
                    .copy_from_slice(entry.internal_addr.as_bytes());
                icmp_payload[inner_payload_off..inner_payload_off + 2]
                    .copy_from_slice(&entry.internal_port.to_be_bytes());

                return Some(*dst_ip);
            }
        }
    }

    None
}

// ============================================================================
// Checksum helpers
// ============================================================================

pub(super) fn transport_checksum_offset(protocol: IpProtocol) -> Option<usize> {
    match protocol {
        IpProtocol::Udp => Some(6),
        IpProtocol::Tcp => Some(16),
        _ => None,
    }
}

pub(super) fn recompute_ipv4_transport_checksum(
    transport: &mut [u8],
    src_ip: Ipv4Address,
    dst_ip: Ipv4Address,
    protocol: IpProtocol,
) {
    let Some(checksum_off) = transport_checksum_offset(protocol) else {
        return;
    };
    if transport.len() < checksum_off + 2 || transport.len() > u16::MAX as usize {
        return;
    }

    // IPv4 UDP checksum may be zero (disabled). Preserve that behavior.
    if protocol == IpProtocol::Udp
        && u16::from_be_bytes([transport[checksum_off], transport[checksum_off + 1]]) == 0
    {
        return;
    }

    transport[checksum_off..checksum_off + 2].copy_from_slice(&0u16.to_be_bytes());
    let pseudo = crate::net::l3::ipv4::pseudo_header_checksum(
        src_ip,
        dst_ip,
        protocol,
        transport.len() as u16,
    );
    let checksum = crate::net::l3::ipv4::data_checksum(transport, pseudo);
    let final_checksum = if checksum == 0 && protocol == IpProtocol::Udp {
        0xFFFF
    } else {
        checksum
    };
    transport[checksum_off..checksum_off + 2].copy_from_slice(&final_checksum.to_be_bytes());
}

// ============================================================================
// Garbage collection
// ============================================================================

pub(super) fn nat_prune_expired(now_ms: u64) -> usize {
    let mut removed = 0usize;
    let mut table = NAT_TABLE.write();
    let mut stale_ports = Vec::new();
    for (&ext_port, entry) in table.iter() {
        let timeout = match entry.tcp_state {
            NatTcpState::Established => NAT_TCP_ESTABLISHED_TIMEOUT_MS,
            NatTcpState::Closing | NatTcpState::SynSent => NAT_TCP_TRANSIT_TIMEOUT_MS,
            NatTcpState::None => NAT_IDLE_TIMEOUT_MS,
        };

        if now_ms.saturating_sub(entry.last_seen) > timeout {
            stale_ports.push(ext_port);
        }
    }
    for ext_port in stale_ports {
        if table.remove(&ext_port).is_some() {
            removed += 1;
        }
    }
    removed
}

pub(super) fn nat_maybe_gc(rx_packets_after_increment: u64) {
    if (rx_packets_after_increment & NAT_GC_EVERY_RX_MASK) != 0 {
        return;
    }
    let now_ms = crate::time::get_uptime_ms();
    let _ = nat_prune_expired(now_ms);
}
