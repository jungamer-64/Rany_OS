// ============================================================================
// src/net/driver_bridge.rs - VirtIO-Net <-> NetworkStack Bridge
// ============================================================================
//!
//! VirtIO-NetドライバとNetworkStackを接続するブリッジモジュール。
//! 送信コールバック設定と受信パケット処理を統合します。


use crate::net::datapath::optimization::{BatchConfig, BatchProcessor};
use crate::net::l2::ethernet::MacAddress;
use crate::net::l3::ipv4::{Ipv4Address, Ipv4Config};
use crate::net::runtime::manager::{self, NetIfId};
use crate::net::runtime::stack::{self, NetworkConfig};
use crate::net::api::shell::{ArpCacheEntry, NetworkConfigSnapshot, NetworkStatsSnapshot};
use crate::net::obs::{
    counters,
    trace::{self, NetEventKind, NetLayer},
};
use crate::io::virtio::{
    VirtioNetDevice, bind_virtio_net_interface, with_virtio_net, with_virtio_net_at_index,
};
use crate::sync::PoisonLock;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use spin::RwLock;

extern crate alloc;

// ============================================================================
// Bridge State
// ============================================================================

/// Bridge initialization state
static BRIDGE_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Packet transmission counter
static TX_PACKETS: AtomicU64 = AtomicU64::new(0);

/// Packet reception counter  
static RX_PACKETS: AtomicU64 = AtomicU64::new(0);

/// Receive buffer for processing
static RX_BUFFER: PoisonLock<[u8; 2048]> = PoisonLock::new([0u8; 2048]);

/// Batch Processor for RX
static BATCH_PROCESSOR: BatchProcessor = BatchProcessor::new(BatchConfig {
    max_batch_size: 64,
    max_delay_us: 50,
    min_pps_threshold: 1000,
    adaptive_batching: true,
});

/// Per-interface bridge stats (transitional; stack path is still single-instance).
static BRIDGE_IF_STATS: RwLock<BTreeMap<NetIfId, BridgeInterfaceStats>> =
    RwLock::new(BTreeMap::new());

/// Primary interface used by legacy bridge wrappers.
static PRIMARY_BRIDGE_IF: RwLock<Option<NetIfId>> = RwLock::new(None);

// ============================================================================
// NAT (Network Address Translation) support
// ============================================================================

#[cfg(any(test, feature = "qemu-test-export"))]
/// Records routing events (if_id,destination) for unit tests.
static FORWARD_EVENTS: RwLock<Vec<(NetIfId, Ipv4Address)>> =
    RwLock::new(Vec::new());

const NAT_EPHEMERAL_START: u16 = 40_000;
const NAT_IDLE_TIMEOUT_MS: u64 = 5 * 60_000;
const NAT_GC_EVERY_RX_MASK: u64 = 0xFF;

/// Simple NAT entry for TCP/UDP port translation.
/// External port is key; value stores internal address/port.
#[derive(Clone, Copy)]
struct NatEntry {
    protocol: crate::net::l3::ipv4::IpProtocol,
    external_addr: Ipv4Address,
    remote_addr: Ipv4Address,
    remote_port: u16,
    egress_if: NetIfId,
    internal_addr: Ipv4Address,
    internal_port: u16,
    last_seen: u64,
}

/// Global NAT mapping: external_port -> NatEntry
static NAT_TABLE: RwLock<alloc::collections::BTreeMap<u16, NatEntry>> =
    RwLock::new(alloc::collections::BTreeMap::new());

/// Next ephemeral port to allocate for NAT
static NAT_NEXT_PORT: AtomicU16 = AtomicU16::new(NAT_EPHEMERAL_START);

/// Perform outbound NAT translation for a packet leaving on `out_if_id`.
/// Returns (translated_src_ip, translated_src_port).
fn nat_translate_out(
    protocol: crate::net::l3::ipv4::IpProtocol,
    internal_ip: Ipv4Address,
    internal_port: u16,
    remote_ip: Ipv4Address,
    remote_port: u16,
    out_if_id: NetIfId,
) -> (Ipv4Address, u16) {
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
                // refresh timestamp
                drop(table);
                let mut tablew = NAT_TABLE.write();
                if let Some(e) = tablew.get_mut(&ext_port) {
                    e.last_seen = crate::time::get_uptime_ms();
                }
                return (ext_ip, ext_port);
            }
        }
    }

    // allocate new external port with collision check
    let mut tablew = NAT_TABLE.write();
    let mut ext_port = NAT_NEXT_PORT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    
    // Ensure we stay in ephemeral range [40000, 65535]
    if ext_port < NAT_EPHEMERAL_START {
        ext_port = NAT_EPHEMERAL_START;
        NAT_NEXT_PORT.store(NAT_EPHEMERAL_START + 1, core::sync::atomic::Ordering::Relaxed);
    }

    // Collision detection: skip ports that are already mapped
    let mut attempts = 0;
    while tablew.contains_key(&ext_port) && attempts < 1000 {
        ext_port = NAT_NEXT_PORT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        if ext_port < NAT_EPHEMERAL_START {
            ext_port = NAT_EPHEMERAL_START;
            NAT_NEXT_PORT.store(NAT_EPHEMERAL_START + 1, core::sync::atomic::Ordering::Relaxed);
        }
        attempts += 1;
    }

    tablew.insert(
        ext_port,
        NatEntry {
            protocol,
            external_addr: ext_ip,
            remote_addr: remote_ip,
            remote_port,
            egress_if: out_if_id,
            internal_addr: internal_ip,
            internal_port,
            last_seen: crate::time::get_uptime_ms(),
        },
    );

    (ext_ip, ext_port)
}

/// Perform inbound NAT translation on a packet arriving on any interface.
/// If translation exists for `dst_port` AND matches remote address/port, 
/// rewrites `dst_ip` and `dst_port` to the internal values and returns true.
/// Caller should recompute checksums.
fn nat_translate_in(
    protocol: crate::net::l3::ipv4::IpProtocol,
    src_ip: Ipv4Address,
    src_port: u16,
    dst_ip: &mut Ipv4Address,
    dst_port: &mut u16,
) -> bool {
    // Only DNAT packets that are actually addressed to one of our local IPs.
    if !is_local_ipv4(*dst_ip) {
        return false;
    }

    let mut tablew = NAT_TABLE.write();
    if let Some(entry) = tablew.get_mut(dst_port) {
        // Security check: Verify protocol, local destination IP, AND the remote source IP/port.
        // This prevents unsolicited traffic from hijacking the NAT port.
        if entry.protocol != protocol 
            || entry.external_addr != *dst_ip
            || entry.remote_addr != src_ip
            || entry.remote_port != src_port
        {
            return false;
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

fn transport_checksum_offset(protocol: crate::net::l3::ipv4::IpProtocol) -> Option<usize> {
    match protocol {
        crate::net::l3::ipv4::IpProtocol::Udp => Some(6),
        crate::net::l3::ipv4::IpProtocol::Tcp => Some(16),
        _ => None,
    }
}

fn recompute_ipv4_transport_checksum(
    transport: &mut [u8],
    src_ip: Ipv4Address,
    dst_ip: Ipv4Address,
    protocol: crate::net::l3::ipv4::IpProtocol,
) {
    let Some(checksum_off) = transport_checksum_offset(protocol) else {
        return;
    };
    if transport.len() < checksum_off + 2 || transport.len() > u16::MAX as usize {
        return;
    }

    // IPv4 UDP checksum may be zero (disabled). Preserve that behavior.
    if protocol == crate::net::l3::ipv4::IpProtocol::Udp
        && u16::from_be_bytes([transport[checksum_off], transport[checksum_off + 1]]) == 0
    {
        return;
    }

    transport[checksum_off..checksum_off + 2].copy_from_slice(&0u16.to_be_bytes());
    let pseudo =
        crate::net::l3::ipv4::pseudo_header_checksum(src_ip, dst_ip, protocol, transport.len() as u16);
    let checksum = crate::net::l3::ipv4::data_checksum(transport, pseudo);
    let final_checksum = if checksum == 0 { 0xFFFF } else { checksum };
    transport[checksum_off..checksum_off + 2].copy_from_slice(&final_checksum.to_be_bytes());
}

fn nat_prune_expired(now_ms: u64, idle_timeout_ms: u64) -> usize {
    let mut removed = 0usize;
    let mut table = NAT_TABLE.write();
    let mut stale_ports = Vec::new();
    for (&ext_port, entry) in table.iter() {
        if now_ms.saturating_sub(entry.last_seen) > idle_timeout_ms {
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

fn nat_maybe_gc(rx_packets_after_increment: u64) {
    if (rx_packets_after_increment & NAT_GC_EVERY_RX_MASK) != 0 {
        return;
    }
    let now_ms = crate::time::get_uptime_ms();
    let _ = nat_prune_expired(now_ms, NAT_IDLE_TIMEOUT_MS);
}

/// Determine if the given IPv4 address is assigned to any local interface.
fn is_local_ipv4(addr: Ipv4Address) -> bool {
    if let Ok(routes) = manager::NETWORK_MANAGER.lock() {
        if let Some(mgr) = routes.as_ref() {
            for iface in mgr.list_interfaces() {
                if let Some(cfg) = iface.config {
                    if cfg.ipv4.address == addr {
                        return true;
                    }
                }
            }
        }
    }
    false
}

fn ensure_bridge_if_state(if_id: NetIfId, virtio_index: Option<u8>) {
    let mut stats = BRIDGE_IF_STATS.write();
    let entry = stats.entry(if_id).or_insert(BridgeInterfaceStats {
        if_id,
        tx_packets: 0,
        rx_packets: 0,
        initialized: false,
        virtio_index,
    });
    if entry.virtio_index.is_none() {
        entry.virtio_index = virtio_index;
    }
    entry.initialized = true;
}

fn record_bridge_if_tx(if_id: NetIfId) {
    let mut stats = BRIDGE_IF_STATS.write();
    let entry = stats.entry(if_id).or_insert(BridgeInterfaceStats {
        if_id,
        tx_packets: 0,
        rx_packets: 0,
        initialized: true,
        virtio_index: None,
    });
    entry.tx_packets = entry.tx_packets.saturating_add(1);
    entry.initialized = true;
}

fn record_bridge_if_rx(if_id: NetIfId) {
    let mut stats = BRIDGE_IF_STATS.write();
    let entry = stats.entry(if_id).or_insert(BridgeInterfaceStats {
        if_id,
        tx_packets: 0,
        rx_packets: 0,
        initialized: true,
        virtio_index: None,
    });
    entry.rx_packets = entry.rx_packets.saturating_add(1);
    entry.initialized = true;
}

fn primary_bridge_if() -> Option<NetIfId> {
    *PRIMARY_BRIDGE_IF.read()
}

fn set_primary_bridge_if_for_virtio(if_id: NetIfId, virtio_index: u8) {
    let mut primary = PRIMARY_BRIDGE_IF.write();
    // Preserve first-registered behavior, but always prefer legacy vnet0 so
    // single-stack compatibility paths keep using the canonical interface.
    if primary.is_none() || virtio_index == 0 {
        *primary = Some(if_id);
    }
}

// ============================================================================
// Transmit Bridge
// ============================================================================

/// Transmit callback for NetworkStack
/// This is called when NetworkStack needs to send a packet.  The first
/// argument is an optional interface identifier; if the stack supplies `None`
/// the bridge will fall back to the legacy ``primary_bridge_if`` behaviour.
fn virtio_transmit(if_id: Option<NetIfId>, data: &[u8]) -> bool {
    if let Some(if_id) = if_id.or_else(primary_bridge_if) {
        return send_packet_on_interface(if_id, data);
    }

    // VirtIO-Netデバイスが利用可能か確認
    let result = with_virtio_net(|device| {
        // 簡単な同期送信を試みる
        // 実際にはsend_asyncを使用するが、ここではシンプルな実装
        transmit_packet(device, data)
    });

    match result {
        Some(Ok(())) => {
            TX_PACKETS.fetch_add(1, Ordering::Relaxed);
            counters::global().record_tx(data.len());
            trace::push_event(NetLayer::Driver, NetEventKind::Tx, "virtio transmit");
            if let Some(if_id) = if_id.or_else(primary_bridge_if) {
                record_bridge_if_tx(if_id);
            }
            true
        }
        Some(Err(_)) => {
            log::info!("[NET BRIDGE] Transmit error");
            counters::global().record_error();
            trace::push_event(NetLayer::Driver, NetEventKind::Error, "virtio transmit error");
            false
        }
        None => {
            // VirtIO-Netが初期化されていない場合はデバッグ出力
            #[cfg(debug_assertions)]
            log::info!("[NET BRIDGE] VirtIO-Net not initialized");
            false
        }
    }
}

/// Low-level packet transmission via VirtIO-Net
fn transmit_packet(device: &VirtioNetDevice, data: &[u8]) -> Result<(), &'static str> {
    // Synchronously submit the packet using a DMA buffer so that the descriptor
    // is added and the device is notified immediately. The DMA buffer is
    // retained in the device's tx_inflight map and freed when the TX completion
    // is processed in the interrupt handler.
    crate::io::log::early_print(&alloc::format!("[EARLY][NET-TX] transmit_packet called len={}\n", data.len()));

    match device.submit_tx(data) {
        Ok(()) => {
            if data.len() >= 14 {
                log::info!(
                    "[NET-TX] {} bytes queued, dst={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    data.len(),
                    data[0],
                    data[1],
                    data[2],
                    data[3],
                    data[4],
                    data[5]
                );
            } else {
                log::info!("[NET-TX] {} bytes queued", data.len());
            }
            Ok(())
        }
        Err(_) => {
            log::info!("[NET-TX] submit failed");
            Err("Failed to submit TX")
        },
    }
}

fn lookup_virtio_index_for_interface(if_id: NetIfId) -> Option<u8> {
    manager::get_interface(if_id)
        .ok()
        .flatten()
        .and_then(|iface| iface.virtio_index)
}

fn transmit_packet_for_interface(if_id: NetIfId, data: &[u8]) -> Result<(), &'static str> {
    let virtio_index =
        lookup_virtio_index_for_interface(if_id).ok_or("VirtIO mapping not found for interface")?;
    match with_virtio_net_at_index(virtio_index, |device| transmit_packet(device, data)) {
        Some(result) => result,
        None => Err("VirtIO-Net device not initialized for interface"),
    }
}

/// Explicit TX submit on a logical interface (transitional helper).
pub fn send_packet_on_interface(if_id: NetIfId, data: &[u8]) -> bool {
    match transmit_packet_for_interface(if_id, data) {
        Ok(()) => {
            TX_PACKETS.fetch_add(1, Ordering::Relaxed);
            counters::global().record_tx(data.len());
            trace::push_event(NetLayer::Driver, NetEventKind::Tx, "interface transmit");
            record_bridge_if_tx(if_id);
            true
        }
        Err(e) => {
            // log the failure reason and interface
            crate::io::log::early_print(&alloc::format!("[DEBUG] send_packet_on_interface if={} err={:?}\n", if_id.0, e));
            log::info!("[NET BRIDGE] Interface transmit error if_id={}", if_id.0);
            counters::global().record_error();
            trace::push_event(
                NetLayer::Driver,
                NetEventKind::Error,
                alloc::format!("interface transmit error if={}", if_id.0),
            );
            false
        }
    }
}

// ============================================================================
// Receive Bridge
// ============================================================================

/// Process a received payload from VirtIO-Net (compatibility wrapper)
/// Call this from older interrupt handlers or polling loops.
/// This delegates to the zero-copy path by allocating a PacketRef and handing it off.
// Compatibility wrapper `process_received_packet` has been removed.
// Use `process_received_packet_zero_copy` directly instead.


/// Process a completed RX buffer without copying: use the provided PacketRef (zero-copy)
pub fn process_received_packet_zero_copy(mut packet: crate::net::datapath::mempool::PacketRef, header_size: usize, payload_len: usize) {
    if let Some(if_id) = primary_bridge_if() {
        process_received_packet_zero_copy_for_interface(if_id, packet, header_size, payload_len);
        return;
    }

    RX_PACKETS.fetch_add(1, Ordering::Relaxed);
    counters::global().record_rx(payload_len);
    trace::push_event(NetLayer::Driver, NetEventKind::Rx, "rx packet");

    // Ensure view length covers header + payload
    packet.set_len(header_size + payload_len);

    // Skip the virtio header so the PacketRef points at the Ethernet frame
    if header_size > 0 {
        packet.advance(header_size);
    }

    // Enqueue to batch processor (zero-copy)
    if let Some(batch) = BATCH_PROCESSOR.enqueue(packet) {
        stack::receive_batch(batch);
    }
}

/// Process a completed RX buffer for a specific logical interface (transitional API).
///
/// This updates per-interface bridge stats while reusing the existing single global stack path.
pub fn process_received_packet_zero_copy_for_interface(
    if_id: NetIfId,
    mut packet: crate::net::datapath::mempool::PacketRef,
    header_size: usize,
    payload_len: usize,
) {
    ensure_bridge_if_state(if_id, None);
    let rx_count = RX_PACKETS.fetch_add(1, Ordering::Relaxed).saturating_add(1);
    counters::global().record_rx(payload_len);
    trace::push_event(
        NetLayer::Driver,
        NetEventKind::Rx,
        alloc::format!("rx packet if={}", if_id.0),
    );
    record_bridge_if_rx(if_id);
    nat_maybe_gc(rx_count);

    packet.set_len(header_size + payload_len);
    if header_size > 0 {
        packet.advance(header_size);
    }

    // Attempt inbound NAT translation first (may rewrite dst address/port)
    {
        let data = packet.data_mut();
        if let Some(mut eth) = crate::net::l2::ethernet::EthernetFrameMut::new(data) {
            let is_ipv4 = eth
                .header_mut()
                .map(|hdr| hdr.ether_type() == crate::net::l2::ethernet::EtherType::Ipv4)
                .unwrap_or(false);
            if is_ipv4 {
                let ip_buf = eth.payload_mut();
                let parsed = crate::net::l3::ipv4::Ipv4Packet::parse(ip_buf).map(|ip_pkt| {
                    (
                        ip_pkt.protocol(),
                        ip_pkt.header().header_len(),
                        ip_pkt.source(),
                        ip_pkt.destination(),
                    )
                });

                let mut translated_dst = None;
                if let Some((proto, header_len, src_ip, mut dst_ip)) = parsed {
                    if (proto == crate::net::l3::ipv4::IpProtocol::Udp
                        || proto == crate::net::l3::ipv4::IpProtocol::Tcp)
                        && header_len <= ip_buf.len().saturating_sub(4)
                    {
                        let (_, transport) = ip_buf.split_at_mut(header_len);
                        let src_port = u16::from_be_bytes([transport[0], transport[1]]);
                        let mut dst_port = u16::from_be_bytes([transport[2], transport[3]]);
                        if nat_translate_in(proto, src_ip, src_port, &mut dst_ip, &mut dst_port) {
                            transport[2..4].copy_from_slice(&dst_port.to_be_bytes());
                            recompute_ipv4_transport_checksum(transport, src_ip, dst_ip, proto);
                            translated_dst = Some(dst_ip);
                        }
                    }
                }

                if let Some(dst_ip) = translated_dst {
                    if let Some(mut ip_pkt) = crate::net::l3::ipv4::Ipv4PacketMut::new(ip_buf) {
                        ip_pkt.set_destination(dst_ip);
                        ip_pkt.update_checksum();
                    }
                }
            }
        }
    }

    // Routing: forward packets not destined for local addresses
    if {
        let data = packet.data_mut();
        let mut forwarded = false;
        if let Some(eth) = crate::net::l2::ethernet::EthernetFrame::parse(&*data) {
            if eth.ether_type() == crate::net::l2::ethernet::EtherType::Ipv4 {
                if let Some(ip_pkt) = crate::net::l3::ipv4::Ipv4Packet::parse(eth.payload()) {
                    let dst = ip_pkt.destination();
                    let dst_octets = dst.octets();
                    let is_limited_broadcast = dst_octets == [255, 255, 255, 255];
                    let is_multicast = (dst_octets[0] & 0xF0) == 0xE0;
                    let should_consume_locally =
                        is_local_ipv4(dst) || is_limited_broadcast || is_multicast;

                    if !should_consume_locally {
                        if let Ok(Some(route)) = manager::lookup_ipv4_route(dst) {
                            if route.if_id != if_id {
                                // record for tests
                                #[cfg(any(test, feature = "qemu-test-export"))]
                                {
                                    let mut ev = FORWARD_EVENTS.write();
                                    ev.push((route.if_id, dst));
                                }
                                // apply NAT outbound if necessary
                                let src = ip_pkt.source();
                                let proto = ip_pkt.protocol();
                                let transport = ip_pkt.payload();
                                // need to parse transport header for ports
                                let (_new_src, _new_port) = match proto {
                                    crate::net::l3::ipv4::IpProtocol::Udp => {
                                        if let Some(udp) = crate::net::l4::udp::UdpPacket::parse(transport) {
                                            let (ns, np) = nat_translate_out(
                                                crate::net::l3::ipv4::IpProtocol::Udp,
                                                src,
                                                udp.src_port(),
                                                dst,
                                                udp.dst_port(),
                                                route.if_id,
                                            );
                                            (ns, np)
                                        } else {
                                            (src, 0)
                                        }
                                    }
                                    crate::net::l3::ipv4::IpProtocol::Tcp => {
                                        let tcp_src_port = transport
                                            .get(..2)
                                            .map(|port| u16::from_be_bytes([port[0], port[1]]))
                                            .unwrap_or(0);
                                        let tcp_dst_port = transport
                                            .get(2..4)
                                            .map(|port| u16::from_be_bytes([port[0], port[1]]))
                                            .unwrap_or(0);
                                        let (ns, np) = nat_translate_out(
                                            crate::net::l3::ipv4::IpProtocol::Tcp,
                                            src,
                                            tcp_src_port,
                                            dst,
                                            tcp_dst_port,
                                            route.if_id,
                                        );
                                        (ns, np)
                                    }
                                    _ => (src, 0),
                                };

                                let ttl = ip_pkt.ttl();
                                if ttl <= 1 {
                                    let original_ip = ip_pkt.as_bytes();
                                    let _ = stack::stack().lock().and_then(|mut g| {
                                        if let Some(ref mut s) = *g {
                                            Ok(s.send_icmp_time_exceeded(
                                                src,
                                                crate::net::l3::icmp::TimeExceededCode::TtlExceeded,
                                                original_ip,
                                            ))
                                        } else {
                                            Ok(false)
                                        }
                                    });
                                } else {
                                    let next_ttl = ttl - 1;
                                    // build new packet via stack send API
                                    match proto {
                                        crate::net::l3::ipv4::IpProtocol::Udp => {
                                            if let Some(udp) = crate::net::l4::udp::UdpPacket::parse(transport) {
                                                let payload = udp.payload();
                                                let src_port = _new_port;
                                                let dst_port = udp.dst_port();
                                                // send via stack
                                                let _ = stack::stack().lock().and_then(|mut g| {
                                                    if let Some(ref mut s) = *g {
                                                        Ok(s.send_udp_raw_on_with_src_ttl(
                                                            route.if_id,
                                                            _new_src,
                                                            src_port,
                                                            dst,
                                                            dst_port,
                                                            payload,
                                                            next_ttl,
                                                        ))
                                                    } else {
                                                        Ok(false)
                                                    }
                                                });
                                            }
                                        }
                                        crate::net::l3::ipv4::IpProtocol::Tcp => {
                                            // entire segment including header
                                            let mut nat_segment = Vec::from(transport);
                                            if _new_port != 0 && nat_segment.len() >= 18 {
                                                nat_segment[0..2].copy_from_slice(&_new_port.to_be_bytes());
                                                recompute_ipv4_transport_checksum(
                                                    &mut nat_segment,
                                                    _new_src,
                                                    dst,
                                                    crate::net::l3::ipv4::IpProtocol::Tcp,
                                                );
                                            }
                                            let _ = stack::stack().lock().and_then(|mut g| {
                                                if let Some(ref mut s) = *g {
                                                    Ok(s.send_tcp_with_ttl(_new_src, dst, &nat_segment, next_ttl))
                                                } else {
                                                    Ok(false)
                                                }
                                            });
                                        }
                                        _ => {}
                                    }
                                }
                                forwarded = true;
                            }
                        }
                    }
                }
            }
        }
        forwarded
    } {
        // packet was forwarded, drop original
        return;
    }

    if let Some(batch) = BATCH_PROCESSOR.enqueue(packet) {
        stack::receive_batch(batch);
    }
}


// ============================================================================
// Initialization
// ============================================================================

/// Initialize the network bridge
/// Connects VirtIO-Net driver to NetworkStack
pub fn init_bridge() -> Result<(), &'static str> {
    if BRIDGE_INITIALIZED.load(Ordering::Acquire) {
        return Ok(()); // Already initialized
    }

    let virtio_present = with_virtio_net(|_| ()).is_some();
    crate::io::log::early_print(&alloc::format!("[DEBUG] init_bridge virtio_present={}\n", virtio_present));
    if !virtio_present {
        log::warn!("[NET BRIDGE] VirtIO-Net not initialized; bridge init deferred");
        return Err("VirtIO-Net device not initialized");
    }

    if BRIDGE_INITIALIZED.swap(true, Ordering::SeqCst) {
        return Ok(());
    }

    log::info!("[NET BRIDGE] Initializing VirtIO-Net <-> NetworkStack bridge...");

    // Get MAC address from VirtIO-Net if available
    let mac = with_virtio_net(|device| {
        let mac_bytes = device.mac_address();
        MacAddress::from_octets(
            mac_bytes[0],
            mac_bytes[1],
            mac_bytes[2],
            mac_bytes[3],
            mac_bytes[4],
            mac_bytes[5],
        )
    })
    .unwrap_or_else(|| {
        // Default MAC for QEMU user mode networking
        MacAddress::from_octets(0x52, 0x54, 0x00, 0x12, 0x34, 0x56)
    });

    // Initialize NetworkStack with configuration
    let config = NetworkConfig {
        mac,
        ipv4: Ipv4Config {
            address: Ipv4Address::new([10, 0, 2, 15]), // QEMU default
            subnet_mask: Ipv4Address::new([255, 255, 255, 0]),
            gateway: Ipv4Address::new([10, 0, 2, 2]), // QEMU gateway
            dns: Some(Ipv4Address::new([10, 0, 2, 3])),
        },
        ipv6: Some(crate::net::l3::ipv6::Ipv6Config::from_mac(mac.as_bytes())),
        icmp_echo_enabled: true,
    };

    // Initialize the stack
    stack::init(config);

    // Transitional multi-NIC groundwork:
    // register the legacy bridge path as primary vnet0 in NetworkManager.
    manager::init_network_manager();
    match manager::register_virtio_port(0, Some(config)) {
        Ok(if_id) => {
            ensure_bridge_if_state(if_id, Some(0));
            set_primary_bridge_if_for_virtio(if_id, 0);
        }
        Err(err) => {
            log::warn!("[NET BRIDGE] failed to register primary vnet0 in NetworkManager: {:?}", err);
        }
    }

    // Set transmit callback
    match stack::stack().lock() {
        Ok(mut guard) => {
            if let Some(ref mut stack) = *guard {
                stack.set_transmit_fn(virtio_transmit);
            }
        }
        Err(_) => log::error!("[NET BRIDGE] Stack poisoned - transmit fn not set"),
    }

    // Do not seed gateway ARP with the local NIC MAC.
    // Let normal ARP resolution discover the peer MAC to avoid self-MAC misrouting.

    if let Err(e) = crate::net::api::shell::init_dhcp_runtime() {
        log::warn!("[NET BRIDGE] DHCP runtime init failed: {}", e);
    }

    log::info!("[NET BRIDGE] Bridge initialized");
    log::info!(
        "  MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac.as_bytes()[0],
        mac.as_bytes()[1],
        mac.as_bytes()[2],
        mac.as_bytes()[3],
        mac.as_bytes()[4],
        mac.as_bytes()[5]
    );
    log::info!("  IP: 10.0.2.15");

    // Enable timer-based fallback RX/TX completion once the bridge is live.
    crate::interrupts::enable_virtio_net_irq_fallback();

    Ok(())
}

/// Check if bridge is initialized
pub fn is_initialized() -> bool {
    BRIDGE_INITIALIZED.load(Ordering::Acquire)
}

/// Check and flush batched packets if timeout occurred
/// Should be called periodically (e.g. from timer interrupt)
pub fn check_batch_timeout(current_tsc: u64, tsc_freq: u64) {
    if let Some(batch) = BATCH_PROCESSOR.check_timeout(current_tsc, tsc_freq) {
        stack::receive_batch(batch);
    }
}

// ============================================================================
// Shell API Integration

// ============================================================================

/// Get bridge statistics
pub fn get_bridge_stats() -> BridgeStats {
    BridgeStats {
        tx_packets: TX_PACKETS.load(Ordering::Relaxed),
        rx_packets: RX_PACKETS.load(Ordering::Relaxed),
        initialized: BRIDGE_INITIALIZED.load(Ordering::Acquire),
    }
}

/// Bridge statistics
#[derive(Debug, Clone, Copy)]
pub struct BridgeStats {
    pub tx_packets: u64,
    pub rx_packets: u64,
    pub initialized: bool,
}

/// Bridge statistics for a specific logical interface.
#[derive(Debug, Clone, Copy)]
pub struct BridgeInterfaceStats {
    pub if_id: NetIfId,
    pub tx_packets: u64,
    pub rx_packets: u64,
    pub initialized: bool,
    pub virtio_index: Option<u8>,
}

/// Register (or reuse) a VirtIO-backed interface in the bridge/manager mapping.
///
/// This is an opt-in helper for multi-NIC wiring. It does not reconfigure `system_impl`.
pub fn register_virtio_port(
    virtio_index: u8,
    initial_config: Option<NetworkConfig>,
) -> Result<NetIfId, &'static str> {
    manager::init_network_manager();
    let if_id = manager::register_virtio_port(virtio_index, initial_config)
        .map_err(|_| "failed to register virtio port")?;
    ensure_bridge_if_state(if_id, Some(virtio_index));
    let _ = bind_virtio_net_interface(virtio_index, if_id);
    set_primary_bridge_if_for_virtio(if_id, virtio_index);
    Ok(if_id)
}

/// Look up the logical interface id mapped to a VirtIO index.
pub fn lookup_if_by_virtio_index(virtio_index: u8) -> Option<NetIfId> {
    manager::lookup_if_by_virtio_index(virtio_index)
}

/// Per-interface bridge stats snapshot.
pub fn get_bridge_stats_for_interface(if_id: NetIfId) -> Option<BridgeInterfaceStats> {
    BRIDGE_IF_STATS.read().get(&if_id).copied()
}

/// List all per-interface bridge stats snapshots.
pub fn list_bridge_stats() -> Vec<BridgeInterfaceStats> {
    BRIDGE_IF_STATS.read().values().copied().collect()
}

/// Get real network configuration from NetworkStack
pub fn get_real_config() -> Option<NetworkConfigSnapshot> {
    match stack::stack().lock() {
        Ok(guard) => {
            let stack = match guard.as_ref() {
                Some(s) => s,
                None => return None,
            };

            let config = stack.config();

            Some(NetworkConfigSnapshot {
                ip: *config.ipv4.address.as_bytes(),
                netmask: *config.ipv4.subnet_mask.as_bytes(),
                gateway: *config.ipv4.gateway.as_bytes(),
                mac: *config.mac.as_bytes(),
            })
        }
        Err(_) => {
            log::error!("[NET BRIDGE] Stack poisoned (get_real_config)");
            None
        }
    }
}

/// Get real network configuration for a specific interface.
///
/// Transitional behavior: returns the single global stack config only for the
/// current primary bridge interface.
pub fn get_real_config_for_interface(if_id: NetIfId) -> Option<NetworkConfigSnapshot> {
    if primary_bridge_if() != Some(if_id) {
        return None;
    }
    get_real_config()
}


#[cfg(any(test, feature = "qemu-test-export"))]
pub(crate) mod tests {
    use super::*;
    use crate::net::datapath::mempool;
    use crate::net::runtime::stack;
    use crate::net::l3::ipv4::{Ipv4PacketMut, Ipv4Address, IpProtocol};
    use crate::net::l4::tcp::{TcpControlBlock, SocketAddr as TcpSocketAddr, Ipv4Addr as TcpIpv4Addr};
    use alloc::collections::BTreeMap;
    use alloc::vec::Vec;
    use crate::net::runtime::manager;

    struct BridgeStateGuard {
        prev_if_stats: BTreeMap<NetIfId, BridgeInterfaceStats>,
        prev_primary_if: Option<NetIfId>,
        prev_nat_table: BTreeMap<u16, NatEntry>,
        prev_nat_next_port: u16,
        prev_forward_events: Vec<(NetIfId, Ipv4Address)>,
        prev_manager: Option<crate::net::runtime::manager::NetworkManager>,
    }

    impl BridgeStateGuard {
        fn new() -> Self {
            let prev_if_stats = core::mem::take(&mut *BRIDGE_IF_STATS.write());
            let prev_primary_if = {
                let mut g = PRIMARY_BRIDGE_IF.write();
                let v = *g;
                *g = None;
                v
            };
            let prev_nat_table = core::mem::take(&mut *NAT_TABLE.write());
            let prev_nat_next_port =
                NAT_NEXT_PORT.swap(NAT_EPHEMERAL_START, core::sync::atomic::Ordering::Relaxed);
            let prev_forward_events = core::mem::take(&mut *FORWARD_EVENTS.write());
            let prev_manager = {
                let mut guard = crate::net::runtime::manager::NETWORK_MANAGER
                    .lock_for_init("[TEST][NET BRIDGE] manager snapshot");
                core::mem::take(&mut *guard)
            };
            Self {
                prev_if_stats,
                prev_primary_if,
                prev_nat_table,
                prev_nat_next_port,
                prev_forward_events,
                prev_manager,
            }
        }
    }

    impl Drop for BridgeStateGuard {
        fn drop(&mut self) {
            *BRIDGE_IF_STATS.write() = core::mem::take(&mut self.prev_if_stats);
            *PRIMARY_BRIDGE_IF.write() = self.prev_primary_if.take();
            *NAT_TABLE.write() = core::mem::take(&mut self.prev_nat_table);
            NAT_NEXT_PORT.store(self.prev_nat_next_port, core::sync::atomic::Ordering::Relaxed);
            *FORWARD_EVENTS.write() = core::mem::take(&mut self.prev_forward_events);
            let mut guard = crate::net::runtime::manager::NETWORK_MANAGER
                .lock_for_init("[TEST][NET BRIDGE] manager restore");
            *guard = self.prev_manager.take();
        }
    }

    // ---------------------------------------------------------------------
    // QEMU deterministic helpers (heap-aware fallback)
    // ---------------------------------------------------------------------

    #[cfg(feature = "qemu-test-export")]
    fn qemu_prepare_zero_copy_env() -> BridgeStateGuard {
        let guard = BridgeStateGuard::new();
        stack::stack().clear_poison();
        guard
    }

    #[cfg(feature = "qemu-test-export")]
    fn qemu_insert_established_tcb(
        local: TcpSocketAddr,
        remote: TcpSocketAddr,
    ) -> Option<alloc::sync::Arc<PoisonLock<TcpControlBlock>>> {
        let mut tcb = TcpControlBlock::new(local);
        tcb.set_remote_addr(remote);
        tcb.enter_established();
        tcb.set_rcv_nxt(1);
        let tcb_arc = alloc::sync::Arc::new(PoisonLock::new(tcb));

        match stack::stack().lock() {
            Ok(mut guard) => {
                let stack = guard.as_mut()?;
                stack.insert_test_tcp_connection(local, remote, tcb_arc.clone());
                Some(tcb_arc)
            }
            Err(_) => None,
        }
    }

    #[cfg(feature = "qemu-test-export")]
    fn qemu_zero_copy_prereq_postcheck(
        tcb_arc: &alloc::sync::Arc<PoisonLock<TcpControlBlock>>,
    ) -> bool {
        check_batch_timeout(100_000, 1);
        match tcb_arc.lock() {
            Ok(guard) => guard.recv_buffer_is_empty() && guard.is_established(),
            Err(_) => false,
        }
    }

    #[cfg(feature = "qemu-test-export")]
    pub fn qemu_packet_path_available() -> bool {
        let _ = mempool::init_net_mempool(1);
        mempool::alloc_packet().is_some()
    }

    #[cfg(feature = "qemu-test-export")]
    fn qemu_zero_copy_prereq_ipv4_heapless_smoke() -> bool {
        let _bridge_guard = qemu_prepare_zero_copy_env();

        let mut config = NetworkConfig::default();
        config.ipv4.address = Ipv4Address::new([127, 0, 0, 1]);
        stack::init(config);

        let local = TcpSocketAddr::new(TcpIpv4Addr::new(127, 0, 0, 1), 1000);
        let remote = TcpSocketAddr::new(TcpIpv4Addr::new(127, 0, 0, 1), 2000);
        let tcb_arc = match qemu_insert_established_tcb(local, remote) {
            Some(tcb) => tcb,
            None => return false,
        };

        qemu_zero_copy_prereq_postcheck(&tcb_arc)
    }

    #[cfg(feature = "qemu-test-export")]
    fn qemu_zero_copy_prereq_ipv6_heapless_smoke() -> bool {
        let _bridge_guard = qemu_prepare_zero_copy_env();

        let mut config = NetworkConfig::default();
        config.ipv6 = Some(crate::net::l3::ipv6::Ipv6Config::from_mac(&[
            0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
        ]));
        stack::init(config);

        let local = TcpSocketAddr::new_v6(crate::net::l3::ipv6::Ipv6Address::LOOPBACK, 1000);
        let remote = TcpSocketAddr::new_v6(crate::net::l3::ipv6::Ipv6Address::LOOPBACK, 2000);
        let tcb_arc = match qemu_insert_established_tcb(local, remote) {
            Some(tcb) => tcb,
            None => return false,
        };

        qemu_zero_copy_prereq_postcheck(&tcb_arc)
    }

    // Heapless fallback for routing/NAT parity when packet-path allocation is unavailable.

    #[cfg(feature = "qemu-test-export")]
    fn qemu_routing_nat_heapless_smoke() -> bool {
        let _guard = BridgeStateGuard::new();
        manager::init_network_manager();

        let if1 = match manager::register_interface("qemu-if-a") {
            Ok(id) => id,
            Err(_) => return false,
        };
        let if2 = match manager::register_interface("qemu-if-b") {
            Ok(id) => id,
            Err(_) => return false,
        };

        let cfg1 = NetworkConfig {
            mac: MacAddress::from_octets(0, 1, 2, 3, 4, 5),
            ipv4: Ipv4Config {
                address: Ipv4Address::new([10, 0, 0, 1]),
                subnet_mask: Ipv4Address::new([255, 255, 255, 0]),
                gateway: Ipv4Address::ANY,
                dns: None,
            },
            ipv6: None,
            icmp_echo_enabled: true,
        };
        let cfg2 = NetworkConfig {
            mac: MacAddress::from_octets(0, 1, 2, 3, 4, 6),
            ipv4: Ipv4Config {
                address: Ipv4Address::new([10, 0, 1, 1]),
                subnet_mask: Ipv4Address::new([255, 255, 255, 0]),
                gateway: Ipv4Address::ANY,
                dns: None,
            },
            ipv6: None,
            icmp_echo_enabled: true,
        };
        if manager::set_interface_config(if1, cfg1).is_err()
            || manager::set_interface_config(if2, cfg2).is_err()
        {
            return false;
        }

        let route = manager::Ipv4Route {
            destination: Ipv4Address::new([10, 0, 1, 0]),
            prefix_len: 24,
            gateway: None,
            if_id: if2,
            metric: 1,
            flags: manager::RouteFlags::connected(),
            admin_enabled: true,
            managed_by_interface: false,
        };
        if manager::add_ipv4_route(route).is_err() {
            return false;
        }

        let route_ok = matches!(
            manager::lookup_ipv4_route(Ipv4Address::new([10, 0, 1, 5])),
            Ok(Some(r)) if r.if_id == if2
        );
        if !route_ok {
            return false;
        }

        true
    }

    // Public QEMU smoke entry points used by net peripheral required suite.

    #[cfg(feature = "qemu-test-export")]
    pub fn qemu_zero_copy_via_bridge_smoke() -> bool {
        qemu_zero_copy_prereq_ipv4_heapless_smoke()
    }

    #[cfg(feature = "qemu-test-export")]
    pub fn qemu_routing_and_nat_smoke() -> bool {
        qemu_routing_nat_heapless_smoke()
    }

    #[cfg(feature = "qemu-test-export")]
    pub fn qemu_zero_copy_via_bridge_v6_smoke() -> bool {
        qemu_zero_copy_prereq_ipv6_heapless_smoke()
    }

    #[cfg_attr(test, test_case)]
    pub fn test_zero_copy_via_bridge() {
        let _guard = BridgeStateGuard::new();
        stack::stack().clear_poison();

        // Initialize mempool and stack
        let _ = mempool::init_net_mempool(4);

        // Configure stack to use 127.0.0.1 for tests
        let mut config = NetworkConfig::default();
        config.ipv4.address = Ipv4Address::new([127, 0, 0, 1]);
        stack::init(config);

        // Prepare a TCB and register it in the global stack
        let local = TcpSocketAddr::new(TcpIpv4Addr::new(127, 0, 0, 1), 1000);
        let remote = TcpSocketAddr::new(TcpIpv4Addr::new(127, 0, 0, 1), 2000);

        let mut tcb = TcpControlBlock::new(local);
        tcb.set_remote_addr(remote);
        tcb.enter_established();
        tcb.set_rcv_nxt(1);
        let tcb_arc = alloc::sync::Arc::new(PoisonLock::new(tcb));

        // Insert into stack's tcp connections
        match stack::stack().lock() {
            Ok(mut guard) => {
                if let Some(ref mut s) = *guard {
                    s.insert_test_tcp_connection(local, remote, tcb_arc.clone());
                }
            }
            Err(_) => panic!("Stack poisoned"),
        }

        // Build packet: virtio header + ethernet + IPv4 + TCP + payload
        let header_size = crate::io::virtio::net::VirtioNetHeader::SIZE;
        let payload = b"hello";
        let tcp_len = 20 + payload.len();
        let ip_total_len = 20 + tcp_len; // IP header + TCP + payload
        let eth_total_len = 14 + ip_total_len; // Ethernet frame length

        // Allocate packet buffer
        let mut packet = mempool::alloc_packet().expect("alloc packet");
        let buf = packet.data_mut();

        // Ensure buffer large enough
        let needed = header_size + eth_total_len;
        assert!(buf.len() >= needed, "Packet buffer too small for test");

        // Virtio header (zero)
        for i in 0..header_size { buf[i] = 0; }

        // Ethernet header
        let eth_off = header_size;
        buf[eth_off..eth_off + 6].copy_from_slice(&[0xff; 6]); // dst
        buf[eth_off + 6..eth_off + 12].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // src
        buf[eth_off + 12..eth_off + 14].copy_from_slice(&[0x08, 0x00]); // EtherType = IPv4

        // IPv4 header
        let ip_off = eth_off + 14;
        {
            let mut ipv4_mut = Ipv4PacketMut::new(&mut buf[ip_off..ip_off + 20]).expect("ipv4 mut");
            ipv4_mut
                .init_header()
                .set_source(Ipv4Address::new([127, 0, 0, 1]))
                .set_destination(Ipv4Address::new([127, 0, 0, 1]))
                .set_protocol(IpProtocol::Tcp)
                .set_identification(1);
        }
        // Write TCP header and payload into IP payload
        let tcp_off = ip_off + 20;
        // Src port 2000, dst port 1000
        buf[tcp_off..tcp_off + 2].copy_from_slice(&2000u16.to_be_bytes());
        buf[tcp_off + 2..tcp_off + 4].copy_from_slice(&1000u16.to_be_bytes());
        // Seq = 1
        buf[tcp_off + 4..tcp_off + 8].copy_from_slice(&1u32.to_be_bytes());
        // Ack = 0
        buf[tcp_off + 8..tcp_off + 12].copy_from_slice(&0u32.to_be_bytes());
        // Data offset = 5 (20 bytes), flags = 0
        let data_off_flags = ((5u16 << 12) | 0u16).to_be_bytes();
        buf[tcp_off + 12..tcp_off + 14].copy_from_slice(&data_off_flags);
        // Window
        buf[tcp_off + 14..tcp_off + 16].copy_from_slice(&65535u16.to_be_bytes());
        // Payload
        buf[tcp_off + 20..tcp_off + 20 + payload.len()].copy_from_slice(payload);

        // Finalize IP header (set total length and checksum)
        Ipv4PacketMut::new(&mut buf[ip_off..ip_off + 20])
            .expect("ipv4 mut")
            .finalize(tcp_len);

        // Set packet length (virtio header + ethernet frame)
        packet.set_len(header_size + eth_total_len);

        // Call bridge zero-copy entry
        process_received_packet_zero_copy(packet, header_size, eth_total_len);

        // Force a batch timeout to flush the packet into the stack
        check_batch_timeout(100_000, 1);

        // Now verify TCB received the payload zero-copy
        if let Ok(guard) = tcb_arc.lock() {
            assert!(!guard.recv_buffer_is_empty());
            assert_eq!(guard.recv_buffer_front_data().unwrap(), payload);
        } else {
            panic!("TCB lock poisoned in test");
        }
    }

    #[cfg_attr(test, test_case)]
    pub fn test_routing_and_nat() {
        // setup environment
        let _guard = BridgeStateGuard::new();
        let _ = mempool::init_net_mempool(4);
        manager::init_network_manager();

        // create two interfaces
        let if1 = manager::register_interface("if1").expect("register if1");
        let if2 = manager::register_interface("if2").expect("register if2");
        // configure addresses
        let cfg1 = NetworkConfig {
            mac: MacAddress::from_octets(0,1,2,3,4,5),
            ipv4: Ipv4Config {
                address: Ipv4Address::new([10,0,0,1]),
                subnet_mask: Ipv4Address::new([255,255,255,0]),
                gateway: Ipv4Address::ANY,
                dns: None,
            },
            ipv6: None,
            icmp_echo_enabled: true,
        };
        let cfg2 = NetworkConfig {
            mac: MacAddress::from_octets(0,1,2,3,4,6),
            ipv4: Ipv4Config {
                address: Ipv4Address::new([10,0,1,1]),
                subnet_mask: Ipv4Address::new([255,255,255,0]),
                gateway: Ipv4Address::ANY,
                dns: None,
            },
            ipv6: None,
            icmp_echo_enabled: true,
        };
        let _ = manager::set_interface_config(if1, cfg1);
        let _ = manager::set_interface_config(if2, cfg2);

        // add route 10.0.1.0/24 via if2
        let route = manager::Ipv4Route {
            destination: Ipv4Address::new([10,0,1,0]),
            prefix_len: 24,
            gateway: None,
            if_id: if2,
            metric: 1,
            flags: manager::RouteFlags::connected(),
            admin_enabled: true,
            managed_by_interface: false,
        };
        let _ = manager::add_ipv4_route(route);

        // craft a UDP packet from 10.0.0.2:1234 to 10.0.1.5:80 arriving on if1
        let header_size = crate::io::virtio::net::VirtioNetHeader::SIZE;
        let mut packet = mempool::alloc_packet().unwrap();
        let buf = packet.data_mut();
        // build ethernet, ip, udp similar to earlier tests
        let eth_off = header_size;
        let ip_off = eth_off + 14;
        // fill with minimal sizes
        buf[0..header_size].fill(0);
        // eth header
        buf[eth_off..eth_off+6].fill(0xff);
        buf[eth_off+6..eth_off+12].copy_from_slice(&[0,1,2,3,4,5]);
        buf[eth_off+12..eth_off+14].copy_from_slice(&[0x08,0x00]); // IPv4
        // ip header
        {
            let mut ipm = Ipv4PacketMut::new(&mut buf[ip_off..ip_off+20]).unwrap();
            ipm.init_header()
                .set_source(Ipv4Address::new([10,0,0,2]))
                .set_destination(Ipv4Address::new([10,0,1,5]))
                .set_protocol(IpProtocol::Udp);
            ipm.set_total_length(28); // 20 ip + 8 udp
            ipm.update_checksum();
        }
        // udp header
        let udp_off = ip_off + 20;
        buf[udp_off..udp_off+2].copy_from_slice(&1234u16.to_be_bytes());
        buf[udp_off+2..udp_off+4].copy_from_slice(&80u16.to_be_bytes());
        buf[udp_off+4..udp_off+6].copy_from_slice(&8u16.to_be_bytes());
        buf[udp_off+6..udp_off+8].copy_from_slice(&0u16.to_be_bytes());

        let total_len = header_size + 14 + 28;
        packet.set_len(total_len);

        // clear forward events
        #[cfg(any(test, feature = "qemu-test-export"))]{
            FORWARD_EVENTS.write().clear();
        }

        process_received_packet_zero_copy_for_interface(if1, packet, header_size, 14+28);

        // verify forwarded to if2 and NAT table contains entry
        #[cfg(any(test, feature = "qemu-test-export"))]{
            let ev = FORWARD_EVENTS.read();
            assert!(ev.iter().any(|(id, dst)| *id == if2 && *dst == Ipv4Address::new([10,0,1,5])));
            // check NAT entry exists for internal port 1234
            let table = NAT_TABLE.read();
            assert!(table.values().any(|e|
                e.protocol == IpProtocol::Udp
                    && e.internal_addr == Ipv4Address::new([10,0,0,2])
                    && e.internal_port == 1234
            ));
        }
    }

    #[cfg_attr(test, test_case)]
    pub fn test_nat_inbound_roundtrip_is_protocol_scoped() {
        let _guard = BridgeStateGuard::new();
        manager::init_network_manager();

        let wan_if = manager::register_interface("wan0").expect("register wan0");
        let other_wan_if = manager::register_interface("wan1").expect("register wan1");
        let wan_cfg = NetworkConfig {
            mac: MacAddress::from_octets(0, 1, 2, 3, 4, 42),
            ipv4: Ipv4Config {
                address: Ipv4Address::new([10, 0, 1, 1]),
                subnet_mask: Ipv4Address::new([255, 255, 255, 0]),
                gateway: Ipv4Address::ANY,
                dns: None,
            },
            ipv6: None,
            icmp_echo_enabled: true,
        };
        let _ = manager::set_interface_config(wan_if, wan_cfg);
        let _ = manager::set_interface_config(
            other_wan_if,
            NetworkConfig {
                mac: MacAddress::from_octets(0, 1, 2, 3, 4, 43),
                ipv4: Ipv4Config {
                    address: Ipv4Address::new([10, 0, 2, 1]),
                    subnet_mask: Ipv4Address::new([255, 255, 255, 0]),
                    gateway: Ipv4Address::ANY,
                    dns: None,
                },
                ipv6: None,
                icmp_echo_enabled: true,
            },
        );

        let internal_ip = Ipv4Address::new([10, 0, 0, 2]);
        let internal_port = 1234;
        let remote_ip = Ipv4Address::new([198, 51, 100, 10]);
        let remote_port = 43210;
        let (ext_ip, ext_port) =
            nat_translate_out(IpProtocol::Udp, internal_ip, internal_port, remote_ip, remote_port, wan_if);

        assert_eq!(ext_ip, Ipv4Address::new([10, 0, 1, 1]));
        assert!(ext_port >= NAT_EPHEMERAL_START);

        let mut dst_ip = ext_ip;
        let mut dst_port = ext_port;
        assert!(nat_translate_in(
            IpProtocol::Udp,
            remote_ip,
            remote_port,
            &mut dst_ip,
            &mut dst_port
        ));
        assert_eq!(dst_ip, internal_ip);
        assert_eq!(dst_port, internal_port);

        // Same external port but different protocol must not match.
        let mut dst_ip = ext_ip;
        let mut dst_port = ext_port;
        assert!(!nat_translate_in(
            IpProtocol::Tcp,
            remote_ip,
            remote_port,
            &mut dst_ip,
            &mut dst_port
        ));
        assert_eq!(dst_ip, ext_ip);
        assert_eq!(dst_port, ext_port);

        // Different local WAN IP (also local) must not match this mapping.
        let mut dst_ip = Ipv4Address::new([10, 0, 2, 1]);
        let mut dst_port = ext_port;
        assert!(!nat_translate_in(
            IpProtocol::Udp,
            remote_ip,
            remote_port,
            &mut dst_ip,
            &mut dst_port
        ));
        assert_eq!(dst_ip, Ipv4Address::new([10, 0, 2, 1]));
        assert_eq!(dst_port, ext_port);

        // Non-local destination addresses must not be rewritten.
        let mut dst_ip = Ipv4Address::new([203, 0, 113, 9]);
        let mut dst_port = ext_port;
        assert!(!nat_translate_in(
            IpProtocol::Udp,
            remote_ip,
            remote_port,
            &mut dst_ip,
            &mut dst_port
        ));
        assert_eq!(dst_ip, Ipv4Address::new([203, 0, 113, 9]));
        assert_eq!(dst_port, ext_port);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_nat_gc_expires_idle_entries() {
        let _guard = BridgeStateGuard::new();
        manager::init_network_manager();

        let wan_if = manager::register_interface("wan0").expect("register wan0");
        let _ = manager::set_interface_config(
            wan_if,
            NetworkConfig {
                mac: MacAddress::from_octets(0, 1, 2, 3, 4, 44),
                ipv4: Ipv4Config {
                    address: Ipv4Address::new([10, 0, 9, 1]),
                    subnet_mask: Ipv4Address::new([255, 255, 255, 0]),
                    gateway: Ipv4Address::ANY,
                    dns: None,
                },
                ipv6: None,
                icmp_echo_enabled: true,
            },
        );

        let (_, stale_port) = nat_translate_out(
            IpProtocol::Udp,
            Ipv4Address::new([10, 0, 0, 2]),
            1111,
            Ipv4Address::new([198, 51, 100, 1]),
            50001,
            wan_if,
        );
        let (_, fresh_port) = nat_translate_out(
            IpProtocol::Udp,
            Ipv4Address::new([10, 0, 0, 3]),
            2222,
            Ipv4Address::new([198, 51, 100, 2]),
            50002,
            wan_if,
        );

        {
            let mut table = NAT_TABLE.write();
            table.get_mut(&stale_port).unwrap().last_seen = 100;
            table.get_mut(&fresh_port).unwrap().last_seen = 900;
        }

        let removed = nat_prune_expired(1_000, 200);
        assert_eq!(removed, 1);

        let table = NAT_TABLE.read();
        assert!(!table.contains_key(&stale_port));
        assert!(table.contains_key(&fresh_port));
    }

    #[cfg_attr(test, test_case)]
    pub fn test_zero_copy_via_bridge_v6() {
        let _guard = BridgeStateGuard::new();
        stack::stack().clear_poison();

        // Initialize mempool and stack
        let _ = mempool::init_net_mempool(4);

        // Configure stack with IPv6 enabled for tests
        let mut config = NetworkConfig::default();
        config.ipv6 = Some(crate::net::l3::ipv6::Ipv6Config::from_mac(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]));
        stack::init(config);

        // Prepare a TCB and register it in the global stack (IPv6)
        let local = TcpSocketAddr::new_v6(crate::net::l3::ipv6::Ipv6Address::LOOPBACK, 1000);
        let remote = TcpSocketAddr::new_v6(crate::net::l3::ipv6::Ipv6Address::LOOPBACK, 2000);

        let mut tcb = TcpControlBlock::new(local);
        tcb.set_remote_addr(remote);
        tcb.enter_established();
        tcb.set_rcv_nxt(1);
        let tcb_arc = alloc::sync::Arc::new(PoisonLock::new(tcb));

        // Insert into stack's tcp connections
        match stack::stack().lock() {
            Ok(mut guard) => {
                if let Some(ref mut s) = *guard {
                    s.insert_test_tcp_connection(local, remote, tcb_arc.clone());
                }
            }
            Err(_) => panic!("Stack poisoned"),
        }

        // Build packet: virtio header + ethernet + IPv6 + TCP + payload
        let header_size = crate::io::virtio::net::VirtioNetHeader::SIZE;
        let payload = b"hello-v6";
        let tcp_len = 20 + payload.len();
        let ipv6_total_len = 40 + tcp_len; // IPv6 header + TCP + payload
        let eth_total_len = 14 + ipv6_total_len; // Ethernet frame length

        // Allocate packet buffer
        let mut packet = mempool::alloc_packet().expect("alloc packet");
        let buf = packet.data_mut();

        // Ensure buffer large enough
        let needed = header_size + eth_total_len;
        assert!(buf.len() >= needed, "Packet buffer too small for test");

        // Virtio header (zero)
        for i in 0..header_size { buf[i] = 0; }

        // Ethernet header
        let eth_off = header_size;
        buf[eth_off..eth_off + 6].copy_from_slice(&[0xff; 6]); // dst
        buf[eth_off + 6..eth_off + 12].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // src
        buf[eth_off + 12..eth_off + 14].copy_from_slice(&[0x86, 0xdd]); // EtherType = IPv6

        // IPv6 header
        let ip_off = eth_off + 14;
        {
            let mut ipv6_mut = crate::net::l3::ipv6::Ipv6PacketMut::new(&mut buf[ip_off..ip_off + 40]).expect("ipv6 mut");
            ipv6_mut.init_header();
            ipv6_mut.set_source(&crate::net::l3::ipv6::Ipv6Address::LOOPBACK);
            ipv6_mut.set_destination(&crate::net::l3::ipv6::Ipv6Address::LOOPBACK);
            ipv6_mut.set_next_header(crate::net::l3::ipv4::IpProtocol::Tcp);
            ipv6_mut.set_payload_length(tcp_len as u16);
        }

        // Write TCP header and payload into IPv6 payload
        let tcp_off = ip_off + 40;
        // Src port 2000, dst port 1000
        buf[tcp_off..tcp_off + 2].copy_from_slice(&2000u16.to_be_bytes());
        buf[tcp_off + 2..tcp_off + 4].copy_from_slice(&1000u16.to_be_bytes());
        // Seq = 1
        buf[tcp_off + 4..tcp_off + 8].copy_from_slice(&1u32.to_be_bytes());
        // Ack = 0
        buf[tcp_off + 8..tcp_off + 12].copy_from_slice(&0u32.to_be_bytes());
        // Data offset = 5 (20 bytes), flags = 0
        let data_off_flags = ((5u16 << 12) | 0u16).to_be_bytes();
        buf[tcp_off + 12..tcp_off + 14].copy_from_slice(&data_off_flags);
        // Window
        buf[tcp_off + 14..tcp_off + 16].copy_from_slice(&65535u16.to_be_bytes());
        // Payload
        buf[tcp_off + 20..tcp_off + 20 + payload.len()].copy_from_slice(payload);

        // Set packet length (virtio header + ethernet frame)
        packet.set_len(header_size + eth_total_len);

        // Call bridge zero-copy entry
        process_received_packet_zero_copy(packet, header_size, eth_total_len);

        // Force a batch timeout to flush the packet into the stack
        check_batch_timeout(100_000, 1);

        // Now verify TCB received the payload zero-copy
        if let Ok(guard) = tcb_arc.lock() {
            assert!(!guard.recv_buffer_is_empty());
            assert_eq!(guard.recv_buffer_front_data().unwrap(), payload);
        } else {
            panic!("TCB lock poisoned in test");
        }
    }

    #[cfg_attr(test, test_case)]
    pub fn test_per_interface_bridge_stats_are_separated() {
        let _guard = BridgeStateGuard::new();
        let if0 = NetIfId(10);
        let if1 = NetIfId(11);

        ensure_bridge_if_state(if0, Some(0));
        ensure_bridge_if_state(if1, Some(1));
        record_bridge_if_rx(if0);
        record_bridge_if_rx(if0);
        record_bridge_if_tx(if1);

        let s0 = get_bridge_stats_for_interface(if0).expect("if0 stats");
        let s1 = get_bridge_stats_for_interface(if1).expect("if1 stats");
        assert_eq!(s0.rx_packets, 2);
        assert_eq!(s0.tx_packets, 0);
        assert_eq!(s1.rx_packets, 0);
        assert_eq!(s1.tx_packets, 1);
        assert_eq!(list_bridge_stats().len(), 2);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_register_virtio_port_is_idempotent_and_records_mapping() {
        let _guard = BridgeStateGuard::new();

        let if0 = register_virtio_port(0, None).expect("register vnet0");
        let if0_again = register_virtio_port(0, None).expect("register vnet0 again");
        let if1 = register_virtio_port(1, None).expect("register vnet1");

        assert_eq!(if0, if0_again);
        assert_ne!(if0, if1);
        assert_eq!(lookup_if_by_virtio_index(0), Some(if0));
        assert_eq!(lookup_if_by_virtio_index(1), Some(if1));

        let s0 = get_bridge_stats_for_interface(if0).expect("if0 stats");
        let s1 = get_bridge_stats_for_interface(if1).expect("if1 stats");
        assert_eq!(s0.virtio_index, Some(0));
        assert_eq!(s1.virtio_index, Some(1));
        assert_eq!(list_bridge_stats().len(), 2);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_register_virtio_port_prefers_vnet0_as_primary() {
        let _guard = BridgeStateGuard::new();

        let if1 = register_virtio_port(1, None).expect("register vnet1");
        assert_eq!(primary_bridge_if(), Some(if1));

        let if0 = register_virtio_port(0, None).expect("register vnet0");
        assert_eq!(primary_bridge_if(), Some(if0));

        let _if2 = register_virtio_port(2, None).expect("register vnet2");
        assert_eq!(primary_bridge_if(), Some(if0));
    }

    #[cfg_attr(test, test_case)]
    pub fn test_virtio_transmit_interface_argument() {
        // using a dummy interface id should simply delegate to the
        // per-interface send function, which currently fails (no mapping)
        let dummy = NetIfId(7);
        assert!(!virtio_transmit(Some(dummy), b"hello"));
    }
}

/// Get real network statistics from NetworkStack
pub fn get_real_stats() -> Option<NetworkStatsSnapshot> {
    match stack::stack().lock() {
        Ok(guard) => {
            let stack = match guard.as_ref() {
                Some(s) => s,
                None => return None,
            };

            let stats = stack.stats();

            Some(NetworkStatsSnapshot {
                rx_packets: stats.rx_packets.load(Ordering::Relaxed),
                tx_packets: stats.tx_packets.load(Ordering::Relaxed),
                rx_bytes: stats.rx_bytes.load(Ordering::Relaxed),
                tx_bytes: stats.tx_bytes.load(Ordering::Relaxed),
                rx_errors: stats.rx_errors.load(Ordering::Relaxed),
                rx_dropped: stats.rx_dropped.load(Ordering::Relaxed),
            })
        }
        Err(_) => {
            log::error!("[NET BRIDGE] Stack poisoned (get_real_stats)");
            None
        }
    }
}

/// Get real network statistics for a specific interface.
///
/// Transitional behavior: returns the single global stack stats only for the
/// current primary bridge interface.
pub fn get_real_stats_for_interface(if_id: NetIfId) -> Option<NetworkStatsSnapshot> {
    if primary_bridge_if() != Some(if_id) {
        return None;
    }
    get_real_stats()
}

/// Send ICMP echo via real NetworkStack
pub fn send_real_icmp_echo(target: [u8; 4], seq: u16) -> Result<u64, &'static str> {
    // Avoid IRQ re-entry deadlock: RX IRQ path also touches the global stack lock.
    x86_64::instructions::interrupts::without_interrupts(|| {
        match stack::stack().lock() {
            Ok(mut guard) => match guard.as_mut() {
                Some(stack) => {
                    let target_ip = Ipv4Address::new(target);
                    stack
                        .send_icmp_echo_request(target_ip, seq)
                        .map_err(|_| "Failed to send ICMP echo request")
                }
                None => Err("Network stack not initialized"),
            },
            Err(_) => {
                log::error!("[NET BRIDGE] Stack poisoned (send_real_icmp_echo)");
                Err("Network stack not initialized")
            }
        }
    })
}

/// Get ARP cache entries from real NetworkStack
pub fn get_real_arp_cache() -> Vec<ArpCacheEntry> {
    match stack::stack().lock() {
        Ok(guard) => match guard.as_ref() {
            Some(stack) => {
                let arp_cache = stack.arp_cache();
                let mut entries = Vec::new();

                for (ip, mac) in arp_cache {
                    entries.push(ArpCacheEntry {
                        ip: *ip.as_bytes(),
                        mac: *mac.as_bytes(),
                        complete: true,
                    });
                }

                entries
            }
            None => Vec::new(),
        },
        Err(_) => {
            log::error!("[NET BRIDGE] Stack poisoned (get_real_arp_cache)");
            Vec::new()
        }
    }
}
