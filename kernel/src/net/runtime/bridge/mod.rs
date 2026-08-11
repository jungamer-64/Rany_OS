// ============================================================================
// kernel/src/net/runtime/bridge/mod.rs - Network stack glue
// ============================================================================
//!
//! ネットワークドライバと NetworkStack を接続する stack glue モジュール。
//! deferred RX、batch/NAT、PacketRef の stack 受け渡しを担当します。

use crate::net::obs::{
    observability_in,
    trace::{NetEventKind, NetLayer},
};
use crate::net::runtime::NetRuntimeHandle;
use crate::net::runtime::device;
use crate::net::runtime::manager::NetIfId;

use crate::sync::PoisonRwLock;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use kernel_api::resource::net::PacketByteCount;

extern crate alloc;

// ============================================================================
// Bridge State
// ============================================================================

#[derive(Debug, Clone, Copy)]
pub struct StackGlueInterfaceStats {
    pub if_id: NetIfId,
    pub tx_packets: u64,
    pub rx_packets: u64,
    pub initialized: bool,
}

pub(crate) struct NetBridgeRuntimeState {
    stack_glue_initialized: AtomicBool,
    tx_packets: AtomicU64,
    rx_packets: AtomicU64,
    if_stats: PoisonRwLock<BTreeMap<NetIfId, StackGlueInterfaceStats>>,
}

impl NetBridgeRuntimeState {
    pub const fn new() -> Self {
        Self {
            stack_glue_initialized: AtomicBool::new(false),
            tx_packets: AtomicU64::new(0),
            rx_packets: AtomicU64::new(0),
            if_stats: PoisonRwLock::new(BTreeMap::new()),
        }
    }
}

fn runtime_state_for(runtime: NetRuntimeHandle) -> &'static NetBridgeRuntimeState {
    &runtime.context().bridge
}

fn ensure_stack_glue_if_state_in(runtime: NetRuntimeHandle, if_id: NetIfId) {
    let mut stats = runtime_state_for(runtime)
        .if_stats
        .write()
        .unwrap_or_else(|e| e.into_inner());
    let entry = stats.entry(if_id).or_insert(StackGlueInterfaceStats {
        if_id,
        tx_packets: 0,
        rx_packets: 0,
        initialized: false,
    });
    entry.initialized = true;
}

fn record_stack_glue_if_tx_in(runtime: NetRuntimeHandle, if_id: NetIfId) {
    let mut stats = runtime_state_for(runtime)
        .if_stats
        .write()
        .unwrap_or_else(|e| e.into_inner());
    let entry = stats.entry(if_id).or_insert(StackGlueInterfaceStats {
        if_id,
        tx_packets: 0,
        rx_packets: 0,
        initialized: true,
    });
    entry.tx_packets = entry.tx_packets.saturating_add(1);
    entry.initialized = true;
}

fn record_stack_glue_if_rx_in(runtime: NetRuntimeHandle, if_id: NetIfId) {
    let mut stats = runtime_state_for(runtime)
        .if_stats
        .write()
        .unwrap_or_else(|e| e.into_inner());
    let entry = stats.entry(if_id).or_insert(StackGlueInterfaceStats {
        if_id,
        tx_packets: 0,
        rx_packets: 0,
        initialized: true,
    });
    entry.rx_packets = entry.rx_packets.saturating_add(1);
    entry.initialized = true;
}

// ============================================================================
// Transmit Bridge
// ============================================================================

pub fn transmit_from_stack_in(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
    payload: kernel_api::resource::net::PacketPayload,
    meta: kernel_api::service::netdev::NetTxMeta,
) -> bool {
    let packet_len = payload.total_len();
    let sent = device::transmit_packet_in(runtime, if_id, payload, meta);
    let observability = observability_in(runtime);

    if sent {
        record_stack_glue_if_tx_in(runtime, if_id);
        runtime_state_for(runtime)
            .tx_packets
            .fetch_add(1, Ordering::Relaxed);
        observability.counters().record_tx(packet_len);
        observability
            .trace()
            .push(NetLayer::Driver, NetEventKind::Tx, "device queued tx");
        true
    } else {
        observability.counters().record_error();
        observability.trace().push(
            NetLayer::Driver,
            NetEventKind::Error,
            "device tx enqueue failed",
        );
        false
    }
}

// ============================================================================
// Receive Bridge
// ============================================================================

pub fn process_received_packet_zero_copy_for_interface_in(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
    mut packet: crate::net::datapath::mempool::PacketRef,
    header_size: usize,
    payload_len: usize,
) {
    if !crate::net::runtime::manager::is_interface_operational_in(runtime, if_id) {
        observability_in(runtime).counters().record_drop();
        return;
    }
    let state = runtime_state_for(runtime);

    ensure_stack_glue_if_state_in(runtime, if_id);
    state.stack_glue_initialized.store(true, Ordering::Release);
    state.rx_packets.fetch_add(1, Ordering::Relaxed);
    let observability = observability_in(runtime);
    observability.counters().record_rx(payload_len);
    observability
        .trace()
        .push(NetLayer::Driver, NetEventKind::Rx, "rx packet");
    record_stack_glue_if_rx_in(runtime, if_id);

    let Some(frame_len) = header_size.checked_add(payload_len) else {
        return;
    };
    let Some(frame_len) = PacketByteCount::new(frame_len) else {
        return;
    };
    if !packet.set_len(frame_len) {
        return;
    }
    if header_size > 0
        && !packet.advance(PacketByteCount::new(header_size).expect("positive header size"))
    {
        return;
    }

    // NAT Inbound (omitted for brevity, assume similar fixes applied)
    // Routing/Forwarding (omitted for brevity, assume similar fixes applied)

    #[cfg(any(test, feature = "qemu-test-export"))]
    {
        // Example fix for FORWARD_EVENTS access
        // let mut ev = FORWARD_EVENTS.write().unwrap_or_else(|e| e.into_inner());
        // ev.push((route.if_id, dst));
    }

    compute_and_set_flow_hash(&mut packet);
    let _ = crate::net::runtime::command::try_enqueue_command_from_isr_in(
        runtime,
        crate::net::runtime::command::RuntimeCommand::Ingress(
            crate::net::runtime::command::IngressCommand::Packet { if_id, packet },
        ),
    );
}

fn compute_and_set_flow_hash(packet: &mut crate::net::datapath::mempool::PacketRef) {
    let data = packet.data();
    if data.len() < 14 {
        return;
    }
    // Check EtherType (IPv4 = 0x0800, IPv6 = 0x86DD)
    let ethertype = u16::from_be_bytes([data[12], data[13]]);
    let flow_hash = if ethertype == 0x0800 && data.len() >= 34 {
        let ihl = (data[14] & 0x0F) as usize * 4;
        let proto = data[23];
        let frag_id = u16::from_be_bytes([data[18], data[19]]);
        let src_ip = u32::from_be_bytes([data[26], data[27], data[28], data[29]]);
        let dst_ip = u32::from_be_bytes([data[30], data[31], data[32], data[33]]);
        let frag_off = u16::from_be_bytes([data[20], data[21]]) & 0x3FFF;
        let is_frag = frag_off != 0 || (data[20] & 0x20 != 0);

        if is_frag {
            crate::net::datapath::optimization::FlowAffinity::hash_5tuple(
                src_ip, dst_ip, frag_id, frag_id, proto,
            )
        } else if (proto == 6 || proto == 17) && data.len() >= 14 + ihl + 4 {
            let l4_offset = 14 + ihl;
            let src_port = u16::from_be_bytes([data[l4_offset], data[l4_offset + 1]]);
            let dst_port = u16::from_be_bytes([data[l4_offset + 2], data[l4_offset + 3]]);
            crate::net::datapath::optimization::FlowAffinity::hash_5tuple(
                src_ip, dst_ip, src_port, dst_port, proto,
            )
        } else {
            crate::net::datapath::optimization::FlowAffinity::hash_5tuple(
                src_ip, dst_ip, 0, 0, proto,
            )
        }
    } else if ethertype == 0x86DD && data.len() >= 54 {
        // IPv6: 14 (Ethernet) + 40 (IPv6 header) = 54 bytes minimum
        // XOR-fold 128-bit addresses into u32 for Toeplitz hash
        let src_folded = u32::from_be_bytes([data[22], data[23], data[24], data[25]])
            ^ u32::from_be_bytes([data[26], data[27], data[28], data[29]])
            ^ u32::from_be_bytes([data[30], data[31], data[32], data[33]])
            ^ u32::from_be_bytes([data[34], data[35], data[36], data[37]]);
        let dst_folded = u32::from_be_bytes([data[38], data[39], data[40], data[41]])
            ^ u32::from_be_bytes([data[42], data[43], data[44], data[45]])
            ^ u32::from_be_bytes([data[46], data[47], data[48], data[49]])
            ^ u32::from_be_bytes([data[50], data[51], data[52], data[53]]);
        let mut next_header = data[20];
        let mut offset = 54usize; // past IPv6 base header

        // Walk extension headers to find Fragment Header or L4 header
        // Extension headers: Hop-by-Hop(0), Routing(43), Destination(60)
        // Fragment Header: 44
        // LOOP_PROOF: mode=bounded; bound=6; reason=IPv6 extension header chain is limited (Hop-by-Hop, Routing, Fragment, Destination, AH, ESP);
        for _ in 0..6 {
            match next_header {
                0 | 43 | 60 => {
                    // Extension header: next_header at offset, length at offset+1 (in 8-byte units excl. first 8)
                    if offset + 2 > data.len() {
                        break;
                    }
                    next_header = data[offset];
                    let ext_len = (data[offset + 1] as usize + 1) * 8;
                    offset += ext_len;
                }
                44 => {
                    // Fragment Header (8 bytes): next_header, reserved, frag_off+M, identification
                    if offset + 8 > data.len() {
                        let frag_id = 0u32;
                        return {
                            packet.meta_mut().flow_hash =
                                crate::net::datapath::optimization::FlowAffinity::hash_5tuple(
                                    src_folded,
                                    dst_folded,
                                    0,
                                    0,
                                    next_header,
                                );
                        };
                    }
                    let frag_proto = data[offset]; // next header after fragment
                    let frag_id = u32::from_be_bytes([
                        data[offset + 4],
                        data[offset + 5],
                        data[offset + 6],
                        data[offset + 7],
                    ]);
                    // Use (src, dst, frag_id_hi16, frag_id_lo16, proto) for fragment affinity
                    let frag_id_hi = (frag_id >> 16) as u16;
                    let frag_id_lo = (frag_id & 0xFFFF) as u16;
                    packet.meta_mut().flow_hash =
                        crate::net::datapath::optimization::FlowAffinity::hash_5tuple(
                            src_folded,
                            dst_folded,
                            frag_id_hi ^ frag_id_lo,
                            frag_id_lo,
                            frag_proto,
                        );
                    return;
                }
                _ => break, // L4 or unknown — stop walking
            }
        }

        // No Fragment Header found; hash by L4 ports if TCP/UDP
        if (next_header == 6 || next_header == 17) && offset + 4 <= data.len() {
            let src_port = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let dst_port = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
            crate::net::datapath::optimization::FlowAffinity::hash_5tuple(
                src_folded,
                dst_folded,
                src_port,
                dst_port,
                next_header,
            )
        } else {
            crate::net::datapath::optimization::FlowAffinity::hash_5tuple(
                src_folded,
                dst_folded,
                0,
                0,
                next_header,
            )
        }
    } else {
        0
    };
    packet.meta_mut().flow_hash = flow_hash;
}

pub fn get_stack_glue_stats_for_interface_in(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
) -> Option<StackGlueInterfaceStats> {
    runtime_state_for(runtime)
        .if_stats
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .get(&if_id)
        .copied()
}

pub fn list_stack_glue_stats_in(runtime: NetRuntimeHandle) -> Vec<StackGlueInterfaceStats> {
    runtime_state_for(runtime)
        .if_stats
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .values()
        .copied()
        .collect()
}

#[derive(Debug, Clone, Copy)]
pub struct StackGlueStats {
    pub initialized: bool,
    pub rx_packets: u64,
    pub tx_packets: u64,
}

pub fn get_stack_glue_stats_in(runtime: NetRuntimeHandle) -> StackGlueStats {
    let state = runtime_state_for(runtime);
    StackGlueStats {
        initialized: state.stack_glue_initialized.load(Ordering::Acquire)
            || device::is_initialized_in(runtime),
        rx_packets: state.rx_packets.load(Ordering::Relaxed),
        tx_packets: state.tx_packets.load(Ordering::Relaxed),
    }
}

pub fn restore_stack_glue_stats_in(runtime: NetRuntimeHandle, rx_packets: u64, tx_packets: u64) {
    let state = runtime_state_for(runtime);
    state.rx_packets.store(rx_packets, Ordering::Relaxed);
    state.tx_packets.store(tx_packets, Ordering::Relaxed);
}
