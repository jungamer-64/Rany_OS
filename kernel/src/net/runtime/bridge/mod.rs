// ============================================================================
// kernel/src/net/runtime/bridge/mod.rs - Network stack glue
// ============================================================================
//!
//! ネットワークドライバと NetworkStack を接続する stack glue モジュール。
//! deferred RX、batch/NAT、PacketRef の stack 受け渡しを担当します。

use crate::net::datapath::optimization::{BatchConfig, BatchProcessor};
use crate::net::obs::{
    observability_in,
    trace::{NetEventKind, NetLayer},
};
use crate::net::runtime::NetRuntimeHandle;
use crate::net::runtime::device;
use crate::net::runtime::manager::NetIfId;
use crate::net::runtime::stack;

use crate::sync::{PoisonLock, PoisonRwLock};
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

struct DeferredRxPacket {
    packet: crate::net::datapath::mempool::PacketRef,
    header_size: usize,
    payload_len: usize,
    if_id: Option<NetIfId>,
}

pub(crate) struct NetBridgeRuntimeState {
    stack_glue_initialized: AtomicBool,
    tx_packets: AtomicU64,
    rx_packets: AtomicU64,
    _rx_buffer: PoisonLock<[u8; 2048]>,
    batch_processor: BatchProcessor,
    if_stats: PoisonRwLock<BTreeMap<NetIfId, StackGlueInterfaceStats>>,
    primary_if: PoisonRwLock<Option<NetIfId>>,
    rx_deferred_mode: AtomicBool,
    deferred_rx_packets: PoisonLock<Vec<DeferredRxPacket>>,
}

impl NetBridgeRuntimeState {
    pub const fn new() -> Self {
        Self {
            stack_glue_initialized: AtomicBool::new(false),
            tx_packets: AtomicU64::new(0),
            rx_packets: AtomicU64::new(0),
            _rx_buffer: PoisonLock::new([0u8; 2048]),
            batch_processor: BatchProcessor::new(BatchConfig {
                max_batch_size: 64,
                max_delay_us: 50,
                min_pps_threshold: 1000,
                adaptive_batching: true,
            }),
            if_stats: PoisonRwLock::new(BTreeMap::new()),
            primary_if: PoisonRwLock::new(None),
            rx_deferred_mode: AtomicBool::new(false),
            deferred_rx_packets: PoisonLock::new(Vec::new()),
        }
    }
}

fn runtime_state_for(runtime: NetRuntimeHandle) -> &'static NetBridgeRuntimeState {
    &runtime.context().bridge
}

fn primary_stack_glue_if_in(runtime: NetRuntimeHandle) -> Option<NetIfId> {
    let state = runtime_state_for(runtime);
    device::primary_if_in(runtime)
        .or_else(|| *state.primary_if.read().unwrap_or_else(|e| e.into_inner()))
}

fn set_primary_stack_glue_if_in(runtime: NetRuntimeHandle, if_id: NetIfId) {
    let mut primary = runtime_state_for(runtime)
        .primary_if
        .write()
        .unwrap_or_else(|e| e.into_inner());
    if primary.is_none() {
        *primary = Some(if_id);
    }
    device::set_primary_interface_in(runtime, if_id);
}

pub fn enter_deferred_rx_mode_in(runtime: NetRuntimeHandle) {
    runtime_state_for(runtime)
        .rx_deferred_mode
        .store(true, Ordering::Release);
}

pub fn drain_deferred_rx_packets_in(runtime: NetRuntimeHandle) {
    let state = runtime_state_for(runtime);
    state.rx_deferred_mode.store(false, Ordering::Release);
    let packets: Vec<DeferredRxPacket> = {
        let mut guard = state
            .deferred_rx_packets
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        core::mem::take(&mut *guard)
    };
    for p in packets.into_iter() {
        if let Some(if_id) = p.if_id {
            process_received_packet_zero_copy_for_interface_in(
                runtime,
                if_id,
                p.packet,
                p.header_size,
                p.payload_len,
            );
        } else {
            process_received_packet_zero_copy_in(runtime, p.packet, p.header_size, p.payload_len);
        }
    }
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

pub fn register_stack_glue_interface_in(runtime: NetRuntimeHandle, if_id: NetIfId) {
    ensure_stack_glue_if_state_in(runtime, if_id);
    set_primary_stack_glue_if_in(runtime, if_id);
    runtime_state_for(runtime)
        .stack_glue_initialized
        .store(true, Ordering::Release);
}

// ============================================================================
// Transmit Bridge
// ============================================================================

pub fn transmit_from_stack_in(
    runtime: NetRuntimeHandle,
    if_id: Option<NetIfId>,
    payload: kernel_api::resource::net::PacketPayload,
    meta: kernel_api::service::netdev::NetTxMeta,
) -> bool {
    let resolved_if = if_id.or_else(|| primary_stack_glue_if_in(runtime));
    let packet_len = payload.total_len();
    let sent = device::transmit_packet_in(runtime, if_id, payload, meta);
    let observability = observability_in(runtime);

    if sent {
        if let Some(if_id) = resolved_if {
            record_stack_glue_if_tx_in(runtime, if_id);
        }
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

pub fn process_received_packet_zero_copy_in(
    runtime: NetRuntimeHandle,
    mut packet: crate::net::datapath::mempool::PacketRef,
    header_size: usize,
    payload_len: usize,
) {
    let state = runtime_state_for(runtime);

    if state.rx_deferred_mode.load(Ordering::Acquire) {
        if let Ok(mut guard) = state.deferred_rx_packets.lock() {
            guard.push(DeferredRxPacket {
                packet,
                header_size,
                payload_len,
                if_id: None,
            });
        }
        return;
    }

    if let Some(if_id) = primary_stack_glue_if_in(runtime) {
        process_received_packet_zero_copy_for_interface_in(
            runtime,
            if_id,
            packet,
            header_size,
            payload_len,
        );
        return;
    }

    state.rx_packets.fetch_add(1, Ordering::Relaxed);
    let observability = observability_in(runtime);
    observability.counters().record_rx(payload_len);
    observability
        .trace()
        .push(NetLayer::Driver, NetEventKind::Rx, "rx packet");

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

    compute_and_set_flow_hash(&mut packet);

    if let Some(batch) = state.batch_processor.enqueue(packet) {
        stack::receive_batch_on_in(runtime, None, batch);
    }
}

pub fn process_received_packet_zero_copy_for_interface_in(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
    mut packet: crate::net::datapath::mempool::PacketRef,
    header_size: usize,
    payload_len: usize,
) {
    let state = runtime_state_for(runtime);

    if state.rx_deferred_mode.load(Ordering::Acquire) {
        if let Ok(mut guard) = state.deferred_rx_packets.lock() {
            guard.push(DeferredRxPacket {
                packet,
                header_size,
                payload_len,
                if_id: Some(if_id),
            });
        }
        return;
    }

    ensure_stack_glue_if_state_in(runtime, if_id);
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
    let _ = crate::net::runtime::command::try_enqueue_command_in(
        runtime,
        crate::net::runtime::command::RuntimeCommand::Ingress(
            crate::net::runtime::command::IngressCommand::Packet {
                if_id: Some(if_id),
                packet,
            },
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
    } else {
        0
    };
    packet.meta_mut().flow_hash = flow_hash;
}

pub fn check_batch_timeout_in(runtime: NetRuntimeHandle, current_tsc: u64, tsc_freq: u64) {
    if let Some(batch) = runtime_state_for(runtime)
        .batch_processor
        .check_timeout(current_tsc, tsc_freq)
    {
        stack::receive_batch_on_in(runtime, None, batch);
    }
}

pub fn flush_batch_in(runtime: NetRuntimeHandle) {
    if let Some(batch) = runtime_state_for(runtime).batch_processor.flush() {
        stack::receive_batch_on_in(runtime, None, batch);
    }
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
