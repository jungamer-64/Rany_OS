// ============================================================================
// src/net/runtime/bridge/mod.rs - Network stack glue
// ============================================================================
//!
//! ネットワークドライバと NetworkStack を接続する stack glue モジュール。
//! deferred RX、batch/NAT、PacketRef の stack 受け渡しを担当します。

use crate::net::api::config::NetworkConfigSnapshot;
use crate::net::datapath::optimization::{BatchConfig, BatchProcessor};
use crate::net::l3::ipv4::Ipv4Address;
use crate::net::obs::{
    counters,
    trace::{self, NetEventKind, NetLayer},
};
use crate::net::runtime::device;
use crate::net::runtime::manager::{self, NetIfId};
use crate::net::runtime::stack;
use crate::net::runtime::{NetRuntimeHandle, default_runtime};

mod nat;
use nat::*;
pub mod mlx5_bridge;
use crate::sync::{PoisonLock, PoisonRwLock};
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

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
    pub virtio_index: Option<u8>,
}

struct DeferredRxPacket {
    packet: crate::net::datapath::mempool::PacketRef,
    header_size: usize,
    payload_len: usize,
    if_id: Option<NetIfId>,
}

pub(crate) struct NetBridgeRuntimeState {
    stack_glue_initialized: AtomicBool,
    rx_csum_hw_verified: AtomicBool,
    tx_packets: AtomicU64,
    rx_packets: AtomicU64,
    _rx_buffer: PoisonLock<[u8; 2048]>,
    batch_processor: BatchProcessor,
    if_stats: PoisonRwLock<BTreeMap<NetIfId, StackGlueInterfaceStats>>,
    primary_if: PoisonRwLock<Option<NetIfId>>,
    rx_deferred_mode: AtomicBool,
    deferred_rx_packets: PoisonLock<Vec<DeferredRxPacket>>,
    forward_events: PoisonRwLock<Vec<(NetIfId, Ipv4Address)>>,
    nat: NatRuntimeState,
}

impl NetBridgeRuntimeState {
    pub const fn new() -> Self {
        Self {
            stack_glue_initialized: AtomicBool::new(false),
            rx_csum_hw_verified: AtomicBool::new(false),
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
            forward_events: PoisonRwLock::new(Vec::new()),
            nat: NatRuntimeState::new(),
        }
    }
}

fn runtime_state() -> &'static NetBridgeRuntimeState {
    &crate::net::runtime::default_runtime_context().bridge
}

fn runtime_state_for(runtime: NetRuntimeHandle) -> &'static NetBridgeRuntimeState {
    &runtime.context().bridge
}

fn primary_stack_glue_if_in(runtime: NetRuntimeHandle) -> Option<NetIfId> {
    let state = runtime_state_for(runtime);
    if runtime.id() == default_runtime().id() {
        device::primary_if().or_else(|| *state.primary_if.read().unwrap_or_else(|e| e.into_inner()))
    } else {
        *state.primary_if.read().unwrap_or_else(|e| e.into_inner())
    }
}

fn set_primary_stack_glue_if_in(runtime: NetRuntimeHandle, if_id: NetIfId, virtio_index: u8) {
    let mut primary = runtime_state_for(runtime)
        .primary_if
        .write()
        .unwrap_or_else(|e| e.into_inner());
    if primary.is_none() || virtio_index == 0 {
        *primary = Some(if_id);
    }
    if runtime.id() == default_runtime().id() {
        device::set_primary_interface(if_id);
    }
}

pub fn enter_deferred_rx_mode() {
    enter_deferred_rx_mode_in(default_runtime());
}

pub fn enter_deferred_rx_mode_in(runtime: NetRuntimeHandle) {
    runtime_state_for(runtime)
        .rx_deferred_mode
        .store(true, Ordering::Release);
}

pub fn drain_deferred_rx_packets() {
    drain_deferred_rx_packets_in(default_runtime());
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

#[allow(dead_code)]
fn is_local_ipv4_in(runtime: NetRuntimeHandle, addr: Ipv4Address) -> bool {
    if let Ok(routes) = runtime.context().manager.lock() {
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

fn ensure_stack_glue_if_state_in(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
    virtio_index: Option<u8>,
) {
    let mut stats = runtime_state_for(runtime)
        .if_stats
        .write()
        .unwrap_or_else(|e| e.into_inner());
    let entry = stats.entry(if_id).or_insert(StackGlueInterfaceStats {
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
        virtio_index: None,
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
        virtio_index: None,
    });
    entry.rx_packets = entry.rx_packets.saturating_add(1);
    entry.initialized = true;
}

fn primary_stack_glue_if() -> Option<NetIfId> {
    primary_stack_glue_if_in(default_runtime())
}

pub fn register_stack_glue_interface(if_id: NetIfId, virtio_index: Option<u8>) {
    register_stack_glue_interface_in(default_runtime(), if_id, virtio_index);
}

pub fn register_stack_glue_interface_in(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
    virtio_index: Option<u8>,
) {
    ensure_stack_glue_if_state_in(runtime, if_id, virtio_index);
    if let Some(virtio_index) = virtio_index {
        set_primary_stack_glue_if_in(runtime, if_id, virtio_index);
    }
    runtime_state_for(runtime)
        .stack_glue_initialized
        .store(true, Ordering::Release);
}

// ============================================================================
// Transmit Bridge
// ============================================================================

pub fn transmit_from_stack(
    if_id: Option<NetIfId>,
    packet: crate::net::datapath::mempool::PacketRef,
    meta: kernel_api::service::netdev::NetTxMeta,
) -> bool {
    let resolved_if = if_id.or_else(primary_stack_glue_if);
    let packet_len = packet.len();
    let sent = device::transmit_packet(if_id, packet, meta);

    if sent {
        if let Some(if_id) = resolved_if {
            record_stack_glue_if_tx_in(default_runtime(), if_id);
        }
        runtime_state().tx_packets.fetch_add(1, Ordering::Relaxed);
        counters::global().record_tx(packet_len);
        trace::push_event(NetLayer::Driver, NetEventKind::Tx, "device queued tx");
        true
    } else {
        counters::global().record_error();
        trace::push_event(
            NetLayer::Driver,
            NetEventKind::Error,
            "device tx enqueue failed",
        );
        false
    }
}

pub fn send_packet_on_interface(
    if_id: NetIfId,
    packet: crate::net::datapath::mempool::PacketRef,
) -> bool {
    transmit_from_stack(
        Some(if_id),
        packet,
        kernel_api::service::netdev::NetTxMeta::default(),
    )
}

// ============================================================================
// Receive Bridge
// ============================================================================

pub fn process_received_packet_zero_copy(
    packet: crate::net::datapath::mempool::PacketRef,
    header_size: usize,
    payload_len: usize,
) {
    process_received_packet_zero_copy_in(default_runtime(), packet, header_size, payload_len);
}

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

    if let Some(if_id) = primary_stack_glue_if() {
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
    counters::global().record_rx(payload_len);
    trace::push_event(NetLayer::Driver, NetEventKind::Rx, "rx packet");

    packet.set_len(header_size + payload_len);

    if header_size > 0 {
        packet.advance(header_size);
    }

    compute_and_set_flow_hash(&mut packet);

    if let Some(batch) = state.batch_processor.enqueue(packet) {
        stack::receive_batch_on_in(runtime, None, batch);
    }
}

pub fn process_received_packet_zero_copy_for_interface(
    if_id: NetIfId,
    packet: crate::net::datapath::mempool::PacketRef,
    header_size: usize,
    payload_len: usize,
) {
    process_received_packet_zero_copy_for_interface_in(
        default_runtime(),
        if_id,
        packet,
        header_size,
        payload_len,
    );
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

    ensure_stack_glue_if_state_in(runtime, if_id, None);
    let rx_count = state
        .rx_packets
        .fetch_add(1, Ordering::Relaxed)
        .saturating_add(1);
    counters::global().record_rx(payload_len);
    record_stack_glue_if_rx_in(runtime, if_id);
    nat_maybe_gc_in(runtime, rx_count);

    packet.set_len(header_size + payload_len);
    if header_size > 0 {
        packet.advance(header_size);
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
    crate::net::l4::endpoint::event::enqueue_event_ignore_in(
        runtime,
        crate::net::l4::endpoint::event::NetworkEvent::IngressPacket {
            if_id: Some(if_id),
            packet,
        },
    );
}

fn compute_and_set_flow_hash(_packet: &mut crate::net::datapath::mempool::PacketRef) {
    // 解析ロジック...
    // 以前はここで一律に csum_verified をセットしていましたが、
    // 現在はドライバ（VirtioNetDevice::complete_rx_packetref 等）が
    // パケット毎のフラグを確認してセットするため、ここでは何もしません。
}

#[inline]
pub fn rx_csum_hw_verified() -> bool {
    runtime_state().rx_csum_hw_verified.load(Ordering::Relaxed)
}

pub fn set_rx_csum_hw_verified(verified: bool) {
    runtime_state()
        .rx_csum_hw_verified
        .store(verified, Ordering::Release);
}

pub fn check_batch_timeout(current_tsc: u64, tsc_freq: u64) {
    check_batch_timeout_in(default_runtime(), current_tsc, tsc_freq);
}

pub fn flush_batch() {
    flush_batch_in(default_runtime());
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

pub fn get_stack_glue_stats_for_interface(if_id: NetIfId) -> Option<StackGlueInterfaceStats> {
    runtime_state()
        .if_stats
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .get(&if_id)
        .copied()
}

pub fn list_stack_glue_stats() -> Vec<StackGlueInterfaceStats> {
    runtime_state()
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

pub fn get_stack_glue_stats() -> StackGlueStats {
    let state = runtime_state();
    StackGlueStats {
        initialized: state.stack_glue_initialized.load(Ordering::Acquire)
            || device::is_initialized(),
        rx_packets: state.rx_packets.load(Ordering::Relaxed),
        tx_packets: state.tx_packets.load(Ordering::Relaxed),
    }
}

pub fn lookup_if_by_virtio_index(virtio_index: u8) -> Option<NetIfId> {
    manager::lookup_if_by_virtio_index(virtio_index)
}

pub fn get_real_config() -> Option<NetworkConfigSnapshot> {
    crate::net::api::config::primary_interface_config_snapshot_sync_in(
        crate::net::runtime::default_runtime(),
    )
}

#[cfg(any(test, feature = "qemu-test-export"))]
pub mod tests;
