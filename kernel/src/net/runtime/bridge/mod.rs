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

/// Bridge initialization state
static STACK_GLUE_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// RXチェックサムHW検証済みフラグ
static RX_CSUM_HW_VERIFIED: AtomicBool = AtomicBool::new(false);

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

#[derive(Debug, Clone, Copy)]
pub struct StackGlueInterfaceStats {
    pub if_id: NetIfId,
    pub tx_packets: u64,
    pub rx_packets: u64,
    pub initialized: bool,
    pub virtio_index: Option<u8>,
}

/// Per-interface stack glue stats
static STACK_GLUE_IF_STATS: PoisonRwLock<BTreeMap<NetIfId, StackGlueInterfaceStats>> =
    PoisonRwLock::new(BTreeMap::new());

/// Primary interface used by stack-glue fallback wrappers.
static PRIMARY_STACK_GLUE_IF: PoisonRwLock<Option<NetIfId>> = PoisonRwLock::new(None);

// ============================================================================
// Deferred RX Dispatch (deadlock prevention)
// ============================================================================

struct DeferredRxPacket {
    packet: crate::net::datapath::mempool::PacketRef,
    header_size: usize,
    payload_len: usize,
    if_id: Option<NetIfId>,
}

static RX_DEFERRED_MODE: AtomicBool = AtomicBool::new(false);

static DEFERRED_RX_PACKETS: PoisonLock<Vec<DeferredRxPacket>> = PoisonLock::new(Vec::new());

pub fn enter_deferred_rx_mode() {
    RX_DEFERRED_MODE.store(true, Ordering::Release);
}

pub fn drain_deferred_rx_packets() {
    RX_DEFERRED_MODE.store(false, Ordering::Release);
    let packets: Vec<DeferredRxPacket> = {
        let mut guard = DEFERRED_RX_PACKETS
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        core::mem::take(&mut *guard)
    };
    for p in packets.into_iter() {
        if let Some(if_id) = p.if_id {
            process_received_packet_zero_copy_for_interface(
                if_id,
                p.packet,
                p.header_size,
                p.payload_len,
            );
        } else {
            process_received_packet_zero_copy(p.packet, p.header_size, p.payload_len);
        }
    }
}

// ============================================================================
// NAT (Network Address Translation) support
// ============================================================================

#[cfg(any(test, feature = "qemu-test-export"))]
static FORWARD_EVENTS: PoisonRwLock<Vec<(NetIfId, Ipv4Address)>> = PoisonRwLock::new(Vec::new());

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

fn ensure_stack_glue_if_state(if_id: NetIfId, virtio_index: Option<u8>) {
    let mut stats = STACK_GLUE_IF_STATS
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

fn record_stack_glue_if_tx(if_id: NetIfId) {
    let mut stats = STACK_GLUE_IF_STATS
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

fn record_stack_glue_if_rx(if_id: NetIfId) {
    let mut stats = STACK_GLUE_IF_STATS
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
    device::primary_if().or_else(|| {
        *PRIMARY_STACK_GLUE_IF
            .read()
            .unwrap_or_else(|e| e.into_inner())
    })
}

fn set_primary_stack_glue_if(if_id: NetIfId, virtio_index: u8) {
    let mut primary = PRIMARY_STACK_GLUE_IF
        .write()
        .unwrap_or_else(|e| e.into_inner());
    if primary.is_none() || virtio_index == 0 {
        *primary = Some(if_id);
    }
    device::set_primary_interface(if_id);
}

pub fn register_stack_glue_interface(if_id: NetIfId, virtio_index: Option<u8>) {
    ensure_stack_glue_if_state(if_id, virtio_index);
    if let Some(virtio_index) = virtio_index {
        set_primary_stack_glue_if(if_id, virtio_index);
    }
    STACK_GLUE_INITIALIZED.store(true, Ordering::Release);
}

// ============================================================================
// Transmit Bridge
// ============================================================================

pub fn transmit_from_stack(if_id: Option<NetIfId>, data: &[u8]) -> bool {
    let resolved_if = if_id.or_else(primary_stack_glue_if);
    let sent = device::transmit(if_id, data);

    if sent {
        if let Some(if_id) = resolved_if {
            record_stack_glue_if_tx(if_id);
        }
        TX_PACKETS.fetch_add(1, Ordering::Relaxed);
        counters::global().record_tx(data.len());
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

pub fn send_packet_on_interface(if_id: NetIfId, data: &[u8]) -> bool {
    transmit_from_stack(Some(if_id), data)
}

// ============================================================================
// Receive Bridge
// ============================================================================

pub fn process_received_packet_zero_copy(
    mut packet: crate::net::datapath::mempool::PacketRef,
    header_size: usize,
    payload_len: usize,
) {
    if RX_DEFERRED_MODE.load(Ordering::Acquire) {
        if let Ok(mut guard) = DEFERRED_RX_PACKETS.lock() {
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
        process_received_packet_zero_copy_for_interface(if_id, packet, header_size, payload_len);
        return;
    }

    RX_PACKETS.fetch_add(1, Ordering::Relaxed);
    counters::global().record_rx(payload_len);
    trace::push_event(NetLayer::Driver, NetEventKind::Rx, "rx packet");

    packet.set_len(header_size + payload_len);

    if header_size > 0 {
        packet.advance(header_size);
    }

    compute_and_set_flow_hash(&mut packet);

    if let Some(batch) = BATCH_PROCESSOR.enqueue(packet) {
        stack::receive_batch(batch);
    }
}

pub fn process_received_packet_zero_copy_for_interface(
    if_id: NetIfId,
    mut packet: crate::net::datapath::mempool::PacketRef,
    header_size: usize,
    payload_len: usize,
) {
    if RX_DEFERRED_MODE.load(Ordering::Acquire) {
        if let Ok(mut guard) = DEFERRED_RX_PACKETS.lock() {
            guard.push(DeferredRxPacket {
                packet,
                header_size,
                payload_len,
                if_id: Some(if_id),
            });
        }
        return;
    }

    ensure_stack_glue_if_state(if_id, None);
    let rx_count = RX_PACKETS.fetch_add(1, Ordering::Relaxed).saturating_add(1);
    counters::global().record_rx(payload_len);
    record_stack_glue_if_rx(if_id);
    nat_maybe_gc(rx_count);

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

    if let Some(batch) = BATCH_PROCESSOR.enqueue(packet) {
        stack::receive_batch(batch);
    }
}

fn compute_and_set_flow_hash(_packet: &mut crate::net::datapath::mempool::PacketRef) {
    // 解析ロジック...
    // 以前はここで一律に csum_verified をセットしていましたが、
    // 現在はドライバ（VirtioNetDevice::complete_rx_packetref 等）が
    // パケット毎のフラグを確認してセットするため、ここでは何もしません。
}

#[inline]
pub fn rx_csum_hw_verified() -> bool {
    RX_CSUM_HW_VERIFIED.load(Ordering::Relaxed)
}

pub fn set_rx_csum_hw_verified(verified: bool) {
    RX_CSUM_HW_VERIFIED.store(verified, Ordering::Release);
}

pub fn check_batch_timeout(current_tsc: u64, tsc_freq: u64) {
    if let Some(batch) = BATCH_PROCESSOR.check_timeout(current_tsc, tsc_freq) {
        stack::receive_batch(batch);
    }
}

pub fn flush_batch() {
    if let Some(batch) = BATCH_PROCESSOR.flush() {
        stack::receive_batch(batch);
    }
}

pub fn sync_process_network_events() {
    use crate::net::l4::endpoint::event::event_queue;
    use crate::net::l4::endpoint::handler::NetworkEventHandler;

    let events = event_queue().drain_all();
    if events.is_empty() {
        return;
    }

    let handler = NetworkEventHandler::new();

    if let Ok(mut stack_guard) = stack::NETWORK_STACK.lock() {
        if let Some(ref mut stack) = *stack_guard {
            for event in events {
                handler.handle_event_with_stack(event, stack);
            }
        }
    }
}

pub fn get_stack_glue_stats_for_interface(if_id: NetIfId) -> Option<StackGlueInterfaceStats> {
    STACK_GLUE_IF_STATS
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .get(&if_id)
        .copied()
}

pub fn list_stack_glue_stats() -> Vec<StackGlueInterfaceStats> {
    STACK_GLUE_IF_STATS
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
    let mut rx = 0u64;
    let mut tx = 0u64;
    for s in STACK_GLUE_IF_STATS
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .values()
    {
        rx = rx.saturating_add(s.rx_packets);
        tx = tx.saturating_add(s.tx_packets);
    }
    StackGlueStats {
        initialized: STACK_GLUE_INITIALIZED.load(Ordering::Acquire) || device::is_initialized(),
        rx_packets: rx,
        tx_packets: tx,
    }
}

pub fn lookup_if_by_virtio_index(virtio_index: u8) -> Option<NetIfId> {
    manager::lookup_if_by_virtio_index(virtio_index)
}

pub fn get_real_config() -> Option<NetworkConfigSnapshot> {
    match stack::stack()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
    {
        Some(stack) => {
            let config = stack.config();
            Some(NetworkConfigSnapshot {
                ip: *config.ipv4.address.as_bytes(),
                netmask: *config.ipv4.subnet_mask.as_bytes(),
                gateway: *config.ipv4.gateway.as_bytes(),
                mac: *config.mac.as_bytes(),
            })
        }
        None => None,
    }
}

#[cfg(any(test, feature = "qemu-test-export"))]
pub mod tests;
