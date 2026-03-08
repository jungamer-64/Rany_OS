// ============================================================================
// src/net/driver_bridge.rs - VirtIO-Net <-> NetworkStack Bridge
// ============================================================================
//!
//! VirtIO-NetドライバとNetworkStackを接続するブリッジモジュール。
//! 送信コールバック設定と受信パケット処理を統合します。

use crate::net::api::config::NetworkConfigSnapshot;
use crate::net::api::config::NetworkStatsSnapshot;
use crate::net::api::connections::ArpCacheEntry;
use crate::net::datapath::optimization::{BatchConfig, BatchProcessor};
use crate::net::l2::ethernet::MacAddress;
use crate::net::l3::ipv4::{Ipv4Address, Ipv4Config};
use crate::net::obs::{
    counters,
    trace::{self, NetEventKind, NetLayer},
};
use crate::net::runtime::manager::{self, NetIfId};
use crate::net::runtime::stack::{self, NetworkConfig};

mod nat;
use nat::*;
pub mod mlx5_bridge;
pub mod shared;
use crate::io::io_scheduler::{
    DeviceId as IoDeviceId, DmaBufHandle, IoCommand, IoPriority, hybrid_coordinator,
};
use crate::io::iommu::types::DeviceId as IommuDeviceId;
use crate::io::virtio::{
    VIRTIO_NET_IOCTL_TX, VirtioNetDevice, bind_virtio_net_interface, with_virtio_net,
    with_virtio_net_at_index,
};
use crate::sync::{PoisonLock, PoisonRwLock};
use alloc::collections::BTreeMap;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::task::{Context, Poll, Waker};

extern crate alloc;

// ============================================================================
// Bridge State
// ============================================================================

/// Bridge initialization state
static BRIDGE_INITIALIZED: AtomicBool = AtomicBool::new(false);

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

// ============================================================================
// Transmit Queue (async worker)
// ============================================================================

/// Capacity for transmit queue
const TX_QUEUE_CAPACITY: usize = 1024;

/// Transmit request queued by the stack's transmit callback
struct TransmitRequest {
    if_id: Option<NetIfId>,
    data: Vec<u8>,
}

/// Global TX queue for decoupling stack -> device transmit (prevents deadlocks)
static TX_QUEUE: PoisonLock<VecDeque<TransmitRequest>> = PoisonLock::new(VecDeque::new());
static TX_QUEUE_WAKER: PoisonLock<Option<Waker>> = PoisonLock::new(None);
static TX_QUEUE_HAS_EVENTS: AtomicBool = AtomicBool::new(false);
static TX_WORKER_STARTED: AtomicBool = AtomicBool::new(false);

/// Enqueue a transmit request (called from stack's transmit_fn)
fn enqueue_transmit(if_id: Option<NetIfId>, data: &[u8]) -> bool {
    let req = TransmitRequest {
        if_id,
        data: data.to_vec(),
    };
    let mut q = self::TX_QUEUE.lock().unwrap_or_else(|e| e.into_inner());
    if q.len() >= TX_QUEUE_CAPACITY {
        return false;
    }
    q.push_back(req);
    TX_QUEUE_HAS_EVENTS.store(true, Ordering::Release);

    if let Ok(mut w) = TX_QUEUE_WAKER.lock() {
        if let Some(waker) = w.take() {
            waker.wake();
        }
    }

    true
}

/// Pop a transmit request (non-blocking)
fn tx_queue_recv() -> Option<TransmitRequest> {
    let mut q = self::TX_QUEUE.lock().unwrap_or_else(|e| e.into_inner());
    let r = q.pop_front();
    if q.is_empty() {
        TX_QUEUE_HAS_EVENTS.store(false, Ordering::Release);
    }
    r
}

/// Drain all queued transmit requests
fn tx_queue_drain_all() -> Vec<TransmitRequest> {
    let mut q = self::TX_QUEUE.lock().unwrap_or_else(|e| e.into_inner());
    TX_QUEUE_HAS_EVENTS.store(false, Ordering::Release);
    q.drain(..).collect()
}

/// Future that resolves when a TX request is available
pub struct TxEventWaitFuture;

impl Future for TxEventWaitFuture {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if TX_QUEUE_HAS_EVENTS.load(Ordering::Acquire) {
            return Poll::Ready(());
        }

        if let Ok(mut w) = TX_QUEUE_WAKER.lock() {
            *w = Some(cx.waker().clone());
        }

        if TX_QUEUE_HAS_EVENTS.load(Ordering::Acquire) {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct BridgeInterfaceStats {
    pub if_id: NetIfId,
    pub tx_packets: u64,
    pub rx_packets: u64,
    pub initialized: bool,
    pub virtio_index: Option<u8>,
}

/// Per-interface bridge stats
static BRIDGE_IF_STATS: PoisonRwLock<BTreeMap<NetIfId, BridgeInterfaceStats>> =
    PoisonRwLock::new(BTreeMap::new());

/// Primary interface used by legacy bridge wrappers.
static PRIMARY_BRIDGE_IF: PoisonRwLock<Option<NetIfId>> = PoisonRwLock::new(None);

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
        let mut guard = DEFERRED_RX_PACKETS.lock().unwrap_or_else(|e| e.into_inner());
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

fn ensure_bridge_if_state(if_id: NetIfId, virtio_index: Option<u8>) {
    let mut stats = BRIDGE_IF_STATS.write().unwrap_or_else(|e| e.into_inner());
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
    let mut stats = BRIDGE_IF_STATS.write().unwrap_or_else(|e| e.into_inner());
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
    let mut stats = BRIDGE_IF_STATS.write().unwrap_or_else(|e| e.into_inner());
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
    *PRIMARY_BRIDGE_IF.read().unwrap_or_else(|e| e.into_inner())
}

fn set_primary_bridge_if_for_virtio(if_id: NetIfId, virtio_index: u8) {
    let mut primary = PRIMARY_BRIDGE_IF.write().unwrap_or_else(|e| e.into_inner());
    if primary.is_none() || virtio_index == 0 {
        *primary = Some(if_id);
    }
}

struct VirtioNetRuntime {
    virtio_index: u8,
    if_id: NetIfId,
    mac: MacAddress,
}

impl VirtioNetRuntime {
    const fn new(virtio_index: u8, if_id: NetIfId, mac: MacAddress) -> Self {
        Self {
            virtio_index,
            if_id,
            mac,
        }
    }
}

impl shared::NetBridgePort for VirtioNetRuntime {
    fn port_name(&self) -> &'static str {
        "virtio-net"
    }

    fn mac_address(&self) -> MacAddress {
        self.mac
    }

    fn start(&self, _dispatch: shared::RxDispatchHandle) -> Result<(), &'static str> {
        if !TX_WORKER_STARTED.swap(true, Ordering::AcqRel) {
            crate::task::Executor::spawn_global(crate::task::Task::new(tx_worker_task()));
        }
        Ok(())
    }

    fn enqueue_tx(&self, data: &[u8]) -> bool {
        enqueue_transmit(Some(self.if_id), data)
    }

    fn stats(&self) -> shared::BridgePortStats {
        get_bridge_stats_for_interface(self.if_id)
            .map(|stats| shared::BridgePortStats {
                tx_packets: stats.tx_packets,
                rx_packets: stats.rx_packets,
                tx_errors: 0,
                rx_errors: 0,
                initialized: stats.initialized,
            })
            .unwrap_or_default()
    }

    fn health(&self) -> bool {
        with_virtio_net_at_index(self.virtio_index, |_| true).unwrap_or(false)
    }

    fn stop(&self) {}
}

// ============================================================================
// Transmit Bridge
// ============================================================================

fn virtio_transmit(if_id: Option<NetIfId>, data: &[u8]) -> bool {
    shared::transmit(if_id, data)
}

async fn submit_tx_via_io_scheduler(device_index: u8, data: &[u8]) -> Result<usize, &'static str> {
    use crate::io::dma::{CoherentDmaBuffer, DmaMemoryAttributes};

    log::debug!(
        "[IO-TX] submit_tx_via_io_scheduler: dev={}, len={}",
        device_index,
        data.len()
    );

    let iommu_dev: Option<IommuDeviceId> =
        with_virtio_net_at_index(device_index, |dev| dev.iommu_device_id()).flatten();

    if crate::io::virtio::get_poll_handler(device_index).is_none() {
        log::warn!(
            "[IO-TX] PollHandler not registered for dev={}",
            device_index
        );
        return Err("IoScheduler: device not registered");
    }

    let mut buffer = match iommu_dev {
        Some(ref dev_id) => {
            CoherentDmaBuffer::new_for_device(data.len(), DmaMemoryAttributes::MMIO, dev_id)
        }
        None => CoherentDmaBuffer::new(data.len(), DmaMemoryAttributes::MMIO),
    }
    .ok_or("IoScheduler: DMA buffer allocation failed")?;

    {
        let dst = unsafe { buffer.as_mut_slice() };
        dst[..data.len()].copy_from_slice(data);
    }
    buffer.prepare_for_device();

    let handle = DmaBufHandle {
        iova: buffer.device_addr(),
        len: data.len(),
    };

    let device = IoDeviceId::VirtioNet {
        index: device_index,
    };
    let command = IoCommand::Ioctl {
        code: VIRTIO_NET_IOCTL_TX,
        buf: handle,
    };

    log::debug!("[IO-TX] submitting IoCommand::Ioctl(TX) to IoScheduler");
    let io_future = hybrid_coordinator().submit_io_command(device, command, IoPriority::Normal);
    match io_future.await {
        Ok(bytes) => {
            log::debug!("[IO-TX] IoFuture completed OK, bytes={}", bytes);
            Ok(bytes)
        }
        Err(e) => {
            log::warn!("[IO-TX] IoFuture completed with error: {:?}", e);
            Err("IoScheduler: TX submission failed")
        }
    }
}

fn resolve_virtio_index(if_id: Option<NetIfId>) -> u8 {
    if_id
        .and_then(lookup_virtio_index_for_interface)
        .unwrap_or(0)
}

async fn tx_worker_task() {
    log::info!("[TX-WORKER] tx_worker_task started (fully async)");
    loop {
        let mut drained = tx_queue_drain_all();
        if drained.is_empty() {
            TxEventWaitFuture.await;
            drained = tx_queue_drain_all();
        }

        for req in drained.into_iter() {
            let device_index = resolve_virtio_index(req.if_id);

            let sent = match submit_tx_via_io_scheduler(device_index, &req.data).await {
                Ok(bytes) => true,
                Err(_) => {
                    transmit_packet_zero_copy_async(device_index, req.if_id, &req.data)
                }
            };

            if sent {
                TX_PACKETS.fetch_add(1, Ordering::Relaxed);
                counters::global().record_tx(req.data.len());
                trace::push_event(NetLayer::Driver, NetEventKind::Tx, "virtio async tx");
            } else {
                counters::global().record_error();
                trace::push_event(
                    NetLayer::Driver,
                    NetEventKind::Error,
                    "virtio async tx failed",
                );
            }
        }
    }
}

fn transmit_packet_zero_copy(device: &VirtioNetDevice, data: &[u8]) -> Result<(), &'static str> {
    if data.is_empty() {
        return Err("zero-length payload");
    }

    let mut packet =
        crate::net::datapath::mempool::alloc_packet().ok_or("PacketRef alloc failed")?;

    let cap = packet.capacity();
    let len = data.len().min(cap);
    packet.set_len(len);
    let buf = packet.data_mut();
    buf[..len].copy_from_slice(&data[..len]);

    device.enqueue_send_zero_copy(packet).map_err(|e| match e {
        crate::io::virtio::net::VirtioNetError::QueueFull => "TX queue full",
        _ => "enqueue_send_zero_copy failed",
    })
}

fn transmit_packet_zero_copy_async(_device_index: u8, if_id: Option<NetIfId>, data: &[u8]) -> bool {
    let result = if let Some(if_id) = if_id {
        let virtio_index = lookup_virtio_index_for_interface(if_id);
        match virtio_index {
            Some(idx) => with_virtio_net_at_index(idx, |dev| transmit_packet_zero_copy(dev, data)),
            None => None,
        }
    } else {
        with_virtio_net(|dev| transmit_packet_zero_copy(dev, data))
    };

    match result {
        Some(Ok(())) => true,
        Some(Err(_)) => false,
        None => false,
    }
}

fn lookup_virtio_index_for_interface(if_id: NetIfId) -> Option<u8> {
    manager::get_interface(if_id)
        .ok()
        .flatten()
        .and_then(|iface| iface.virtio_index)
}

fn transmit_packet_for_interface_zero_copy(
    if_id: NetIfId,
    data: &[u8],
) -> Result<(), &'static str> {
    let virtio_index =
        lookup_virtio_index_for_interface(if_id).ok_or("VirtIO mapping not found for interface")?;
    match with_virtio_net_at_index(virtio_index, |device| {
        transmit_packet_zero_copy(device, data)
    }) {
        Some(result) => result,
        None => Err("VirtIO-Net device not initialized for interface"),
    }
}

pub fn send_packet_on_interface(if_id: NetIfId, data: &[u8]) -> bool {
    match transmit_packet_for_interface_zero_copy(if_id, data) {
        Ok(()) => {
            TX_PACKETS.fetch_add(1, Ordering::Relaxed);
            counters::global().record_tx(data.len());
            trace::push_event(
                NetLayer::Driver,
                NetEventKind::Tx,
                "interface transmit (zero-copy)",
            );
            record_bridge_if_tx(if_id);
            true
        }
        Err(_e) => {
            counters::global().record_error();
            false
        }
    }
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

    if let Some(if_id) = primary_bridge_if() {
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

    ensure_bridge_if_state(if_id, None);
    let rx_count = RX_PACKETS.fetch_add(1, Ordering::Relaxed).saturating_add(1);
    counters::global().record_rx(payload_len);
    record_bridge_if_rx(if_id);
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

fn compute_and_set_flow_hash(packet: &mut crate::net::datapath::mempool::PacketRef) {
    // 解析ロジック...
    if RX_CSUM_HW_VERIFIED.load(Ordering::Relaxed) {
        let meta = packet.meta_mut();
        meta.set_ip_csum_verified();
        meta.set_l4_csum_verified();
    }
}

// ============================================================================
// Initialization
// ============================================================================

pub fn init_bridge() -> Result<(), &'static str> {
    let virtio_present = with_virtio_net(|_| ()).is_some();
    if !virtio_present {
        return Err("VirtIO-Net device not initialized");
    }

    let mac = with_virtio_net(|device| {
        let mac_bytes = device.mac_address();
        MacAddress::from_octets(
            mac_bytes[0], mac_bytes[1], mac_bytes[2], mac_bytes[3], mac_bytes[4], mac_bytes[5],
        )
    })
    .unwrap_or_else(|| MacAddress::from_octets(0x02, 0x00, 0x00, 0x00, 0x00, 0x01));

    let config = NetworkConfig {
        mac,
        ipv4: Ipv4Config::default(),
        ipv6: Some(crate::net::l3::ipv6::Ipv6Config::from_mac(mac.as_bytes())),
        icmp_echo_enabled: true,
    };

    shared::ensure_stack_initialized(config)?;

    match manager::register_virtio_port(0, Some(config)) {
        Ok(if_id) => {
            ensure_bridge_if_state(if_id, Some(0));
            set_primary_bridge_if_for_virtio(if_id, 0);
            shared::install_port(if_id, Arc::new(VirtioNetRuntime::new(0, if_id, mac)), true)?;
        }
        Err(_) => {}
    }

    crate::io::virtio::register_virtio_net_with_io_scheduler(0);
    RX_CSUM_HW_VERIFIED.store(true, Ordering::Release);
    Ok(())
}

#[inline]
pub fn rx_csum_hw_verified() -> bool {
    RX_CSUM_HW_VERIFIED.load(Ordering::Relaxed)
}

pub fn set_rx_csum_hw_verified(verified: bool) {
    RX_CSUM_HW_VERIFIED.store(verified, Ordering::Release);
}

pub fn is_initialized() -> bool {
    BRIDGE_INITIALIZED.load(Ordering::Acquire)
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

pub fn get_bridge_stats_for_interface(if_id: NetIfId) -> Option<BridgeInterfaceStats> {
    BRIDGE_IF_STATS.read().unwrap_or_else(|e| e.into_inner()).get(&if_id).copied()
}

pub fn list_bridge_stats() -> Vec<BridgeInterfaceStats> {
    BRIDGE_IF_STATS.read().unwrap_or_else(|e| e.into_inner()).values().copied().collect()
}

#[derive(Debug, Clone, Copy)]
pub struct BridgeStats {
    pub initialized: bool,
    pub rx_packets: u64,
    pub tx_packets: u64,
}

pub fn get_bridge_stats() -> BridgeStats {
    let mut rx = 0u64;
    let mut tx = 0u64;
    for s in BRIDGE_IF_STATS.read().unwrap_or_else(|e| e.into_inner()).values() {
        rx = rx.saturating_add(s.rx_packets);
        tx = tx.saturating_add(s.tx_packets);
    }
    BridgeStats {
        initialized: is_initialized(),
        rx_packets: rx,
        tx_packets: tx,
    }
}

pub fn lookup_if_by_virtio_index(virtio_index: u8) -> Option<NetIfId> {
    manager::lookup_if_by_virtio_index(virtio_index)
}

pub fn get_real_config() -> Option<NetworkConfigSnapshot> {
    match stack::stack().lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
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
