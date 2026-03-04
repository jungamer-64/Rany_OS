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

mod nat;
use nat::*;
use crate::io::virtio::{
    VirtioNetDevice, bind_virtio_net_interface, with_virtio_net, with_virtio_net_at_index,
    VIRTIO_NET_IOCTL_TX,
};
use crate::io::io_scheduler::{
    DeviceId as IoDeviceId, DmaBufHandle, IoCommand, IoPriority, hybrid_coordinator,
};
use crate::io::iommu::types::DeviceId as IommuDeviceId;
use crate::sync::PoisonLock;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use alloc::collections::VecDeque;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::RwLock;

extern crate alloc;

// ============================================================================
// Bridge State
// ============================================================================

/// Bridge initialization state
static BRIDGE_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// RXチェックサムHW検証済みフラグ
///
/// VirtIOでGUEST_CSUMが非ネゴシエートの場合、ホスト側が完全な
/// チェックサムを付与するため、ソフトウェア検証をスキップできる。
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

/// Enqueue a transmit request (called from stack's transmit_fn)
fn enqueue_transmit(if_id: Option<NetIfId>, data: &[u8]) -> bool {
    let req = TransmitRequest { if_id, data: data.to_vec() };
    let Ok(mut q) = TX_QUEUE.lock() else { return false; };
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
    let Ok(mut q) = TX_QUEUE.lock() else { return None; };
    let r = q.pop_front();
    if q.is_empty() {
        TX_QUEUE_HAS_EVENTS.store(false, Ordering::Release);
    }
    r
}

/// Drain all queued transmit requests
fn tx_queue_drain_all() -> Vec<TransmitRequest> {
    let Ok(mut q) = TX_QUEUE.lock() else { return Vec::new(); };
    TX_QUEUE_HAS_EVENTS.store(false, Ordering::Release);
    q.drain(..).collect()
}

/// Future that resolves when a TX request is available
pub struct TxEventWaitFuture;

impl Future for TxEventWaitFuture {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // If there are items, return immediately
        if TX_QUEUE_HAS_EVENTS.load(Ordering::Acquire) {
            return Poll::Ready(());
        }

        // Register waker
        if let Ok(mut w) = TX_QUEUE_WAKER.lock() {
            *w = Some(cx.waker().clone());
        }

        // Re-check
        if TX_QUEUE_HAS_EVENTS.load(Ordering::Acquire) {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

/// Per-interface bridge stats (transitional; stack path is still single-instance).
static BRIDGE_IF_STATS: RwLock<BTreeMap<NetIfId, BridgeInterfaceStats>> =
    RwLock::new(BTreeMap::new());

/// Primary interface used by legacy bridge wrappers.
static PRIMARY_BRIDGE_IF: RwLock<Option<NetIfId>> = RwLock::new(None);

// ============================================================================
// Deferred RX Dispatch (deadlock prevention)
// ============================================================================
//
// When the VirtIO device lock is held during polling, RX packet processing
// must be deferred to avoid the following deadlock chain:
//   VIRTIO_NET_DEVICE.lock() → handle_interrupt() → bridge dispatch
//   → stack.receive() → ARP reply → transmit → VIRTIO_NET_DEVICE.lock() ← DEADLOCK
//
// In deferred mode, received packets are buffered and dispatched only after
// the device lock is released.

/// Packet awaiting dispatch after device lock release.
struct DeferredRxPacket {
    packet: crate::net::datapath::mempool::PacketRef,
    header_size: usize,
    payload_len: usize,
    if_id: Option<NetIfId>,
}

/// When true, `process_received_packet_zero_copy*` buffers packets instead of
/// dispatching them inline.
static RX_DEFERRED_MODE: AtomicBool = AtomicBool::new(false);

/// Buffer for packets deferred during poll mode.
static DEFERRED_RX_PACKETS: PoisonLock<Vec<DeferredRxPacket>> = PoisonLock::new(Vec::new());

/// Enter deferred RX mode. Call before acquiring the VirtIO device lock
/// in a synchronous poll context.
pub fn enter_deferred_rx_mode() {
    RX_DEFERRED_MODE.store(true, Ordering::Release);
}

/// Leave deferred RX mode and dispatch all buffered packets.
/// Call after releasing the VirtIO device lock.
pub fn drain_deferred_rx_packets() {
    RX_DEFERRED_MODE.store(false, Ordering::Release);
    let packets: Vec<DeferredRxPacket> = {
        let Ok(mut guard) = DEFERRED_RX_PACKETS.lock() else {
            return;
        };
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
/// Records routing events (if_id,destination) for unit tests.
static FORWARD_EVENTS: RwLock<Vec<(NetIfId, Ipv4Address)>> =
    RwLock::new(Vec::new());

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
    // 非同期化: スタックからの送信要求はTXキューへエンキューして即時戻す。
    // これによりデバイスロックを保持したまま同期送信が行われる経路を回避する。
    if let Some(if_id) = if_id.or_else(primary_bridge_if) {
        return enqueue_transmit(Some(if_id), data);
    }

    // No specific interface: enqueue for generic device
    if enqueue_transmit(None, data) {
        true
    } else {
        // Queue full or error
        counters::global().record_error();
        trace::push_event(NetLayer::Driver, NetEventKind::Error, "virtio transmit enqueue failed");
        false
    }
}

/// IoScheduler 経由で VirtIO-Net にパケットを非同期送信する。
///
/// 1. VirtIO デバイスから IOMMU デバイスIDを取得
/// 2. CoherentDmaBuffer を割り当て（IOMMU 自動マッピング付き）
/// 3. データをコピーし IoScheduler 経由でサブミット
/// 4. IoFuture の完了を await（バッファは完了まで生存）
///
/// IoScheduler にデバイスが未登録または DMA 割り当て失敗時は `Err` を返す。
async fn submit_tx_via_io_scheduler(device_index: u8, data: &[u8]) -> Result<usize, &'static str> {
    use crate::io::dma::{CoherentDmaBuffer, DmaMemoryAttributes};

    log::debug!("[IO-TX] submit_tx_via_io_scheduler: dev={}, len={}", device_index, data.len());

    // IOMMU デバイスIDを取得（デバイスコールバック内で Clone して返す）
    let iommu_dev: Option<IommuDeviceId> = with_virtio_net_at_index(device_index, |dev| {
        dev.iommu_device_id()
    }).flatten();

    log::debug!("[IO-TX] iommu_dev={:?}", iommu_dev.is_some());

    // IoScheduler にデバイス登録済みか確認（PollHandler の存在で判定）
    if crate::io::virtio::get_poll_handler(device_index).is_none() {
        log::warn!("[IO-TX] PollHandler not registered for dev={}", device_index);
        return Err("IoScheduler: device not registered");
    }

    // DMA バッファ割り当て
    let mut buffer = match iommu_dev {
        Some(ref dev_id) => CoherentDmaBuffer::new_for_device(
            data.len(),
            DmaMemoryAttributes::MMIO,
            dev_id,
        ),
        None => CoherentDmaBuffer::new(
            data.len(),
            DmaMemoryAttributes::MMIO,
        ),
    }.ok_or("IoScheduler: DMA buffer allocation failed")?;

    log::debug!("[IO-TX] DMA buffer allocated: iova=0x{:x}, len={}", buffer.device_addr(), data.len());

    // ペイロードを DMA バッファにコピー
    {
        let dst = unsafe { buffer.as_mut_slice() };
        dst[..data.len()].copy_from_slice(data);
    }
    buffer.prepare_for_device();

    let handle = DmaBufHandle {
        iova: buffer.device_addr(),
        len: data.len(),
    };

    let device = IoDeviceId::VirtioNet { index: device_index };
    let command = IoCommand::Ioctl {
        code: VIRTIO_NET_IOCTL_TX,
        buf: handle,
    };

    // IoScheduler 経由でサブミット → IoFuture を await
    log::debug!("[IO-TX] submitting IoCommand::Ioctl(TX) to IoScheduler");
    let io_future = hybrid_coordinator().submit_io_command(device, command, IoPriority::Normal);
    log::debug!("[IO-TX] IoFuture created, awaiting completion...");
    match io_future.await {
        Ok(bytes) => {
            log::debug!("[IO-TX] IoFuture completed OK, bytes={}", bytes);
            // buffer はここで Drop（IOMMU unmap を含む）
            Ok(bytes)
        }
        Err(e) => {
            log::warn!("[IO-TX] IoFuture completed with error: {:?}", e);
            Err("IoScheduler: TX submission failed")
        }
    }
}

/// Resolve the VirtIO device index for a given interface (or default to 0).
fn resolve_virtio_index(if_id: Option<NetIfId>) -> u8 {
    if_id
        .and_then(lookup_virtio_index_for_interface)
        .unwrap_or(0)
}

/// Background TX worker: drains TX_QUEUE and performs actual device submits.
///
/// IoScheduler 経路が利用可能な場合は非同期で送信し、完了を await する。
/// IoScheduler 未登録またはDMA割り当て失敗時はゼロコピー非同期経路にフォールバックする。
/// 【完全非同期化】旧来の同期 submit_tx フォールバックを完全に排除。
async fn tx_worker_task() {
    log::info!("[TX-WORKER] tx_worker_task started (fully async)");
    loop {
        // Drain any pending entries without awaiting
        let mut drained = tx_queue_drain_all();
        if drained.is_empty() {
            // Wait for new events
            TxEventWaitFuture.await;
            // After being awakened, continue to drain
            drained = tx_queue_drain_all();
        }

        log::debug!("[TX-WORKER] drained {} TX requests", drained.len());

        for req in drained.into_iter() {
            let device_index = resolve_virtio_index(req.if_id);

            log::debug!("[TX-WORKER] processing req: dev={}, len={}", device_index, req.data.len());

            // Try IoScheduler path first
            let sent = match submit_tx_via_io_scheduler(device_index, &req.data).await {
                Ok(bytes) => {
                    log::debug!("[TX-WORKER] IoScheduler path succeeded, bytes={}", bytes);
                    true
                }
                Err(reason) => {
                    log::debug!("[TX-WORKER] IoScheduler path unavailable: {}, using zero-copy async fallback", reason);
                    // 【完全非同期化】ゼロコピー非同期経路でフォールバック
                    // 旧来の同期 submit_tx() は完全に排除
                    transmit_packet_zero_copy_async(device_index, req.if_id, &req.data)
                }
            };

            if sent {
                TX_PACKETS.fetch_add(1, Ordering::Relaxed);
                counters::global().record_tx(req.data.len());
                trace::push_event(NetLayer::Driver, NetEventKind::Tx, "virtio async tx");
            } else {
                counters::global().record_error();
                trace::push_event(NetLayer::Driver, NetEventKind::Error, "virtio async tx failed");
            }
        }
    }
}

/// 【完全非同期化】ゼロコピー非同期パケット送信
///
/// PacketRefをmempool経由で割り当て、`enqueue_send_zero_copy`で
/// DMAキューに投入する。同期的な`submit_tx()`は完全に排除。
fn transmit_packet_zero_copy(device: &VirtioNetDevice, data: &[u8]) -> Result<(), &'static str> {
    // Mempool からバッファを確保してペイロードをコピー
    let mut packet = crate::net::datapath::mempool::alloc_packet()
        .ok_or("PacketRef alloc failed")?;
    let buf = packet.data_mut();
    let len = data.len().min(buf.len());
    buf[..len].copy_from_slice(&data[..len]);
    packet.set_len(len);

    // ゼロコピーでDMAキューに投入（非同期完了は割り込みハンドラで処理）
    device.enqueue_send_zero_copy(packet).map_err(|e| {
        match e {
            crate::io::virtio::VirtioNetError::QueueFull => "TX queue full",
            _ => "enqueue_send_zero_copy failed",
        }
    })
}

/// 【完全非同期化】デバイスインデックス指定のゼロコピー非同期送信フォールバック
///
/// tx_worker_task内のIoScheduler失敗時フォールバックとして使用。
/// 同期的な`submit_tx()`による送信を完全に排除し、
/// `enqueue_send_zero_copy()`経由のゼロコピー非同期パスのみ使用する。
fn transmit_packet_zero_copy_async(device_index: u8, if_id: Option<NetIfId>, data: &[u8]) -> bool {
    let result = if let Some(if_id) = if_id {
        let virtio_index = lookup_virtio_index_for_interface(if_id);
        match virtio_index {
            Some(idx) => with_virtio_net_at_index(idx, |dev| transmit_packet_zero_copy(dev, data)),
            None => {
                log::warn!("[TX-WORKER] VirtIO mapping not found for interface if_id={}", if_id.0);
                None
            }
        }
    } else {
        with_virtio_net(|dev| transmit_packet_zero_copy(dev, data))
    };

    match result {
        Some(Ok(())) => true,
        Some(Err(e)) => {
            log::warn!("[TX-WORKER] zero-copy async TX failed: {}", e);
            false
        }
        None => {
            log::warn!("[TX-WORKER] VirtIO-Net device not available");
            false
        }
    }
}

fn lookup_virtio_index_for_interface(if_id: NetIfId) -> Option<u8> {
    manager::get_interface(if_id)
        .ok()
        .flatten()
        .and_then(|iface| iface.virtio_index)
}

fn transmit_packet_for_interface_zero_copy(if_id: NetIfId, data: &[u8]) -> Result<(), &'static str> {
    let virtio_index =
        lookup_virtio_index_for_interface(if_id).ok_or("VirtIO mapping not found for interface")?;
    match with_virtio_net_at_index(virtio_index, |device| transmit_packet_zero_copy(device, data)) {
        Some(result) => result,
        None => Err("VirtIO-Net device not initialized for interface"),
    }
}

/// 【完全非同期化】インターフェース上のパケット送信
///
/// 旧来の同期`submit_tx()`を使用する`send_packet_on_interface`を
/// ゼロコピー非同期パスに完全移行。
pub fn send_packet_on_interface(if_id: NetIfId, data: &[u8]) -> bool {
    match transmit_packet_for_interface_zero_copy(if_id, data) {
        Ok(()) => {
            TX_PACKETS.fetch_add(1, Ordering::Relaxed);
            counters::global().record_tx(data.len());
            trace::push_event(NetLayer::Driver, NetEventKind::Tx, "interface transmit (zero-copy)");
            record_bridge_if_tx(if_id);
            true
        }
        Err(_e) => {
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
    // Deferred mode: buffer packet for later dispatch to avoid deadlock
    if RX_DEFERRED_MODE.load(Ordering::Acquire) {
        if let Ok(mut guard) = DEFERRED_RX_PACKETS.lock() {
            guard.push(DeferredRxPacket { packet, header_size, payload_len, if_id: None });
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

    // Ensure view length covers header + payload
    packet.set_len(header_size + payload_len);

    // Skip the virtio header so the PacketRef points at the Ethernet frame
    if header_size > 0 {
        packet.advance(header_size);
    }

    // Flow Hash 計算: パケットメタにRSSハッシュを設定
    compute_and_set_flow_hash(&mut packet);

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
    // Deferred mode: buffer packet for later dispatch to avoid deadlock
    if RX_DEFERRED_MODE.load(Ordering::Acquire) {
        if let Ok(mut guard) = DEFERRED_RX_PACKETS.lock() {
            guard.push(DeferredRxPacket { packet, header_size, payload_len, if_id: Some(if_id) });
        }
        return;
    }

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
                       
                       let mut tcp_flags = 0u8;
                       if proto == crate::net::l3::ipv4::IpProtocol::Tcp && transport.len() >= 14 {
                           tcp_flags = transport[13]; // TCP flags (SYN, FIN, RST, etc)
                       }

                       if nat_translate_in(proto, src_ip, src_port, &mut dst_ip, &mut dst_port, tcp_flags) {
                           transport[2..4].copy_from_slice(&dst_port.to_be_bytes());
                           recompute_ipv4_transport_checksum(transport, src_ip, dst_ip, proto);
                           translated_dst = Some(dst_ip);
                       }
                   } else if proto == crate::net::l3::ipv4::IpProtocol::Icmp && header_len <= ip_buf.len().saturating_sub(8) {
                       let (_, transport) = ip_buf.split_at_mut(header_len);
                       if let Some(new_dst) = nat_translate_in_icmp(src_ip, &mut dst_ip, transport) {
                           // ICMP checksum needs to be recomputed. 
                           // Since we might have modified the payload (for ICMP errors), 
                           // we just clear and recompute the whole thing.
                           transport[2] = 0;
                           transport[3] = 0;
                           let checksum = crate::net::l3::ipv4::data_checksum(transport, 0);
                           transport[2] = (checksum >> 8) as u8;
                           transport[3] = (checksum & 0xff) as u8;
                           translated_dst = Some(new_dst);
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
                    let src = ip_pkt.source();
                    let dst = ip_pkt.destination();

                    // Security: Ingress Filtering (BCP 38 / RFC 2827)
                    // If the source IP belongs to a local network, it MUST arrive on the 
                    // interface associated with that network. If it arrives on a different 
                    // interface, it's a spoofed packet.
                    if let Ok(Some(src_route)) = manager::lookup_ipv4_route(src) {
                        if src_route.if_id != if_id && src_route.flags.connected {
                            log::warn!(
                                "[NET BRIDGE] Ingress filtering drop: src {} on if {} (expected if {})",
                                src, if_id.0, src_route.if_id.0
                            );
                            return;
                        }
                    }

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
                                let translated = match proto {
                                    crate::net::l3::ipv4::IpProtocol::Udp => {
                                        if let Some(udp) = crate::net::l4::udp::UdpPacket::parse(transport) {
                                            nat_translate_out(
                                                crate::net::l3::ipv4::IpProtocol::Udp,
                                                src,
                                                udp.src_port(),
                                                dst,
                                                udp.dst_port(),
                                                route.if_id,
                                                0, // UDP has no TCP flags
                                            )
                                        } else {
                                            None
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
                                        let tcp_flags = transport.get(13).copied().unwrap_or(0);
                                        nat_translate_out(
                                            crate::net::l3::ipv4::IpProtocol::Tcp,
                                            src,
                                            tcp_src_port,
                                            dst,
                                            tcp_dst_port,
                                            route.if_id,
                                            tcp_flags,
                                        )
                                    }
                                    crate::net::l3::ipv4::IpProtocol::Icmp => {
                                        nat_translate_out_icmp(src, dst, transport, route.if_id)
                                    }
                                    _ => None,
                                };

                                let (_new_src, _new_port) = match translated {
                                    Some(pair) => pair,
                                    None => {
                                        // If NAT is enabled but failed (table full, etc), drop to prevent internal IP leak
                                        log::warn!("[NET BRIDGE] NAT failed for {:?}, dropping packet", proto);
                                        return;
                                    }
                                };

                                let ttl = ip_pkt.ttl();
                                if ttl <= 1 {
                                    // TTL切れ: イベントキュー経由でICMP Time Exceeded送信（デッドロック回避）
                                    let original_ip_header = Vec::from(ip_pkt.as_bytes());
                                    crate::net::l4::endpoint::event::send_event_ignore(
                                        crate::net::l4::endpoint::event::NetworkEvent::NatIcmpTimeExceeded {
                                            src_ip: *src.as_bytes(),
                                            original_ip_header,
                                        },
                                    );
                                } else {
                                    let next_ttl = ttl - 1;
                                    // イベントキュー経由でNAT転送（デッドロック回避）
                                    match proto {
                                        crate::net::l3::ipv4::IpProtocol::Udp => {
                                            if let Some(udp) = crate::net::l4::udp::UdpPacket::parse(transport) {
                                                let payload = Vec::from(udp.payload());
                                                let src_port = _new_port;
                                                let dst_port = udp.dst_port();
                                                crate::net::l4::endpoint::event::send_event_ignore(
                                                    crate::net::l4::endpoint::event::NetworkEvent::NatForwardUdp {
                                                        if_id: route.if_id.0,
                                                        src_ip: *_new_src.as_bytes(),
                                                        src_port,
                                                        dst_ip: *dst.as_bytes(),
                                                        dst_port,
                                                        payload,
                                                        ttl: next_ttl,
                                                    },
                                                );
                                            }
                                        }
                                        crate::net::l3::ipv4::IpProtocol::Tcp => {
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
                                            crate::net::l4::endpoint::event::send_event_ignore(
                                                crate::net::l4::endpoint::event::NetworkEvent::NatForwardTcp {
                                                    src_ip: *_new_src.as_bytes(),
                                                    dst_ip: *dst.as_bytes(),
                                                    segment: nat_segment,
                                                    ttl: next_ttl,
                                                },
                                            );
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

    // Flow Hash 計算: パケットメタにRSSハッシュを設定
    compute_and_set_flow_hash(&mut packet);

    if let Some(batch) = BATCH_PROCESSOR.enqueue(packet) {
        stack::receive_batch(batch);
    }
}

/// パケットのEthernet/IP/L4ヘッダからFlow Hashを計算しPacketMetaに設定
///
/// RSSフローハッシュを計算することで、GRO集約やフロー制御に活用する。
/// IPv4 TCP/UDPパケットのみ5タプルハッシュを計算する。
fn compute_and_set_flow_hash(packet: &mut crate::net::datapath::mempool::PacketRef) {
    // Step 1: 不変参照でヘッダを解析し、結果をローカル変数にコピー
    let parsed = {
        let data = packet.data();
        // Ethernet header: 14 bytes (no VLAN)
        if data.len() < 14 {
            return;
        }
        let ether_type = u16::from_be_bytes([data[12], data[13]]);
        if ether_type != 0x0800 {
            // IPv4のみ対応
            return;
        }
        let ip_start = 14usize;
        if data.len() < ip_start + 20 {
            return;
        }
        let ihl = ((data[ip_start] & 0x0F) as usize) * 4;
        if ihl < 20 || data.len() < ip_start + ihl {
            return;
        }
        let protocol = data[ip_start + 9];
        let src_ip = u32::from_be_bytes([
            data[ip_start + 12], data[ip_start + 13],
            data[ip_start + 14], data[ip_start + 15],
        ]);
        let dst_ip = u32::from_be_bytes([
            data[ip_start + 16], data[ip_start + 17],
            data[ip_start + 18], data[ip_start + 19],
        ]);

        let l4_start = ip_start + ihl;
        // TCP (6) / UDP (17) のみポート情報を抽出
        let (src_port, dst_port) = if (protocol == 6 || protocol == 17) && data.len() >= l4_start + 4 {
            (
                u16::from_be_bytes([data[l4_start], data[l4_start + 1]]),
                u16::from_be_bytes([data[l4_start + 2], data[l4_start + 3]]),
            )
        } else {
            (0, 0)
        };

        // L4ヘッダ長の計算
        let l4_hdr_len = if protocol == 6 || protocol == 17 {
            if protocol == 6 && data.len() >= l4_start + 13 {
                (((data[l4_start + 12] >> 4) & 0x0F) as u8) * 4
            } else if protocol == 17 {
                8u8
            } else {
                0u8
            }
        } else {
            0u8
        };

        // 借用はここで終了
        (src_ip, dst_ip, src_port, dst_port, protocol, ihl as u8, l4_hdr_len)
    };

    let (src_ip, dst_ip, src_port, dst_port, protocol, ihl, l4_hdr_len) = parsed;

    // Step 2: Flow Hash 計算
    let flow_hash = crate::net::datapath::optimization::FlowAffinity::hash_5tuple(
        src_ip, dst_ip, src_port, dst_port, protocol,
    );

    // Step 3: 可変参照でメタデータを設定
    let meta = packet.meta_mut();
    meta.flow_hash = flow_hash;
    meta.l2_len = 14;
    meta.l3_len = ihl;
    meta.l4_proto = protocol;
    meta.l4_len = l4_hdr_len;

    // HWチェックサム検証済みフラグの伝搬
    if RX_CSUM_HW_VERIFIED.load(Ordering::Relaxed) {
        meta.set_ip_csum_verified();
        meta.set_l4_csum_verified();
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
    if !virtio_present {
        log::warn!("[NET BRIDGE] VirtIO-Net not initialized; bridge init deferred");
        return Err("VirtIO-Net device not initialized");
    }

    if BRIDGE_INITIALIZED.swap(true, Ordering::SeqCst) {
        return Ok(());
    }

    // Initialize zero-copy packet mempool (required for alloc_packet() in TX path)
    if let Err(e) = crate::net::datapath::mempool::init_net_mempool(256) {
        log::warn!("[NET BRIDGE] mempool init failed: {}", e);
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

    // Register VirtIO-Net device (index 0) with IoScheduler for adaptive
    // polling/interrupt switching and completion tracking.
    crate::io::virtio::register_virtio_net_with_io_scheduler(0);
    log::info!("[NET BRIDGE] VirtIO-Net registered with IoScheduler");

    // Set transmit callback
    match stack::stack().lock() {
        Ok(mut guard) => {
            if let Some(ref mut stack) = *guard {
                stack.set_transmit_fn(virtio_transmit);
                // Spawn background TX worker to process enqueued transmit requests.
                // Use the main Executor's global queue so the task is polled by the
                // primary executor loop (task::Executor::run).
                crate::task::Executor::spawn_global(crate::task::Task::new(tx_worker_task()));
            } else {
                log::warn!("[NET BRIDGE] Stack is None after init - tx_worker NOT spawned");
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

    // VirtIO GUEST_CSUM 非ネゴシエート時、ホストが完全なチェックサムを
    // 付与するためRXソフトウェア検証をスキップ可能にする。
    // 現在のfeatureネゴシエーションではGUEST_CSUMを含めていないため有効化。
    RX_CSUM_HW_VERIFIED.store(true, Ordering::Release);
    log::info!("[NET BRIDGE] RX checksum skip enabled (host-verified)");

    Ok(())
}

/// RXチェックサムがHW検証済みか確認する
///
/// TCP/UDP受信パスでチェックサム検証をスキップするために使用。
#[inline]
pub fn rx_csum_hw_verified() -> bool {
    RX_CSUM_HW_VERIFIED.load(Ordering::Relaxed)
}

/// RXチェックサムHW検証フラグを設定する
///
/// VirtIOのfeatureネゴシエーション後に呼び出す。
pub fn set_rx_csum_hw_verified(verified: bool) {
    RX_CSUM_HW_VERIFIED.store(verified, Ordering::Release);
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

/// 保留中のバッチを即座にフラッシュしてスタックに渡す。
///
/// 同期的なポーリングループ（初期化時のping等）で使用する。
pub fn flush_pending_batch() {
    if let Some(batch) = BATCH_PROCESSOR.flush() {
        stack::receive_batch(batch);
    }
}

/// TX_QUEUEに溜まったパケットを同期的にドレインし、VirtIOデバイスに直接サブミットする。
///
/// asyncエグゼキュータが起動する前の同期ポーリングコンテキスト（初期化時ping等）で使用する。
/// `tx_worker_task`はasyncタスクなので、エグゼキュータ未起動時には動作しない。
/// この関数がその役割を同期的に代行する。
pub fn sync_drain_tx_queue() {
    let drained = tx_queue_drain_all();
    if drained.is_empty() {
        return;
    }

    log::debug!("[TX-SYNC] draining {} TX requests synchronously", drained.len());

    for req in drained.into_iter() {
        let sent = if let Some(if_id) = req.if_id {
            send_packet_on_interface(if_id, &req.data)
        } else {
            let result = with_virtio_net(|device| transmit_packet(device, &req.data));
            matches!(result, Some(Ok(())))
        };

        if sent {
            TX_PACKETS.fetch_add(1, Ordering::Relaxed);
            counters::global().record_tx(req.data.len());
            trace::push_event(NetLayer::Driver, NetEventKind::Tx, "sync tx drain");
        } else {
            log::warn!("[TX-SYNC] failed to submit packet (len={})", req.data.len());
            counters::global().record_error();
            trace::push_event(NetLayer::Driver, NetEventKind::Error, "sync tx drain failed");
        }
    }
}

/// NETWORK_EVENT_QUEUEに溜まったイベントを同期的にドレインし処理する。
///
/// asyncエグゼキュータが起動する前の同期ポーリングコンテキスト（初期化時ping等）で使用する。
/// 通常はasyncイベントループが`EventWaitFuture`でイベントを消費するが、
/// エグゼキュータ未起動時にはイベントがキューに滞留する。
/// この関数がARP応答等のIngressPacketイベントを同期的に処理する。
pub fn sync_process_network_events() {
    use crate::net::l4::endpoint::event::{event_queue, NetworkEvent};
    use crate::net::l4::endpoint::handler::NetworkEventHandler;

    let events = event_queue().drain_all();
    if events.is_empty() {
        return;
    }

    log::debug!("[NET-SYNC] processing {} queued network events synchronously", events.len());

    let handler = NetworkEventHandler::new();

    if let Ok(mut stack_guard) = stack::NETWORK_STACK.lock() {
        if let Some(ref mut stack) = *stack_guard {
            for event in events {
                match &event {
                    NetworkEvent::IngressPacket { .. } => {
                        log::trace!("[NET-SYNC] processing IngressPacket event");
                    }
                    other => {
                        log::trace!("[NET-SYNC] processing {:?} event", core::mem::discriminant(other));
                    }
                }
                handler.handle_event_with_stack(event, stack);
            }
        }
    } else {
        log::warn!("[NET-SYNC] NETWORK_STACK lock poisoned; re-enqueuing events");
        // スタックロックが取れない場合はイベントを再エンキューする
        for event in events {
            crate::net::l4::endpoint::event::send_event_ignore(event);
        }
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
#[path = "tests.rs"]
pub(crate) mod tests;

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

/// Send ICMP echo via real NetworkStack (非推奨: ping_async を使用してください)
///
/// この関数はIRQ無効化 + 同期ロックを使用するため、デッドロックリスクがある。
/// 新規コードでは `crate::net::api::icmp::ping_async()` または
/// `IcmpEchoFuture` を使用すること。
///
/// 初期化時のブートストラップping（sync_drain_tx_queue前提）では
/// 引き続き使用可能。
#[deprecated(note = "use crate::net::api::icmp::ping_async() or IcmpEchoFuture instead")]
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
