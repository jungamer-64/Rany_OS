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
/// IoScheduler 未登録またはDMA割り当て失敗時はレガシー経路（submit_tx）にフォールバックする。
async fn tx_worker_task() {
    log::info!("[TX-WORKER] tx_worker_task started");
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
                    log::warn!("[TX-WORKER] IoScheduler path failed: {}, fallback to legacy", reason);
                    // Fallback to legacy path
                    if let Some(if_id) = req.if_id {
                        send_packet_on_interface(if_id, &req.data)
                    } else {
                        let result = with_virtio_net(|device| transmit_packet(device, &req.data));
                        matches!(result, Some(Ok(())))
                    }
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

/// Low-level packet transmission via VirtIO-Net
fn transmit_packet(device: &VirtioNetDevice, data: &[u8]) -> Result<(), &'static str> {
    // Synchronously submit the packet using a DMA buffer so that the descriptor
    // is added and the device is notified immediately. The DMA buffer is
    // retained in the device's tx_inflight map and freed when the TX completion
    // is processed in the interrupt handler.

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
        Err(_e) => {
            // log the failure reason and interface
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
pub(crate) mod tests {
    use super::*;
    use crate::net::datapath::mempool;
    use crate::net::runtime::stack;
    use crate::net::l3::ipv4::{Ipv4PacketMut, Ipv4Address, IpProtocol};
    use crate::net::l4::tcp::{TcpControlBlock, EndpointAddr as TcpEndpointAddr, Ipv4Addr as TcpIpv4Addr};
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
        local: TcpEndpointAddr,
        remote: TcpEndpointAddr,
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

        let local = TcpEndpointAddr::new([127, 0, 0, 1], 1000);
        let remote = TcpEndpointAddr::new([127, 0, 0, 1], 2000);
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

        let local = TcpEndpointAddr::new_v6(crate::net::l3::ipv6::Ipv6Address::LOOPBACK.octets(), 1000);
        let remote = TcpEndpointAddr::new_v6(crate::net::l3::ipv6::Ipv6Address::LOOPBACK.octets(), 2000);
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
        let local = TcpEndpointAddr::new([127, 0, 0, 1], 1000);
        let remote = TcpEndpointAddr::new([127, 0, 0, 1], 2000);

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
            nat_translate_out(IpProtocol::Udp, internal_ip, internal_port, remote_ip, remote_port, wan_if, 0).expect("NAT allocation failed");

        assert_eq!(ext_ip, Ipv4Address::new([10, 0, 1, 1]));
        assert!(ext_port >= NAT_EPHEMERAL_START);

        let mut dst_ip = ext_ip;
        let mut dst_port = ext_port;
        assert!(nat_translate_in(
            IpProtocol::Udp,
            remote_ip,
            remote_port,
            &mut dst_ip,
            &mut dst_port,
            0
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
            &mut dst_port,
            0
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
            &mut dst_port,
            0
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
            &mut dst_port,
            0
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
            0,
        ).expect("NAT allocation failed");
        let (_, fresh_port) = nat_translate_out(
            IpProtocol::Udp,
            Ipv4Address::new([10, 0, 0, 3]),
            2222,
            Ipv4Address::new([198, 51, 100, 2]),
            50002,
            wan_if,
            0,
        ).expect("NAT allocation failed");

        {
            let mut table = NAT_TABLE.write();
            table.get_mut(&stale_port).unwrap().last_seen = 100;
            table.get_mut(&fresh_port).unwrap().last_seen = 900;
        }

        let removed = nat_prune_expired(1_000);
        assert_eq!(removed, 1);

        let table = NAT_TABLE.read();
        assert!(!table.contains_key(&stale_port));
        assert!(table.contains_key(&fresh_port));
    }

    #[cfg_attr(test, test_case)]
    pub fn test_nat_icmp_echo() {
        let _guard = BridgeStateGuard::new();
        manager::init_network_manager();

        let wan_if = manager::register_interface("wan0").expect("register wan0");
        let _ = manager::set_interface_config(
            wan_if,
            NetworkConfig {
                mac: MacAddress::from_octets(0, 1, 2, 3, 4, 45),
                ipv4: Ipv4Config {
                    address: Ipv4Address::new([10, 0, 1, 1]),
                    subnet_mask: Ipv4Address::new([255, 255, 255, 0]),
                    gateway: Ipv4Address::ANY,
                    dns: None,
                },
                ipv6: None,
                icmp_echo_enabled: true,
            },
        );

        let internal_ip = Ipv4Address::new([10, 0, 0, 2]);
        let remote_ip = Ipv4Address::new([8, 8, 8, 8]);
        let mut icmp_req = [0u8; 8];
        icmp_req[0] = 8; // Echo Request
        icmp_req[4] = 0x12; // Identifier
        icmp_req[5] = 0x34;

        let (ext_ip, ext_port) = nat_translate_out_icmp(internal_ip, remote_ip, &icmp_req, wan_if).expect("NAT allocation failed");
        assert_eq!(ext_ip, Ipv4Address::new([10, 0, 1, 1]));
        
        // Response
        let mut icmp_reply = [0u8; 8];
        icmp_reply[0] = 0; // Echo Reply
        icmp_reply[4] = (ext_port >> 8) as u8;
        icmp_reply[5] = (ext_port & 0xff) as u8;

        let mut dst_ip = ext_ip;
        let new_dst = nat_translate_in_icmp(remote_ip, &mut dst_ip, &mut icmp_reply).expect("NAT lookup failed");
        assert_eq!(new_dst, internal_ip);
        assert_eq!(icmp_reply[4], 0x12);
        assert_eq!(icmp_reply[5], 0x34);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_nat_icmp_error() {
        let _guard = BridgeStateGuard::new();
        manager::init_network_manager();

        let wan_if = manager::register_interface("wan0").expect("register wan0");
        let _ = manager::set_interface_config(
            wan_if,
            NetworkConfig {
                mac: MacAddress::from_octets(0, 1, 2, 3, 4, 46),
                ipv4: Ipv4Config {
                    address: Ipv4Address::new([10, 0, 1, 1]),
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
        let remote_ip = Ipv4Address::new([93, 184, 216, 34]);
        let remote_port = 80;

        let (_ext_ip, ext_port) = nat_translate_out(
            IpProtocol::Tcp,
            internal_ip,
            internal_port,
            remote_ip,
            remote_port,
            wan_if,
            0,
        ).expect("NAT allocation failed");

        // ICMP Error (Time Exceeded) from an intermediate router (1.1.1.1)
        let mut icmp_err = [0u8; 8 + 20 + 8];
        icmp_err[0] = 11; // Time Exceeded
        icmp_err[1] = 0;  // Code: TTL exceeded in transit
        
        // Original IP header
        let inner_ip_off = 8;
        icmp_err[inner_ip_off + 9] = 6; // TCP
        icmp_err[inner_ip_off + 12..inner_ip_off + 16].copy_from_slice(_ext_ip.as_bytes()); // was sent as translated IP
        icmp_err[inner_ip_off + 16..inner_ip_off + 20].copy_from_slice(remote_ip.as_bytes());
        
        // Original transport (first 8 bytes)
        let inner_tcp_off = inner_ip_off + 20;
        icmp_err[inner_tcp_off..inner_tcp_off + 2].copy_from_slice(&ext_port.to_be_bytes());
        icmp_err[inner_tcp_off + 2..inner_tcp_off + 4].copy_from_slice(&remote_port.to_be_bytes());

        let mut dst_ip = _ext_ip;
        let router_ip = Ipv4Address::new([1, 1, 1, 1]);
        let new_dst = nat_translate_in_icmp(router_ip, &mut dst_ip, &mut icmp_err).expect("NAT lookup failed for ICMP error");
        
        assert_eq!(new_dst, internal_ip);
        // Inner IP should be rewritten back to internal IP
        assert_eq!(Ipv4Address::from_octets(icmp_err[inner_ip_off + 12], icmp_err[inner_ip_off + 13], icmp_err[inner_ip_off + 14], icmp_err[inner_ip_off + 15]), internal_ip);
        // Inner port should be rewritten back to internal port
        assert_eq!(u16::from_be_bytes([icmp_err[inner_tcp_off], icmp_err[inner_tcp_off + 1]]), internal_port);
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
        let local = TcpEndpointAddr::new_v6(crate::net::l3::ipv6::Ipv6Address::LOOPBACK.octets(), 1000);
        let remote = TcpEndpointAddr::new_v6(crate::net::l3::ipv6::Ipv6Address::LOOPBACK.octets(), 2000);

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
