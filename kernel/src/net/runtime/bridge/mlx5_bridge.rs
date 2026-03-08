// ============================================================================
// src/net/runtime/bridge/mlx5_bridge.rs - ConnectX Family <-> NetworkStack Bridge
// ============================================================================
//!
//! ConnectX ファミリ (mlx5) ドライバとNetworkStackを接続するブリッジモジュール。
//!
//! ## 設計
//!
//! - **送信パス**: スタックの transmit_fn コールバック → DMA バッファ構築 → SQ 投入
//! - **受信パス**: CQ ポーリング → CQE デコード → PacketRef 構築 → スタック配送
//! - **適応的ポーリング**: 低負荷時は割り込み駆動、高負荷時はビジーポーリング
//!
//! ## ExoRust 原則
//!
//! - ゼロコピーパスを維持（バッファ所有権の移動で管理）
//! - ISR 内で `wake()` を直接呼ばない（MPMC キュー経由）
//! - Async-First: ポーリングタスクは Future ベース

extern crate alloc;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;

use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::task::{Context, Poll, Waker};

use crate::net::obs::{
    counters,
    trace::{self, NetEventKind, NetLayer},
};
use crate::net::runtime::manager::NetIfId;
use crate::sync::PoisonLock;
use crate::task::interrupt_waker::{InterruptSource, wait_for_interrupt};

use mlx5_driver::Mlx5Device;

use crate::net::datapath::mempool::PacketRef;

// ============================================================================
// Bridge State
// ============================================================================

/// mlx5 ブリッジ初期化状態
static MLX5_BRIDGE_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// mlx5 デバイスインスタンス（PoisonLock で保護）
static MLX5_DEVICE: PoisonLock<Option<Mlx5Device>> = PoisonLock::new(None);

/// mlx5 ブリッジの論理インターフェースID
static MLX5_IF_ID: PoisonLock<Option<NetIfId>> = PoisonLock::new(None);

/// RX バッファトラッキング（ゼロコピー用、キューごと）
static MLX5_RX_BUFS: PoisonLock<Vec<Vec<Option<PacketRef>>>> = PoisonLock::new(Vec::new());

/// TX バッファトラッキング（安全な非同期送信用、キューごと）
static MLX5_TX_BUFS: PoisonLock<Vec<Vec<Option<PacketRef>>>> = PoisonLock::new(Vec::new());

/// 送信パケットカウンタ
static MLX5_TX_PACKETS: AtomicU64 = AtomicU64::new(0);

/// 受信パケットカウンタ
static MLX5_RX_PACKETS: AtomicU64 = AtomicU64::new(0);

/// 送信エラーカウンタ
static MLX5_TX_ERRORS: AtomicU64 = AtomicU64::new(0);

/// 受信エラーカウンタ
static MLX5_RX_ERRORS: AtomicU64 = AtomicU64::new(0);

/// 割り込み起床カウンタ
static MLX5_WAKE_COUNTS: AtomicU64 = AtomicU64::new(0);

/// DMAマッピングエラー
static MLX5_DMA_ERRORS: AtomicU64 = AtomicU64::new(0);

/// RX CQ ポーリングバッチサイズ
const MLX5_RX_POLL_BATCH: u32 = 64;

struct Mlx5TransmitRequest {
    data: Vec<u8>,
    vlan_tag: Option<u16>,
}

struct Mlx5Runtime;

static MLX5_TX_QUEUE: PoisonLock<VecDeque<Mlx5TransmitRequest>> = PoisonLock::new(VecDeque::new());
static MLX5_TX_QUEUE_WAKER: PoisonLock<Option<Waker>> = PoisonLock::new(None);
static MLX5_TX_QUEUE_HAS_EVENTS: AtomicBool = AtomicBool::new(false);
static MLX5_POLL_TASK_STARTED: AtomicBool = AtomicBool::new(false);
static MLX5_TX_TASK_STARTED: AtomicBool = AtomicBool::new(false);

// ============================================================================
// Device Registration
// ============================================================================

/// mlx5 デバイスをブリッジに登録する
///
/// `mlx5_registry.rs` の `probe_device` から呼び出される。
pub fn register_mlx5_device(device: Mlx5Device) {
    if let Ok(mut guard) = MLX5_DEVICE.lock() {
        *guard = Some(device);
        log::info!(target: "mlx5::bridge", "mlx5 device registered with bridge");
    }
}

/// mlx5 デバイスをブリッジから取り出す（所有権移動）
pub fn take_mlx5_device() -> Option<Mlx5Device> {
    MLX5_DEVICE.lock().ok().and_then(|mut guard| guard.take())
}

/// デバイスロックを取得してクロージャを実行
fn with_mlx5_device<R>(f: impl FnOnce(&mut Mlx5Device) -> R) -> Option<R> {
    MLX5_DEVICE
        .lock()
        .ok()
        .and_then(|mut guard| guard.as_mut().map(|dev| f(dev)))
}

fn mlx5_mac_address() -> crate::net::l2::ethernet::MacAddress {
    let mut mac = with_mlx5_device(|dev| {
        dev.port(0).map(|port| {
            let mac = port.mac_address();
            crate::net::l2::ethernet::MacAddress::from_octets(
                mac.0[0], mac.0[1], mac.0[2], mac.0[3], mac.0[4], mac.0[5],
            )
        })
    })
    .flatten()
    .unwrap_or_else(|| {
        crate::net::l2::ethernet::MacAddress::from_octets(0x02, 0x00, 0x5E, 0x00, 0x53, 0x01)
    });

    if mac.as_bytes() == &[0, 0, 0, 0, 0, 0] {
        mac = crate::net::l2::ethernet::MacAddress::from_octets(0x02, 0x00, 0x5E, 0x00, 0x53, 0x01);
    }
    mac
}

fn enqueue_mlx5_tx(data: &[u8]) -> bool {
    let Ok(mut queue) = MLX5_TX_QUEUE.lock() else {
        return false;
    };
    queue.push_back(Mlx5TransmitRequest {
        data: data.to_vec(),
        vlan_tag: None,
    });
    MLX5_TX_QUEUE_HAS_EVENTS.store(true, Ordering::Release);

    if let Ok(mut waker) = MLX5_TX_QUEUE_WAKER.lock() {
        if let Some(waker) = waker.take() {
            waker.wake();
        }
    }

    true
}

fn recv_mlx5_tx() -> Option<Mlx5TransmitRequest> {
    let Ok(mut queue) = MLX5_TX_QUEUE.lock() else {
        return None;
    };
    let request = queue.pop_front();
    if queue.is_empty() {
        MLX5_TX_QUEUE_HAS_EVENTS.store(false, Ordering::Release);
    }
    request
}

struct Mlx5TxEventWaitFuture;

impl Future for Mlx5TxEventWaitFuture {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if MLX5_TX_QUEUE_HAS_EVENTS.load(Ordering::Acquire) {
            return Poll::Ready(());
        }

        if let Ok(mut waker) = MLX5_TX_QUEUE_WAKER.lock() {
            *waker = Some(cx.waker().clone());
        }

        if MLX5_TX_QUEUE_HAS_EVENTS.load(Ordering::Acquire) {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

impl crate::net::runtime::bridge::shared::NetBridgePort for Mlx5Runtime {
    fn port_name(&self) -> &'static str {
        "mlx5"
    }

    fn mac_address(&self) -> crate::net::l2::ethernet::MacAddress {
        mlx5_mac_address()
    }

    fn start(
        &self,
        dispatch: crate::net::runtime::bridge::shared::RxDispatchHandle,
    ) -> Result<(), &'static str> {
        if let Ok(mut guard) = MLX5_IF_ID.lock() {
            *guard = Some(dispatch.if_id());
        }

        if MLX5_BRIDGE_INITIALIZED.swap(true, Ordering::AcqRel) {
            return Ok(());
        }

        let num_rqs = with_mlx5_device(|dev| dev.num_rqs()).unwrap_or(1);
        if let Ok(mut bufs) = MLX5_RX_BUFS.lock() {
            if bufs.is_empty() {
                bufs.resize_with(num_rqs, || {
                    let mut v = Vec::with_capacity(mlx5_driver::defs::MLX5_WQ_DEPTH as usize);
                    v.resize_with(mlx5_driver::defs::MLX5_WQ_DEPTH as usize, || None);
                    v
                });
            }
        }

        let num_sqs = with_mlx5_device(|dev| dev.num_sqs()).unwrap_or(0);
        if let Ok(mut bufs) = MLX5_TX_BUFS.lock() {
            if bufs.is_empty() && num_sqs > 0 {
                bufs.resize_with(num_sqs, || {
                    let mut v = Vec::with_capacity((mlx5_driver::defs::MLX5_WQ_DEPTH * 4) as usize);
                    v.resize_with((mlx5_driver::defs::MLX5_WQ_DEPTH * 4) as usize, || None);
                    v
                });
            }
        }

        prefill_rx_buffers();

        if !MLX5_POLL_TASK_STARTED.swap(true, Ordering::AcqRel) {
            crate::task::Executor::spawn_global(crate::task::Task::new(mlx5_poll_task()));
        }
        if !MLX5_TX_TASK_STARTED.swap(true, Ordering::AcqRel) {
            crate::task::Executor::spawn_global(crate::task::Task::new(mlx5_tx_worker_task()));
        }

        Ok(())
    }

    fn enqueue_tx(&self, data: &[u8]) -> bool {
        enqueue_mlx5_tx(data)
    }

    fn stats(&self) -> crate::net::runtime::bridge::shared::BridgePortStats {
        let stats = get_mlx5_bridge_stats();
        crate::net::runtime::bridge::shared::BridgePortStats {
            tx_packets: stats.tx_packets,
            rx_packets: stats.rx_packets,
            tx_errors: stats.tx_errors,
            rx_errors: stats.rx_errors,
            initialized: stats.initialized,
        }
    }

    fn health(&self) -> bool {
        mlx5_health_check()
    }

    fn stop(&self) {
        cleanup_mlx5_bridge();
    }
}

pub fn activate_mlx5_vfs(num_vfs: u16) -> Result<(), mlx5_driver::Mlx5Error> {
    with_mlx5_device(|device| unsafe { device.activate_vfs(num_vfs) })
        .unwrap_or(Err(mlx5_driver::Mlx5Error::DeviceNotFound))
}

pub fn deactivate_mlx5_vfs(num_vfs: u16) -> Result<(), mlx5_driver::Mlx5Error> {
    with_mlx5_device(|device| unsafe { device.deactivate_vfs(num_vfs) })
        .unwrap_or(Err(mlx5_driver::Mlx5Error::DeviceNotFound))
}

// ============================================================================
// Transmit Path
// ============================================================================

fn submit_mlx5_tx(data: &[u8], vlan_tag: Option<u16>) -> bool {
    let mut tx_bufs_guard = match MLX5_TX_BUFS.lock() {
        Ok(guard) => guard,
        Err(_) => return false,
    };

    let result = with_mlx5_device(|device| {
        if !device.is_active() {
            return false;
        }

        // 送信バッファを mempool から割り当て（安全な DMA バッファの確保）
        let mut pkt = match crate::net::datapath::mempool::alloc_packet() {
            Some(p) => p,
            None => {
                log::trace!(target: "mlx5::bridge", "TX packet alloc failed");
                return false;
            }
        };

        // データをコピー
        let copy_len = core::cmp::min(data.len(), pkt.capacity());
        pkt.set_len(copy_len);
        pkt.data_mut()[..copy_len].copy_from_slice(&data[..copy_len]);

        let data_virt = pkt.as_ptr() as u64;
        let data_device = pkt.device_address(); // IOMMU-safe
        let data_len = pkt.len() as u32;

        // Ethernet ヘッダ（先頭14バイト）をインラインヘッダとして設定
        let inline_hdr_len = core::cmp::min(data_len as usize, 18);
        let inline_hdr = &pkt.data()[..inline_hdr_len];

        // CPU ID に基づいて SQ を選択（マルチコア分散）
        let cpu_id = crate::per_cpu::try_current_cpu_id().unwrap_or(0);
        let num_sqs = tx_bufs_guard.len();
        if num_sqs == 0 {
            log::trace!(target: "mlx5::bridge", "No active SQs available for TX");
            return false;
        }
        let sq_index = (cpu_id % num_sqs) as usize;

        // Safety: デバイスアドレスが正しく取得されていること
        let mut tx_options = mlx5_driver::wq::TxOptions::default();
        tx_options.vlan_tag = vlan_tag.unwrap_or(0);
        tx_options.l3_cs = true;
        tx_options.l4_cs = true;

        match unsafe {
            device.transmit(
                sq_index,
                data_device,
                data_virt,
                data_len,
                inline_hdr,
                tx_options,
            )
        } {
            Ok(wqe_idx) => {
                let bb_idx = (wqe_idx as u32 % mlx5_driver::defs::MLX5_WQ_DEPTH) as usize * 4;
                if let Some(queue_bufs) = tx_bufs_guard.get_mut(sq_index) {
                    queue_bufs[bb_idx] = Some(pkt);
                }

                MLX5_TX_PACKETS.fetch_add(1, Ordering::Relaxed);
                counters::global().record_tx(data.len());
                trace::push_event(NetLayer::Driver, NetEventKind::Tx, "mlx5 tx");
                true
            }
            Err(e) => {
                MLX5_TX_ERRORS.fetch_add(1, Ordering::Relaxed);
                counters::global().record_error();
                log::trace!(target: "mlx5::bridge", "TX failed: {:?}", e);
                false
            }
        }
    });

    result.unwrap_or(false)
}

/// mlx5 送信コールバック（互換ラッパ）
pub fn mlx5_transmit(if_id: Option<NetIfId>, data: &[u8]) -> bool {
    super::shared::transmit(if_id, data)
}

// ============================================================================
// Receive Path
// ============================================================================

/// mlx5 RX CQ をポーリングして受信パケットをスタックに配送する
///
/// # Safety
/// - CQ/RQ バッファが有効であること
pub unsafe fn mlx5_poll_rx() -> u32 {
    let mut rx_bufs_guard = match MLX5_RX_BUFS.lock() {
        Ok(guard) => guard,
        Err(_) => return 0,
    };

    let mut tx_bufs_guard = match MLX5_TX_BUFS.lock() {
        Ok(guard) => guard,
        Err(_) => return 0,
    };

    let result = with_mlx5_device(|device| {
        let mut total_processed = 0;

        // すべての RX CQ をポーリング
        for rq_index in 0..rx_bufs_guard.len() {
            let Some(rx_cq_index) = device.rx_cq_index_for_rq(rq_index) else {
                continue;
            };

            let cqes = device.poll_cq(rx_cq_index, MLX5_RX_POLL_BATCH);
            total_processed += cqes.len() as u32;

            for cqe in &cqes {
                let wqe_counter = cqe.wqe_counter;
                let byte_count = cqe.byte_count as usize;

                if let Some(rx_info) =
                    device.process_rx_completion(rq_index, wqe_counter, cqe.l3_ok, cqe.l4_ok)
                {
                    MLX5_RX_PACKETS.fetch_add(1, Ordering::Relaxed);
                    counters::global().record_rx(byte_count);
                    trace::push_event(NetLayer::Driver, NetEventKind::Rx, "mlx5 rx");

                    let idx = (wqe_counter as u32 % mlx5_driver::defs::MLX5_WQ_DEPTH) as usize;
                    if let Some(mut pkt) = rx_bufs_guard[rq_index][idx].take() {
                        pkt.set_len(byte_count);
                        let meta = pkt.meta_mut();
                        if cqe.l3_ok {
                            meta.set_ip_csum_verified();
                        }
                        if cqe.l4_ok {
                            meta.set_l4_csum_verified();
                        }
                        meta.vlan_tag = cqe.vlan_tag;
                        meta.timestamp = cqe.timestamp;

                        let if_id = MLX5_IF_ID.lock().ok().and_then(|guard| *guard);
                        if let Some(if_id) = if_id {
                            super::shared::RxDispatchHandle::new(if_id)
                                .dispatch_zero_copy(pkt, 0, byte_count);
                        } else {
                            super::process_received_packet_zero_copy(pkt, 0, byte_count);
                        }

                        // Replenish
                        if let Some(new_pkt) = crate::net::datapath::mempool::alloc_packet() {
                            let new_virt = new_pkt.as_ptr() as u64;
                            let new_device = new_pkt.device_address();
                            let buf_size = new_pkt.capacity() as u32;

                            rx_bufs_guard[rq_index][idx] = Some(new_pkt);
                            let _ = device.post_receive(rq_index, new_device, new_virt, buf_size);
                        } else {
                            MLX5_RX_ERRORS.fetch_add(1, Ordering::Relaxed);
                        }
                    } else {
                        // Fallback
                        let _ = device.post_receive(
                            rq_index,
                            rx_info.device_addr,
                            rx_info.virt_addr,
                            rx_info.size,
                        );
                    }
                }
            }
        }

        // すべての TX CQ をポーリング
        for sq_index in 0..tx_bufs_guard.len() {
            let Some(tx_cq_index) = device.tx_cq_index_for_sq(sq_index) else {
                continue;
            };

            let tx_cqes = device.poll_cq(tx_cq_index, MLX5_RX_POLL_BATCH);
            for cqe in &tx_cqes {
                let infos = device.process_tx_completions(sq_index, cqe.wqe_counter);
                for _info in infos {
                    let idx = (cqe.wqe_counter as u32 % mlx5_driver::defs::MLX5_WQ_DEPTH) as usize;
                    // Note: In MPWQE, we'd need a more complex mapping if we wanted to
                    // precisely take the right buf from the bridge's tracking.
                    // For now, we clear the tracking based on the buf_idx.
                    if let Some(queue_bufs) = tx_bufs_guard.get_mut(sq_index) {
                        // For simple post_send, idx is correct. For MPWQE,
                        // multiple slots (WQEBBs) were used. complete_tx already
                        // cleared the hardware-side tracking.
                        // We need to clear bridge-side tracking for all 4 slots.
                        for i in 0..4 {
                            let bb_idx = idx * 4 + i;
                            if bb_idx < queue_bufs.len() {
                                let _ = queue_bufs[bb_idx].take();
                            }
                        }
                    }
                }
            }
        }

        total_processed
    });

    result.unwrap_or(0)
}

/// mlx5 ポーリングタスク（async ワーカー）
///
/// エグゼキュータに登録され、定期的に CQ をポーリングする。
/// 適応的ポーリングにより、高負荷時はビジーポーリング、
/// 低負荷時は割り込み駆動（yield）に切り替える。
pub async fn mlx5_poll_task() {
    log::info!(target: "mlx5::bridge", "mlx5 poll task started");

    let mut msix_vector = None;

    loop {
        if !MLX5_BRIDGE_INITIALIZED.load(Ordering::Acquire) {
            crate::task::yield_now().await;
            continue;
        }

        // MSI-Xベクタを遅延取得
        if msix_vector.is_none() {
            msix_vector = with_mlx5_device(|dev| dev.eqn_msix_vector(0)).flatten();
        }

        // Safety: デバイスが初期化済みであること
        let processed = unsafe { mlx5_poll_rx() };

        // 適応的ポーリング: 処理があった場合は即座に再ポーリング、
        // 無い場合は割り込み待ち
        if processed == 0 {
            if let Some(vec) = msix_vector {
                // 割り込み待ち (Interrupt-Waker Bridge)
                wait_for_interrupt(InterruptSource::Irq(vec as u8)).await;
                MLX5_WAKE_COUNTS.fetch_add(1, Ordering::Relaxed);
            } else {
                // MSI-X未設定時は従来通り yield
                crate::task::yield_now().await;
            }
        }
        // processed > 0 → 即座に次のポーリングサイクルへ（ビジーポーリング）
    }
}

async fn mlx5_tx_worker_task() {
    loop {
        if !MLX5_BRIDGE_INITIALIZED.load(Ordering::Acquire) {
            crate::task::yield_now().await;
            continue;
        }

        let mut request = recv_mlx5_tx();
        if request.is_none() {
            Mlx5TxEventWaitFuture.await;
            request = recv_mlx5_tx();
        }

        while let Some(current) = request {
            let _ = submit_mlx5_tx(&current.data, current.vlan_tag);
            request = recv_mlx5_tx();
        }
    }
}

// ============================================================================
// Initialization
// ============================================================================

/// mlx5 ブリッジを初期化する
///
/// `mlx5_registry.rs` の probe 成功後に呼び出される。
/// デバイスをネットワークスタックに接続し、ポーリングタスクを起動する。
pub fn init_mlx5_bridge() -> Result<(), &'static str> {
    // デバイスが登録されているか確認
    let has_device = with_mlx5_device(|dev| dev.is_active()).unwrap_or(false);
    if !has_device {
        log::warn!(target: "mlx5::bridge", "mlx5 device not registered or not active");
        return Err("mlx5 device not available");
    }

    let _ = with_mlx5_device(|dev| unsafe { dev.refresh_port_runtime_state(0) });
    let mac = mlx5_mac_address();

    log::info!(
        target: "mlx5::bridge",
        "Initializing mlx5 bridge (MAC={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x})",
        mac.as_bytes()[0], mac.as_bytes()[1], mac.as_bytes()[2],
        mac.as_bytes()[3], mac.as_bytes()[4], mac.as_bytes()[5],
    );

    use crate::net::l3::ipv4::Ipv4Config;
    use crate::net::runtime::stack::NetworkConfig;

    let config = NetworkConfig {
        mac,
        ipv4: Ipv4Config::default(),
        ipv6: Some(crate::net::l3::ipv6::Ipv6Config::from_mac(mac.as_bytes())),
        icmp_echo_enabled: true,
    };

    super::shared::ensure_stack_initialized(config)?;
    crate::net::runtime::manager::init_network_manager();
    let if_id = if let Some(if_id) = mlx5_if_id() {
        if_id
    } else {
        crate::net::runtime::manager::register_interface("mlx5")
            .map_err(|_| "failed to register mlx5 interface")?
    };
    let _ = crate::net::runtime::manager::set_interface_config(if_id, config);
    super::ensure_bridge_if_state(if_id, None);
    super::shared::install_port(
        if_id,
        Arc::new(Mlx5Runtime),
        super::primary_bridge_if().is_none(),
    )?;
    log::info!(target: "mlx5::bridge", "mlx5 bridge initialized (if={})", if_id.0);

    Ok(())
}

/// RX バッファをプリフィルする
///
/// すべての受信キューにバッファを事前投入して受信準備を整える。
fn prefill_rx_buffers() {
    let mut bufs_guard = match MLX5_RX_BUFS.lock() {
        Ok(guard) => guard,
        Err(_) => return,
    };

    with_mlx5_device(|device| {
        let num_rqs = bufs_guard.len();
        let mut total_filled = 0u32;

        for rq_idx in 0..num_rqs {
            let mut filled = 0u32;
            for i in 0..mlx5_driver::defs::MLX5_WQ_DEPTH {
                if let Some(pkt) = crate::net::datapath::mempool::alloc_packet() {
                    let buf_virt = pkt.as_ptr() as u64;
                    let buf_device = pkt.device_address();
                    let buf_size = pkt.capacity() as u32;

                    bufs_guard[rq_idx][i as usize] = Some(pkt);

                    // Safety: バッファは有効
                    match unsafe { device.post_receive(rq_idx, buf_device, buf_virt, buf_size) } {
                        Ok(_) => filled += 1,
                        Err(_) => {
                            bufs_guard[rq_idx][i as usize] = None;
                            break;
                        }
                    }
                } else {
                    break;
                }
            }
            total_filled += filled;
        }

        log::info!(
            target: "mlx5::bridge",
            "Prefilled {} RX buffers across {} queues",
            total_filled,
            num_rqs
        );
    });
}

// ============================================================================
// Statistics
// ============================================================================

/// mlx5 ブリッジ統計情報
#[derive(Debug, Clone, Copy)]
pub struct Mlx5BridgeStats {
    /// 送信パケット数
    pub tx_packets: u64,
    /// 受信パケット数
    pub rx_packets: u64,
    /// 送信エラー数
    pub tx_errors: u64,
    /// 受信エラー数
    pub rx_errors: u64,
    /// 初期化済みフラグ
    pub initialized: bool,
}

/// mlx5 ブリッジ統計情報を取得
pub fn get_mlx5_bridge_stats() -> Mlx5BridgeStats {
    Mlx5BridgeStats {
        tx_packets: MLX5_TX_PACKETS.load(Ordering::Relaxed),
        rx_packets: MLX5_RX_PACKETS.load(Ordering::Relaxed),
        tx_errors: MLX5_TX_ERRORS.load(Ordering::Relaxed),
        rx_errors: MLX5_RX_ERRORS.load(Ordering::Relaxed),
        initialized: MLX5_BRIDGE_INITIALIZED.load(Ordering::Acquire),
    }
}

/// mlx5 ブリッジが初期化済みか確認
pub fn is_mlx5_bridge_initialized() -> bool {
    MLX5_BRIDGE_INITIALIZED.load(Ordering::Acquire)
}

pub fn mlx5_if_id() -> Option<NetIfId> {
    MLX5_IF_ID.lock().ok().and_then(|guard| *guard)
}

/// ポート統計を取得する
pub fn get_mlx5_port_stats(port_index: usize) -> Option<mlx5_driver::port::PortStats> {
    with_mlx5_device(|device| {
        // ハードウェアカウンタを同期（Safe Rust の wrapper 経由で unsafe 呼び出し）
        unsafe {
            let _ = device.update_port_stats(port_index);
        }
        device.port(port_index).map(|port| port.stats().clone())
    })
    .flatten()
}

/// mlx5 ブリッジを停止し、リソースを解放する
pub fn cleanup_mlx5_bridge() {
    MLX5_BRIDGE_INITIALIZED.store(false, Ordering::Release);
    MLX5_TX_QUEUE_HAS_EVENTS.store(false, Ordering::Release);

    // RX バッファの解放
    if let Ok(mut bufs) = MLX5_RX_BUFS.lock() {
        for queue_bufs in bufs.iter_mut() {
            for buf in queue_bufs.iter_mut() {
                let _ = buf.take(); // PacketRef がドロップされる
            }
            queue_bufs.clear();
        }
        bufs.clear();
    }

    // TX バッファの解放
    if let Ok(mut bufs) = MLX5_TX_BUFS.lock() {
        for queue_bufs in bufs.iter_mut() {
            for buf in queue_bufs.iter_mut() {
                let _ = buf.take();
            }
            queue_bufs.clear();
        }
        bufs.clear();
    }

    if let Ok(mut queue) = MLX5_TX_QUEUE.lock() {
        queue.clear();
    }
    if let Ok(mut waker) = MLX5_TX_QUEUE_WAKER.lock() {
        let _ = waker.take();
    }

    if let Ok(mut if_id) = MLX5_IF_ID.lock() {
        *if_id = None;
    }

    log::info!(target: "mlx5::bridge", "mlx5 bridge cleaned up");
}

// ============================================================================
// Health Check
// ============================================================================

/// mlx5 デバイスの健全性チェック
///
/// # Returns
/// - `true`: デバイスは健全
/// - `false`: FW エラーが検出された
pub fn mlx5_health_check() -> bool {
    with_mlx5_device(|device| {
        // Safety: bar0_base が有効であること
        unsafe { device.health_check() }
    })
    .unwrap_or(false)
}
