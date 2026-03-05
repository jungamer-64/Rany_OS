// ============================================================================
// src/net/runtime/bridge/mlx5_bridge.rs - ConnectX-4 Lx <-> NetworkStack Bridge
// ============================================================================
//!
//! ConnectX-4 Lx (mlx5) ドライバとNetworkStackを接続するブリッジモジュール。
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

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::sync::PoisonLock;
use crate::net::runtime::manager::NetIfId;
use crate::net::obs::{
    counters,
    trace::{self, NetEventKind, NetLayer},
};

use mlx5_driver::Mlx5Device;

// ============================================================================
// Bridge State
// ============================================================================

/// mlx5 ブリッジ初期化状態
static MLX5_BRIDGE_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// mlx5 デバイスインスタンス（PoisonLock で保護）
static MLX5_DEVICE: PoisonLock<Option<Mlx5Device>> = PoisonLock::new(None);

/// mlx5 ブリッジの論理インターフェースID
static MLX5_IF_ID: PoisonLock<Option<NetIfId>> = PoisonLock::new(None);

/// 送信パケットカウンタ
static MLX5_TX_PACKETS: AtomicU64 = AtomicU64::new(0);

/// 受信パケットカウンタ
static MLX5_RX_PACKETS: AtomicU64 = AtomicU64::new(0);

/// 送信エラーカウンタ
static MLX5_TX_ERRORS: AtomicU64 = AtomicU64::new(0);

/// 受信エラーカウンタ
static MLX5_RX_ERRORS: AtomicU64 = AtomicU64::new(0);

/// RX CQ ポーリングバッチサイズ
const MLX5_RX_POLL_BATCH: u32 = 64;

/// TX CQ インデックス
const MLX5_TX_CQ_INDEX: usize = 0;

/// RX CQ インデックス
const MLX5_RX_CQ_INDEX: usize = 1;

/// SQ インデックス
const MLX5_SQ_INDEX: usize = 0;

/// RQ インデックス
const MLX5_RQ_INDEX: usize = 0;

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

// ============================================================================
// Transmit Path
// ============================================================================

/// mlx5 送信コールバック（NetworkStack の transmit_fn として登録）
///
/// スタックからの送信要求を mlx5 SQ に投入する。
/// Ethernet フレーム全体（14バイトヘッダ含む）を受け取る。
///
/// ## 制限事項
///
/// 現状、SAS identity mapping を前提とした疑似 DMA を使用。
/// 将来的には Exchange Heap 経由の正式な DMA バッファに移行する。
pub fn mlx5_transmit(if_id: Option<NetIfId>, data: &[u8]) -> bool {
    if !MLX5_BRIDGE_INITIALIZED.load(Ordering::Acquire) {
        return false;
    }

    let result = with_mlx5_device(|device| {
        if !device.is_active() {
            return false;
        }

        // Ethernet ヘッダ（先頭14バイト）をインラインヘッダとして設定
        let inline_hdr_len = core::cmp::min(data.len(), 18); // ETH header + optional bytes
        let inline_hdr = &data[..inline_hdr_len];

        // 残りのデータは DMA バッファとして設定
        // SAS identity mapping: virt == phys
        let data_phys = data.as_ptr() as u64;
        let data_virt = data_phys;
        let data_len = data.len() as u32;

        // Safety: SAS identity mapping 前提でアドレスは有効
        match unsafe { device.transmit(MLX5_SQ_INDEX, data_phys, data_virt, data_len, inline_hdr) } {
            Ok(_wqe_idx) => {
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

// ============================================================================
// Receive Path
// ============================================================================

/// mlx5 RX CQ をポーリングして受信パケットをスタックに配送する
///
/// # Safety
/// - CQ/RQ バッファが有効であること
pub unsafe fn mlx5_poll_rx() -> u32 {
    let result = with_mlx5_device(|device| {
        let cqes = device.poll_cq(MLX5_RX_CQ_INDEX, MLX5_RX_POLL_BATCH);
        let processed = cqes.len() as u32;

        for cqe in &cqes {
            // CQE から受信情報を取得
            let wqe_counter = cqe.wqe_counter;
            let byte_count = cqe.byte_count as usize;

            // RQ から受信バッファ情報を取得
            if let Some(rx_info) = device.process_rx_completion(MLX5_RQ_INDEX, wqe_counter) {
                MLX5_RX_PACKETS.fetch_add(1, Ordering::Relaxed);
                counters::global().record_rx(byte_count);
                trace::push_event(NetLayer::Driver, NetEventKind::Rx, "mlx5 rx");

                // ゼロコピーパス: mempool の PacketRef を構築してスタックに配送
                // mlx5 は VirtIO ヘッダが無いので header_size = 0
                let virt_addr = rx_info.virt_addr as *const u8;
                let rx_slice = core::slice::from_raw_parts(virt_addr, byte_count);

                // mempool 経由で PacketRef を割り当て、データをコピー
                if let Some(mut pkt) = crate::net::datapath::mempool::alloc_packet() {
                    let copy_len = core::cmp::min(byte_count, pkt.capacity());
                    pkt.data_mut()[..copy_len].copy_from_slice(&rx_slice[..copy_len]);
                    pkt.set_len(copy_len);

                    // mlx5 はハードウェアチェックサム検証をサポート
                    if cqe.checksum_ok {
                        let meta = pkt.meta_mut();
                        meta.set_ip_csum_verified();
                        meta.set_l4_csum_verified();
                    }

                    // header_size = 0 (mlx5 は VirtIO ヘッダ無し)
                    super::process_received_packet_zero_copy(pkt, 0, copy_len);
                } else {
                    MLX5_RX_ERRORS.fetch_add(1, Ordering::Relaxed);
                    log::trace!(target: "mlx5::bridge", "RX packet alloc failed");
                }

                // RQ にバッファを再投入
                let _ = device.post_receive(
                    MLX5_RQ_INDEX,
                    rx_info.phys_addr,
                    rx_info.virt_addr,
                    rx_info.size,
                );
            }
        }

        // TX CQ の完了も処理（送信バッファの解放）
        let tx_cqes = device.poll_cq(MLX5_TX_CQ_INDEX, MLX5_RX_POLL_BATCH);
        for cqe in &tx_cqes {
            let _ = device.process_tx_completions(MLX5_SQ_INDEX, cqe.wqe_counter);
        }

        processed
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

    loop {
        if !MLX5_BRIDGE_INITIALIZED.load(Ordering::Acquire) {
            // 未初期化時は yield して次のポーリングサイクルを待つ
            core::future::pending::<()>().await;
            continue;
        }

        // Safety: デバイスが初期化済みであること
        let processed = unsafe { mlx5_poll_rx() };

        // 適応的ポーリング: 処理があった場合は即座に再ポーリング、
        // 無い場合は yield してCPUを解放
        if processed == 0 {
            // 空ポーリング → 他のタスクに CPU を譲渡
            crate::task::yield_now().await;
        }
        // processed > 0 → 即座に次のポーリングサイクルへ（ビジーポーリング）
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
    if MLX5_BRIDGE_INITIALIZED.load(Ordering::Acquire) {
        return Ok(());
    }

    // デバイスが登録されているか確認
    let has_device = with_mlx5_device(|dev| dev.is_active()).unwrap_or(false);
    if !has_device {
        log::warn!(target: "mlx5::bridge", "mlx5 device not registered or not active");
        return Err("mlx5 device not available");
    }

    // MAC アドレスを取得
    let mac = with_mlx5_device(|dev| {
        dev.port(0).map(|port| {
            let mac = port.mac_address();
            crate::net::l2::ethernet::MacAddress::from_octets(
                mac.0[0],
                mac.0[1],
                mac.0[2],
                mac.0[3],
                mac.0[4],
                mac.0[5],
            )
        })
    })
    .flatten()
    .unwrap_or_else(|| {
        // フォールバック MAC
        crate::net::l2::ethernet::MacAddress::from_octets(0x02, 0x00, 0x5E, 0x00, 0x53, 0x01)
    });

    log::info!(
        target: "mlx5::bridge",
        "Initializing mlx5 bridge (MAC={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x})",
        mac.as_bytes()[0], mac.as_bytes()[1], mac.as_bytes()[2],
        mac.as_bytes()[3], mac.as_bytes()[4], mac.as_bytes()[5],
    );

    // 注: ブリッジの VirtIO 側が既にスタックを初期化している場合は
    // 送信コールバックのみを切り替える。
    // そうでない場合（mlx5 のみの環境）は新規にスタックを初期化する。
    if !super::is_initialized() {
        // mempool 初期化
        if let Err(e) = crate::net::datapath::mempool::init_net_mempool(1024) {
            log::warn!(target: "mlx5::bridge", "mempool init failed: {}", e);
        }

        use crate::net::runtime::stack::{self, NetworkConfig};
        use crate::net::l3::ipv4::Ipv4Config;

        let config = NetworkConfig {
            mac,
            ipv4: Ipv4Config::default(),
            ipv6: Some(crate::net::l3::ipv6::Ipv6Config::from_mac(mac.as_bytes())),
            icmp_echo_enabled: true,
        };

        stack::init(config);

        // 送信コールバック登録
        if let Ok(mut guard) = stack::stack().lock() {
            if let Some(ref mut stack) = *guard {
                stack.set_transmit_fn(mlx5_transmit);
            }
        }

        // DHCP ランタイム初期化
        if let Err(e) = crate::net::api::dhcp::init_dhcp_runtime() {
            log::warn!(target: "mlx5::bridge", "DHCP runtime init failed: {}", e);
        }
    }

    // ポーリングタスクをスポーン
    crate::task::Executor::spawn_global(
        crate::task::Task::new(mlx5_poll_task()),
    );
    log::info!(target: "mlx5::bridge", "mlx5 poll task spawned");

    // RX バッファのプリフィル
    prefill_rx_buffers();

    MLX5_BRIDGE_INITIALIZED.store(true, Ordering::Release);
    log::info!(target: "mlx5::bridge", "mlx5 bridge initialized");

    Ok(())
}

/// RX バッファをプリフィルする
///
/// 受信キューにバッファを事前投入して受信準備を整える。
fn prefill_rx_buffers() {
    const RX_PREFILL_COUNT: u32 = 64;
    const RX_BUF_SIZE: u32 = 2048;

    with_mlx5_device(|device| {
        let mut filled = 0u32;
        for _ in 0..RX_PREFILL_COUNT {
            if let Some(pkt) = crate::net::datapath::mempool::alloc_packet() {
                let buf_virt = pkt.data().as_ptr() as u64;
                let buf_phys = buf_virt; // SAS identity mapping
                let buf_size = RX_BUF_SIZE;

                // PacketRef をリークして所有権をデバイスに移動
                // (CQ 完了時に回収される)
                core::mem::forget(pkt);

                // Safety: SAS identity mapping, バッファは有効
                match unsafe { device.post_receive(MLX5_RQ_INDEX, buf_phys, buf_virt, buf_size) } {
                    Ok(_) => filled += 1,
                    Err(_) => break,
                }
            } else {
                break;
            }
        }

        log::info!(
            target: "mlx5::bridge",
            "Prefilled {} RX buffers",
            filled
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

/// ポート統計を取得する（ソフトウェアカウンタから）
pub fn get_mlx5_port_stats(port_index: usize) -> Option<mlx5_driver::port::PortStats> {
    with_mlx5_device(|device| {
        device.port(port_index).map(|port| port.stats().clone())
    })
    .flatten()
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
