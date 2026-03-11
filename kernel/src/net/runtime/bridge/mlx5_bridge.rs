// ============================================================================
// src/net/runtime/bridge/mlx5_bridge.rs - ConnectX Family <-> NetworkStack Bridge
// ============================================================================
//!
//! ConnectX ファミリ (mlx5) ドライバと NetworkStack を接続する stack glue モジュール。
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
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use core::fmt::Write as _;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::net::obs::{
    counters,
    trace::{self, NetEventKind, NetLayer},
};
use crate::net::runtime::device::{self, NetDeviceKey};
use crate::net::runtime::manager::NetIfId;
use crate::sync::PoisonLock;
use crate::task::interrupt_waker::{InterruptSource, wait_for_interrupt};
use crate::task::{TimeoutResult, with_timeout};

use kernel_api::resource::net::PacketRef;
use kernel_api::service::netdev::{
    MacAddress, NETDEV_FLAG_HEALTHY, NETDEV_FLAG_LINK_UP, NetDeviceInfo, NetDevicePort,
    NetDriverEvent, NetPortKind, NetPortRuntime, NetPortStats, NetTxMeta,
};
use mlx5_driver::Mlx5Device;

// ============================================================================
// Bridge State
// ============================================================================

/// mlx5 port runtime 初期化状態
static MLX5_PORT_RUNTIME_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// mlx5 デバイスインスタンス（PoisonLock で保護）
static MLX5_DEVICE: PoisonLock<Option<Mlx5Device>> = PoisonLock::new(None);

/// mlx5 port runtime の論理インターフェースID
static MLX5_IF_ID: PoisonLock<Option<NetIfId>> = PoisonLock::new(None);
static MLX5_PORT_RUNTIME: PoisonLock<Option<Arc<dyn NetPortRuntime>>> = PoisonLock::new(None);

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
/// 割り込み待ちタイムアウト回数（RX 診断用）
static MLX5_WAKE_TIMEOUTS: AtomicU64 = AtomicU64::new(0);

/// DMAマッピングエラー
static MLX5_DMA_ERRORS: AtomicU64 = AtomicU64::new(0);

/// RX 連続アイドルポーリング回数
static MLX5_RX_IDLE_POLLS: AtomicU64 = AtomicU64::new(0);

/// RX CQE の詳細ログ出力予算（起動直後の切り分け用）
static MLX5_RX_CQE_LOG_BUDGET: AtomicU64 = AtomicU64::new(32);
/// TX CQE の詳細ログ出力予算（送信経路切り分け用）
static MLX5_TX_CQE_LOG_BUDGET: AtomicU64 = AtomicU64::new(32);
/// 短い Ethernet frame を TX 前にパディングした回数のログ予算
static MLX5_TX_PAD_LOG_BUDGET: AtomicU64 = AtomicU64::new(16);
/// 固定 60B の診断 TX frame を流す回数
static MLX5_TX_DIAG_FRAME_BUDGET: AtomicU64 = AtomicU64::new(1);
/// runtime 初期化直後に固定 60B の診断 TX frame を流す回数
static MLX5_STARTUP_TX_DIAG_FRAME_BUDGET: AtomicU64 = AtomicU64::new(1);
/// RX アイドル時スナップショット出力回数の上限
static MLX5_RX_DEBUG_SNAPSHOT_BUDGET: AtomicU64 = AtomicU64::new(16);
/// 受信フレーム先頭のプレビュー出力回数
static MLX5_RX_FRAME_LOG_BUDGET: AtomicU64 = AtomicU64::new(8);

/// RX CQ ポーリングバッチサイズ
const MLX5_RX_POLL_BATCH: u32 = 64;
/// RX が進まないときの診断ダンプ間隔（idle poll 回数）
const MLX5_RX_DEBUG_IDLE_INTERVAL: u64 = 512;
/// RX 問題切り分けのため、割り込み待ちを使わず常時ポーリングする
const MLX5_FORCE_POLL_ONLY: bool = false;
/// 割り込み待ちから再ポーリングに戻すタイムアウト（ms）
const MLX5_INTERRUPT_WAIT_TIMEOUT_MS: u64 = 5;

#[derive(Debug, Clone, Copy)]
struct Mlx5NetDriverAdapter;

pub fn mlx5_net_driver_adapter() -> Arc<dyn NetDevicePort> {
    Arc::new(Mlx5NetDriverAdapter)
}

static MLX5_POLL_TASK_STARTED: AtomicBool = AtomicBool::new(false);

fn initialize_mlx5_runtime() -> Result<(), &'static str> {
    crate::io::log::early_print("[MLX5_BRIDGE] initialize runtime enter\n");
    if MLX5_PORT_RUNTIME_INITIALIZED.swap(true, Ordering::AcqRel) {
        crate::io::log::early_print("[MLX5_BRIDGE] initialize runtime already initialized\n");
        return Ok(());
    }

    if let Some(device_id) = with_mlx5_device(|dev| dev.dma_device_id()) {
        crate::net::datapath::mempool::set_packet_dma_device(Some(device_id));
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

    MLX5_RX_IDLE_POLLS.store(0, Ordering::Release);
    MLX5_RX_CQE_LOG_BUDGET.store(32, Ordering::Release);
    MLX5_TX_CQE_LOG_BUDGET.store(32, Ordering::Release);
    MLX5_TX_PAD_LOG_BUDGET.store(16, Ordering::Release);
    MLX5_TX_DIAG_FRAME_BUDGET.store(1, Ordering::Release);
    MLX5_STARTUP_TX_DIAG_FRAME_BUDGET.store(1, Ordering::Release);
    MLX5_RX_FRAME_LOG_BUDGET.store(8, Ordering::Release);
    MLX5_RX_DEBUG_SNAPSHOT_BUDGET.store(16, Ordering::Release);
    MLX5_WAKE_COUNTS.store(0, Ordering::Release);
    MLX5_WAKE_TIMEOUTS.store(0, Ordering::Release);
    crate::io::log::early_print("[MLX5_BRIDGE] prefill rx enter\n");
    prefill_rx_buffers();
    crate::io::log::early_print("[MLX5_BRIDGE] prefill rx done\n");
    crate::io::log::early_print("[MLX5_BRIDGE] startup diag enter\n");
    submit_startup_mlx5_diag_frame();
    crate::io::log::early_print("[MLX5_BRIDGE] startup diag done\n");

    if !MLX5_POLL_TASK_STARTED.swap(true, Ordering::AcqRel) {
        crate::io::log::early_print("[MLX5_BRIDGE] spawn poll task\n");
        crate::task::Executor::spawn_global(crate::task::Task::new(mlx5_poll_task()));
    }

    crate::io::log::early_print("[MLX5_BRIDGE] initialize runtime done\n");
    Ok(())
}

// ============================================================================
// Device Registration
// ============================================================================

/// mlx5 デバイスをブリッジに登録する
///
/// `mlx5_registry.rs` の `probe_device` から呼び出される。
pub fn register_mlx5_device(device: Mlx5Device) {
    if let Ok(mut guard) = MLX5_DEVICE.lock() {
        *guard = Some(device);
        log::info!(target: "mlx5::bridge", "mlx5 device registered with port runtime");
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

impl NetDevicePort for Mlx5NetDriverAdapter {
    fn info(&self) -> NetDeviceInfo {
        NetDeviceInfo {
            port_id: NetDeviceKey::Mlx5(0).port_id(),
            if_id: MLX5_IF_ID
                .lock()
                .ok()
                .and_then(|guard| guard.map(|if_id| if_id.0)),
            kind: NetPortKind::Mlx5,
            driver_name: "mlx5",
            queue_pairs: with_mlx5_device(|device| {
                core::cmp::max(device.num_rqs(), device.num_sqs())
            })
            .unwrap_or(1) as u16,
            mtu: crate::net::runtime::stack::MTU as u32,
            mac: MacAddress(*mlx5_mac_address().as_bytes()),
            flags: if mlx5_health_check() {
                NETDEV_FLAG_HEALTHY | NETDEV_FLAG_LINK_UP
            } else {
                0
            },
        }
    }

    fn start(&self, runtime: Arc<dyn NetPortRuntime>) -> Result<(), &'static str> {
        if let Ok(mut guard) = MLX5_PORT_RUNTIME.lock() {
            *guard = Some(runtime);
        }
        initialize_mlx5_runtime()
    }

    fn bind(&self, if_id: u16) -> Result<(), &'static str> {
        if let Ok(mut guard) = MLX5_IF_ID.lock() {
            *guard = Some(NetIfId(if_id));
            Ok(())
        } else {
            Err("mlx5 interface binding poisoned")
        }
    }

    fn submit_tx(&self, packet: PacketRef, meta: NetTxMeta) -> Result<(), &'static str> {
        if submit_mlx5_tx_packet(packet, meta.vlan_tag) {
            Ok(())
        } else {
            Err("mlx5 TX submission failed")
        }
    }

    fn poll(&self, _if_id: u16) -> Result<(), &'static str> {
        Ok(())
    }

    fn handle_event(&self, _if_id: u16, event: NetDriverEvent) -> Result<(), &'static str> {
        match event {
            NetDriverEvent::Interrupt | NetDriverEvent::Poll | NetDriverEvent::QueueWake { .. } => {
                Ok(())
            }
        }
    }

    fn stats(&self) -> NetPortStats {
        current_mlx5_port_stats()
    }

    fn stop(&self) {
        if let Ok(mut guard) = MLX5_PORT_RUNTIME.lock() {
            *guard = None;
        }
        reset_mlx5_port_runtime();
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

fn dispatch_mlx5_rx_packet(packet: PacketRef, payload_len: usize) {
    if let Ok(guard) = MLX5_PORT_RUNTIME.lock() {
        if let Some(runtime) = guard.as_ref() {
            let _ = runtime.submit_rx(
                packet,
                kernel_api::service::netdev::NetRxMeta {
                    queue_index: 0,
                    header_len: 0,
                    payload_len: payload_len as u16,
                    flags: 0,
                },
            );
            return;
        }
    }

    let if_id = MLX5_IF_ID.lock().ok().and_then(|guard| *guard);
    if let Some(if_id) = if_id {
        super::process_received_packet_zero_copy_for_interface(if_id, packet, 0, payload_len);
    } else {
        super::process_received_packet_zero_copy(packet, 0, payload_len);
    }
}

fn format_head_bytes(data: &[u8], max_len: usize) -> String {
    let mut out = String::new();
    for (idx, byte) in data.iter().take(max_len).enumerate() {
        if idx != 0 {
            let _ = out.write_str(" ");
        }
        let _ = write!(out, "{:02x}", byte);
    }
    out
}

fn read_be16_slice(data: &[u8], offset: usize) -> u16 {
    if offset + 2 > data.len() {
        return 0;
    }
    u16::from_be_bytes([data[offset], data[offset + 1]])
}

fn read_be32_slice(data: &[u8], offset: usize) -> u32 {
    if offset + 4 > data.len() {
        return 0;
    }
    u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

fn read_be64_slice(data: &[u8], offset: usize) -> u64 {
    if offset + 8 > data.len() {
        return 0;
    }
    u64::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ])
}

fn format_mlx5_tx_wqe_layout(wqe: &[u8], inline_hdr_len: u16) -> String {
    let opmod_idx = read_be32_slice(wqe, 0x00);
    let qpn_ds = read_be32_slice(wqe, 0x04);
    let fm_ce_se = wqe.get(0x0b).copied().unwrap_or(0);
    let general_id = read_be32_slice(wqe, 0x0c);
    let opcode = opmod_idx & 0xff;
    let idx = (opmod_idx >> 8) & 0xffff;
    let opmod = (opmod_idx >> 24) & 0xff;
    let qpn = (qpn_ds >> 8) & 0x00ff_ffff;
    let ds_count = qpn_ds & 0xff;

    let cs_flags = wqe.get(0x14).copied().unwrap_or(0);
    let swp_flags = wqe.get(0x15).copied().unwrap_or(0);
    let mss = read_be16_slice(wqe, 0x16);
    let flow_table_metadata = read_be32_slice(wqe, 0x18);
    let inline_size = read_be16_slice(wqe, 0x1c);
    let inline_ds = if inline_hdr_len > 2 {
        (usize::from(inline_hdr_len) - 2).div_ceil(16)
    } else {
        0
    };
    let data_seg_base = 0x20 + inline_ds * 16;
    let data_seg_count = ds_count.saturating_sub((2 + inline_ds) as u32);
    let inline_preview_len = usize::from(inline_hdr_len)
        .min(data_seg_base.saturating_sub(0x1e))
        .min(wqe.len().saturating_sub(0x1e));
    let inline_preview = if inline_preview_len == 0 {
        String::from("--")
    } else {
        format_head_bytes(&wqe[0x1e..0x1e + inline_preview_len], inline_preview_len)
    };

    let mut layout = format!(
        "ctrl{{opcode={:#04x} opmod={:#04x} idx={} qpn={:#x} ds={} fm_ce_se={:#04x} general_id={:#x}}} \
eth{{cs={:#04x} swp={:#04x} mss={} ft_meta={:#x} inline_hdr_sz={} inline_field={}}} \
inline[{}]",
        opcode,
        opmod,
        idx,
        qpn,
        ds_count,
        fm_ce_se,
        general_id,
        cs_flags,
        swp_flags,
        mss,
        flow_table_metadata,
        inline_hdr_len,
        inline_size,
        inline_preview
    );

    for seg_idx in 0..core::cmp::min(data_seg_count as usize, 2) {
        let off = data_seg_base + seg_idx * 16;
        let byte_count = read_be32_slice(wqe, off);
        let lkey = read_be32_slice(wqe, off + 4);
        let addr = read_be64_slice(wqe, off + 8);
        let _ = write!(
            layout,
            " data{}{{off={:#x} bc={} lkey={:#x} addr={:#x}}}",
            seg_idx, off, byte_count, lkey, addr
        );
    }

    layout
}

fn pad_mlx5_tx_packet_if_needed(mut pkt: PacketRef) -> Option<PacketRef> {
    const MIN_ETH_FRAME_LEN: usize = 60;

    if pkt.len() >= MIN_ETH_FRAME_LEN {
        return Some(pkt);
    }

    let original_len = pkt.len();
    if pkt.capacity() >= MIN_ETH_FRAME_LEN {
        pkt.set_len(MIN_ETH_FRAME_LEN);
        pkt.data_mut()[original_len..MIN_ETH_FRAME_LEN].fill(0);
        if MLX5_TX_PAD_LOG_BUDGET.fetch_sub(1, Ordering::Relaxed) > 0 {
            log::info!(
                target: "mlx5::bridge",
                "Padding short TX frame in-place from {} to {} bytes",
                original_len,
                MIN_ETH_FRAME_LEN
            );
        }
        return Some(pkt);
    }

    let meta = *pkt.meta();
    let mut padded = crate::net::datapath::mempool::alloc_packet_for_active_dma_device()?;
    if padded.capacity() < MIN_ETH_FRAME_LEN {
        return None;
    }

    padded.set_len(MIN_ETH_FRAME_LEN);
    padded.data_mut()[..original_len].copy_from_slice(pkt.data());
    padded.data_mut()[original_len..MIN_ETH_FRAME_LEN].fill(0);
    padded.set_meta(meta);
    if MLX5_TX_PAD_LOG_BUDGET.fetch_sub(1, Ordering::Relaxed) > 0 {
        log::info!(
            target: "mlx5::bridge",
            "Padding short TX frame via DMA bounce buffer from {} to {} bytes",
            original_len,
            MIN_ETH_FRAME_LEN
        );
    }
    Some(padded)
}

fn poll_mlx5_tx_cqs(
    device: &mut Mlx5Device,
    tx_bufs_guard: &mut [Vec<Option<PacketRef>>],
) -> usize {
    let mut total_processed = 0usize;

    for sq_index in 0..tx_bufs_guard.len() {
        let Some(tx_cq_index) = device.tx_cq_index_for_sq(sq_index) else {
            continue;
        };

        let tx_cqes = unsafe { device.poll_cq(tx_cq_index, MLX5_RX_POLL_BATCH) };
        total_processed += tx_cqes.len();

        for cqe in &tx_cqes {
            if MLX5_TX_CQE_LOG_BUDGET
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |v| v.checked_sub(1))
                .is_ok()
            {
                log::info!(
                    target: "mlx5::bridge",
                    "TX CQE: sq={} cq={} op={:?} wqe_counter={} byte_count={} raw_byte_count={} qpn={:#x} syndrome={:?} vendor={:?} src_wqe_op={:?}",
                    sq_index,
                    tx_cq_index,
                    cqe.opcode,
                    cqe.wqe_counter,
                    cqe.byte_count,
                    cqe.raw_byte_count,
                    cqe.qpn,
                    cqe.error_syndrome,
                    cqe.vendor_error_syndrome,
                    cqe.error_wqe_opcode
                );
            }
            if matches!(
                cqe.opcode,
                mlx5_driver::defs::CqeOpcode::ReqErr | mlx5_driver::defs::CqeOpcode::RespErr
            ) {
                if let Some(sq_state) = unsafe { device.debug_tx_queue_state(sq_index) } {
                    let wqe_info = unsafe {
                        device
                            .debug_tx_wqe_state(sq_index, cqe.wqe_counter)
                            .unwrap_or(mlx5_driver::wq::TxWqeDebugInfo {
                                valid: false,
                                wqe_counter: sq_state.last_wqe_counter,
                                wqe_addr: sq_state.last_wqe_addr,
                                inline_hdr_sz: sq_state.last_wqe_inline_hdr_sz,
                                opmod_idx: sq_state.last_wqe_opmod_idx,
                                qpn_ds: sq_state.last_wqe_qpn_ds,
                                general_id: sq_state.last_wqe_general_id,
                                byte_count: sq_state.last_wqe_byte_count,
                                lkey: sq_state.last_wqe_lkey,
                                device_addr: sq_state.last_wqe_device_addr,
                                wqe_bytes: sq_state.last_wqe_bytes,
                            })
                    };
                    let tracked_idx =
                        (cqe.wqe_counter as u32 % mlx5_driver::defs::MLX5_WQ_DEPTH) as usize * 4;
                    let wqe_layout =
                        format_mlx5_tx_wqe_layout(&wqe_info.wqe_bytes, wqe_info.inline_hdr_sz);
                    let pkt_head = tx_bufs_guard
                        .get(sq_index)
                        .and_then(|queue| queue.get(tracked_idx))
                        .and_then(|slot| slot.as_ref())
                        .map(|pkt| format_head_bytes(pkt.data(), 48))
                        .unwrap_or_else(|| String::from("--"));
                    log::warn!(
                        target: "mlx5::bridge",
                        "TX error context: sq={} sqn={:#x} tisn={:#x} wqe_counter={} dbg_counter={} dbg_exact={} inl={} opmod_idx={:#x} qpn_ds={:#x} general_id={:#x} bc={} lkey={:#x} data_addr={:#x} layout=\"{}\" wqe=[{}] pkt_head=[{}]",
                        sq_index,
                        sq_state.sqn,
                        sq_state.tisn,
                        cqe.wqe_counter,
                        wqe_info.wqe_counter,
                        wqe_info.valid,
                        wqe_info.inline_hdr_sz,
                        wqe_info.opmod_idx,
                        wqe_info.qpn_ds,
                        wqe_info.general_id,
                        wqe_info.byte_count,
                        wqe_info.lkey,
                        wqe_info.device_addr,
                        wqe_layout,
                        format_head_bytes(&wqe_info.wqe_bytes, 64),
                        pkt_head
                    );
                }
            }
            let infos = device.process_tx_completions(sq_index, cqe.wqe_counter);
            for _info in infos {
                let idx = (cqe.wqe_counter as u32 % mlx5_driver::defs::MLX5_WQ_DEPTH) as usize;
                if let Some(queue_bufs) = tx_bufs_guard.get_mut(sq_index) {
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
}

fn build_mlx5_diag_tx_frame(src: [u8; 6]) -> Option<PacketRef> {
    const DIAG_FRAME_LEN: usize = 60;

    let mut pkt = crate::net::datapath::mempool::alloc_packet_for_active_dma_device()?;
    if pkt.capacity() < DIAG_FRAME_LEN {
        return None;
    }

    pkt.set_len(DIAG_FRAME_LEN);
    let data = pkt.data_mut();
    data[..6].fill(0xff);
    data[6..12].copy_from_slice(&src);
    data[12] = 0x88;
    data[13] = 0xb5;
    data[14..18].copy_from_slice(b"MLX5");
    for (idx, byte) in data[18..DIAG_FRAME_LEN].iter_mut().enumerate() {
        *byte = 0xa0u8.wrapping_add(idx as u8);
    }

    Some(pkt)
}

fn submit_startup_mlx5_diag_frame() {
    crate::io::log::early_print("[MLX5_BRIDGE] startup diag budget check\n");
    if MLX5_STARTUP_TX_DIAG_FRAME_BUDGET
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |remaining| {
            remaining.checked_sub(1)
        })
        .is_err()
    {
        crate::io::log::early_print("[MLX5_BRIDGE] startup diag skipped by budget\n");
        return;
    }

    let submitted = {
        crate::io::log::early_print("[MLX5_BRIDGE] startup diag txbuf lock enter\n");
        let mut tx_bufs_guard = match MLX5_TX_BUFS.lock() {
            Ok(guard) => guard,
            Err(_) => {
                crate::io::log::early_print("[MLX5_BRIDGE] startup diag txbuf lock failed\n");
                log::warn!(
                    target: "mlx5::bridge",
                    "Skipping startup mlx5 diagnostic TX frame: TX buffer tracking lock poisoned"
                );
                return;
            }
        };
        crate::io::log::early_print("[MLX5_BRIDGE] startup diag txbuf lock done\n");

        crate::io::log::early_print("[MLX5_BRIDGE] startup diag device lock enter\n");
        with_mlx5_device(|device| {
            crate::io::log::early_print("[MLX5_BRIDGE] startup diag device lock done\n");
            if !device.is_active() {
                log::warn!(
                    target: "mlx5::bridge",
                    "Skipping startup mlx5 diagnostic TX frame: mlx5 device is not active yet"
                );
                return false;
            }

            let mut src = device
                .port(0)
                .map(|port| port.mac_address().0)
                .unwrap_or([0x02, 0x00, 0x5e, 0x00, 0x53, 0x01]);
            if src == [0; 6] {
                src = [0x02, 0x00, 0x5e, 0x00, 0x53, 0x01];
            }

            match build_mlx5_diag_tx_frame(src) {
                Some(diag_pkt) => {
                    crate::io::log::early_print("[MLX5_BRIDGE] startup diag submit enter\n");
                    log::warn!(
                        target: "mlx5::bridge",
                        "Submitting startup mlx5 diagnostic 60B TX frame"
                    );
                    let submitted = submit_mlx5_tx_packet_on_device(
                        device,
                        tx_bufs_guard.as_mut_slice(),
                        diag_pkt,
                        None,
                        false,
                    );
                    crate::io::log::early_print("[MLX5_BRIDGE] startup diag submit returned\n");
                    submitted
                }
                None => {
                    crate::io::log::early_print("[MLX5_BRIDGE] startup diag alloc failed\n");
                    log::warn!(
                        target: "mlx5::bridge",
                        "Failed to allocate startup mlx5 diagnostic TX frame"
                    );
                    false
                }
            }
        })
        .unwrap_or(false)
    };

    log::warn!(
        target: "mlx5::bridge",
        "Startup mlx5 diagnostic TX submission submitted={}",
        submitted
    );

    if !submitted {
        crate::io::log::early_print("[MLX5_BRIDGE] startup diag submit=false\n");
        return;
    }

    let completions = {
        crate::io::log::early_print("[MLX5_BRIDGE] startup diag drain lock enter\n");
        let mut tx_bufs_guard = match MLX5_TX_BUFS.lock() {
            Ok(guard) => guard,
            Err(_) => {
                crate::io::log::early_print("[MLX5_BRIDGE] startup diag drain lock failed\n");
                log::warn!(
                    target: "mlx5::bridge",
                    "Unable to drain startup mlx5 diagnostic TX CQ: TX buffer tracking lock poisoned"
                );
                return;
            }
        };
        crate::io::log::early_print("[MLX5_BRIDGE] startup diag drain lock done\n");

        crate::io::log::early_print("[MLX5_BRIDGE] startup diag drain device lock enter\n");
        with_mlx5_device(|device| {
            crate::io::log::early_print("[MLX5_BRIDGE] startup diag drain device lock done\n");
            let mut total = 0usize;
            // Surface the first TX CQE immediately so the boot log captures the failure mode
            // even when higher-layer traffic has not started yet.
            for _ in 0..64 {
                total += poll_mlx5_tx_cqs(device, tx_bufs_guard.as_mut_slice());
                if total > 0 {
                    break;
                }
                core::hint::spin_loop();
            }
            total
        })
        .unwrap_or(0)
    };
    crate::io::log::early_print("[MLX5_BRIDGE] startup diag drain returned\n");

    log::warn!(
        target: "mlx5::bridge",
        "Startup mlx5 diagnostic TX CQ drain completions={}",
        completions
    );
}

fn submit_mlx5_tx_packet_on_device(
    device: &mut Mlx5Device,
    tx_bufs_guard: &mut [Vec<Option<PacketRef>>],
    pkt: PacketRef,
    vlan_tag: Option<u16>,
    track_stats: bool,
) -> bool {
    let pkt = match pad_mlx5_tx_packet_if_needed(pkt) {
        Some(pkt) => pkt,
        None => {
            log::warn!(
                target: "mlx5::bridge",
                "Failed to provision padded DMA-safe packet for short mlx5 TX frame"
            );
            return false;
        }
    };

    let data_virt = pkt.as_ptr() as u64;
    let data_device = pkt.device_address();
    let data_len = pkt.len() as u32;

    let min_inline_mode = device
        .port(0)
        .map(|port| port.min_wqe_inline_mode())
        .unwrap_or(0);
    let inline_hdr_len = match min_inline_mode {
        0 => 0,
        1 => core::cmp::min(pkt.len(), 18),
        unsupported => {
            log::warn!(
                target: "mlx5::bridge",
                "Unsupported mlx5 TX min_wqe_inline_mode={} for simple SEND path",
                unsupported
            );
            return false;
        }
    };
    let inline_hdr = &pkt.data()[..inline_hdr_len];

    let cpu_id = crate::per_cpu::try_current_cpu_id().unwrap_or(0);
    let num_sqs = tx_bufs_guard.len();
    if num_sqs == 0 {
        log::trace!(target: "mlx5::bridge", "No active SQs available for TX");
        return false;
    }
    let sq_index = (cpu_id % num_sqs) as usize;

    let mut tx_options = mlx5_driver::wq::TxOptions::default();
    tx_options.vlan_tag = vlan_tag.unwrap_or(0);
    tx_options.l3_cs = false;
    tx_options.l4_cs = false;

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

            if track_stats {
                MLX5_TX_PACKETS.fetch_add(1, Ordering::Relaxed);
                counters::global().record_tx(data_len as usize);
                trace::push_event(NetLayer::Driver, NetEventKind::Tx, "mlx5 tx");
            }
            true
        }
        Err(e) => {
            if track_stats {
                MLX5_TX_ERRORS.fetch_add(1, Ordering::Relaxed);
                counters::global().record_error();
            }
            log::warn!(
                target: "mlx5::bridge",
                "TX submit failed: sq={} len={} inline={} vlan={:?} track_stats={} err={:?}",
                sq_index,
                data_len,
                inline_hdr_len,
                vlan_tag,
                track_stats,
                e
            );
            false
        }
    }
}

// ============================================================================
// Transmit Path
// ============================================================================

fn submit_mlx5_tx_packet(pkt: PacketRef, vlan_tag: Option<u16>) -> bool {
    let mut tx_bufs_guard = match MLX5_TX_BUFS.lock() {
        Ok(guard) => guard,
        Err(_) => return false,
    };

    let result = with_mlx5_device(|device| {
        if !device.is_active() {
            return false;
        }
        if MLX5_TX_DIAG_FRAME_BUDGET
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
        {
            let mut src = device
                .port(0)
                .map(|port| port.mac_address().0)
                .unwrap_or([0x02, 0x00, 0x5e, 0x00, 0x53, 0x01]);
            if src == [0; 6] {
                src = [0x02, 0x00, 0x5e, 0x00, 0x53, 0x01];
            }

            match build_mlx5_diag_tx_frame(src) {
                Some(diag_pkt) => {
                    log::warn!(
                        target: "mlx5::bridge",
                        "Submitting one-shot mlx5 diagnostic 60B TX frame"
                    );
                    let _ = submit_mlx5_tx_packet_on_device(
                        device,
                        tx_bufs_guard.as_mut_slice(),
                        diag_pkt,
                        None,
                        false,
                    );
                }
                None => {
                    log::warn!(
                        target: "mlx5::bridge",
                        "Failed to allocate mlx5 diagnostic TX frame"
                    );
                }
            }
        }

        submit_mlx5_tx_packet_on_device(device, tx_bufs_guard.as_mut_slice(), pkt, vlan_tag, true)
    });

    result.unwrap_or(false)
}

/// mlx5 送信コールバック（互換ラッパ）
pub fn mlx5_transmit(if_id: Option<NetIfId>, data: &[u8]) -> bool {
    device::transmit(if_id, data)
}

// ============================================================================
// Receive Path
// ============================================================================

unsafe fn log_mlx5_rx_debug_snapshot(idle_polls: u64) {
    let _ = with_mlx5_device(|device| {
        log::warn!(
            target: "mlx5::bridge",
            "RX debug snapshot: idle_polls={} wakeups={} wake_timeouts={} rx_pkts={} tx_pkts={} rx_err={} tx_err={} rqs={} sqs={}",
            idle_polls,
            MLX5_WAKE_COUNTS.load(Ordering::Relaxed),
            MLX5_WAKE_TIMEOUTS.load(Ordering::Relaxed),
            MLX5_RX_PACKETS.load(Ordering::Relaxed),
            MLX5_TX_PACKETS.load(Ordering::Relaxed),
            MLX5_RX_ERRORS.load(Ordering::Relaxed),
            MLX5_TX_ERRORS.load(Ordering::Relaxed),
            device.num_rqs(),
            device.num_sqs(),
        );

        for rq_index in 0..device.num_rqs() {
            let rq = unsafe { device.debug_rx_queue_state(rq_index) };
            let cq_index = device.rx_cq_index_for_rq(rq_index);
            let cq = cq_index.and_then(|idx| unsafe { device.debug_cq_state(idx) });

            match (rq, cq_index, cq) {
                (Some(rq_state), Some(cq_idx), Some(cq_state)) => {
                    log::warn!(
                        target: "mlx5::bridge",
                        "RX debug rq={} rqn={} prod={} avail={}/{} db={:#x} last_wqe:bc={} lkey={:#x} addr={:#x} | cq={} cqn={} ci={} arm_sn={} idx={} exp_owner={} obs_owner={} op={:?} wqe={} bc={} cq_db={:#x} arm_db={:#x}",
                        rq_index,
                        rq_state.rqn,
                        rq_state.producer_counter,
                        rq_state.available_slots,
                        rq_state.rq_depth,
                        rq_state.doorbell_host,
                        rq_state.last_wqe_byte_count,
                        rq_state.last_wqe_lkey,
                        rq_state.last_wqe_device_addr,
                        cq_idx,
                        cq_state.cqn,
                        cq_state.consumer_counter,
                        cq_state.arm_sn,
                        cq_state.head_index,
                        cq_state.expected_owner,
                        cq_state.observed_owner,
                        cq_state.observed_opcode,
                        cq_state.observed_wqe_counter,
                        cq_state.observed_byte_count,
                        cq_state.doorbell_host,
                        cq_state.arm_db_host,
                    );
                }
                _ => {
                    log::warn!(
                        target: "mlx5::bridge",
                        "RX debug rq={} state unavailable (rq/cq not ready)",
                        rq_index
                    );
                }
            }
        }

        for sq_index in 0..device.num_sqs() {
            let sq = unsafe { device.debug_tx_queue_state(sq_index) };
            let cq_index = device.tx_cq_index_for_sq(sq_index);
            let cq = cq_index.and_then(|idx| unsafe { device.debug_cq_state(idx) });

            match (sq, cq_index, cq) {
                (Some(sq_state), Some(cq_idx), Some(cq_state)) => {
                    let wqe_layout = format_mlx5_tx_wqe_layout(
                        &sq_state.last_wqe_bytes,
                        sq_state.last_wqe_inline_hdr_sz,
                    );
                    log::warn!(
                        target: "mlx5::bridge",
                        "TX debug sq={} sqn={} prod={}/{} db={:#x} bf={:#x} last_wqe:inl={} opmod_idx={:#x} qpn_ds={:#x} bc={} lkey={:#x} data_addr={:#x} addr={:#x} head=[{}] layout=\"{}\" | cq={} cqn={} ci={} arm_sn={} idx={} exp_owner={} obs_owner={} op={:?} wqe={} bc={} cq_db={:#x} arm_db={:#x}",
                        sq_index,
                        sq_state.sqn,
                        sq_state.producer_counter,
                        sq_state.sq_depth,
                        sq_state.doorbell_host,
                        sq_state.last_bf_offset,
                        sq_state.last_wqe_inline_hdr_sz,
                        sq_state.last_wqe_opmod_idx,
                        sq_state.last_wqe_qpn_ds,
                        sq_state.last_wqe_byte_count,
                        sq_state.last_wqe_lkey,
                        sq_state.last_wqe_device_addr,
                        sq_state.last_wqe_addr,
                        format_head_bytes(&sq_state.last_wqe_bytes, 48),
                        wqe_layout,
                        cq_idx,
                        cq_state.cqn,
                        cq_state.consumer_counter,
                        cq_state.arm_sn,
                        cq_state.head_index,
                        cq_state.expected_owner,
                        cq_state.observed_owner,
                        cq_state.observed_opcode,
                        cq_state.observed_wqe_counter,
                        cq_state.observed_byte_count,
                        cq_state.doorbell_host,
                        cq_state.arm_db_host,
                    );
                }
                _ => {
                    log::warn!(
                        target: "mlx5::bridge",
                        "TX debug sq={} state unavailable (sq/cq not ready)",
                        sq_index
                    );
                }
            }
        }

        if let Err(err) = unsafe { device.update_port_stats(0) } {
            log::warn!(
                target: "mlx5::bridge",
                "RX debug update_port_stats failed: {:?}",
                err
            );
        }

        if let Some(port) = device.port(0) {
            let s = port.stats();
            log::warn!(
                target: "mlx5::bridge",
                "RX debug port0 stats: rx_pkts={} rx_bytes={} rx_err={} rx_drop={} tx_pkts={} tx_bytes={} tx_err={} tx_drop={}",
                s.rx_packets,
                s.rx_bytes,
                s.rx_errors,
                s.rx_dropped,
                s.tx_packets,
                s.tx_bytes,
                s.tx_errors,
                s.tx_dropped
            );
        }
    });
}

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

            let remaining_budget = MLX5_RX_CQE_LOG_BUDGET.load(Ordering::Relaxed);
            if !cqes.is_empty() && remaining_budget > 0 {
                let to_log = core::cmp::min(cqes.len() as u64, remaining_budget) as usize;
                log::info!(
                    target: "mlx5::bridge",
                    "RX CQ activity: rq={} cq={} completions={} (logging {} entries, budget_left={})",
                    rq_index,
                    rx_cq_index,
                    cqes.len(),
                    to_log,
                    remaining_budget
                );
                for cqe in cqes.iter().take(to_log) {
                    match cqe.opcode {
                        mlx5_driver::defs::CqeOpcode::ReqErr
                        | mlx5_driver::defs::CqeOpcode::RespErr => {
                            log::info!(
                                target: "mlx5::bridge",
                                "RX CQE: rq={} cq={} op={:?} wqe_counter={} raw_byte_count={} qpn={:#x} syndrome={:#x} vendor={:#x} src_wqe_op={:#x}",
                                rq_index,
                                rx_cq_index,
                                cqe.opcode,
                                cqe.wqe_counter,
                                cqe.raw_byte_count,
                                cqe.qpn,
                                cqe.error_syndrome.unwrap_or(0),
                                cqe.vendor_error_syndrome.unwrap_or(0),
                                cqe.error_wqe_opcode.unwrap_or(0)
                            );
                        }
                        _ => {
                            log::info!(
                                target: "mlx5::bridge",
                                "RX CQE: rq={} cq={} op={:?} wqe_counter={} byte_count={} qpn={:#x} l3_ok={} l4_ok={} vlan={:?}",
                                rq_index,
                                rx_cq_index,
                                cqe.opcode,
                                cqe.wqe_counter,
                                cqe.byte_count,
                                cqe.qpn,
                                cqe.l3_ok,
                                cqe.l4_ok,
                                cqe.vlan_tag
                            );
                        }
                    }
                }
                MLX5_RX_CQE_LOG_BUDGET.fetch_sub(to_log as u64, Ordering::Relaxed);
            }

            for cqe in &cqes {
                let wqe_counter = cqe.wqe_counter;
                let byte_count = cqe.byte_count as usize;
                let idx = (wqe_counter as u32 % mlx5_driver::defs::MLX5_WQ_DEPTH) as usize;

                if matches!(
                    cqe.opcode,
                    mlx5_driver::defs::CqeOpcode::ReqErr | mlx5_driver::defs::CqeOpcode::RespErr
                ) {
                    MLX5_RX_ERRORS.fetch_add(1, Ordering::Relaxed);
                    if let Some(rx_info) =
                        device.process_rx_completion(rq_index, wqe_counter, false, false)
                    {
                        if let Some(pkt) = rx_bufs_guard[rq_index][idx].take() {
                            let buf_virt = pkt.as_ptr() as u64;
                            let buf_device = pkt.device_address();
                            let buf_size = pkt.capacity() as u32;
                            rx_bufs_guard[rq_index][idx] = Some(pkt);
                            let _ = device.post_receive(rq_index, buf_device, buf_virt, buf_size);
                        } else {
                            let _ = device.post_receive(
                                rq_index,
                                rx_info.device_addr,
                                rx_info.virt_addr,
                                rx_info.size,
                            );
                        }
                    }
                    continue;
                }

                if let Some(rx_info) =
                    device.process_rx_completion(rq_index, wqe_counter, cqe.l3_ok, cqe.l4_ok)
                {
                    MLX5_RX_PACKETS.fetch_add(1, Ordering::Relaxed);
                    counters::global().record_rx(byte_count);
                    trace::push_event(NetLayer::Driver, NetEventKind::Rx, "mlx5 rx");

                    if let Some(mut pkt) = rx_bufs_guard[rq_index][idx].take() {
                        pkt.set_len(byte_count);
                        if MLX5_RX_FRAME_LOG_BUDGET.load(Ordering::Relaxed) > 0 {
                            let frame = pkt.data();
                            let dst = if frame.len() >= 6 {
                                format!(
                                    "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                                    frame[0], frame[1], frame[2], frame[3], frame[4], frame[5]
                                )
                            } else {
                                String::from("--")
                            };
                            let src = if frame.len() >= 12 {
                                format!(
                                    "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                                    frame[6], frame[7], frame[8], frame[9], frame[10], frame[11]
                                )
                            } else {
                                String::from("--")
                            };
                            let ether_type = if frame.len() >= 14 {
                                u16::from_be_bytes([frame[12], frame[13]])
                            } else {
                                0
                            };
                            let head = format_head_bytes(frame, 32);
                            log::info!(
                                target: "mlx5::bridge",
                                "RX frame: rq={} idx={} len={} op={:?} wqe_counter={} ethertype={:#06x} dst={} src={} head=[{}]",
                                rq_index,
                                idx,
                                byte_count,
                                cqe.opcode,
                                wqe_counter,
                                ether_type,
                                dst,
                                src,
                                head
                            );
                            MLX5_RX_FRAME_LOG_BUDGET.fetch_sub(1, Ordering::Relaxed);
                        }
                        let meta = pkt.meta_mut();
                        if cqe.l3_ok {
                            meta.set_ip_csum_verified();
                        }
                        if cqe.l4_ok {
                            meta.set_l4_csum_verified();
                        }
                        meta.vlan_tag = cqe.vlan_tag;
                        meta.timestamp = cqe.timestamp;

                        dispatch_mlx5_rx_packet(pkt, byte_count);

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

        total_processed += poll_mlx5_tx_cqs(device, tx_bufs_guard.as_mut_slice()) as u32;

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
    if MLX5_FORCE_POLL_ONLY {
        log::warn!(
            target: "mlx5::bridge",
            "mlx5 RX diagnostics: forcing poll-only mode (interrupt wait disabled)"
        );
    }

    let mut msix_vector = None;

    // LOOP_PROOF: mode=event; reason=Loop progress is controlled by explicit break or return on state transitions/events.;
    loop {
        if !MLX5_PORT_RUNTIME_INITIALIZED.load(Ordering::Acquire) {
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
            let idle_polls = MLX5_RX_IDLE_POLLS.fetch_add(1, Ordering::Relaxed) + 1;
            if idle_polls % MLX5_RX_DEBUG_IDLE_INTERVAL == 0 {
                let snapshot_budget = MLX5_RX_DEBUG_SNAPSHOT_BUDGET.load(Ordering::Relaxed);
                if snapshot_budget > 0 {
                    MLX5_RX_DEBUG_SNAPSHOT_BUDGET.fetch_sub(1, Ordering::Relaxed);
                    unsafe { log_mlx5_rx_debug_snapshot(idle_polls) };
                }
            }

            if MLX5_FORCE_POLL_ONLY {
                crate::task::yield_now().await;
            } else {
                if let Some(vec) = msix_vector {
                    // 割り込み待ち (Interrupt-Waker Bridge)。
                    // RX 問題切り分け時に永久待機しないよう、短いタイムアウトで
                    // 定期的にポーリングへ戻す。
                    match with_timeout(
                        wait_for_interrupt(InterruptSource::Irq(vec as u8)),
                        MLX5_INTERRUPT_WAIT_TIMEOUT_MS,
                    )
                    .await
                    {
                        TimeoutResult::Completed(_) => {
                            MLX5_WAKE_COUNTS.fetch_add(1, Ordering::Relaxed);
                        }
                        TimeoutResult::TimedOut => {
                            MLX5_WAKE_TIMEOUTS.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                } else {
                    // MSI-X未設定時は従来通り yield
                    crate::task::yield_now().await;
                }
            }
        } else {
            MLX5_RX_IDLE_POLLS.store(0, Ordering::Relaxed);
        }
        // processed > 0 → 即座に次のポーリングサイクルへ（ビジーポーリング）
    }
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

            // RQ投入直後の状態を記録（WQE/DBRの初期診断用）
            if let Some(state) = unsafe { device.debug_rx_queue_state(rq_idx) } {
                log::info!(
                    target: "mlx5::bridge",
                    "RQ prefill: rq={} rqn={} filled={} prod={} db_host={:#x} last_wqe={:#x} byte_count={} lkey={:#x} addr={:#x}",
                    rq_idx,
                    state.rqn,
                    filled,
                    state.producer_counter,
                    state.doorbell_host,
                    state.last_wqe_addr,
                    state.last_wqe_byte_count,
                    state.last_wqe_lkey,
                    state.last_wqe_device_addr
                );
            }
        }

        log::info!(
            target: "mlx5::bridge",
            "Prefilled {} RX buffers across {} queues",
            total_filled,
            num_rqs
        );
    });
}

fn current_mlx5_port_stats() -> NetPortStats {
    NetPortStats {
        tx_packets: MLX5_TX_PACKETS.load(Ordering::Relaxed),
        rx_packets: MLX5_RX_PACKETS.load(Ordering::Relaxed),
        tx_errors: MLX5_TX_ERRORS.load(Ordering::Relaxed),
        rx_errors: MLX5_RX_ERRORS.load(Ordering::Relaxed),
        initialized: MLX5_PORT_RUNTIME_INITIALIZED.load(Ordering::Acquire),
    }
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

pub(crate) fn reset_mlx5_port_runtime() {
    MLX5_PORT_RUNTIME_INITIALIZED.store(false, Ordering::Release);
    crate::net::datapath::mempool::set_packet_dma_device(None);
    MLX5_RX_IDLE_POLLS.store(0, Ordering::Release);
    MLX5_RX_CQE_LOG_BUDGET.store(0, Ordering::Release);
    MLX5_RX_DEBUG_SNAPSHOT_BUDGET.store(0, Ordering::Release);
    MLX5_WAKE_COUNTS.store(0, Ordering::Release);
    MLX5_WAKE_TIMEOUTS.store(0, Ordering::Release);

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

    if let Ok(mut if_id) = MLX5_IF_ID.lock() {
        *if_id = None;
    }

    log::info!(target: "mlx5::bridge", "mlx5 port runtime reset");
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
