// ============================================================================
// drivers/mlx5/src/wq.rs - Work Queues (SQ/RQ)
// ============================================================================
//! Work Queue — 送信キュー(SQ)と受信キュー(RQ)
//!
//! ## Send Queue (SQ)
//! 送信WQEを投入し、HWがEthernetフレームを送信する。
//! WQEはコントロールセグメント + Ethernetセグメント + データセグメントで構成。
//!
//! ## Receive Queue (RQ)
//! 受信バッファを事前投入し、HWがパケットを受信してCQEで通知する。
//!
//! ## ゼロコピー設計
//! バッファの所有権をSW↔HW間で明示的に移動する。
//! DMAバッファの物理アドレスをWQEに直接設定する。

use crate::defs::{MLX5_SQ_STRIDE, WQEBB_SIZE, WqeOpcode};
use crate::regs::wqe;
use alloc::collections::VecDeque;
use core::sync::atomic::{Ordering, fence};

const MLX5_WQE_CTRL_CQ_UPDATE: u8 = 2 << 2;
const MLX5_ETH_WQE_L3_CSUM: u8 = 1 << 6;
const MLX5_ETH_WQE_L4_CSUM: u8 = 1 << 7;

/// Work Queue Entry Buffer Block (WQEBB) — 16バイト
#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub struct Wqebb {
    pub data: [u8; WQEBB_SIZE],
}

impl Wqebb {
    pub const fn zeroed() -> Self {
        Self {
            data: [0u8; WQEBB_SIZE],
        }
    }
}

// ============================================================================
// Send Queue
// ============================================================================

/// 送信バッファ情報（SQに投入されたDMAバッファのトラッキング）
#[derive(Clone, Copy, Debug, Default)]
pub struct TxBufferInfo {
    /// DMAバッファの仮想アドレス
    pub virt_addr: u64,
    /// DMAバッファのデバイスアドレス（IOMMU IOVA）
    pub device_addr: u64,
    /// バッファサイズ
    pub size: u32,
    /// 使用中フラグ
    pub in_use: bool,
}

/// DMAセグメント（Scatter/Gather用）
#[derive(Clone, Copy, Debug)]
pub struct DmaSegment {
    /// デバイスアドレス (IOMMU IOVA)
    pub device_addr: u64,
    /// 仮想アドレス（トラッキング用）
    pub virt_addr: u64,
    /// 長さ
    pub len: u32,
}

/// 送信オプション
#[derive(Clone, Copy, Debug, Default)]
pub struct TxOptions {
    /// IPv4 チェックサムオフロードを要求
    pub l3_cs: bool,
    /// TCP/UDP チェックサムオフロードを要求
    pub l4_cs: bool,
    /// TSO MSS。0 の場合は TSO を使用しない。
    pub mss: u16,
    /// 挿入する VLAN タグ (TCI)。0 の場合は挿入しない。
    pub vlan_tag: u16,
}

/// Send Queue のデバッグスナップショット
#[derive(Debug, Clone, Copy)]
pub struct TxQueueDebugState {
    pub sqn: u32,
    pub tisn: u32,
    pub producer_counter: u16,
    pub sq_depth: u32,
    pub doorbell_be: u32,
    pub doorbell_host: u32,
    pub last_wqe_counter: u16,
    pub last_wqe_offset: usize,
    pub last_wqe_opmod_idx: u32,
    pub last_wqe_qpn_ds: u32,
    pub last_wqe_general_id: u32,
    pub last_wqe_byte_count: u32,
    pub last_wqe_lkey: u32,
    pub last_wqe_device_addr: u64,
    pub last_bf_offset: u16,
    pub last_wqe_bytes: [u8; MLX5_SQ_STRIDE],
}

#[derive(Debug, Clone, Copy)]
pub struct TxWqeDebugInfo {
    pub valid: bool,
    pub wqe_counter: u16,
    pub wqe_offset: usize,
    pub opmod_idx: u32,
    pub qpn_ds: u32,
    pub general_id: u32,
    pub byte_count: u32,
    pub lkey: u32,
    pub device_addr: u64,
    pub wqe_bytes: [u8; MLX5_SQ_STRIDE],
}

impl Default for TxWqeDebugInfo {
    fn default() -> Self {
        Self {
            valid: false,
            wqe_counter: 0,
            wqe_offset: 0,
            opmod_idx: 0,
            qpn_ds: 0,
            general_id: 0,
            byte_count: 0,
            lkey: 0,
            device_addr: 0,
            wqe_bytes: [0u8; MLX5_SQ_STRIDE],
        }
    }
}

// ============================================================================
// Receive Queue
// ============================================================================

/// RX Work Queue の実行モード
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RxWqMode {
    Cyclic,
    LinkedList,
}

impl RxWqMode {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Cyclic => "cyclic",
            Self::LinkedList => "linked",
        }
    }
}

/// QUERY_RQ で確定した RX WQ レイアウト
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolvedRqLayout {
    pub wq_mode: RxWqMode,
    pub slot_size_bytes: usize,
    pub data_seg_offset: usize,
    pub has_next_segment: bool,
    pub rq_num: u32,
    pub cqn: u32,
    pub raw_mem_rq_type: u8,
    pub raw_wq_type: u8,
    pub raw_log_wq_stride: u8,
    pub raw_end_padding_mode: u8,
    pub raw_log_wq_sz: u8,
    pub rmpn: Option<u32>,
}

impl ResolvedRqLayout {
    pub const LINK_SEG_SIZE: usize = WQEBB_SIZE;
    pub const DATA_SEG_SIZE: usize = WQEBB_SIZE;

    #[expect(
        clippy::too_many_arguments,
        reason = "retains the queried hardware fields together with the resolved receive descriptor layout"
    )]
    pub const fn cyclic(
        rq_num: u32,
        cqn: u32,
        slot_size_bytes: usize,
        raw_mem_rq_type: u8,
        raw_wq_type: u8,
        raw_log_wq_stride: u8,
        raw_end_padding_mode: u8,
        raw_log_wq_sz: u8,
        rmpn: Option<u32>,
    ) -> Self {
        Self {
            wq_mode: RxWqMode::Cyclic,
            slot_size_bytes,
            data_seg_offset: 0,
            has_next_segment: false,
            rq_num,
            cqn,
            raw_mem_rq_type,
            raw_wq_type,
            raw_log_wq_stride,
            raw_end_padding_mode,
            raw_log_wq_sz,
            rmpn,
        }
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "retains the queried hardware fields together with the resolved receive descriptor layout"
    )]
    pub const fn linked(
        rq_num: u32,
        cqn: u32,
        slot_size_bytes: usize,
        raw_mem_rq_type: u8,
        raw_wq_type: u8,
        raw_log_wq_stride: u8,
        raw_end_padding_mode: u8,
        raw_log_wq_sz: u8,
        rmpn: Option<u32>,
    ) -> Self {
        Self {
            wq_mode: RxWqMode::LinkedList,
            slot_size_bytes,
            data_seg_offset: Self::LINK_SEG_SIZE,
            has_next_segment: true,
            rq_num,
            cqn,
            raw_mem_rq_type,
            raw_wq_type,
            raw_log_wq_stride,
            raw_end_padding_mode,
            raw_log_wq_sz,
            rmpn,
        }
    }

    pub const fn slot_offset(self, slot_index: u16) -> usize {
        slot_index as usize * self.slot_size_bytes
    }

    pub const fn data_seg_offset(self) -> usize {
        self.data_seg_offset
    }
}

/// 受信バッファ情報（RQに投入されたDMAバッファのトラッキング）
#[derive(Clone, Copy, Debug, Default)]
pub struct RxBufferInfo {
    /// バッファが対応する RQ スロット番号
    pub slot_index: u16,
    /// DMAバッファのデバイスアドレス（IOMMU IOVA）
    pub device_addr: u64,
    /// バッファサイズ
    pub size: u32,
    /// L3 チェックサム検証成功
    pub l3_ok: bool,
    /// L4 チェックサム検証成功
    pub l4_ok: bool,
}

/// Receive Queue のデバッグスナップショット
#[derive(Debug, Clone, Copy)]
pub struct RxQueueDebugState {
    pub rqn: u32,
    pub producer_counter: u16,
    pub rq_depth: u32,
    pub available_slots: u32,
    pub layout_mode: RxWqMode,
    pub layout_slot_size_bytes: usize,
    pub layout_data_seg_offset: usize,
    pub layout_raw_wq_type: u8,
    pub layout_raw_log_wq_stride: u8,
    pub layout_rmpn: Option<u32>,
    pub doorbell_be: u32,
    pub doorbell_host: u32,
    pub last_wqe_counter: u16,
    pub last_wqe_offset: usize,
    pub last_wqe_byte_count: u32,
    pub last_wqe_lkey: u32,
    pub last_wqe_device_addr: u64,
}

mod owned;
pub use owned::{ReceivePost, ReceiveQueue, SendQueue};
pub(crate) use owned::{ReceiveStorage, SendStorage};
