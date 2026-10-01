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

/// Send Queue (SQ) 管理構造体
pub struct SendQueue {
    pub(crate) memory: crate::queue_memory::QueueMemory<2>,
    pub(crate) grant: crate::queue_memory::QueueGrant,
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



/// Metadata storage is allocated before CREATE_SQ publishes a hardware queue.
/// Binding a successful queue consumes it without further allocation.




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
    pub last_wqe_addr: u64,
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
    pub wqe_addr: u64,
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
            wqe_addr: 0,
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
    /// DMAバッファの仮想アドレス
    pub virt_addr: u64,
    /// DMAバッファのデバイスアドレス（IOMMU IOVA）
    pub device_addr: u64,
    /// バッファサイズ
    pub size: u32,
    /// 使用中フラグ
    pub in_use: bool,
    /// L3 チェックサム検証成功
    pub l3_ok: bool,
    /// L4 チェックサム検証成功
    pub l4_ok: bool,
}

/// Receive Queue (RQ) 管理構造体
pub struct ReceiveQueue {
    pub(crate) memory: crate::queue_memory::QueueMemory<4>,
    pub(crate) grant: crate::queue_memory::QueueGrant,
    pub(crate) rmp_grant: crate::queue_memory::QueueGrant,
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
    pub last_wqe_addr: u64,
    pub last_wqe_byte_count: u32,
    pub last_wqe_lkey: u32,
    pub last_wqe_device_addr: u64,
}

// ============================================================================
// Helper Functions (raw pointer writes)
// ============================================================================

/// ビッグエンディアンu32をrawポインタに書き込む
///
/// # Safety
/// - `base` が有効なポインタであること
/// - `offset + 4` がバッファ範囲内であること
unsafe fn write_be32_raw(base: *mut u8, offset: usize, value: u32) {
    let bytes = value.to_be_bytes();
    core::ptr::copy_nonoverlapping(bytes.as_ptr(), base.add(offset), 4);
}

/// 8-bit値をrawポインタに書き込む
unsafe fn write_u8_raw(base: *mut u8, offset: usize, value: u8) {
    core::ptr::write(base.add(offset), value);
}

/// ビッグエンディアンu16をrawポインタに書き込む
unsafe fn write_be16_raw(base: *mut u8, offset: usize, value: u16) {
    let bytes = value.to_be_bytes();
    core::ptr::copy_nonoverlapping(bytes.as_ptr(), base.add(offset), 2);
}

/// ビッグエンディアンu64をrawポインタに書き込む
unsafe fn write_be64_raw(base: *mut u8, offset: usize, value: u64) {
    let bytes = value.to_be_bytes();
    core::ptr::copy_nonoverlapping(bytes.as_ptr(), base.add(offset), 8);
}

/// ビッグエンディアンu32をrawポインタから読み込む
///
/// # Safety
/// - `base` が有効なポインタであること
/// - `offset + 4` がバッファ範囲内であること
unsafe fn read_be32_raw(base: *const u8, offset: usize) -> u32 {
    let ptr = base.add(offset);
    let b0 = core::ptr::read_volatile(ptr);
    let b1 = core::ptr::read_volatile(ptr.add(1));
    let b2 = core::ptr::read_volatile(ptr.add(2));
    let b3 = core::ptr::read_volatile(ptr.add(3));
    u32::from_be_bytes([b0, b1, b2, b3])
}

/// ビッグエンディアンu16をrawポインタから読み込む
#[cfg(test)]
unsafe fn read_be16_raw(base: *const u8, offset: usize) -> u16 {
    let ptr = base.add(offset);
    let b0 = core::ptr::read_volatile(ptr);
    let b1 = core::ptr::read_volatile(ptr.add(1));
    u16::from_be_bytes([b0, b1])
}

/// ビッグエンディアンu64をrawポインタから読み込む
///
/// # Safety
/// - `base` が有効なポインタであること
/// - `offset + 8` がバッファ範囲内であること
unsafe fn read_be64_raw(base: *const u8, offset: usize) -> u64 {
    let ptr = base.add(offset);
    let b0 = core::ptr::read_volatile(ptr);
    let b1 = core::ptr::read_volatile(ptr.add(1));
    let b2 = core::ptr::read_volatile(ptr.add(2));
    let b3 = core::ptr::read_volatile(ptr.add(3));
    let b4 = core::ptr::read_volatile(ptr.add(4));
    let b5 = core::ptr::read_volatile(ptr.add(5));
    let b6 = core::ptr::read_volatile(ptr.add(6));
    let b7 = core::ptr::read_volatile(ptr.add(7));
    u64::from_be_bytes([b0, b1, b2, b3, b4, b5, b6, b7])
}

#[inline(always)]
fn dma_store_barrier() {
    fence(Ordering::Release);
    hal::mmio::sfence();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cyclic_layout(slot_size_bytes: usize) -> ResolvedRqLayout {
        ResolvedRqLayout::cyclic(
            0x10,
            0x20,
            slot_size_bytes,
            0,
            1,
            if slot_size_bytes == 64 { 6 } else { 4 },
            1,
            2,
            None,
        )
    }

    fn linked_layout() -> ResolvedRqLayout {
        ResolvedRqLayout::linked(0x10, 0x20, 64, 0, 0, 6, 0, 2, None)
    }

    #[test]
    fn cyclic_16b_post_complete_recycle_uses_fifo_slot_bookkeeping() {
        let mut rq_mem = [0u8; 64];
        let mut db = [0u32; 1];
        let mut rq = ReceiveQueue::new(
            0x10,
            rq_mem.as_mut_ptr() as u64,
            0x2000,
            db.as_mut_ptr() as u64,
            2,
            0x20,
            cyclic_layout(16),
            0xdead_beef,
            false,
        );

        unsafe {
            assert_eq!(rq.post_recv(0x1000, 0x2000, 1500), Some(0));
            assert_eq!(rq.post_recv(0x1100, 0x2100, 1501), Some(1));
            assert_eq!(rq.post_recv(0x1200, 0x2200, 1502), Some(2));
            assert_eq!(rq.post_recv(0x1300, 0x2300, 1503), Some(3));
        }
        assert_eq!(rq.available_slots(), 0);

        let completed = rq.complete_rx(0, true, false).unwrap();
        assert_eq!(completed.slot_index, 0);
        assert_eq!(completed.device_addr, 0x1000);
        assert!(completed.l3_ok);
        assert!(!completed.l4_ok);

        unsafe {
            assert_eq!(rq.post_recv(0x1400, 0x2400, 1600), Some(4));
            let completed = rq.complete_rx(3, false, true).unwrap();
            assert_eq!(completed.slot_index, 3);
            assert_eq!(completed.device_addr, 0x1300);
            assert!(!completed.l3_ok);
            assert!(completed.l4_ok);
        }
    }

    #[test]
    fn cyclic_completion_mismatch_recovers_expected_slot_without_corrupting_recycling() {
        let mut rq_mem = [0u8; 64];
        let mut db = [0u32; 1];
        let mut rq = ReceiveQueue::new(
            0x10,
            rq_mem.as_mut_ptr() as u64,
            0x2500,
            db.as_mut_ptr() as u64,
            2,
            0x20,
            cyclic_layout(16),
            0xdead_beef,
            false,
        );

        unsafe {
            assert_eq!(rq.post_recv(0x1000, 0x2000, 1500), Some(0));
            assert_eq!(rq.post_recv(0x1100, 0x2100, 1501), Some(1));
            assert_eq!(rq.post_recv(0x1200, 0x2200, 1502), Some(2));
            assert_eq!(rq.post_recv(0x1300, 0x2300, 1503), Some(3));
        }

        let completed = rq.complete_rx(2, true, true).unwrap();
        assert_eq!(completed.slot_index, 2);
        assert_eq!(completed.device_addr, 0x1200);
        assert_eq!(rq.available_slots(), 1);

        unsafe {
            assert_eq!(rq.post_recv(0x1400, 0x2400, 2048), Some(4));
        }
        let completed = rq.complete_rx(0, false, false).unwrap();
        assert_eq!(completed.slot_index, 0);
        assert_eq!(rq.available_slots(), 1);
    }

    #[test]
    fn cyclic_completion_missing_expected_slot_returns_none_without_mutating_state() {
        let mut rq_mem = [0u8; 64];
        let mut db = [0u32; 1];
        let mut rq = ReceiveQueue::new(
            0x10,
            rq_mem.as_mut_ptr() as u64,
            0x2600,
            db.as_mut_ptr() as u64,
            2,
            0x20,
            cyclic_layout(16),
            0xdead_beef,
            false,
        );

        unsafe {
            assert_eq!(rq.post_recv(0x1000, 0x2000, 1500), Some(0));
            assert_eq!(rq.post_recv(0x1100, 0x2100, 1501), Some(1));
            assert_eq!(rq.post_recv(0x1200, 0x2200, 1502), Some(2));
            assert_eq!(rq.post_recv(0x1300, 0x2300, 1503), Some(3));
        }

        rq.rx_buffers[2] = RxBufferInfo::default();
        let free_len_before = rq.free_slots.len();

        assert!(rq.complete_rx(2, false, false).is_none());

        assert!(!rq.inflight_slots.iter().any(|&slot| slot == 2));
        assert_eq!(rq.free_slots.len(), free_len_before + 1);
        assert_eq!(rq.free_slots.iter().filter(|&&slot| slot == 2).count(), 1);
        assert_eq!(rq.available_slots(), 1);

        let inflight_after = rq.inflight_slots.clone();
        let free_after = rq.free_slots.clone();
        assert!(rq.complete_rx(2, false, false).is_none());
        assert_eq!(rq.inflight_slots, inflight_after);
        assert_eq!(rq.free_slots, free_after);
    }

    #[test]
    fn cyclic_64b_post_writes_data_segment_at_64b_stride() {
        let mut rq_mem = [0u8; 128];
        let mut db = [0u32; 1];
        let mut rq = ReceiveQueue::new(
            0x10,
            rq_mem.as_mut_ptr() as u64,
            0x3000,
            db.as_mut_ptr() as u64,
            1,
            0x20,
            cyclic_layout(64),
            0xabcd_ef01,
            false,
        );

        unsafe {
            assert_eq!(rq.post_recv(0x4000, 0x5000, 2048), Some(0));
            assert_eq!(rq.post_recv(0x4100, 0x5100, 4096), Some(1));
            let second_slot = rq_mem.as_ptr().add(64);
            assert_eq!(read_be32_raw(second_slot, wqe::data::BYTE_COUNT), 4096);
            assert_eq!(read_be32_raw(second_slot, wqe::data::LKEY), 0xabcd_ef01);
            assert_eq!(read_be64_raw(second_slot, wqe::data::ADDR), 0x4100);
        }
    }

    #[test]
    fn linked_64b_initializes_next_segment_and_recycles_slots() {
        let mut rq_mem = [0u8; 128];
        let mut db = [0u32; 1];
        let mut rq = ReceiveQueue::new(
            0x10,
            rq_mem.as_mut_ptr() as u64,
            0x6000,
            db.as_mut_ptr() as u64,
            1,
            0x20,
            linked_layout(),
            0x1234_5678,
            false,
        );

        unsafe {
            assert_eq!(rq.post_recv(0x7000, 0x7100, 1024), Some(0));
            assert_eq!(rq.post_recv(0x7200, 0x7300, 2048), Some(1));

            let first_slot = rq_mem.as_ptr();
            let second_slot = rq_mem.as_ptr().add(64);

            assert_eq!(read_be16_raw(first_slot, 0x02), 4);
            assert_eq!(
                read_be32_raw(first_slot.add(16), wqe::data::BYTE_COUNT),
                1024
            );
            assert_eq!(read_be64_raw(first_slot.add(16), wqe::data::ADDR), 0x7000);
            assert_eq!(read_be16_raw(second_slot, 0x02), 0);
            assert_eq!(
                read_be32_raw(second_slot.add(16), wqe::data::BYTE_COUNT),
                2048
            );

            let completed = rq.complete_rx(0x4444, false, false).unwrap();
            assert_eq!(completed.slot_index, 0);
            assert_eq!(rq.post_recv(0x7400, 0x7500, 3072), Some(2));
            let completed = rq.complete_rx(0x5555, true, true).unwrap();
            assert_eq!(completed.slot_index, 1);
        }
    }

    #[test]
    fn linked_completion_keeps_fifo_order_independent_of_wqe_counter() {
        let mut rq_mem = [0u8; 128];
        let mut db = [0u32; 1];
        let mut rq = ReceiveQueue::new(
            0x10,
            rq_mem.as_mut_ptr() as u64,
            0x6100,
            db.as_mut_ptr() as u64,
            1,
            0x20,
            linked_layout(),
            0x1234_5678,
            false,
        );

        unsafe {
            assert_eq!(rq.post_recv(0x7000, 0x7100, 1024), Some(0));
            assert_eq!(rq.post_recv(0x7200, 0x7300, 2048), Some(1));
        }

        let completed = rq.complete_rx(0x5555, false, false).unwrap();
        assert_eq!(completed.slot_index, 0);
        let completed = rq.complete_rx(0x0001, true, false).unwrap();
        assert_eq!(completed.slot_index, 1);
        assert_eq!(rq.available_slots(), 2);
    }
}
