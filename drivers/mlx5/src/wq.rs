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

use crate::defs::{WqeOpcode, WQEBB_SIZE};
use crate::regs::wqe;

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

    fn write_be32(&mut self, offset: usize, value: u32) {
        let bytes = value.to_be_bytes();
        self.data[offset..offset + 4].copy_from_slice(&bytes);
    }

    fn write_be16(&mut self, offset: usize, value: u16) {
        let bytes = value.to_be_bytes();
        self.data[offset..offset + 2].copy_from_slice(&bytes);
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
    /// DMAバッファの物理アドレス（デバイスアドレス）
    pub phys_addr: u64,
    /// バッファサイズ
    pub size: u32,
    /// 使用中フラグ
    pub in_use: bool,
}

/// Send Queue (SQ) 管理構造体
pub struct SendQueue {
    /// SQのハードウェア番号
    pub sqn: u32,
    /// WQバッファの仮想アドレス
    buf_virt: u64,
    /// WQバッファの物理アドレス
    buf_phys: u64,
    /// ドアベルレコードの仮想アドレス
    doorbell_virt: u64,
    /// UAR（BlueFlame用）ベースアドレス
    uar_base: u64,
    /// ログ2 SQサイズ
    log_sq_size: u8,
    /// SQエントリ数
    sq_depth: u32,
    /// プロデューサインデックス
    producer_counter: u16,
    /// TIS (Transport Interface Send) 番号
    pub tisn: u32,
    /// 紐づくCQ番号
    pub cqn: u32,
    /// 送信バッファトラッキング
    tx_buffers: alloc::vec::Vec<TxBufferInfo>,
    /// Memory Key (L-Key)
    pub mkey: u32,
}

impl SendQueue {
    /// 新しいSend Queueを作成
    pub fn new(
        sqn: u32,
        buf_virt: u64,
        buf_phys: u64,
        doorbell_virt: u64,
        uar_base: u64,
        log_sq_size: u8,
        tisn: u32,
        cqn: u32,
        mkey: u32,
    ) -> Self {
        let depth = 1u32 << log_sq_size;
        let mut tx_buffers = alloc::vec::Vec::with_capacity(depth as usize);
        tx_buffers.resize(depth as usize, TxBufferInfo::default());

        Self {
            sqn,
            buf_virt,
            buf_phys,
            doorbell_virt,
            uar_base,
            log_sq_size,
            sq_depth: depth,
            producer_counter: 0,
            tisn,
            cqn,
            tx_buffers,
            mkey,
        }
    }

    /// 送信可能なWQEスロットがあるか
    pub fn has_space(&self) -> bool {
        // 簡易チェック: 次のスロットが未使用か
        let idx = (self.producer_counter as u32 % self.sq_depth) as usize;
        !self.tx_buffers[idx].in_use
    }

    /// 送信WQEを構築してSQに投入
    ///
    /// # Arguments
    /// - `data_phys`: 送信データのDMA物理アドレス
    /// - `data_virt`: 送信データの仮想アドレス（完了時の解放用）
    /// - `data_len`: 送信データ長
    /// - `inline_hdr`: インラインEthernetヘッダ（最初の18バイト以下）
    ///
    /// # Safety
    /// - buf_virt, doorbell_virt, uar_base が有効であること
    /// - data_phys がDMAアクセス可能なアドレスであること
    ///
    /// # Returns
    /// 投入したWQEインデックス
    pub unsafe fn post_send(
        &mut self,
        data_phys: u64,
        data_virt: u64,
        data_len: u32,
        inline_hdr: &[u8],
    ) -> Option<u16> {
        if !self.has_space() {
            return None;
        }

        let wqe_idx = self.producer_counter;
        let buf_idx = (wqe_idx as u32 % self.sq_depth) as usize;

        // WQEの構築: ctrl(16) + eth(16) + data(16) = 3 WQEBBs
        // 実際はWQE全体がSQバッファの連続領域に配置される
        // SQ uses 64-byte WQE stride (log_wq_stride=6).
        let wqe_offset = buf_idx * 64;
        let wqe_ptr = (self.buf_virt as usize + wqe_offset) as *mut u8;

        // Control Segment (16 bytes)
        let ctrl_ptr = wqe_ptr;
        // OPMOD_IDX_OPCODE: [31:24]=opcode, [23:0]=wqe_index
        let opmod_idx = ((WqeOpcode::EthSend as u32) << 24) | (wqe_idx as u32 & 0x00FF_FFFF);
        write_be32_raw(ctrl_ptr, wqe::ctrl::OPMOD_IDX_OPCODE, opmod_idx);
        // QPN_DS: [31:8]=QPN, [7:0]=DS count (3 for min TX WQE)
        let qpn_ds = ((self.sqn & 0x00FF_FFFF) << 8) | 3;
        write_be32_raw(ctrl_ptr, wqe::ctrl::QPN_DS, qpn_ds);
        // FM_CE_SE: completion enable
        write_be32_raw(ctrl_ptr, wqe::ctrl::FM_CE_SE, 0x08); // CE=1 (completion requested)

        // Ethernet Segment (16 bytes) at offset 16
        let eth_ptr = ctrl_ptr.add(16);
        // Inline header size
        let inline_sz = inline_hdr.len().min(18) as u16;
        write_be16_raw(eth_ptr, wqe::eth::INLINE_HDR_SZ, inline_sz);
        // CS flags: L3/L4 checksum offload
        write_be16_raw(eth_ptr, wqe::eth::CS_FLAGS, 0x03);

        // Copy inline header (Ethernet header)
        if !inline_hdr.is_empty() {
            let hdr_dst = eth_ptr.add(wqe::eth::INLINE_HDR_START);
            let copy_len = inline_hdr.len().min(18);
            core::ptr::copy_nonoverlapping(inline_hdr.as_ptr(), hdr_dst, copy_len);
        }

        // Data Segment (16 bytes) at offset 32
        let data_seg_ptr = ctrl_ptr.add(32);
        // Byte count
        write_be32_raw(data_seg_ptr, wqe::data::BYTE_COUNT, data_len);
        // L-Key (Memory Key)
        write_be32_raw(data_seg_ptr, wqe::data::LKEY, self.mkey);
        // Address (64-bit physical)
        write_be64_raw(data_seg_ptr, wqe::data::ADDR, data_phys);

        // バッファトラッキング
        self.tx_buffers[buf_idx] = TxBufferInfo {
            virt_addr: data_virt,
            phys_addr: data_phys,
            size: data_len,
            in_use: true,
        };

        // プロデューサカウンタを進める
        self.producer_counter = self.producer_counter.wrapping_add(1);

        // SQドアベル更新
        self.ring_doorbell();

        Some(wqe_idx)
    }

    /// SQドアベルをリング
    ///
    /// # Safety
    /// - uar_base が有効であること
    unsafe fn ring_doorbell(&self) {
        let db_val: u32 = ((self.sqn & 0x00FF_FFFF) << 8) | (self.producer_counter as u32 & 0xFF);
        crate::mmio_write_be32(
            self.uar_base as usize + crate::regs::uar::SQ_DOORBELL,
            db_val,
        );
    }

    /// 送信完了を処理（CQEのWQEカウンタに基づくバッファ解放）
    pub fn complete_tx(&mut self, wqe_counter: u16) -> Option<TxBufferInfo> {
        let idx = (wqe_counter as u32 % self.sq_depth) as usize;
        if self.tx_buffers[idx].in_use {
            let info = self.tx_buffers[idx];
            self.tx_buffers[idx] = TxBufferInfo::default();
            Some(info)
        } else {
            None
        }
    }
}

// ============================================================================
// Receive Queue
// ============================================================================

/// 受信バッファ情報（RQに投入されたDMAバッファのトラッキング）
#[derive(Clone, Copy, Debug, Default)]
pub struct RxBufferInfo {
    /// DMAバッファの仮想アドレス
    pub virt_addr: u64,
    /// DMAバッファの物理アドレス（デバイスアドレス）
    pub phys_addr: u64,
    /// バッファサイズ
    pub size: u32,
    /// 使用中フラグ
    pub in_use: bool,
}

/// Receive Queue (RQ) 管理構造体
pub struct ReceiveQueue {
    /// RQのハードウェア番号
    pub rqn: u32,
    /// WQバッファの仮想アドレス
    buf_virt: u64,
    /// WQバッファの物理アドレス
    buf_phys: u64,
    /// ドアベルレコードの仮想アドレス
    doorbell_virt: u64,
    /// ログ2 RQサイズ
    log_rq_size: u8,
    /// RQエントリ数
    rq_depth: u32,
    /// プロデューサインデックス
    producer_counter: u16,
    /// 紐づくCQ番号
    pub cqn: u32,
    /// TIR (Transport Interface Receive) 番号
    pub tirn: u32,
    /// 受信バッファトラッキング
    rx_buffers: alloc::vec::Vec<RxBufferInfo>,
    /// Memory Key (L-Key)
    pub mkey: u32,
}

impl ReceiveQueue {
    /// 新しいReceive Queueを作成
    pub fn new(
        rqn: u32,
        buf_virt: u64,
        buf_phys: u64,
        doorbell_virt: u64,
        log_rq_size: u8,
        cqn: u32,
        tirn: u32,
        mkey: u32,
    ) -> Self {
        let depth = 1u32 << log_rq_size;
        let mut rx_buffers = alloc::vec::Vec::with_capacity(depth as usize);
        rx_buffers.resize(depth as usize, RxBufferInfo::default());

        Self {
            rqn,
            buf_virt,
            buf_phys,
            doorbell_virt,
            log_rq_size,
            rq_depth: depth,
            producer_counter: 0,
            cqn,
            tirn,
            rx_buffers,
            mkey,
        }
    }

    /// 受信バッファをRQに投入
    ///
    /// # Arguments
    /// - `buf_phys`: 受信バッファのDMA物理アドレス
    /// - `buf_virt`: 受信バッファの仮想アドレス
    /// - `buf_size`: バッファサイズ
    ///
    /// # Safety
    /// - buf_virt が有効なマッピングであること
    /// - buf_phys がDMAアクセス可能であること
    ///
    /// # Returns
    /// 投入したWQEインデックス
    pub unsafe fn post_recv(&mut self, buf_phys: u64, buf_virt: u64, buf_size: u32) -> Option<u16> {
        let wqe_idx = self.producer_counter;
        let buf_idx = (wqe_idx as u32 % self.rq_depth) as usize;

        if self.rx_buffers[buf_idx].in_use {
            return None; // キューフル
        }

        // RQ WQE: データセグメントのみ（16バイト）
        let wqe_offset = buf_idx * WQEBB_SIZE;
        let wqe_ptr = (self.buf_virt as usize + wqe_offset) as *mut u8;

        // Data Segment
        write_be32_raw(wqe_ptr, wqe::data::BYTE_COUNT, buf_size);
        write_be32_raw(wqe_ptr, wqe::data::LKEY, self.mkey);
        write_be64_raw(wqe_ptr, wqe::data::ADDR, buf_phys);

        // バッファトラッキング
        self.rx_buffers[buf_idx] = RxBufferInfo {
            virt_addr: buf_virt,
            phys_addr: buf_phys,
            size: buf_size,
            in_use: true,
        };

        // プロデューサカウンタを進める
        self.producer_counter = self.producer_counter.wrapping_add(1);

        // ドアベル更新
        let db_val: u32 = self.producer_counter as u32 & 0x0000_FFFF;
        let db_ptr = self.doorbell_virt as *mut u32;
        core::ptr::write_volatile(db_ptr, db_val.to_be());

        Some(wqe_idx)
    }

    /// 受信完了を処理して受信バッファ情報を返す
    pub fn complete_rx(&mut self, wqe_counter: u16) -> Option<RxBufferInfo> {
        let idx = (wqe_counter as u32 % self.rq_depth) as usize;
        if self.rx_buffers[idx].in_use {
            let info = self.rx_buffers[idx];
            self.rx_buffers[idx] = RxBufferInfo::default();
            Some(info)
        } else {
            None
        }
    }

    /// RQの空きスロット数
    pub fn available_slots(&self) -> u32 {
        self.rx_buffers.iter().filter(|b| !b.in_use).count() as u32
    }

    /// RQバッファの物理アドレス
    pub fn buffer_phys(&self) -> u64 {
        self.buf_phys
    }
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
