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

use crate::defs::{WQEBB_SIZE, WqeOpcode};
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
    /// DMAバッファのデバイスアドレス（IOMMU IOVA）
    pub device_addr: u64,
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
    /// WQバッファのデバイスアドレス
    buf_device: u64,
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
    /// チェックサムオフロード対応
    pub csum_offload: bool,
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

impl SendQueue {
    /// 新しいSend Queueを作成
    pub fn new(
        sqn: u32,
        buf_virt: u64,
        buf_device: u64,
        doorbell_virt: u64,
        uar_base: u64,
        log_sq_size: u8,
        tisn: u32,
        cqn: u32,
        mkey: u32,
        csum_offload: bool,
    ) -> Self {
        let depth = 1u32 << log_sq_size;
        let mut tx_buffers = alloc::vec::Vec::with_capacity(depth as usize);
        tx_buffers.resize(depth as usize, TxBufferInfo::default());

        Self {
            sqn,
            buf_virt,
            buf_device,
            doorbell_virt,
            uar_base,
            log_sq_size,
            sq_depth: depth,
            producer_counter: 0,
            tisn,
            cqn,
            tx_buffers,
            mkey,
            csum_offload,
        }
    }

    /// 送信可能なWQEスロットがあるか
    pub fn has_space(&self) -> bool {
        // 簡易チェック: 次のスロットが未使用か
        let idx = (self.producer_counter as u32 % self.sq_depth) as usize;
        !self.tx_buffers[idx].in_use
    }
}

/// 送信オプション
#[derive(Clone, Copy, Debug, Default)]
pub struct TxOptions {
    /// IPv4 チェックサムオフロードを要求
    pub l3_cs: bool,
    /// TCP/UDP チェックサムオフロードを要求
    pub l4_cs: bool,
    /// インラインヘッダの長さ
    pub inline_len: u16,
    /// TSO MSS。0 の場合は TSO を使用しない。
    pub mss: u16,
    /// 挿入する VLAN タグ。0 の場合は挿入しない。
    pub vlan_tag: u16,
}

impl SendQueue {
    /// 送信WQEを構築してSQに投入
    pub unsafe fn post_send(
        &mut self,
        segments: &[DmaSegment],
        inline_hdr: &[u8],
        options: TxOptions,
    ) -> Option<u16> {
        if !self.has_space() || segments.is_empty() || segments.len() > 2 {
            return None;
        }

        let wqe_idx = self.producer_counter;
        let buf_idx = (wqe_idx as u32 % self.sq_depth) as usize;

        let wqe_offset = buf_idx * 64;
        let wqe_ptr = (self.buf_virt as usize + wqe_offset) as *mut u8;

        // Control Segment (16 bytes)
        let ctrl_ptr = wqe_ptr;
        let opmod_idx = ((WqeOpcode::EthSend as u32) << 24) | (wqe_idx as u32 & 0x00FF_FFFF);
        write_be32_raw(ctrl_ptr, wqe::ctrl::OPMOD_IDX_OPCODE, opmod_idx);
        let ds_count = 2 + segments.len() as u32;
        let qpn_ds = ((self.sqn & 0x00FF_FFFF) << 8) | ds_count;
        write_be32_raw(ctrl_ptr, wqe::ctrl::QPN_DS, qpn_ds);
        write_be32_raw(ctrl_ptr, wqe::ctrl::FM_CE_SE, 0x08); // CE=1

        // Ethernet Segment (16 bytes)
        let eth_ptr = ctrl_ptr.add(16);
        let inline_sz = inline_hdr.len().min(18) as u16;
        write_be16_raw(eth_ptr, wqe::eth::INLINE_HDR_SZ, inline_sz);

        // チェックサムオフロードおよび TSO 設定
        let mut cs_flags = 0u16;
        if self.csum_offload {
            if options.l3_cs { cs_flags |= 0x01; }
            if options.l4_cs { cs_flags |= 0x02; }
        }
        write_be16_raw(eth_ptr, wqe::eth::CS_FLAGS, cs_flags);

        // TSO MSS
        write_be16_raw(eth_ptr, wqe::eth::MSS, options.mss);

        // Copy inline header (Ethernet header)
        if !inline_hdr.is_empty() {
            let hdr_dst = eth_ptr.add(wqe::eth::INLINE_HDR_START);
            let copy_len = inline_hdr.len().min(18);
            core::ptr::copy_nonoverlapping(inline_hdr.as_ptr(), hdr_dst, copy_len);
        }

        // Data Segments (16 bytes each) starting at offset 32
        for (i, seg) in segments.iter().enumerate() {
            let data_seg_ptr = ctrl_ptr.add(32 + i * 16);
            // Byte count
            write_be32_raw(data_seg_ptr, wqe::data::BYTE_COUNT, seg.len);
            // L-Key (Memory Key)
            write_be32_raw(data_seg_ptr, wqe::data::LKEY, self.mkey);
            // Address (64-bit device address)
            write_be64_raw(data_seg_ptr, wqe::data::ADDR, seg.device_addr);
        }

        // バッファトラッキング (単一バッファの互換性維持のため、最初のセグメントを保存)
        // 本来は全セグメントをトラッキングすべきだが、現在は1パケット1エントリ
        self.tx_buffers[buf_idx] = TxBufferInfo {
            virt_addr: segments[0].virt_addr,
            device_addr: segments[0].device_addr,
            size: segments[0].len,
            in_use: true,
        };

        // プロデューサカウンタを進める
        self.producer_counter = self.producer_counter.wrapping_add(1);

        // SQドアベル更新（BlueFlame 試行用 WQE ポインタを渡す）
        self.ring_doorbell(wqe_ptr);

        Some(wqe_idx)
    }

    /// SQドアベルをリング
    ///
    /// # Safety
    /// - uar_base が有効であること
    unsafe fn ring_doorbell(&self, wqe_ptr: *const u8) {
        // BlueFlame 試行: WQEの最初の8バイト（Control Segmentの一部）をUARに直接書き込む
        // これにより、ドアベルのみの場合よりも低遅延で送信が開始される可能性がある。
        // 注意: 64ビットアトミック書き込みが必要。
        let bf_ptr = (self.uar_base as usize + crate::regs::uar::BLUEFLAME) as *mut u64;
        let ctrl_8 = *(wqe_ptr as *const u64);
        
        // メモリバリア
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
        
        // BlueFlame 書き込み
        core::ptr::write_volatile(bf_ptr, ctrl_8.to_be());
        
        // フォールバック: 標準的なドアベルレジスタへの通知
        // (BlueFlameが失敗した場合や、一部のハードウェア制限に備える)
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
    /// RQのハードウェア番号
    pub rqn: u32,
    /// WQバッファの仮想アドレス
    buf_virt: u64,
    /// WQバッファのデバイスアドレス
    buf_device: u64,
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
    /// チェックサムオフロード対応
    pub csum_offload: bool,
}

impl ReceiveQueue {
    /// 新しいReceive Queueを作成
    pub fn new(
        rqn: u32,
        buf_virt: u64,
        buf_device: u64,
        doorbell_virt: u64,
        log_rq_size: u8,
        cqn: u32,
        mkey: u32,
        csum_offload: bool,
    ) -> Self {
        let depth = 1u32 << log_rq_size;
        let mut rx_buffers = alloc::vec::Vec::with_capacity(depth as usize);
        rx_buffers.resize(depth as usize, RxBufferInfo::default());

        Self {
            rqn,
            buf_virt,
            buf_device,
            doorbell_virt,
            log_rq_size,
            rq_depth: depth,
            producer_counter: 0,
            cqn,
            tirn: 0,
            rx_buffers,
            mkey,
            csum_offload,
        }
    }

    /// 受信バッファをRQに投入
    ///
    /// # Arguments
    /// - `device_addr`: 受信バッファのデバイスアドレス (IOMMU IOVA)
    /// - `buf_virt`: 受信バッファの仮想アドレス
    /// - `buf_size`: バッファサイズ
    ///
    /// # Safety
    /// - buf_virt が有効なマッピングであること
    /// - device_addr がDMAアクセス可能であること
    ///
    /// # Returns
    /// 投入したWQEインデックス
    pub unsafe fn post_recv(
        &mut self,
        device_addr: u64,
        buf_virt: u64,
        buf_size: u32,
    ) -> Option<u16> {
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
        write_be64_raw(wqe_ptr, wqe::data::ADDR, device_addr);

        // バッファトラッキング
        self.rx_buffers[buf_idx] = RxBufferInfo {
            virt_addr: buf_virt,
            device_addr,
            size: buf_size,
            in_use: true,
            l3_ok: false,
            l4_ok: false,
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
    pub fn complete_rx(&mut self, wqe_counter: u16, l3_ok: bool, l4_ok: bool) -> Option<RxBufferInfo> {
        let idx = (wqe_counter as u32 % self.rq_depth) as usize;
        if self.rx_buffers[idx].in_use {
            let mut info = self.rx_buffers[idx];
            info.l3_ok = l3_ok;
            info.l4_ok = l4_ok;
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

    /// RQバッファのデバイスアドレス
    pub fn buffer_device(&self) -> u64 {
        self.buf_device
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
