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
    /// 送信バッファトラッキング (WQEBB単位で管理、4 WQEBB = 1 WQE)
    tx_buffers: alloc::vec::Vec<Option<TxBufferInfo>>,
    /// WQE ごとのデバッグスナップショット
    debug_wqe_ring: alloc::vec::Vec<TxWqeDebugInfo>,
    /// Memory Key (L-Key)
    pub mkey: u32,
    /// チェックサムオフロード対応
    pub csum_offload: bool,
    /// 直近の BlueFlame バッファオフセット
    last_bf_offset: u16,
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
        // WQE 1つあたり 4 WQEBB (64 bytes)
        let mut tx_buffers = alloc::vec::Vec::with_capacity((depth * 4) as usize);
        tx_buffers.resize((depth * 4) as usize, None);
        let mut debug_wqe_ring = alloc::vec::Vec::with_capacity(depth as usize);
        debug_wqe_ring.resize(depth as usize, TxWqeDebugInfo::default());

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
            debug_wqe_ring,
            mkey,
            csum_offload,
            last_bf_offset: 0,
        }
    }

    /// 送信可能なWQEスロットがあるか
    pub fn has_space(&self) -> bool {
        // 次の WQE の最初の WQEBB が未使用かチェック
        let wqe_idx = (self.producer_counter as u32 % self.sq_depth) as usize;
        let bb_idx = wqe_idx * 4;
        self.tx_buffers[bb_idx].is_none()
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
    /// 挿入する VLAN タグ (TCI)。0 の場合は挿入しない。
    pub vlan_tag: u16,
}

impl SendQueue {
    unsafe fn record_wqe_debug_snapshot(
        &mut self,
        buf_idx: usize,
        wqe_counter: u16,
        wqe_ptr: *const u8,
        inline_hdr_sz: u16,
        data_seg_ptr: *const u8,
    ) {
        let mut wqe_bytes = [0u8; 64];
        core::ptr::copy_nonoverlapping(wqe_ptr, wqe_bytes.as_mut_ptr(), 64);
        self.debug_wqe_ring[buf_idx] = TxWqeDebugInfo {
            valid: true,
            wqe_counter,
            wqe_addr: wqe_ptr as u64,
            inline_hdr_sz,
            opmod_idx: read_be32_raw(wqe_ptr, wqe::ctrl::OPMOD_IDX_OPCODE),
            qpn_ds: read_be32_raw(wqe_ptr, wqe::ctrl::QPN_DS),
            general_id: read_be32_raw(wqe_ptr, wqe::ctrl::GENERAL_ID),
            byte_count: read_be32_raw(data_seg_ptr, wqe::data::BYTE_COUNT),
            lkey: read_be32_raw(data_seg_ptr, wqe::data::LKEY),
            device_addr: read_be64_raw(data_seg_ptr, wqe::data::ADDR),
            wqe_bytes,
        };
    }

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

        let inline_len = inline_hdr.len().min(u16::MAX as usize);
        let inline_ds = if inline_len > 2 {
            (inline_len - 2).div_ceil(16)
        } else {
            0
        };
        let ds_count = 2 + inline_ds as u32 + segments.len() as u32;
        if ds_count > 4 {
            return None;
        }

        let wqe_idx = self.producer_counter;
        let buf_idx = (wqe_idx as u32 % self.sq_depth) as usize;

        let wqe_offset = buf_idx * 64;
        let wqe_ptr = (self.buf_virt as usize + wqe_offset) as *mut u8;
        core::ptr::write_bytes(wqe_ptr, 0, 64);

        // Control Segment (16 bytes)
        let ctrl_ptr = wqe_ptr;
        let opmod_idx = ((wqe_idx as u32) << 8) | (WqeOpcode::EthSend as u32);
        write_be32_raw(ctrl_ptr, wqe::ctrl::OPMOD_IDX_OPCODE, opmod_idx);
        let qpn_ds = ((self.sqn & 0x00FF_FFFF) << 8) | ds_count;
        write_be32_raw(ctrl_ptr, wqe::ctrl::QPN_DS, qpn_ds);
        write_u8_raw(ctrl_ptr, wqe::ctrl::FM_CE_SE, MLX5_WQE_CTRL_CQ_UPDATE);

        // Ethernet Segment (16 bytes)
        let eth_ptr = ctrl_ptr.add(16);
        let _ = options.vlan_tag;

        // チェックサムオフロードおよび TSO 設定
        let mut cs_flags = 0u8;
        if self.csum_offload {
            if options.l3_cs {
                cs_flags |= MLX5_ETH_WQE_L3_CSUM;
            }
            if options.l4_cs {
                cs_flags |= MLX5_ETH_WQE_L4_CSUM;
            }
        }
        write_u8_raw(eth_ptr, wqe::eth::CS_FLAGS, cs_flags);

        // TSO MSS
        write_be16_raw(eth_ptr, wqe::eth::MSS, options.mss);

        if inline_len > 0 {
            write_be16_raw(
                eth_ptr,
                wqe::eth::TRAILER_OR_INLINE_HDR_SZ,
                inline_len as u16,
            );
            core::ptr::copy_nonoverlapping(
                inline_hdr.as_ptr(),
                eth_ptr.add(wqe::eth::INLINE_HDR_START),
                inline_len,
            );
        }

        let data_seg_base = 32 + inline_ds * 16;

        // Data Segments (16 bytes each) after the optional inline header spill area
        for (i, seg) in segments.iter().enumerate() {
            let data_seg_ptr = ctrl_ptr.add(data_seg_base + i * 16);
            // Byte count
            write_be32_raw(data_seg_ptr, wqe::data::BYTE_COUNT, seg.len);
            // L-Key (Memory Key)
            write_be32_raw(data_seg_ptr, wqe::data::LKEY, self.mkey);
            // Address (64-bit device address)
            write_be64_raw(data_seg_ptr, wqe::data::ADDR, seg.device_addr);
        }

        let first_data_seg_ptr = ctrl_ptr.add(data_seg_base);
        self.record_wqe_debug_snapshot(
            buf_idx,
            wqe_idx,
            wqe_ptr as *const u8,
            inline_len as u16,
            first_data_seg_ptr as *const u8,
        );

        // バッファトラッキング
        let bb_idx = buf_idx * 4;
        self.tx_buffers[bb_idx] = Some(TxBufferInfo {
            virt_addr: segments[0].virt_addr,
            device_addr: segments[0].device_addr,
            size: segments[0].len,
            in_use: true,
        });

        // プロデューサカウンタを進める
        self.producer_counter = self.producer_counter.wrapping_add(1);

        // SQドアベル更新
        self.ring_doorbell(wqe_ptr);

        Some(wqe_idx)
    }

    /// Enhanced Multi-Packet WQE (MPWQE) を構築して投入
    /// 同一サイズの複数パケットを1つのWQEで効率的に送信する。
    pub unsafe fn post_send_mpwqe(
        &mut self,
        packets: &[DmaSegment],
        options: TxOptions,
    ) -> Option<u16> {
        // Enhanced MPWQE は最大 4 Data Segments (1 WQEBB = 1 Data Segment)
        // Control(1) + Eth(1) + Data(2) = 1 WQE (4 WQEBB)
        if !self.has_space() || packets.is_empty() || packets.len() > 2 {
            return None;
        }

        let wqe_idx = self.producer_counter;
        let buf_idx = (wqe_idx as u32 % self.sq_depth) as usize;
        let wqe_offset = buf_idx * 64;
        let wqe_ptr = (self.buf_virt as usize + wqe_offset) as *mut u8;
        core::ptr::write_bytes(wqe_ptr, 0, 64);

        // Control Segment
        let ctrl_ptr = wqe_ptr;
        let opmod_idx = ((wqe_idx as u32) << 8) | (WqeOpcode::EnhancedMpwqe as u32);
        write_be32_raw(ctrl_ptr, wqe::ctrl::OPMOD_IDX_OPCODE, opmod_idx);
        let ds_count = 2 + packets.len() as u32;
        let qpn_ds = ((self.sqn & 0x00FF_FFFF) << 8) | ds_count;
        write_be32_raw(ctrl_ptr, wqe::ctrl::QPN_DS, qpn_ds);
        write_u8_raw(ctrl_ptr, wqe::ctrl::FM_CE_SE, MLX5_WQE_CTRL_CQ_UPDATE);

        // Ethernet Segment (MPWQEではパケット間の共通設定を保持)
        let eth_ptr = ctrl_ptr.add(16);
        let _ = options.vlan_tag;

        let mut cs_flags = 0u8;
        if self.csum_offload {
            if options.l3_cs {
                cs_flags |= MLX5_ETH_WQE_L3_CSUM;
            }
            if options.l4_cs {
                cs_flags |= MLX5_ETH_WQE_L4_CSUM;
            }
        }
        write_u8_raw(eth_ptr, wqe::eth::CS_FLAGS, cs_flags);
        write_be16_raw(eth_ptr, wqe::eth::MSS, options.mss);
        // MPWQE では inline header は通常使用しない（各パケットが独立した L2 ヘッダを持つため）

        // Data Segments
        for (i, pkt) in packets.iter().enumerate() {
            let data_seg_ptr = ctrl_ptr.add(32 + i * 16);
            write_be32_raw(data_seg_ptr, wqe::data::BYTE_COUNT, pkt.len);
            write_be32_raw(data_seg_ptr, wqe::data::LKEY, self.mkey);
            write_be64_raw(data_seg_ptr, wqe::data::ADDR, pkt.device_addr);

            // 各パケットのバッファをトラッキング
            let bb_idx = buf_idx * 4 + 2 + i; // Control(0), Eth(1), Data(2,3)
            self.tx_buffers[bb_idx] = Some(TxBufferInfo {
                virt_addr: pkt.virt_addr,
                device_addr: pkt.device_addr,
                size: pkt.len,
                in_use: true,
            });
        }

        let first_data_seg_ptr = ctrl_ptr.add(32);
        self.record_wqe_debug_snapshot(
            buf_idx,
            wqe_idx,
            wqe_ptr as *const u8,
            0,
            first_data_seg_ptr as *const u8,
        );

        // 最初の WQEBB にもマーカーを置く（has_space チェック用）
        let bb0_idx = buf_idx * 4;
        if self.tx_buffers[bb0_idx].is_none() {
            self.tx_buffers[bb0_idx] = Some(TxBufferInfo {
                virt_addr: 0,
                device_addr: 0,
                size: 0,
                in_use: true,
            });
        }

        self.producer_counter = self.producer_counter.wrapping_add(1);
        self.ring_doorbell(wqe_ptr);

        Some(wqe_idx)
    }

    /// SQドアベルをリング
    ///
    /// # Safety
    /// - uar_base が有効であること
    unsafe fn ring_doorbell(&mut self, wqe_ptr: *const u8) {
        // Maintain the standard mlx5 SQ doorbell ordering:
        //  1. make WQE visible
        //  2. publish producer counter in DB record
        //  3. issue a write barrier before the MMIO doorbell
        let fm_ce_se =
            core::ptr::read_volatile(wqe_ptr.add(wqe::ctrl::FM_CE_SE)) | MLX5_WQE_CTRL_CQ_UPDATE;
        write_u8_raw(wqe_ptr as *mut u8, wqe::ctrl::FM_CE_SE, fm_ce_se);
        dma_store_barrier();

        // Send queues use the SND_DBR slot (word 1) in the WQ doorbell record.
        let db_ptr = (self.doorbell_virt as *mut u32).add(1);
        core::ptr::write_volatile(db_ptr, (self.producer_counter as u32).to_be());
        fence(Ordering::SeqCst);
        hal::mmio::sfence();

        // Ring the SQ via the selected BF register base without per-packet
        // slot toggling. Use the first BF slot until bfreg allocation is
        // modeled explicitly.
        let bf_addr = self.uar_base as usize + crate::regs::uar::BLUEFLAME;
        let ctrl_qword = core::ptr::read_unaligned(wqe_ptr as *const u64);
        hal::mmio::mmio_write_u64(bf_addr, ctrl_qword);
        self.last_bf_offset = 0;
    }

    /// 送信完了を処理（CQEのWQEカウンタに基づくバッファ解放）
    pub fn complete_tx(&mut self, wqe_counter: u16) -> alloc::vec::Vec<TxBufferInfo> {
        let buf_idx = (wqe_counter as u32 % self.sq_depth) as usize;
        let mut completed = alloc::vec::Vec::new();

        // WQE に含まれる全 WQEBB (最大4つ) をチェックして解放
        for i in 0..4 {
            let bb_idx = buf_idx * 4 + i;
            if let Some(info) = self.tx_buffers[bb_idx].take() {
                if info.size > 0 {
                    // マーカー（size=0）は含めない
                    completed.push(info);
                }
            }
        }
        completed
    }

    /// SQ の状態をデバッグ用に取得
    ///
    /// # Safety
    /// - SQ バッファと doorbell_virt が有効であること
    pub unsafe fn debug_state(&self) -> TxQueueDebugState {
        let last_wqe_counter = self.producer_counter.wrapping_sub(1);
        let last_idx = (last_wqe_counter as u32 % self.sq_depth) as usize;
        let last_wqe_ptr = (self.buf_virt as usize + last_idx * 64) as *const u8;
        let last_inline_hdr_sz =
            read_be16_raw(last_wqe_ptr.add(16), wqe::eth::TRAILER_OR_INLINE_HDR_SZ) as usize;
        let last_inline_ds = if last_inline_hdr_sz > 2 {
            (last_inline_hdr_sz - 2).div_ceil(16)
        } else {
            0
        };
        let last_data_seg_ptr = last_wqe_ptr.add(32 + last_inline_ds * 16);

        let doorbell_be = core::ptr::read_volatile((self.doorbell_virt as *const u32).add(1));
        let doorbell_host = u32::from_be(doorbell_be) & 0x0000_ffff;
        let mut last_wqe_bytes = [0u8; 64];
        core::ptr::copy_nonoverlapping(last_wqe_ptr, last_wqe_bytes.as_mut_ptr(), 64);

        TxQueueDebugState {
            sqn: self.sqn,
            tisn: self.tisn,
            producer_counter: self.producer_counter,
            sq_depth: self.sq_depth,
            doorbell_be,
            doorbell_host,
            last_wqe_counter,
            last_wqe_addr: last_wqe_ptr as u64,
            last_wqe_inline_hdr_sz: last_inline_hdr_sz as u16,
            last_wqe_opmod_idx: read_be32_raw(last_wqe_ptr, wqe::ctrl::OPMOD_IDX_OPCODE),
            last_wqe_qpn_ds: read_be32_raw(last_wqe_ptr, wqe::ctrl::QPN_DS),
            last_wqe_general_id: read_be32_raw(last_wqe_ptr, wqe::ctrl::GENERAL_ID),
            last_wqe_byte_count: read_be32_raw(last_data_seg_ptr, wqe::data::BYTE_COUNT),
            last_wqe_lkey: read_be32_raw(last_data_seg_ptr, wqe::data::LKEY),
            last_wqe_device_addr: read_be64_raw(last_data_seg_ptr, wqe::data::ADDR),
            last_bf_offset: self.last_bf_offset,
            last_wqe_bytes,
        }
    }

    /// 指定した WQE カウンタに対応する送信 WQE のデバッグ情報を取得
    ///
    /// # Safety
    /// - SQ メモリが有効であること
    pub unsafe fn debug_wqe_state(&self, wqe_counter: u16) -> Option<TxWqeDebugInfo> {
        let idx = (wqe_counter as u32 % self.sq_depth) as usize;
        let info = *self.debug_wqe_ring.get(idx)?;
        if info.valid && info.wqe_counter == wqe_counter {
            Some(info)
        } else {
            None
        }
    }
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
    pub last_wqe_inline_hdr_sz: u16,
    pub last_wqe_opmod_idx: u32,
    pub last_wqe_qpn_ds: u32,
    pub last_wqe_general_id: u32,
    pub last_wqe_byte_count: u32,
    pub last_wqe_lkey: u32,
    pub last_wqe_device_addr: u64,
    pub last_bf_offset: u16,
    pub last_wqe_bytes: [u8; 64],
}

#[derive(Debug, Clone, Copy)]
pub struct TxWqeDebugInfo {
    pub valid: bool,
    pub wqe_counter: u16,
    pub wqe_addr: u64,
    pub inline_hdr_sz: u16,
    pub opmod_idx: u32,
    pub qpn_ds: u32,
    pub general_id: u32,
    pub byte_count: u32,
    pub lkey: u32,
    pub device_addr: u64,
    pub wqe_bytes: [u8; 64],
}

impl Default for TxWqeDebugInfo {
    fn default() -> Self {
        Self {
            valid: false,
            wqe_counter: 0,
            wqe_addr: 0,
            inline_hdr_sz: 0,
            opmod_idx: 0,
            qpn_ds: 0,
            general_id: 0,
            byte_count: 0,
            lkey: 0,
            device_addr: 0,
            wqe_bytes: [0u8; 64],
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
    /// 実際に採用された RQ レイアウト
    layout: ResolvedRqLayout,
    /// プロデューサインデックス
    producer_counter: u16,
    /// 紐づくCQ番号
    pub cqn: u32,
    /// TIR (Transport Interface Receive) 番号
    pub tirn: u32,
    /// 受信バッファトラッキング
    rx_buffers: alloc::vec::Vec<RxBufferInfo>,
    /// HW に公開済みスロットの FIFO
    inflight_slots: VecDeque<u16>,
    /// 再利用可能なスロットの FIFO
    free_slots: VecDeque<u16>,
    /// 最後に投入したスロット
    last_posted_slot: Option<u16>,
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
        layout: ResolvedRqLayout,
        mkey: u32,
        csum_offload: bool,
    ) -> Self {
        let depth = 1u32 << log_rq_size;
        let mut rx_buffers = alloc::vec::Vec::with_capacity(depth as usize);
        rx_buffers.resize(depth as usize, RxBufferInfo::default());
        let mut free_slots = VecDeque::with_capacity(depth as usize);
        for slot in 0..depth {
            free_slots.push_back(slot as u16);
        }

        Self {
            rqn,
            buf_virt,
            buf_device,
            doorbell_virt,
            log_rq_size,
            rq_depth: depth,
            layout,
            producer_counter: 0,
            cqn,
            tirn: 0,
            rx_buffers,
            inflight_slots: VecDeque::with_capacity(depth as usize),
            free_slots,
            last_posted_slot: None,
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
        let slot_index = self.free_slots.pop_front()?;
        let buf_idx = slot_index as usize;

        if self.rx_buffers[buf_idx].in_use {
            self.free_slots.push_front(slot_index);
            return None; // キューフル
        }

        let wqe_offset = self.layout.slot_offset(slot_index);
        let wqe_ptr = (self.buf_virt as usize + wqe_offset) as *mut u8;
        core::ptr::write_bytes(wqe_ptr, 0, self.layout.slot_size_bytes);

        if self.layout.has_next_segment {
            let next_slot = ((slot_index as u32 + 1) % self.rq_depth) as u16;
            self.write_link_segment(wqe_ptr, next_slot);
        }

        let data_seg_ptr = wqe_ptr.add(self.layout.data_seg_offset());
        write_be32_raw(data_seg_ptr, wqe::data::BYTE_COUNT, buf_size);
        write_be32_raw(data_seg_ptr, wqe::data::LKEY, self.mkey);
        write_be64_raw(data_seg_ptr, wqe::data::ADDR, device_addr);

        // バッファトラッキング
        self.rx_buffers[buf_idx] = RxBufferInfo {
            slot_index,
            virt_addr: buf_virt,
            device_addr,
            size: buf_size,
            in_use: true,
            l3_ok: false,
            l4_ok: false,
        };

        // プロデューサカウンタを進める
        self.producer_counter = self.producer_counter.wrapping_add(1);
        self.inflight_slots.push_back(slot_index);
        self.last_posted_slot = Some(slot_index);

        // ドアベル更新
        fence(Ordering::Release);
        let db_val: u32 = self.producer_counter as u32 & 0x0000_FFFF;
        let db_ptr = self.doorbell_virt as *mut u32;
        core::ptr::write_volatile(db_ptr, db_val.to_be());

        Some(wqe_idx)
    }

    /// 受信完了を処理して受信バッファ情報を返す
    pub fn complete_rx(
        &mut self,
        wqe_counter: u16,
        l3_ok: bool,
        l4_ok: bool,
    ) -> Option<RxBufferInfo> {
        let slot_index = match self.layout.wq_mode {
            RxWqMode::Cyclic => self.resolve_cyclic_completion_slot(wqe_counter)?,
            RxWqMode::LinkedList => self.take_linked_completion_slot(wqe_counter)?,
        };

        self.complete_rx_slot(slot_index, wqe_counter, l3_ok, l4_ok)
    }

    /// RQの空きスロット数
    pub fn available_slots(&self) -> u32 {
        self.free_slots.len() as u32
    }

    /// RQバッファのデバイスアドレス
    pub fn buffer_device(&self) -> u64 {
        self.buf_device
    }

    /// RQ の状態をデバッグ用に取得
    ///
    /// # Safety
    /// - RQ バッファと doorbell_virt が有効であること
    pub unsafe fn debug_state(&self) -> RxQueueDebugState {
        let last_wqe_counter = self.producer_counter.wrapping_sub(1);
        let last_wqe_ptr = self
            .last_posted_slot
            .map(|slot| (self.buf_virt as usize + self.layout.slot_offset(slot)) as *const u8)
            .unwrap_or(self.buf_virt as *const u8);
        let data_seg_ptr = last_wqe_ptr.add(self.layout.data_seg_offset());

        let doorbell_be = core::ptr::read_volatile(self.doorbell_virt as *const u32);
        let doorbell_host = u32::from_be(doorbell_be) & 0x0000_ffff;

        RxQueueDebugState {
            rqn: self.rqn,
            producer_counter: self.producer_counter,
            rq_depth: self.rq_depth,
            available_slots: self.available_slots(),
            layout_mode: self.layout.wq_mode,
            layout_slot_size_bytes: self.layout.slot_size_bytes,
            layout_data_seg_offset: self.layout.data_seg_offset,
            layout_raw_wq_type: self.layout.raw_wq_type,
            layout_raw_log_wq_stride: self.layout.raw_log_wq_stride,
            layout_rmpn: self.layout.rmpn,
            doorbell_be,
            doorbell_host,
            last_wqe_counter,
            last_wqe_addr: last_wqe_ptr as u64,
            last_wqe_byte_count: read_be32_raw(data_seg_ptr, wqe::data::BYTE_COUNT),
            last_wqe_lkey: read_be32_raw(data_seg_ptr, wqe::data::LKEY),
            last_wqe_device_addr: read_be64_raw(data_seg_ptr, wqe::data::ADDR),
        }
    }

    unsafe fn write_link_segment(&self, slot_ptr: *mut u8, next_slot: u16) {
        const NEXT_SEG_NEXT_WQE_INDEX: usize = 0x02;
        let next_stride_index =
            (self.layout.slot_offset(next_slot) / ResolvedRqLayout::LINK_SEG_SIZE) as u16;
        write_be16_raw(slot_ptr, NEXT_SEG_NEXT_WQE_INDEX, next_stride_index);
    }

    fn resolve_cyclic_completion_slot(&mut self, wqe_counter: u16) -> Option<u16> {
        let expected_slot = (wqe_counter as u32 % self.rq_depth) as u16;
        let front_slot = self.inflight_slots.front().copied()?;

        if !self.rx_buffers[expected_slot as usize].in_use {
            log::warn!(
                target: "mlx5",
                "RX completion referenced inactive cyclic slot: rqn={:#x} wqe_counter={} expected_slot={} front_slot={} inflight_len={}",
                self.rqn,
                wqe_counter,
                expected_slot,
                front_slot,
                self.inflight_slots.len()
            );
            return None;
        }

        if front_slot == expected_slot {
            let _ = self.inflight_slots.pop_front();
            return Some(expected_slot);
        }

        if let Some(position) = self
            .inflight_slots
            .iter()
            .position(|&slot| slot == expected_slot)
        {
            let removed = self
                .inflight_slots
                .remove(position)
                .unwrap_or(expected_slot);
            log::warn!(
                target: "mlx5",
                "RX completion slot mismatch recovered: rqn={:#x} mode={} wqe_counter={} expected_slot={} front_slot={} recovered_pos={}",
                self.rqn,
                self.layout.wq_mode.label(),
                wqe_counter,
                expected_slot,
                front_slot,
                position
            );
            return Some(removed);
        }

        log::warn!(
            target: "mlx5",
            "RX completion slot mismatch unrecoverable: rqn={:#x} mode={} wqe_counter={} expected_slot={} front_slot={} inflight_len={}",
            self.rqn,
            self.layout.wq_mode.label(),
            wqe_counter,
            expected_slot,
            front_slot,
            self.inflight_slots.len()
        );
        None
    }

    fn take_linked_completion_slot(&mut self, wqe_counter: u16) -> Option<u16> {
        let slot_index = self.inflight_slots.front().copied()?;
        if !self.rx_buffers[slot_index as usize].in_use {
            log::warn!(
                target: "mlx5",
                "RX completion referenced inactive linked slot: rqn={:#x} wqe_counter={} slot={} inflight_len={}",
                self.rqn,
                wqe_counter,
                slot_index,
                self.inflight_slots.len()
            );
            return None;
        }

        let _ = self.inflight_slots.pop_front();
        Some(slot_index)
    }

    fn complete_rx_slot(
        &mut self,
        slot_index: u16,
        wqe_counter: u16,
        l3_ok: bool,
        l4_ok: bool,
    ) -> Option<RxBufferInfo> {
        let idx = slot_index as usize;
        if self.rx_buffers[idx].in_use {
            let mut info = self.rx_buffers[idx];
            info.l3_ok = l3_ok;
            info.l4_ok = l4_ok;
            self.rx_buffers[idx] = RxBufferInfo::default();
            self.free_slots.push_back(slot_index);
            Some(info)
        } else {
            log::warn!(
                target: "mlx5",
                "RX completion referenced empty slot after selection: rqn={:#x} slot={} wqe_counter={}",
                self.rqn,
                slot_index,
                wqe_counter
            );
            None
        }
    }
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
        let inflight_before = rq.inflight_slots.clone();
        let free_before = rq.free_slots.clone();

        assert!(rq.complete_rx(2, false, false).is_none());
        assert_eq!(rq.inflight_slots, inflight_before);
        assert_eq!(rq.free_slots, free_before);
        assert_eq!(rq.available_slots(), 0);
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
