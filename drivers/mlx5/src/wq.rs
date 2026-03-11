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
use core::sync::atomic::{Ordering, compiler_fence, fence};

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
        // Match Linux mlx5e_notify_hw ordering:
        //  1. make WQE visible
        //  2. publish producer counter in DB record
        //  3. issue a write barrier before the MMIO doorbell
        let fm_ce_se =
            core::ptr::read_volatile(wqe_ptr.add(wqe::ctrl::FM_CE_SE)) | MLX5_WQE_CTRL_CQ_UPDATE;
        write_u8_raw(wqe_ptr as *mut u8, wqe::ctrl::FM_CE_SE, fm_ce_se);
        fence(Ordering::Release);

        // Send queues use the SND_DBR slot (word 1) in the WQ doorbell record.
        let db_ptr = (self.doorbell_virt as *mut u32).add(1);
        core::ptr::write_volatile(db_ptr, (self.producer_counter as u32).to_be());
        compiler_fence(Ordering::Release);
        hal::mmio::sfence();

        // Linux rings the SQ via the selected BF register base without
        // per-packet slot toggling. Use the first BF slot until bfreg
        // allocation is modeled explicitly.
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

    /// RQ の状態をデバッグ用に取得
    ///
    /// # Safety
    /// - RQ バッファと doorbell_virt が有効であること
    pub unsafe fn debug_state(&self) -> RxQueueDebugState {
        let last_wqe_counter = self.producer_counter.wrapping_sub(1);
        let last_idx = (last_wqe_counter as u32 % self.rq_depth) as usize;
        let last_wqe_ptr = (self.buf_virt as usize + last_idx * WQEBB_SIZE) as *const u8;

        let doorbell_be = core::ptr::read_volatile(self.doorbell_virt as *const u32);
        let doorbell_host = u32::from_be(doorbell_be) & 0x0000_ffff;

        RxQueueDebugState {
            rqn: self.rqn,
            producer_counter: self.producer_counter,
            rq_depth: self.rq_depth,
            available_slots: self.available_slots(),
            doorbell_be,
            doorbell_host,
            last_wqe_counter,
            last_wqe_addr: last_wqe_ptr as u64,
            last_wqe_byte_count: read_be32_raw(last_wqe_ptr, wqe::data::BYTE_COUNT),
            last_wqe_lkey: read_be32_raw(last_wqe_ptr, wqe::data::LKEY),
            last_wqe_device_addr: read_be64_raw(last_wqe_ptr, wqe::data::ADDR),
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
