// ============================================================================
// drivers/mlx5/src/cq.rs - Completion Queue
// ============================================================================
//! Completion Queue (CQ) — 送受信の完了通知キュー
//!
//! CQはSQ/RQの操作完了をSWに通知するためのリングバッファ。
//! 各CQエントリ（CQE）は64バイトで、完了した操作の詳細情報を含む。

use crate::defs::CqeOpcode;
use crate::regs::{cqe as cqe_regs, uar};
use core::sync::atomic::{AtomicU32, Ordering};

/// Completion Queue Entry (CQE) — 64バイト
#[repr(C, align(64))]
#[derive(Clone, Copy)]
pub struct Cqe {
    pub data: [u8; cqe_regs::SIZE],
}

impl Cqe {
    pub const fn zeroed() -> Self {
        Self {
            data: [0u8; cqe_regs::SIZE],
        }
    }

    /// オペコードを取得
    pub fn opcode(&self) -> CqeOpcode {
        CqeOpcode::from_u8((self.data[cqe_regs::OP_OWN] >> 4) & 0x0F)
    }

    /// オーナービット（cycle bit）を取得
    pub fn owner_bit(&self) -> u8 {
        self.data[cqe_regs::OP_OWN] & 0x01
    }

    /// SWが所有しているか確認
    pub fn is_sw_owned(&self, consumer_counter: u32, log_cq_size: u8) -> bool {
        let expected = ((consumer_counter >> log_cq_size) & 1) as u8;
        self.owner_bit() == expected
    }

    /// CQE上の byte_cnt dword をそのまま読む
    pub fn raw_byte_count(&self) -> u32 {
        u32::from_be_bytes([
            self.data[cqe_regs::BYTE_COUNT],
            self.data[cqe_regs::BYTE_COUNT + 1],
            self.data[cqe_regs::BYTE_COUNT + 2],
            self.data[cqe_regs::BYTE_COUNT + 3],
        ])
    }

    /// 受信バイトカウント
    pub fn byte_count(&self) -> u32 {
        if self.is_error() {
            0
        } else {
            self.raw_byte_count()
        }
    }

    /// WQEカウンタ（SQ/RQインデックス）
    pub fn wqe_counter(&self) -> u16 {
        u16::from_be_bytes([
            self.data[cqe_regs::WQE_COUNTER],
            self.data[cqe_regs::WQE_COUNTER + 1],
        ])
    }

    /// QP番号
    pub fn qpn(&self) -> u32 {
        let raw = u32::from_be_bytes([
            self.data[cqe_regs::QPN],
            self.data[cqe_regs::QPN + 1],
            self.data[cqe_regs::QPN + 2],
            self.data[cqe_regs::QPN + 3],
        ]);
        raw & 0x00FF_FFFF
    }

    /// CQEが有効な（非ゼロ）完了を含むか
    pub fn is_valid_completion(&self) -> bool {
        let op = self.opcode();
        matches!(
            op,
            CqeOpcode::ReqOk
                | CqeOpcode::RespWriteImm
                | CqeOpcode::RespOk
                | CqeOpcode::RespSendImm
                | CqeOpcode::RespSendInv
        )
    }

    /// エラーかチェック
    pub fn is_error(&self) -> bool {
        let op = self.opcode();
        matches!(op, CqeOpcode::ReqErr | CqeOpcode::RespErr)
    }

    /// チェックサムステータス (L3 OK)
    pub fn l3_ok(&self) -> bool {
        false
    }

    /// チェックサムステータス (L4 OK)
    pub fn l4_ok(&self) -> bool {
        false
    }

    /// VLANタグが存在するか確認
    pub fn vlan_present(&self) -> bool {
        (self.data[cqe_regs::L4_L3_HDR_TYPE] & 0x01) != 0
    }

    /// VLANタグ（TCI: Tag Control Information）を取得
    pub fn vlan_tag(&self) -> u16 {
        u16::from_be_bytes([
            self.data[cqe_regs::VLAN_INFO],
            self.data[cqe_regs::VLAN_INFO + 1],
        ])
    }

    /// ハードウェアタイムスタンプを取得 (64-bit)
    pub fn timestamp(&self) -> u64 {
        let hi = u32::from_be_bytes([
            self.data[cqe_regs::TIMESTAMP_H],
            self.data[cqe_regs::TIMESTAMP_H + 1],
            self.data[cqe_regs::TIMESTAMP_H + 2],
            self.data[cqe_regs::TIMESTAMP_H + 3],
        ]) as u64;
        let lo = u32::from_be_bytes([
            self.data[cqe_regs::TIMESTAMP_L],
            self.data[cqe_regs::TIMESTAMP_L + 1],
            self.data[cqe_regs::TIMESTAMP_L + 2],
            self.data[cqe_regs::TIMESTAMP_L + 3],
        ]) as u64;
        (hi << 32) | lo
    }

    /// エラーCQEの vendor error syndrome
    pub fn error_vendor_syndrome(&self) -> Option<u8> {
        self.is_error()
            .then_some(self.data[cqe_regs::ERR_VENDOR_SYNDROME])
    }

    /// エラーCQEの syndrome
    pub fn error_syndrome(&self) -> Option<u8> {
        self.is_error().then_some(self.data[cqe_regs::ERR_SYNDROME])
    }

    /// エラーCQEに含まれる source WQE opcode
    pub fn error_wqe_opcode(&self) -> Option<u8> {
        self.is_error().then_some(self.data[cqe_regs::QPN])
    }
}

/// Completion Queue 管理構造体
pub struct CompletionQueue {
    /// CQのハードウェア番号（CREATE_CQで返される）
    pub cqn: u32,
    /// CQバッファ仮想アドレス
    buf_virt: u64,
    /// CQバッファ物理アドレス
    buf_phys: u64,
    /// UAR（User Access Region）ベースアドレス
    uar_base: u64,
    /// ドアベルレコードの仮想アドレス（8バイト: CQ番号 + CI）
    doorbell_virt: u64,
    /// ログ2 CQサイズ
    log_cq_size: u8,
    /// CQエントリ数
    cq_depth: u32,
    /// コンシューマカウンタ
    consumer_counter: u32,
    /// 紐づくEQ番号
    pub eq_number: u32,
    /// CQ ARM シーケンス番号
    arm_sn: AtomicU32,
}

impl CompletionQueue {
    /// 新しいCompletion Queueを作成
    pub fn new(
        cqn: u32,
        buf_virt: u64,
        buf_phys: u64,
        uar_base: u64,
        doorbell_virt: u64,
        log_cq_size: u8,
        eq_number: u32,
    ) -> Self {
        Self {
            cqn,
            buf_virt,
            buf_phys,
            uar_base,
            doorbell_virt,
            log_cq_size,
            cq_depth: 1 << log_cq_size,
            consumer_counter: 0,
            eq_number,
            arm_sn: AtomicU32::new(0),
        }
    }

    /// CQバッファの物理アドレス
    pub fn buffer_phys(&self) -> u64 {
        self.buf_phys
    }

    /// 次のCQEを取得
    ///
    /// # Safety
    /// - buf_virt が有効なマッピングであること
    pub unsafe fn poll_cqe(&self) -> Option<&Cqe> {
        let idx = (self.consumer_counter % self.cq_depth) as usize;
        let cqe_ptr = (self.buf_virt as usize + idx * cqe_regs::SIZE) as *const Cqe;
        let cqe_ref = &*cqe_ptr;

        if cqe_ref.is_sw_owned(self.consumer_counter, self.log_cq_size) {
            Some(cqe_ref)
        } else {
            None
        }
    }

    /// コンシューマカウンタを進める
    pub fn advance_consumer(&mut self) {
        self.consumer_counter = self.consumer_counter.wrapping_add(1);
    }

    /// CQドアベルを更新
    ///
    /// # Safety
    /// - doorbell_virt が有効であること
    pub unsafe fn update_doorbell(&self) {
        // ドアベルレコード: [31:8] = consumer_counter, [7:0] = reserved
        let db_val: u32 = self.consumer_counter & 0x00FF_FFFF;
        let db_ptr = self.doorbell_virt as *mut u32;
        core::ptr::write_volatile(db_ptr, db_val.to_be());
    }

    /// CQをARMする（次のイベント通知をEQに要求）
    ///
    /// # Safety
    /// - uar_base が有効であること
    pub unsafe fn arm(&self) {
        // Linux/PRM format:
        // doorbell[0] = be32(sn << 28 | cmd | ci), doorbell[1] = be32(cqn)
        // written as a single raw 64-bit MMIO store to MLX5_CQ_DOORBELL.
        let sn = self.arm_sn.fetch_add(1, Ordering::Relaxed) & 0x3;
        let ci = self.consumer_counter & 0x00FF_FFFF;
        let arm_db = (sn << 28) | ci;
        let arm_db_ptr = (self.doorbell_virt as *mut u32).add(1);
        core::ptr::write_volatile(arm_db_ptr, arm_db.to_be());
        core::sync::atomic::fence(Ordering::Release);
        let mut raw = [0u8; 8];
        raw[..4].copy_from_slice(&arm_db.to_be_bytes());
        raw[4..].copy_from_slice(&self.cqn.to_be_bytes());
        let arm_val = u64::from_ne_bytes(raw);
        hal::mmio::mmio_write_u64(self.uar_base as usize + uar::CQ_DOORBELL, arm_val);
    }

    /// CQ内の全保留完了を処理してCQEのリストを返す
    ///
    /// # Safety
    /// - buf_virt, doorbell_virt, uar_base が有効であること
    ///
    /// # Arguments
    /// - `max_batch`: 一度に処理するCQEの最大数
    ///
    /// # Returns
    /// 処理したCQEの情報（WQEインデックス, バイト数, オペコード）
    pub unsafe fn poll_batch(&mut self, max_batch: u32) -> alloc::vec::Vec<CqeInfo> {
        let mut results = alloc::vec::Vec::new();
        let mut count = 0u32;

        // LOOP_PROOF: mode=event; reason=Polling loop is capped by max_batch and also breaks when no new CQE is available.;
        loop {
            if count >= max_batch {
                break;
            }

            match self.poll_cqe() {
                Some(cqe) => {
                    let info = CqeInfo {
                        wqe_counter: cqe.wqe_counter(),
                        byte_count: cqe.byte_count(),
                        raw_byte_count: cqe.raw_byte_count(),
                        opcode: cqe.opcode(),
                        qpn: cqe.qpn(),
                        l3_ok: cqe.l3_ok(),
                        l4_ok: cqe.l4_ok(),
                        vlan_tag: if cqe.vlan_present() {
                            Some(cqe.vlan_tag())
                        } else {
                            None
                        },
                        timestamp: cqe.timestamp(),
                        error_syndrome: cqe.error_syndrome(),
                        vendor_error_syndrome: cqe.error_vendor_syndrome(),
                        error_wqe_opcode: cqe.error_wqe_opcode(),
                    };
                    results.push(info);
                    self.advance_consumer();
                    count += 1;
                }
                None => break,
            }
        }

        if count > 0 {
            self.update_doorbell();
        }

        results
    }

    /// CQ のヘッド状態をデバッグ用に取得
    ///
    /// # Safety
    /// - CQ バッファおよび doorbell_virt が有効であること
    pub unsafe fn debug_state(&self) -> CqDebugState {
        let idx = self.consumer_counter % self.cq_depth;
        let cqe_ptr = (self.buf_virt as usize + (idx as usize) * cqe_regs::SIZE) as *const Cqe;
        let cqe_ref = &*cqe_ptr;
        let expected_owner = ((self.consumer_counter >> self.log_cq_size) & 1) as u8;

        let doorbell_be = core::ptr::read_volatile(self.doorbell_virt as *const u32);
        let doorbell_host = u32::from_be(doorbell_be) & 0x00ff_ffff;
        let arm_db_be = core::ptr::read_volatile((self.doorbell_virt as *const u32).add(1));
        let arm_db_host = u32::from_be(arm_db_be);

        CqDebugState {
            cqn: self.cqn,
            consumer_counter: self.consumer_counter,
            cq_depth: self.cq_depth,
            log_cq_size: self.log_cq_size,
            arm_sn: self.arm_sn.load(Ordering::Relaxed),
            head_index: idx,
            expected_owner,
            observed_owner: cqe_ref.owner_bit(),
            observed_opcode: cqe_ref.opcode(),
            observed_wqe_counter: cqe_ref.wqe_counter(),
            observed_byte_count: cqe_ref.raw_byte_count(),
            doorbell_be,
            doorbell_host,
            arm_db_be,
            arm_db_host,
        }
    }
}

/// CQE処理結果の情報
#[derive(Debug, Clone)]
pub struct CqeInfo {
    /// WQEカウンタ（対応するSQ/RQのインデックス）
    pub wqe_counter: u16,
    /// 受信/送信バイト数
    pub byte_count: u32,
    /// CQE上の byte_cnt dword 生値
    pub raw_byte_count: u32,
    /// 完了オペコード
    pub opcode: CqeOpcode,
    /// QP番号
    pub qpn: u32,
    /// L3 チェックサム検証成功
    pub l3_ok: bool,
    /// L4 チェックサム検証成功
    pub l4_ok: bool,
    /// 抽出された VLAN タグ (TCI)
    pub vlan_tag: Option<u16>,
    /// ハードウェアタイムスタンプ
    pub timestamp: u64,
    /// エラーCQEの syndrome
    pub error_syndrome: Option<u8>,
    /// エラーCQEの vendor syndrome
    pub vendor_error_syndrome: Option<u8>,
    /// エラーCQEに含まれる source WQE opcode
    pub error_wqe_opcode: Option<u8>,
}

/// Completion Queue のデバッグスナップショット
#[derive(Debug, Clone, Copy)]
pub struct CqDebugState {
    pub cqn: u32,
    pub consumer_counter: u32,
    pub cq_depth: u32,
    pub log_cq_size: u8,
    pub arm_sn: u32,
    pub head_index: u32,
    pub expected_owner: u8,
    pub observed_owner: u8,
    pub observed_opcode: CqeOpcode,
    pub observed_wqe_counter: u16,
    pub observed_byte_count: u32,
    pub doorbell_be: u32,
    pub doorbell_host: u32,
    pub arm_db_be: u32,
    pub arm_db_host: u32,
}
