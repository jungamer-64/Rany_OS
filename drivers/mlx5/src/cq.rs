// ============================================================================
// drivers/mlx5/src/cq.rs - Completion Queue
// ============================================================================
//! Completion Queue (CQ) — 送受信の完了通知キュー
//!
//! CQはSQ/RQの操作完了をSWに通知するためのリングバッファ。
//! 各CQエントリ（CQE）は64バイトで、完了した操作の詳細情報を含む。

use crate::defs::CqeOpcode;
use crate::regs::{cqe as cqe_regs, uar};

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

    /// 受信バイトカウント
    pub fn byte_count(&self) -> u32 {
        u32::from_be_bytes([
            self.data[cqe_regs::BYTE_COUNT],
            self.data[cqe_regs::BYTE_COUNT + 1],
            self.data[cqe_regs::BYTE_COUNT + 2],
            self.data[cqe_regs::BYTE_COUNT + 3],
        ])
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
        matches!(op, CqeOpcode::ReqOk | CqeOpcode::RespOk)
    }

    /// エラーかチェック
    pub fn is_error(&self) -> bool {
        let op = self.opcode();
        matches!(op, CqeOpcode::ReqErr | CqeOpcode::RespErr)
    }

    /// チェックサムステータス (L3 OK)
    pub fn l3_ok(&self) -> bool {
        let flags = u32::from_be_bytes([
            self.data[cqe_regs::CHECKSUM],
            self.data[cqe_regs::CHECKSUM + 1],
            self.data[cqe_regs::CHECKSUM + 2],
            self.data[cqe_regs::CHECKSUM + 3],
        ]);
        (flags & cqe_regs::L3_OK) != 0
    }

    /// チェックサムステータス (L4 OK)
    pub fn l4_ok(&self) -> bool {
        let flags = u32::from_be_bytes([
            self.data[cqe_regs::CHECKSUM],
            self.data[cqe_regs::CHECKSUM + 1],
            self.data[cqe_regs::CHECKSUM + 2],
            self.data[cqe_regs::CHECKSUM + 3],
        ]);
        (flags & cqe_regs::L4_OK) != 0
    }

    /// VLANタグが存在するか確認
    pub fn vlan_present(&self) -> bool {
        // bit 15 of word at 0x18 (byte 0x1a in big-endian)
        (self.data[cqe_regs::VLAN_INFO + 2] & 0x80) != 0
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
        u64::from_be_bytes([
            self.data[0x10], self.data[0x11], self.data[0x12], self.data[0x13],
            self.data[0x14], self.data[0x15], self.data[0x16], self.data[0x17],
        ])
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
        // ARM CQ ドアベル: CQ番号とコンシューマカウンタを書き込み
        let arm_val: u64 =
            ((self.cqn as u64) << 32) | ((self.consumer_counter as u64) & 0x00FF_FFFF);
        let arm_ptr = (self.uar_base as usize + uar::CQ_ARM_DOORBELL) as *mut u64;
        core::ptr::write_volatile(arm_ptr, arm_val.to_be());
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
                        opcode: cqe.opcode(),
                        qpn: cqe.qpn(),
                        l3_ok: cqe.l3_ok(),
                        l4_ok: cqe.l4_ok(),
                        vlan_tag: if cqe.vlan_present() { Some(cqe.vlan_tag()) } else { None },
                        timestamp: cqe.timestamp(),
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

        CqDebugState {
            cqn: self.cqn,
            consumer_counter: self.consumer_counter,
            cq_depth: self.cq_depth,
            log_cq_size: self.log_cq_size,
            head_index: idx,
            expected_owner,
            observed_owner: cqe_ref.owner_bit(),
            observed_opcode: cqe_ref.opcode(),
            observed_wqe_counter: cqe_ref.wqe_counter(),
            observed_byte_count: cqe_ref.byte_count(),
            doorbell_be,
            doorbell_host,
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
}

/// Completion Queue のデバッグスナップショット
#[derive(Debug, Clone, Copy)]
pub struct CqDebugState {
    pub cqn: u32,
    pub consumer_counter: u32,
    pub cq_depth: u32,
    pub log_cq_size: u8,
    pub head_index: u32,
    pub expected_owner: u8,
    pub observed_owner: u8,
    pub observed_opcode: CqeOpcode,
    pub observed_wqe_counter: u16,
    pub observed_byte_count: u32,
    pub doorbell_be: u32,
    pub doorbell_host: u32,
}
