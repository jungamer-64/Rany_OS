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

    /// チェックサムステータスビット
    pub fn checksum_ok(&self) -> bool {
        // CS flagsのbit 1 = L3 OK, bit 0 = L4 OK
        let cs = self.data[cqe_regs::CHECKSUM];
        (cs & 0x03) == 0x03
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
        let arm_val: u64 = ((self.cqn as u64) << 32)
            | ((self.consumer_counter as u64) & 0x00FF_FFFF);
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
    pub unsafe fn poll_batch(
        &mut self,
        max_batch: u32,
    ) -> alloc::vec::Vec<CqeInfo> {
        let mut results = alloc::vec::Vec::new();
        let mut count = 0u32;

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
                        checksum_ok: cqe.checksum_ok(),
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
    /// チェックサムOK
    pub checksum_ok: bool,
}
