// ============================================================================
// drivers/mlx5/src/cq.rs - Completion Queue
// ============================================================================
//! Completion Queue (CQ) — 送受信の完了通知キュー
//!
//! CQはSQ/RQの操作完了をSWに通知するためのリングバッファ。
//! 各CQエントリ（CQE）は64バイトで、完了した操作の詳細情報を含む。

use crate::defs::CqeOpcode;
use crate::regs::cqe as cqe_regs;
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
        (self.data[cqe_regs::HDS_IP_EXT] & cqe_regs::CQE_L3_OK) != 0
    }

    /// チェックサムステータス (L4 OK)
    pub fn l4_ok(&self) -> bool {
        (self.data[cqe_regs::HDS_IP_EXT] & cqe_regs::CQE_L4_OK) != 0
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_flags_default_to_false() {
        let cqe = Cqe::zeroed();
        assert!(!cqe.l3_ok());
        assert!(!cqe.l4_ok());
    }

    #[test]
    fn checksum_flags_decode_l3_only() {
        let mut cqe = Cqe::zeroed();
        cqe.data[cqe_regs::HDS_IP_EXT] = cqe_regs::CQE_L3_OK;
        assert!(cqe.l3_ok());
        assert!(!cqe.l4_ok());
    }

    #[test]
    fn checksum_flags_decode_l3_and_l4() {
        let mut cqe = Cqe::zeroed();
        cqe.data[cqe_regs::HDS_IP_EXT] = cqe_regs::CQE_L3_OK | cqe_regs::CQE_L4_OK;
        assert!(cqe.l3_ok());
        assert!(cqe.l4_ok());
    }
}

/// Completion Queue 管理構造体
pub struct CompletionQueue {
    doorbell: crate::registers::CqDoorbell,
    /// CQのハードウェア番号（CREATE_CQで返される）
    pub cqn: u32,
    /// CQバッファ仮想アドレス
    buf_virt: u64,
    /// CQバッファ物理アドレス
    buf_phys: u64,
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
