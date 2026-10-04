// ============================================================================
// drivers/mlx5/src/cq.rs - Completion Queue
// ============================================================================
//! Completion Queue (CQ) — 送受信の完了通知キュー
//!
//! CQはSQ/RQの操作完了をSWに通知するためのリングバッファ。
//! 各CQエントリ（CQE）は64バイトで、完了した操作の詳細情報を含む。

use crate::defs::CqeOpcode;
use crate::regs::cqe as cqe_regs;
use core::sync::atomic::{Ordering, fence};

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

/// Completion ring and its doorbell record share one queue generation and
/// retain their linear capabilities through failed creation/finalization.
pub struct CompletionQueue {
    pub(crate) grant: crate::queue_memory::QueueGrant,
    pub(crate) memory: crate::queue_memory::QueueMemory<2>,
    pub(crate) doorbell: crate::registers::CqDoorbell,
    pub(crate) log_cq_size: u8,
    consumer_counter: u32,
    pub eq_number: u32,
    arm_sn: u32,
}

impl CompletionQueue {
    pub(crate) fn new(
        identity: kernel_api::dma::DmaQueueIdentity,
        leases: [kernel_api::dma::CpuDmaLease; 2],
        doorbell: crate::registers::CqDoorbell,
        log_cq_size: u8,
        eq_number: u32,
    ) -> Self {
        Self {
            grant: crate::queue_memory::QueueGrant::Unpublished,
            memory: crate::queue_memory::QueueMemory::new(identity, leases),
            doorbell,
            log_cq_size,
            consumer_counter: 0,
            eq_number,
            arm_sn: 0,
        }
    }

    /// Firmware identity is unavailable during pending or completed destruction.
    pub fn number(&self) -> Option<u32> {
        self.grant.number()
    }

    pub(crate) fn prepare(&mut self) -> crate::error::Mlx5Result<()> {
        use crate::queue_memory::RegionLayout;
        use kernel_api::dma::DmaDirection;
        let bytes = (1usize << self.log_cq_size) * cqe_regs::SIZE;
        self.memory.prepare(
            [
                RegionLayout {
                    bytes,
                    direction: DmaDirection::FromDevice,
                    alignment: crate::defs::MLX5_PAGE_SIZE,
                },
                RegionLayout {
                    bytes: 8,
                    direction: DmaDirection::ToDevice,
                    alignment: 8,
                },
            ],
            |index, region| {
                region.fill(0);
                if index == 0 {
                    for entry in region[..bytes].as_chunks_mut::<{ cqe_regs::SIZE }>().0 {
                        entry[cqe_regs::OP_OWN] = 1;
                    }
                } else {
                    region[4..8].copy_from_slice(&(2u32 << 28).to_be_bytes());
                }
            },
        )
    }

    pub(crate) fn next(&mut self) -> crate::error::Mlx5Result<Option<CqeInfo>> {
        if self.number().is_none() {
            return Err(crate::error::Mlx5Error::DeviceNotReady);
        }
        let offset = (self.consumer_counter % (1u32 << self.log_cq_size)) as usize * cqe_regs::SIZE;
        let owner = self.memory.read_byte(0, offset + cqe_regs::OP_OWN)? & 1;
        let expected = ((self.consumer_counter >> self.log_cq_size) & 1) as u8;
        if owner != expected {
            return Ok(None);
        }
        fence(Ordering::Acquire);
        let entry = Cqe {
            data: self.memory.read(0, offset)?,
        };
        if !entry.is_valid_completion() && !entry.is_error() {
            // Unsupported CQ formats/opcodes cannot witness packet retirement.
            // Leave the entry unconsumed so recovery retains the exact head.
            return Err(crate::error::Mlx5Error::InvalidResponse);
        }
        let info = CqeInfo {
            wqe_counter: entry.wqe_counter(),
            byte_count: entry.byte_count(),
            raw_byte_count: entry.raw_byte_count(),
            opcode: entry.opcode(),
            qpn: entry.qpn(),
            l3_ok: entry.l3_ok(),
            l4_ok: entry.l4_ok(),
            vlan_tag: entry.vlan_present().then(|| entry.vlan_tag()),
            timestamp: entry.timestamp(),
            error_syndrome: entry.error_syndrome(),
            vendor_error_syndrome: entry.error_vendor_syndrome(),
            error_wqe_opcode: entry.error_wqe_opcode(),
        };
        self.consumer_counter = self.consumer_counter.wrapping_add(1);
        Ok(Some(info))
    }

    pub(crate) fn acknowledge(&mut self) -> crate::error::Mlx5Result<()> {
        self.memory
            .write_be32(1, 0, self.consumer_counter & 0x00ff_ffff)
    }

    pub(crate) fn arm(&mut self) -> crate::error::Mlx5Result<()> {
        let number = self
            .number()
            .ok_or(crate::error::Mlx5Error::DeviceNotReady)?;
        let word = ((self.arm_sn & 3) << 28) | (self.consumer_counter & 0x00ff_ffff);
        self.memory.write_be32(1, 4, word)?;
        fence(Ordering::Release);
        self.doorbell.arm(word, number);
        self.arm_sn = self.arm_sn.wrapping_add(1);
        Ok(())
    }

    pub(crate) fn snapshot(&mut self) -> crate::error::Mlx5Result<CqDebugState> {
        let number = self
            .number()
            .ok_or(crate::error::Mlx5Error::DeviceNotReady)?;
        let depth = 1u32 << self.log_cq_size;
        let index = self.consumer_counter % depth;
        // Observational sample: hardware may still own this slot. No RAM
        // reference escapes and the sample is never a completion witness.
        let entry = Cqe {
            data: self.memory.read(0, index as usize * cqe_regs::SIZE)?,
        };
        let records = self.memory.read::<8>(1, 0)?;
        let consumer: [u8; 4] = records[..4]
            .try_into()
            .expect("fixed four-byte doorbell field");
        let arm: [u8; 4] = records[4..].try_into().expect("fixed four-byte arm field");
        Ok(CqDebugState {
            cqn: number,
            consumer_counter: self.consumer_counter,
            cq_depth: depth,
            log_cq_size: self.log_cq_size,
            arm_sn: self.arm_sn,
            head_index: index,
            expected_owner: ((self.consumer_counter >> self.log_cq_size) & 1) as u8,
            observed_owner: entry.owner_bit(),
            observed_opcode: entry.opcode(),
            observed_wqe_counter: entry.wqe_counter(),
            observed_byte_count: entry.raw_byte_count(),
            doorbell_be: u32::from_ne_bytes(consumer),
            doorbell_host: u32::from_be_bytes(consumer) & 0x00ff_ffff,
            arm_db_be: u32::from_ne_bytes(arm),
            arm_db_host: u32::from_be_bytes(arm),
        })
    }
}

/// All consumed entries remain available even if a later read or doorbell
/// update fails. The caller must process this prefix and observe completion.
pub(crate) struct CompletionBatch {
    pub(crate) entries: alloc::vec::Vec<CqeInfo>,
    pub(crate) completion: crate::error::Mlx5Result<()>,
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
