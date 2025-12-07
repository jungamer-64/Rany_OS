// ============================================================================
// src/io/nvme/commands.rs - NVMe Command Structures
// ============================================================================
//!
//! NVMeコマンド構造体定義
//!
//! Submission Queue Entry (SQE) と Completion Queue Entry (CQE) の共通定義。

#![allow(dead_code)]

use super::defs::*;

// ============================================================================
// NVMe Submission Queue Entry (Command)
// ============================================================================

/// NVMe Submission Queue Entry (64バイト)
///
/// 全てのNVMeコマンドはこの構造体を使用してSubmission Queueに投入される。
#[repr(C, align(64))]
#[derive(Clone, Copy, Debug, Default)]
pub struct NvmeCommand {
    /// Command Dword 0 (opcode[7:0], fused[9:8], psdt[15:14], cid[31:16])
    pub cdw0: u32,
    /// Namespace ID
    pub nsid: u32,
    /// Reserved / Command Dword 2
    pub cdw2: u32,
    /// Reserved / Command Dword 3
    pub cdw3: u32,
    /// Metadata Pointer
    pub mptr: u64,
    /// Data Pointer - PRP Entry 1 / SGL Entry 1
    pub dptr1: u64,
    /// Data Pointer - PRP Entry 2 / SGL Entry 1 (continued) / SGL Entry 2
    pub dptr2: u64,
    /// Command Dword 10
    pub cdw10: u32,
    /// Command Dword 11
    pub cdw11: u32,
    /// Command Dword 12
    pub cdw12: u32,
    /// Command Dword 13
    pub cdw13: u32,
    /// Command Dword 14
    pub cdw14: u32,
    /// Command Dword 15
    pub cdw15: u32,
}

impl NvmeCommand {
    /// 新しい空のコマンドを作成
    pub const fn new() -> Self {
        Self {
            cdw0: 0,
            nsid: 0,
            cdw2: 0,
            cdw3: 0,
            mptr: 0,
            dptr1: 0,
            dptr2: 0,
            cdw10: 0,
            cdw11: 0,
            cdw12: 0,
            cdw13: 0,
            cdw14: 0,
            cdw15: 0,
        }
    }

    /// オペコードとCIDを指定して新しいコマンドを作成
    pub fn with_opcode_and_cid(opcode: u8, cid: u16) -> Self {
        Self {
            cdw0: (opcode as u32) | ((cid as u32) << 16),
            ..Default::default()
        }
    }

    // ========================================
    // CDW0 accessors
    // ========================================

    /// オペコードを取得
    pub fn opcode(&self) -> u8 {
        (self.cdw0 & 0xFF) as u8
    }

    /// オペコードを設定
    pub fn set_opcode(&mut self, opcode: u8) -> &mut Self {
        self.cdw0 = (self.cdw0 & !0xFF) | (opcode as u32);
        self
    }

    /// Fused Operation (bits 8:9)
    pub fn set_fused(&mut self, fused: u8) -> &mut Self {
        self.cdw0 = (self.cdw0 & !0x300) | (((fused & 0x3) as u32) << 8);
        self
    }

    /// PSDT - PRP or SGL for Data Transfer (bits 14:15)
    pub fn set_psdt(&mut self, psdt: u8) -> &mut Self {
        self.cdw0 = (self.cdw0 & !0xC000) | (((psdt & 0x3) as u32) << 14);
        self
    }

    /// コマンドIDを取得
    pub fn cid(&self) -> u16 {
        (self.cdw0 >> 16) as u16
    }

    /// コマンドIDを設定
    pub fn set_cid(&mut self, cid: u16) -> &mut Self {
        self.cdw0 = (self.cdw0 & 0xFFFF) | ((cid as u32) << 16);
        self
    }

    // ========================================
    // Data Pointer accessors
    // ========================================

    /// PRPエントリを設定
    pub fn set_prp(&mut self, prp1: u64, prp2: u64) -> &mut Self {
        self.dptr1 = prp1;
        self.dptr2 = prp2;
        self
    }

    /// SGLを設定
    pub fn set_sgl(&mut self, sgl: &SglDescriptor) -> &mut Self {
        self.set_psdt(0x01);
        self.dptr1 = sgl.addr;
        self.dptr2 = ((sgl.length as u64) << 32) | (sgl.type_specific as u64);
        self
    }

    // ========================================
    // Admin Commands
    // ========================================

    /// Identify Controller コマンドを作成
    pub fn identify_controller(cid: u16, prp1: u64) -> Self {
        let mut cmd = Self::with_opcode_and_cid(AdminOpcode::Identify as u8, cid);
        cmd.cdw10 = 0x01; // CNS = 01h: Identify Controller
        cmd.set_prp(prp1, 0);
        cmd
    }

    /// Identify Namespace コマンドを作成
    pub fn identify_namespace(cid: u16, nsid: u32, prp1: u64) -> Self {
        let mut cmd = Self::with_opcode_and_cid(AdminOpcode::Identify as u8, cid);
        cmd.nsid = nsid;
        cmd.cdw10 = 0x00; // CNS = 00h: Identify Namespace
        cmd.set_prp(prp1, 0);
        cmd
    }

    /// Identify Active Namespace ID List コマンドを作成
    pub fn identify_namespace_list(cid: u16, start_nsid: u32, prp1: u64) -> Self {
        let mut cmd = Self::with_opcode_and_cid(AdminOpcode::Identify as u8, cid);
        cmd.nsid = start_nsid;
        cmd.cdw10 = 0x02; // CNS = 02h: Active Namespace ID list
        cmd.set_prp(prp1, 0);
        cmd
    }

    /// Create I/O Completion Queue コマンドを作成
    pub fn create_io_cq(
        cid: u16,
        qid: u16,
        queue_size: u16,
        prp: u64,
        irq_vector: u16,
        irq_enabled: bool,
    ) -> Self {
        let mut cmd = Self::with_opcode_and_cid(AdminOpcode::CreateIOCQ as u8, cid);
        cmd.set_prp(prp, 0);
        // CDW10: Queue Size (15:0) | Queue Identifier (31:16)
        cmd.cdw10 = ((qid as u32) << 16) | ((queue_size - 1) as u32);
        // CDW11: Interrupt Vector (31:16) | IEN (1) | PC (0)
        let mut cdw11: u32 = 0x01; // PC=1: Physically Contiguous
        if irq_enabled {
            cdw11 |= 0x02; // IEN=1: Interrupt Enabled
        }
        cdw11 |= (irq_vector as u32) << 16;
        cmd.cdw11 = cdw11;
        cmd
    }

    /// Create I/O Submission Queue コマンドを作成
    pub fn create_io_sq(
        cid: u16,
        qid: u16,
        queue_size: u16,
        prp: u64,
        cqid: u16,
        priority: u8,
    ) -> Self {
        let mut cmd = Self::with_opcode_and_cid(AdminOpcode::CreateIOSQ as u8, cid);
        cmd.set_prp(prp, 0);
        // CDW10: Queue Size (15:0) | Queue Identifier (31:16)
        cmd.cdw10 = ((qid as u32) << 16) | ((queue_size - 1) as u32);
        // CDW11: CQID (31:16) | QPRIO (2:1) | PC (0)
        let mut cdw11: u32 = 0x01; // PC=1: Physically Contiguous
        cdw11 |= ((priority & 0x3) as u32) << 1;
        cdw11 |= (cqid as u32) << 16;
        cmd.cdw11 = cdw11;
        cmd
    }

    /// Delete I/O Submission Queue コマンドを作成
    pub fn delete_io_sq(cid: u16, qid: u16) -> Self {
        let mut cmd = Self::with_opcode_and_cid(AdminOpcode::DeleteIOSQ as u8, cid);
        cmd.cdw10 = qid as u32;
        cmd
    }

    /// Delete I/O Completion Queue コマンドを作成
    pub fn delete_io_cq(cid: u16, qid: u16) -> Self {
        let mut cmd = Self::with_opcode_and_cid(AdminOpcode::DeleteIOCQ as u8, cid);
        cmd.cdw10 = qid as u32;
        cmd
    }

    /// Set Features - Number of Queues コマンドを作成
    pub fn set_features_num_queues(cid: u16, nsq: u16, ncq: u16) -> Self {
        let mut cmd = Self::with_opcode_and_cid(AdminOpcode::SetFeatures as u8, cid);
        cmd.cdw10 = feature_ids::NUM_QUEUES as u32;
        // CDW11: NCQR (31:16) | NSQR (15:0)
        cmd.cdw11 = ((ncq - 1) as u32) << 16 | ((nsq - 1) as u32);
        cmd
    }

    /// Get Features コマンドを作成
    pub fn get_features(cid: u16, fid: u8, nsid: u32) -> Self {
        let mut cmd = Self::with_opcode_and_cid(AdminOpcode::GetFeatures as u8, cid);
        cmd.nsid = nsid;
        cmd.cdw10 = fid as u32;
        cmd
    }

    // ========================================
    // I/O Commands
    // ========================================

    /// Read コマンドを作成
    pub fn read(
        cid: u16,
        nsid: u32,
        slba: u64,
        nlb: u16,
        prp1: u64,
        prp2: u64,
    ) -> Self {
        let mut cmd = Self::with_opcode_and_cid(IoOpcode::Read as u8, cid);
        cmd.nsid = nsid;
        cmd.set_prp(prp1, prp2);
        cmd.cdw10 = slba as u32;
        cmd.cdw11 = (slba >> 32) as u32;
        cmd.cdw12 = nlb as u32; // NLB is 0-based
        cmd
    }

    /// Write コマンドを作成
    pub fn write(
        cid: u16,
        nsid: u32,
        slba: u64,
        nlb: u16,
        prp1: u64,
        prp2: u64,
    ) -> Self {
        let mut cmd = Self::with_opcode_and_cid(IoOpcode::Write as u8, cid);
        cmd.nsid = nsid;
        cmd.set_prp(prp1, prp2);
        cmd.cdw10 = slba as u32;
        cmd.cdw11 = (slba >> 32) as u32;
        cmd.cdw12 = nlb as u32; // NLB is 0-based
        cmd
    }

    /// Flush コマンドを作成
    pub fn flush(cid: u16, nsid: u32) -> Self {
        let mut cmd = Self::with_opcode_and_cid(IoOpcode::Flush as u8, cid);
        cmd.nsid = nsid;
        cmd
    }

    /// Write Zeroes コマンドを作成
    pub fn write_zeroes(cid: u16, nsid: u32, slba: u64, nlb: u16) -> Self {
        let mut cmd = Self::with_opcode_and_cid(IoOpcode::WriteZeroes as u8, cid);
        cmd.nsid = nsid;
        cmd.cdw10 = slba as u32;
        cmd.cdw11 = (slba >> 32) as u32;
        cmd.cdw12 = nlb as u32;
        cmd
    }

    /// Dataset Management (TRIM) コマンドを作成
    pub fn dataset_management(cid: u16, nsid: u32, nr: u8, prp1: u64) -> Self {
        let mut cmd = Self::with_opcode_and_cid(IoOpcode::DatasetManagement as u8, cid);
        cmd.nsid = nsid;
        cmd.set_prp(prp1, 0);
        cmd.cdw10 = nr as u32; // Number of Ranges (0-based)
        cmd.cdw11 = 0x04; // AD=1: Attribute Deallocate
        cmd
    }
}

// ============================================================================
// NVMe Completion Queue Entry
// ============================================================================

/// NVMe Completion Queue Entry (16バイト)
///
/// 全てのコマンド完了はこの構造体を使用してCompletion Queueに返される。
#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, Default)]
pub struct NvmeCompletion {
    /// Command Specific (DW0)
    pub result: u32,
    /// Reserved (DW1)
    pub rsvd: u32,
    /// SQ Head Pointer
    pub sq_head: u16,
    /// SQ Identifier
    pub sq_id: u16,
    /// Command Identifier
    pub cid: u16,
    /// Status Field (P | SC | SCT | CRD | M | DNR)
    pub status: u16,
}

impl NvmeCompletion {
    /// コマンドIDを取得
    pub fn command_id(&self) -> u16 {
        self.cid
    }

    /// フェーズビットを取得
    pub fn phase(&self) -> bool {
        (self.status & 1) != 0
    }

    /// Status Code Type (SCT) を取得
    pub fn sct(&self) -> u8 {
        ((self.status >> 9) & 0x7) as u8
    }

    /// Status Code (SC) を取得
    pub fn sc(&self) -> u8 {
        ((self.status >> 1) & 0xFF) as u8
    }

    /// ステータスコードを取得
    pub fn get_status(&self) -> NvmeStatus {
        NvmeStatus::from(self.status)
    }

    /// 成功かどうか
    pub fn is_success(&self) -> bool {
        (self.status >> 1) & 0xFF == 0
    }

    /// DNR (Do Not Retry) ビット
    pub fn dnr(&self) -> bool {
        (self.status >> 15) & 1 != 0
    }

    /// More (M) ビット
    pub fn more(&self) -> bool {
        (self.status >> 14) & 1 != 0
    }

    /// CRD (Command Retry Delay) を取得
    pub fn crd(&self) -> u8 {
        ((self.status >> 12) & 0x3) as u8
    }
}

// ============================================================================
// Dataset Management Range
// ============================================================================

/// Dataset Management Range Entry (16バイト)
/// TRIM/Deallocateコマンドで使用
#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, Default)]
pub struct DsmRange {
    /// Context Attributes
    pub cattr: u32,
    /// Length in logical blocks
    pub nlb: u32,
    /// Starting LBA
    pub slba: u64,
}

impl DsmRange {
    /// 新しいDSMレンジを作成
    pub fn new(slba: u64, nlb: u32) -> Self {
        Self {
            cattr: 0,
            nlb,
            slba,
        }
    }
}
