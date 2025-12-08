// ============================================================================
// src/io/nvme/regs.rs - NVMe Register Definitions
// ============================================================================
//!
//! NVMeコントローラレジスタ定義
//!
//! NVMe Base Specification 2.0 Section 3.1に基づくレジスタ定義。

#![allow(dead_code)]

// ============================================================================
// Register Offsets
// ============================================================================

/// NVMeコントローラレジスタオフセット
pub mod offsets {
    /// Controller Capabilities (8 bytes) - RO
    pub const CAP: u64 = 0x00;
    /// Version (4 bytes) - RO
    pub const VS: u64 = 0x08;
    /// Interrupt Mask Set (4 bytes) - RW1S
    pub const INTMS: u64 = 0x0C;
    /// Interrupt Mask Clear (4 bytes) - RW1C
    pub const INTMC: u64 = 0x10;
    /// Controller Configuration (4 bytes) - RW
    pub const CC: u64 = 0x14;
    /// Controller Status (4 bytes) - RO
    pub const CSTS: u64 = 0x1C;
    /// NVM Subsystem Reset (4 bytes) - RW
    pub const NSSR: u64 = 0x20;
    /// Admin Queue Attributes (4 bytes) - RW
    pub const AQA: u64 = 0x24;
    /// Admin Submission Queue Base Address (8 bytes) - RW
    pub const ASQ: u64 = 0x28;
    /// Admin Completion Queue Base Address (8 bytes) - RW
    pub const ACQ: u64 = 0x30;
    /// Controller Memory Buffer Location (4 bytes) - RO
    pub const CMBLOC: u64 = 0x38;
    /// Controller Memory Buffer Size (4 bytes) - RO
    pub const CMBSZ: u64 = 0x3C;
    /// Boot Partition Info (4 bytes) - RO
    pub const BPINFO: u64 = 0x40;
    /// Boot Partition Read Select (4 bytes) - RW
    pub const BPRSEL: u64 = 0x44;
    /// Boot Partition Memory Buffer Location (8 bytes) - RW
    pub const BPMBL: u64 = 0x48;
    /// Controller Memory Buffer Memory Space Control (8 bytes) - RW
    pub const CMBMSC: u64 = 0x50;
    /// Controller Memory Buffer Status (4 bytes) - RO
    pub const CMBSTS: u64 = 0x58;
    /// Controller Memory Buffer Elasticity Buffer Size (4 bytes) - RO
    pub const CMBEBS: u64 = 0x5C;
    /// Controller Memory Buffer Sustained Write Throughput (4 bytes) - RO
    pub const CMBSWTP: u64 = 0x60;
    /// NVM Subsystem Shutdown (4 bytes) - RW
    pub const NSSD: u64 = 0x64;
    /// Controller Ready Timeouts (4 bytes) - RO
    pub const CRTO: u64 = 0x68;
    /// PMR Capabilities (4 bytes) - RO
    pub const PMRCAP: u64 = 0xE00;
    /// PMR Control (4 bytes) - RW
    pub const PMRCTL: u64 = 0xE04;
    /// PMR Status (4 bytes) - RO
    pub const PMRSTS: u64 = 0xE08;
    /// Doorbell base offset
    pub const SQ0TDBL: u64 = 0x1000;
}

// ============================================================================
// Controller Configuration (CC) bits
// ============================================================================

/// CC (Controller Configuration) ビット定義
pub mod cc_bits {
    /// Enable
    pub const EN: u32 = 1 << 0;
    /// I/O Command Set Selected - NVM Command Set
    pub const CSS_NVM: u32 = 0 << 4;
    /// Memory Page Size shift
    pub const MPS_SHIFT: u32 = 7;
    /// Arbitration Mechanism Selected - Round Robin
    pub const AMS_RR: u32 = 0 << 11;
    /// Shutdown Notification - None
    pub const SHN_NONE: u32 = 0 << 14;
    /// Shutdown Notification - Normal
    pub const SHN_NORMAL: u32 = 1 << 14;
    /// Shutdown Notification - Abrupt
    pub const SHN_ABRUPT: u32 = 2 << 14;
    /// I/O Submission Queue Entry Size (2^6 = 64 bytes)
    pub const IOSQES_64: u32 = 6 << 16;
    /// I/O Completion Queue Entry Size (2^4 = 16 bytes)
    pub const IOCQES_16: u32 = 4 << 20;
}

// ============================================================================
// Controller Status (CSTS) bits
// ============================================================================

/// CSTS (Controller Status) ビット定義
pub mod csts_bits {
    /// Ready
    pub const RDY: u32 = 1 << 0;
    /// Controller Fatal Status
    pub const CFS: u32 = 1 << 1;
    /// Shutdown Status mask
    pub const SHST_MASK: u32 = 0x3 << 2;
    /// Shutdown Status - Normal operation
    pub const SHST_NORMAL: u32 = 0 << 2;
    /// Shutdown Status - Shutdown processing occurring
    pub const SHST_OCCURRING: u32 = 1 << 2;
    /// Shutdown Status - Shutdown processing complete
    pub const SHST_COMPLETE: u32 = 2 << 2;
    /// NVM Subsystem Reset Occurred
    pub const NSSRO: u32 = 1 << 4;
    /// Processing Paused
    pub const PP: u32 = 1 << 5;
    /// Shutdown Type
    pub const ST: u32 = 1 << 6;
}

// ============================================================================
// Capability Structures
// ============================================================================

/// CAP - Controller Capabilities
#[derive(Debug, Clone, Copy)]
pub struct NvmeCapabilities {
    raw: u64,
}

impl NvmeCapabilities {
    /// 生の値から作成
    pub fn new(raw: u64) -> Self {
        Self { raw }
    }

    /// 生の値を取得
    pub fn raw(&self) -> u64 {
        self.raw
    }

    /// Maximum Queue Entries Supported (0-based)
    pub fn mqes(&self) -> u16 {
        (self.raw & 0xFFFF) as u16
    }

    /// 最大キュー深度（実際の値）
    pub fn max_queue_depth(&self) -> u16 {
        self.mqes() + 1
    }

    /// Contiguous Queues Required
    pub fn cqr(&self) -> bool {
        ((self.raw >> 16) & 1) != 0
    }

    /// Arbitration Mechanism Supported
    pub fn ams(&self) -> u8 {
        ((self.raw >> 17) & 0x3) as u8
    }

    /// Timeout (500ms単位)
    pub fn to(&self) -> u8 {
        ((self.raw >> 24) & 0xFF) as u8
    }

    /// タイムアウト（ミリ秒）
    pub fn timeout_ms(&self) -> u64 {
        (self.to() as u64) * 500
    }

    /// Doorbell Stride (2^(2+DSTRD) bytes)
    pub fn dstrd(&self) -> u8 {
        ((self.raw >> 32) & 0xF) as u8
    }

    /// ドアベルストライド（バイト）
    pub fn doorbell_stride(&self) -> usize {
        4 << self.dstrd()
    }

    /// NVM Subsystem Reset Supported
    pub fn nssrs(&self) -> bool {
        ((self.raw >> 36) & 1) != 0
    }

    /// Command Sets Supported
    pub fn css(&self) -> u8 {
        ((self.raw >> 37) & 0xFF) as u8
    }

    /// NVM Command Set Supported
    pub fn css_nvm(&self) -> bool {
        (self.css() & 1) != 0
    }

    /// Boot Partition Support
    pub fn bps(&self) -> bool {
        ((self.raw >> 45) & 1) != 0
    }

    /// Controller Power Scope
    pub fn cps(&self) -> u8 {
        ((self.raw >> 46) & 0x3) as u8
    }

    /// Memory Page Size Minimum (2^(12+MPSMIN) bytes)
    pub fn mpsmin(&self) -> u8 {
        ((self.raw >> 48) & 0xF) as u8
    }

    /// 最小メモリページサイズ（バイト）
    pub fn min_page_size(&self) -> usize {
        4096 << self.mpsmin()
    }

    /// Memory Page Size Maximum (2^(12+MPSMAX) bytes)
    pub fn mpsmax(&self) -> u8 {
        ((self.raw >> 52) & 0xF) as u8
    }

    /// 最大メモリページサイズ（バイト）
    pub fn max_page_size(&self) -> usize {
        4096 << self.mpsmax()
    }

    /// Persistent Memory Region Supported
    pub fn pmrs(&self) -> bool {
        ((self.raw >> 56) & 1) != 0
    }

    /// Controller Memory Buffer Supported
    pub fn cmbs(&self) -> bool {
        ((self.raw >> 57) & 1) != 0
    }

    /// NVM Subsystem Shutdown Supported
    pub fn nsss(&self) -> bool {
        ((self.raw >> 58) & 1) != 0
    }

    /// Controller Ready Modes Supported
    pub fn crms(&self) -> u8 {
        ((self.raw >> 59) & 0x3) as u8
    }
}

// ============================================================================
// Controller Configuration
// ============================================================================

/// CC - Controller Configuration
#[derive(Debug, Clone, Copy, Default)]
pub struct NvmeControllerConfig {
    raw: u32,
}

impl NvmeControllerConfig {
    /// 新しい設定を作成
    pub fn new() -> Self {
        Self::default()
    }

    /// 生の値から作成
    pub fn from_raw(raw: u32) -> Self {
        Self { raw }
    }

    /// 生の値を取得
    pub fn raw(&self) -> u32 {
        self.raw
    }

    /// Enable (bit 0)
    pub fn set_enable(&mut self, enable: bool) -> &mut Self {
        if enable {
            self.raw |= cc_bits::EN;
        } else {
            self.raw &= !cc_bits::EN;
        }
        self
    }

    /// コントローラが有効かどうか
    pub fn is_enabled(&self) -> bool {
        (self.raw & cc_bits::EN) != 0
    }

    /// I/O Command Set Selected (bits 4:6)
    pub fn set_css(&mut self, css: u8) -> &mut Self {
        self.raw = (self.raw & !0x70) | (((css & 0x7) as u32) << 4);
        self
    }

    /// Memory Page Size (bits 7:10)
    pub fn set_mps(&mut self, mps: u8) -> &mut Self {
        self.raw = (self.raw & !0x780) | (((mps & 0xF) as u32) << 7);
        self
    }

    /// Arbitration Mechanism Selected (bits 11:13)
    pub fn set_ams(&mut self, ams: u8) -> &mut Self {
        self.raw = (self.raw & !0x3800) | (((ams & 0x7) as u32) << 11);
        self
    }

    /// Shutdown Notification (bits 14:15)
    pub fn set_shn(&mut self, shn: u8) -> &mut Self {
        self.raw = (self.raw & !0xC000) | (((shn & 0x3) as u32) << 14);
        self
    }

    /// I/O Submission Queue Entry Size (bits 16:19)
    pub fn set_iosqes(&mut self, iosqes: u8) -> &mut Self {
        self.raw = (self.raw & !0xF0000) | (((iosqes & 0xF) as u32) << 16);
        self
    }

    /// I/O Completion Queue Entry Size (bits 20:23)
    pub fn set_iocqes(&mut self, iocqes: u8) -> &mut Self {
        self.raw = (self.raw & !0xF00000) | (((iocqes & 0xF) as u32) << 20);
        self
    }

    /// 標準的なNVMe設定を適用
    pub fn standard_config(&mut self) -> &mut Self {
        self.set_css(0)      // NVM Command Set
            .set_ams(0)      // Round Robin
            .set_mps(0)      // 4KB pages
            .set_iosqes(6)   // 64-byte SQ entries
            .set_iocqes(4)   // 16-byte CQ entries
    }
}

// ============================================================================
// Controller Status
// ============================================================================

/// CSTS - Controller Status
#[derive(Debug, Clone, Copy)]
pub struct NvmeControllerStatus {
    raw: u32,
}

impl NvmeControllerStatus {
    /// 生の値から作成
    pub fn new(raw: u32) -> Self {
        Self { raw }
    }

    /// 生の値を取得
    pub fn raw(&self) -> u32 {
        self.raw
    }

    /// Ready (bit 0)
    pub fn ready(&self) -> bool {
        (self.raw & csts_bits::RDY) != 0
    }

    /// Controller Fatal Status (bit 1)
    pub fn fatal_status(&self) -> bool {
        (self.raw & csts_bits::CFS) != 0
    }

    /// Shutdown Status (bits 2:3)
    pub fn shutdown_status(&self) -> u8 {
        ((self.raw >> 2) & 0x3) as u8
    }

    /// NVM Subsystem Reset Occurred (bit 4)
    pub fn nssro(&self) -> bool {
        (self.raw & csts_bits::NSSRO) != 0
    }

    /// Processing Paused (bit 5)
    pub fn processing_paused(&self) -> bool {
        (self.raw & csts_bits::PP) != 0
    }

    /// Shutdown Type (bit 6)
    pub fn shutdown_type(&self) -> bool {
        (self.raw & csts_bits::ST) != 0
    }
}

// ============================================================================
// Admin Queue Attributes
// ============================================================================

/// AQA - Admin Queue Attributes
#[derive(Debug, Clone, Copy, Default)]
pub struct NvmeAdminQueueAttributes {
    raw: u32,
}

impl NvmeAdminQueueAttributes {
    /// 新しい属性を作成
    pub fn new() -> Self {
        Self::default()
    }

    /// 生の値を取得
    pub fn raw(&self) -> u32 {
        self.raw
    }

    /// Admin Submission Queue Size (0-based)
    pub fn set_asqs(&mut self, size: u16) -> &mut Self {
        self.raw = (self.raw & !0xFFF) | ((size & 0xFFF) as u32);
        self
    }

    /// Admin Completion Queue Size (0-based)
    pub fn set_acqs(&mut self, size: u16) -> &mut Self {
        self.raw = (self.raw & !0x0FFF0000) | (((size & 0xFFF) as u32) << 16);
        self
    }
}

// ============================================================================
// CMB (Controller Memory Buffer) Structures
// ============================================================================

/// CMBLOC - Controller Memory Buffer Location
#[derive(Debug, Clone, Copy)]
pub struct CmbLocation {
    raw: u32,
}

impl CmbLocation {
    pub fn new(raw: u32) -> Self {
        Self { raw }
    }

    /// BIR - Base Indicator Register (bits 2:0)
    pub fn bir(&self) -> u8 {
        (self.raw & 0x7) as u8
    }

    /// CQMMS - CQ Mixed Memory Support (bit 4)
    pub fn cqmms(&self) -> bool {
        ((self.raw >> 4) & 1) != 0
    }

    /// CQPDS - CQ Physically Discontiguous Pages Support (bit 5)
    pub fn cqpds(&self) -> bool {
        ((self.raw >> 5) & 1) != 0
    }

    /// OFST - Offset (bits 31:12)
    pub fn offset(&self) -> u32 {
        (self.raw >> 12) & 0xFFFFF
    }

    /// オフセット（バイト）
    pub fn offset_bytes(&self) -> u64 {
        (self.offset() as u64) << 12
    }
}

/// CMBSZ - Controller Memory Buffer Size
#[derive(Debug, Clone, Copy)]
pub struct CmbSize {
    raw: u32,
}

impl CmbSize {
    pub fn new(raw: u32) -> Self {
        Self { raw }
    }

    /// SQS - Submission Queue Support
    pub fn sqs(&self) -> bool {
        (self.raw & 1) != 0
    }

    /// CQS - Completion Queue Support
    pub fn cqs(&self) -> bool {
        ((self.raw >> 1) & 1) != 0
    }

    /// LISTS - PRP SGL List Support
    pub fn lists(&self) -> bool {
        ((self.raw >> 2) & 1) != 0
    }

    /// RDS - Read Data Support
    pub fn rds(&self) -> bool {
        ((self.raw >> 3) & 1) != 0
    }

    /// WDS - Write Data Support
    pub fn wds(&self) -> bool {
        ((self.raw >> 4) & 1) != 0
    }

    /// SZU - Size Units (bits 11:8)
    pub fn szu(&self) -> u8 {
        ((self.raw >> 8) & 0xF) as u8
    }

    /// SZ - Size (bits 31:12)
    pub fn sz(&self) -> u32 {
        (self.raw >> 12) & 0xFFFFF
    }

    /// サイズ（バイト）
    pub fn size_bytes(&self) -> u64 {
        let unit_size: u64 = match self.szu() {
            0 => 4 * 1024,                // 4KB
            1 => 64 * 1024,               // 64KB
            2 => 1024 * 1024,             // 1MB
            3 => 16 * 1024 * 1024,        // 16MB
            4 => 256 * 1024 * 1024,       // 256MB
            5 => 4 * 1024 * 1024 * 1024,  // 4GB
            6 => 64 * 1024 * 1024 * 1024, // 64GB
            _ => 0,
        };
        (self.sz() as u64) * unit_size
    }

    /// サポートされているか
    pub fn is_supported(&self) -> bool {
        self.sz() > 0
    }
}
