// ============================================================================
// src/io/nvme/controller.rs - NVMe Controller Registers and Configuration
// ============================================================================
//!
//! # NVMeコントローラレジスタと設定
//!
//! NVMe Base Spec 2.0 Section 3.1に基づくコントローラレジスタ定義。
//! Controller Memory Buffer (CMB) サポート含む。

#![allow(dead_code)]

// ============================================================================
// Constants
// ============================================================================

/// キャッシュラインサイズ（x86_64標準）
pub const CACHE_LINE_SIZE: usize = 64;

/// キューエントリサイズ（64バイト）
pub const QUEUE_ENTRY_SIZE: usize = 64;

/// Completion Entry サイズ（16バイト）
pub const CQ_ENTRY_SIZE: usize = 16;

/// 最大キュー深度
pub const MAX_QUEUE_DEPTH: u16 = 1024;

/// デフォルトキュー深度
pub const DEFAULT_QUEUE_DEPTH: u16 = 256;

/// 最大SGL長
pub const MAX_SGL_ENTRIES: usize = 32;

/// セクタサイズ
pub const SECTOR_SIZE: usize = 512;

/// ページサイズ（4KB）
pub const PAGE_SIZE: usize = 4096;

/// 最大転送サイズ（128KB）
pub const MAX_TRANSFER_SIZE: usize = 128 * 1024;

/// ポーリングバッチサイズ
pub const POLL_BATCH_SIZE: usize = 16;

/// ドアベルバッチ閾値（この数のコマンドが溜まったらフラッシュ）
pub const DOORBELL_BATCH_THRESHOLD: usize = 8;

/// コントローラレディタイムアウト（ミリ秒）
pub const CONTROLLER_READY_TIMEOUT_MS: u64 = 5000;

// ============================================================================
// Admin Command Opcodes
// ============================================================================

pub const ADMIN_DELETE_SQ: u8 = 0x00;
pub const ADMIN_CREATE_SQ: u8 = 0x01;
pub const ADMIN_GET_LOG_PAGE: u8 = 0x02;
pub const ADMIN_DELETE_CQ: u8 = 0x04;
pub const ADMIN_CREATE_CQ: u8 = 0x05;
pub const ADMIN_IDENTIFY: u8 = 0x06;
pub const ADMIN_ABORT: u8 = 0x08;
pub const ADMIN_SET_FEATURES: u8 = 0x09;
pub const ADMIN_GET_FEATURES: u8 = 0x0A;
pub const ADMIN_ASYNC_EVENT_REQ: u8 = 0x0C;
pub const ADMIN_NS_MGMT: u8 = 0x0D;
pub const ADMIN_FW_COMMIT: u8 = 0x10;
pub const ADMIN_FW_DOWNLOAD: u8 = 0x11;

// ============================================================================
// I/O Command Opcodes
// ============================================================================

pub const IO_FLUSH: u8 = 0x00;
pub const IO_WRITE: u8 = 0x01;
pub const IO_READ: u8 = 0x02;
pub const IO_WRITE_UNCORRECTABLE: u8 = 0x04;
pub const IO_COMPARE: u8 = 0x05;
pub const IO_WRITE_ZEROES: u8 = 0x08;
pub const IO_DATASET_MGMT: u8 = 0x09; // TRIM

// ============================================================================
// Feature IDs
// ============================================================================

pub const FEATURE_ARBITRATION: u8 = 0x01;
pub const FEATURE_POWER_MGMT: u8 = 0x02;
pub const FEATURE_LBA_RANGE_TYPE: u8 = 0x03;
pub const FEATURE_TEMP_THRESHOLD: u8 = 0x04;
pub const FEATURE_ERROR_RECOVERY: u8 = 0x05;
pub const FEATURE_VOLATILE_WC: u8 = 0x06;
pub const FEATURE_NUM_QUEUES: u8 = 0x07;
pub const FEATURE_IRQ_COALESCING: u8 = 0x08;
pub const FEATURE_IRQ_CONFIG: u8 = 0x09;
pub const FEATURE_WRITE_ATOMICITY: u8 = 0x0A;
pub const FEATURE_ASYNC_EVENT_CONFIG: u8 = 0x0B;

// ============================================================================
// NVMe Controller Registers (BAR0)
// ============================================================================

/// NVMe Controller Registers マップ
/// NVMe Base Spec 2.0 Section 3.1
#[repr(C)]
pub struct NvmeControllerRegisters {
    /// Controller Capabilities (0x00) - RO
    pub cap: u64,
    /// Version (0x08) - RO
    pub vs: u32,
    /// Interrupt Mask Set (0x0C) - RW1S
    pub intms: u32,
    /// Interrupt Mask Clear (0x10) - RW1C
    pub intmc: u32,
    /// Controller Configuration (0x14) - RW
    pub cc: u32,
    /// Reserved (0x18)
    _reserved1: u32,
    /// Controller Status (0x1C) - RO
    pub csts: u32,
    /// NVM Subsystem Reset (0x20) - RW
    pub nssr: u32,
    /// Admin Queue Attributes (0x24) - RW
    pub aqa: u32,
    /// Admin Submission Queue Base Address (0x28) - RW
    pub asq: u64,
    /// Admin Completion Queue Base Address (0x30) - RW
    pub acq: u64,
    /// Controller Memory Buffer Location (0x38) - RO
    pub cmbloc: u32,
    /// Controller Memory Buffer Size (0x3C) - RO
    pub cmbsz: u32,
    /// Boot Partition Info (0x40) - RO
    pub bpinfo: u32,
    /// Boot Partition Read Select (0x44) - RW
    pub bprsel: u32,
    /// Boot Partition Memory Buffer Location (0x48) - RW
    pub bpmbl: u64,
    /// Controller Memory Buffer Memory Space Control (0x50) - RW
    pub cmbmsc: u64,
    /// Controller Memory Buffer Status (0x58) - RO
    pub cmbsts: u32,
    /// Controller Memory Buffer Elasticity Buffer Size (0x5C) - RO
    pub cmbebs: u32,
    /// Controller Memory Buffer Sustained Write Throughput (0x60) - RO
    pub cmbswtp: u32,
    /// NVM Subsystem Shutdown (0x64) - RW
    pub nssd: u32,
    /// Controller Ready Timeouts (0x68) - RO
    pub crto: u32,
    /// Reserved (0x6C - 0xDFF)
    _reserved2: [u8; 0xD00 - 0x6C],
    /// PMR Capabilities (0xE00) - RO
    pub pmrcap: u32,
    /// PMR Control (0xE04) - RW
    pub pmrctl: u32,
    /// PMR Status (0xE08) - RO
    pub pmrsts: u32,
    /// PMR Elasticity Buffer Size (0xE0C) - RO
    pub pmrebs: u32,
    /// PMR Sustained Write Throughput (0xE10) - RO
    pub pmrswtp: u32,
    /// PMR Memory Space Control (0xE14) - RW
    pub pmrmsc: u64,
}

// ============================================================================
// CAP - Controller Capabilities
// ============================================================================

/// CAP - Controller Capabilities (Offset 0x00)
#[derive(Debug, Clone, Copy)]
pub struct NvmeCapabilities {
    raw: u64,
}

impl NvmeCapabilities {
    pub fn new(raw: u64) -> Self {
        Self { raw }
    }

    /// Maximum Queue Entries Supported (0-based, add 1 for actual count)
    pub fn mqes(&self) -> u16 {
        (self.raw & 0xFFFF) as u16
    }

    /// Contiguous Queues Required
    pub fn cqr(&self) -> bool {
        ((self.raw >> 16) & 1) != 0
    }

    /// Arbitration Mechanism Supported
    pub fn ams(&self) -> u8 {
        ((self.raw >> 17) & 0x3) as u8
    }

    /// Timeout (in 500ms units)
    pub fn to(&self) -> u8 {
        ((self.raw >> 24) & 0xFF) as u8
    }

    /// Doorbell Stride (2^(2+DSTRD) bytes)
    pub fn dstrd(&self) -> u8 {
        ((self.raw >> 32) & 0xF) as u8
    }

    /// NVM Subsystem Reset Supported
    pub fn nssrs(&self) -> bool {
        ((self.raw >> 36) & 1) != 0
    }

    /// Command Sets Supported
    pub fn css(&self) -> u8 {
        ((self.raw >> 37) & 0xFF) as u8
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

    /// Memory Page Size Maximum (2^(12+MPSMAX) bytes)
    pub fn mpsmax(&self) -> u8 {
        ((self.raw >> 52) & 0xF) as u8
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

    /// ドアベルストライド（バイト単位）
    pub fn doorbell_stride_bytes(&self) -> usize {
        4 << self.dstrd()
    }

    /// 最大キュー深度
    pub fn max_queue_depth(&self) -> u16 {
        self.mqes() + 1
    }
}

// ============================================================================
// Controller Memory Buffer (CMB) Support
// ============================================================================

/// CMBLOC - Controller Memory Buffer Location (Offset 0x38)
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

    /// CDPMLS - CMB Data Pointer Mixed Locations Support (bit 6)
    pub fn cdpmls(&self) -> bool {
        ((self.raw >> 6) & 1) != 0
    }

    /// CDPCILS - CMB Data Pointer and Command Independent Locations Support (bit 7)
    pub fn cdpcils(&self) -> bool {
        ((self.raw >> 7) & 1) != 0
    }

    /// CDMMMS - CMB Data Mixed Memory Support (bit 8)
    pub fn cdmmms(&self) -> bool {
        ((self.raw >> 8) & 1) != 0
    }

    /// CQDA - CQ Dword Aligned (bit 9)
    pub fn cqda(&self) -> bool {
        ((self.raw >> 9) & 1) != 0
    }

    /// OFST - Offset (bits 31:12)
    pub fn offset(&self) -> u32 {
        (self.raw >> 12) & 0xFFFFF
    }

    /// オフセットをバイト単位で取得
    pub fn offset_bytes(&self) -> u64 {
        (self.offset() as u64) << 12
    }
}

/// CMBSZ - Controller Memory Buffer Size (Offset 0x3C)
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

    /// CMBサイズをバイト単位で取得
    pub fn size_bytes(&self) -> u64 {
        let unit_size: u64 = match self.szu() {
            0 => 4 * 1024,
            1 => 64 * 1024,
            2 => 1024 * 1024,
            3 => 16 * 1024 * 1024,
            4 => 256 * 1024 * 1024,
            5 => 4 * 1024 * 1024 * 1024,
            6 => 64 * 1024 * 1024 * 1024,
            _ => 0,
        };
        (self.sz() as u64) * unit_size
    }

    /// CMBが使用可能かチェック
    pub fn is_supported(&self) -> bool {
        self.sz() > 0
    }
}

/// CMB情報構造体
#[derive(Debug, Clone)]
pub struct CmbInfo {
    /// CMBがサポートされているか
    pub supported: bool,
    /// SQ配置サポート
    pub sq_support: bool,
    /// CQ配置サポート
    pub cq_support: bool,
    /// PRPリストサポート
    pub prp_list_support: bool,
    /// 読み取りデータサポート
    pub read_data_support: bool,
    /// 書き込みデータサポート
    pub write_data_support: bool,
    /// CMBベースアドレス
    pub base_addr: u64,
    /// CMBサイズ（バイト）
    pub size: u64,
    /// 次に利用可能なオフセット
    pub next_alloc_offset: u64,
}

impl CmbInfo {
    /// CMBレジスタから情報を取得
    pub fn from_registers(bar0: u64, cmbloc: u32, cmbsz: u32, cap: &NvmeCapabilities) -> Self {
        let loc = CmbLocation::new(cmbloc);
        let size = CmbSize::new(cmbsz);

        let supported = cap.cmbs() && size.is_supported();

        let base_addr = if supported && loc.bir() == 0 {
            bar0 + loc.offset_bytes()
        } else {
            0
        };

        Self {
            supported,
            sq_support: size.sqs(),
            cq_support: size.cqs(),
            prp_list_support: size.lists(),
            read_data_support: size.rds(),
            write_data_support: size.wds(),
            base_addr,
            size: if supported { size.size_bytes() } else { 0 },
            next_alloc_offset: 0,
        }
    }

    /// CMBから64バイトアラインされた領域を割り当て
    pub fn allocate(&mut self, size: usize) -> Option<u64> {
        if !self.supported {
            return None;
        }

        let aligned_offset = (self.next_alloc_offset + 63) & !63;
        let end_offset = aligned_offset + size as u64;

        if end_offset > self.size {
            return None;
        }

        let addr = self.base_addr + aligned_offset;
        self.next_alloc_offset = end_offset;
        Some(addr)
    }

    /// Submission Queue用のバッファをCMBから割り当て
    pub fn allocate_sq(&mut self, depth: u16) -> Option<u64> {
        if !self.sq_support {
            return None;
        }
        let size = (depth as usize) * QUEUE_ENTRY_SIZE;
        self.allocate(size)
    }

    /// Completion Queue用のバッファをCMBから割り当て  
    pub fn allocate_cq(&mut self, depth: u16) -> Option<u64> {
        if !self.cq_support {
            return None;
        }
        let size = (depth as usize) * CQ_ENTRY_SIZE;
        self.allocate(size)
    }

    /// PRPリスト用のバッファをCMBから割り当て
    pub fn allocate_prp_list(&mut self, entries: usize) -> Option<u64> {
        if !self.prp_list_support {
            return None;
        }
        let size = entries * 8;
        self.allocate(size)
    }
}

// ============================================================================
// CC - Controller Configuration
// ============================================================================

/// CC - Controller Configuration (Offset 0x14)
#[derive(Debug, Clone, Copy, Default)]
pub struct NvmeControllerConfig {
    raw: u32,
}

impl NvmeControllerConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_raw(raw: u32) -> Self {
        Self { raw }
    }

    pub fn raw(&self) -> u32 {
        self.raw
    }

    /// Enable (bit 0)
    pub fn set_enable(&mut self, enable: bool) -> &mut Self {
        if enable {
            self.raw |= 1;
        } else {
            self.raw &= !1;
        }
        self
    }

    pub fn is_enabled(&self) -> bool {
        (self.raw & 1) != 0
    }

    /// I/O Command Set Selected (bits 4:6)
    pub fn set_css(&mut self, css: u8) -> &mut Self {
        self.raw = (self.raw & !0x70) | (((css & 0x7) as u32) << 4);
        self
    }

    /// Memory Page Size (bits 7:10) - 2^(12+MPS) bytes
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

    /// I/O Submission Queue Entry Size (bits 16:19) - 2^IOSQES bytes
    pub fn set_iosqes(&mut self, iosqes: u8) -> &mut Self {
        self.raw = (self.raw & !0xF0000) | (((iosqes & 0xF) as u32) << 16);
        self
    }

    /// I/O Completion Queue Entry Size (bits 20:23) - 2^IOCQES bytes
    pub fn set_iocqes(&mut self, iocqes: u8) -> &mut Self {
        self.raw = (self.raw & !0xF00000) | (((iocqes & 0xF) as u32) << 20);
        self
    }

    /// Crime (bits 24)
    pub fn set_crime(&mut self, crime: bool) -> &mut Self {
        if crime {
            self.raw |= 1 << 24;
        } else {
            self.raw &= !(1 << 24);
        }
        self
    }
}

// ============================================================================
// CSTS - Controller Status
// ============================================================================

/// CSTS - Controller Status (Offset 0x1C)
#[derive(Debug, Clone, Copy)]
pub struct NvmeControllerStatus {
    raw: u32,
}

impl NvmeControllerStatus {
    pub fn new(raw: u32) -> Self {
        Self { raw }
    }

    /// Ready (bit 0)
    pub fn rdy(&self) -> bool {
        (self.raw & 1) != 0
    }

    /// Controller Fatal Status (bit 1)
    pub fn cfs(&self) -> bool {
        ((self.raw >> 1) & 1) != 0
    }

    /// Shutdown Status (bits 2:3)
    pub fn shst(&self) -> u8 {
        ((self.raw >> 2) & 0x3) as u8
    }

    /// NVM Subsystem Reset Occurred (bit 4)
    pub fn nssro(&self) -> bool {
        ((self.raw >> 4) & 1) != 0
    }

    /// Processing Paused (bit 5)
    pub fn pp(&self) -> bool {
        ((self.raw >> 5) & 1) != 0
    }

    /// Shutdown Type (bit 6)
    pub fn st(&self) -> bool {
        ((self.raw >> 6) & 1) != 0
    }
}

// ============================================================================
// AQA - Admin Queue Attributes
// ============================================================================

/// AQA - Admin Queue Attributes (Offset 0x24)
#[derive(Debug, Clone, Copy, Default)]
pub struct NvmeAdminQueueAttributes {
    raw: u32,
}

impl NvmeAdminQueueAttributes {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn raw(&self) -> u32 {
        self.raw
    }

    /// Admin Submission Queue Size (0-based, bits 0:11)
    pub fn set_asqs(&mut self, size: u16) -> &mut Self {
        self.raw = (self.raw & !0xFFF) | ((size & 0xFFF) as u32);
        self
    }

    /// Admin Completion Queue Size (0-based, bits 16:27)
    pub fn set_acqs(&mut self, size: u16) -> &mut Self {
        self.raw = (self.raw & !0x0FFF0000) | (((size & 0xFFF) as u32) << 16);
        self
    }
}
