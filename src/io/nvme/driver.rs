// ============================================================================
// src/io/nvme/driver.rs - NVMe Polling Mode Driver
// ============================================================================
//!
//! # NVMeポーリングモードドライバ
//!
//! 設計書6.3に基づく高性能NVMeストレージアクセス。
//! コアごとのSubmission/Completion Queueとポーリングモードで
//! 最大スループットを実現。
//!
//! ## 機能
//! - マルチキューサポート（コアごとのSQ/CQ）
//! - ポーリングモード（割り込み不使用）
//! - 非同期コマンド発行
//! - I/O優先度サポート
//! - SGL（Scatter-Gather List）対応
//! - PRPリスト管理（4KB超転送対応）
//! - バッチ完了処理による高速化
//!
//! ## NVMe仕様準拠
//! - NVMe Base Specification 2.0
//! - コントローラ初期化シーケンス
//! - Admin/I/Oキュー管理
//!
//! ## 高速化対策
//! - キャッシュラインアラインメント（偽共有防止）
//! - ロックフリーコアローカルアクセス
//! - ドアベルバッチ処理（MMIOオーバーヘッド削減）
//! - Controller Memory Buffer (CMB) サポート

#![allow(dead_code)]

use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU64, Ordering};
use spin::Mutex;

// ============================================================================
// NVMe Constants
// ============================================================================

/// キャッシュラインサイズ（x86_64標準）
const CACHE_LINE_SIZE: usize = 64;

/// キューエントリサイズ（64バイト）
const QUEUE_ENTRY_SIZE: usize = 64;

/// Completion Entry サイズ（16バイト）
const CQ_ENTRY_SIZE: usize = 16;

/// 最大キュー深度
const MAX_QUEUE_DEPTH: u16 = 1024;

/// デフォルトキュー深度
const DEFAULT_QUEUE_DEPTH: u16 = 256;

/// 最大SGL長
const MAX_SGL_ENTRIES: usize = 32;

/// セクタサイズ
const SECTOR_SIZE: usize = 512;

/// ページサイズ（4KB）
const PAGE_SIZE: usize = 4096;

/// 最大転送サイズ（128KB）
const MAX_TRANSFER_SIZE: usize = 128 * 1024;

/// ポーリングバッチサイズ
const POLL_BATCH_SIZE: usize = 16;

/// ドアベルバッチ閾値（この数のコマンドが溜まったらフラッシュ）
const DOORBELL_BATCH_THRESHOLD: usize = 8;

/// コントローラレディタイムアウト（ミリ秒）
const CONTROLLER_READY_TIMEOUT_MS: u64 = 5000;

// ============================================================================
// NVMe Controller Registers (BAR0)
// ============================================================================

/// NVMe Controller Registers マップ
/// NVMe Base Spec 2.0 Section 3.1
#[repr(C)]
pub struct NvmeControllerRegisters {
    /// Controller Capabilities (0x00) - RO
    /// Bits [63:0]: CAP
    pub cap: u64,
    /// Version (0x08) - RO
    /// Bits [31:16]: MJR, [15:8]: MNR, [7:0]: TER
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
    /// CMBが存在するBAR番号
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
    /// CMBオフセット（4KB単位）
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
    /// 0 = 4KB, 1 = 64KB, 2 = 1MB, 3 = 16MB, 4 = 256MB, 5 = 4GB, 6 = 64GB
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

        // CMBベースアドレスの計算
        // CMBはBIRで指定されたBAR + OFSTオフセットに配置される
        // ここではBAR0の後にCMBがあると仮定（実際はBIR値を確認）
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

        // 64バイトアラインメント
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
        let size = entries * 8; // 各PRPエントリは8バイト
        self.allocate(size)
    }
}

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

// NVMe管理コマンドオペコード
const ADMIN_DELETE_SQ: u8 = 0x00;
const ADMIN_CREATE_SQ: u8 = 0x01;
const ADMIN_GET_LOG_PAGE: u8 = 0x02;
const ADMIN_DELETE_CQ: u8 = 0x04;
const ADMIN_CREATE_CQ: u8 = 0x05;
const ADMIN_IDENTIFY: u8 = 0x06;
const ADMIN_ABORT: u8 = 0x08;
const ADMIN_SET_FEATURES: u8 = 0x09;
const ADMIN_GET_FEATURES: u8 = 0x0A;
const ADMIN_ASYNC_EVENT_REQ: u8 = 0x0C;
const ADMIN_NS_MGMT: u8 = 0x0D;
const ADMIN_FW_COMMIT: u8 = 0x10;
const ADMIN_FW_DOWNLOAD: u8 = 0x11;

// NVMe I/Oコマンドオペコード
const IO_FLUSH: u8 = 0x00;
const IO_WRITE: u8 = 0x01;
const IO_READ: u8 = 0x02;
const IO_WRITE_UNCORRECTABLE: u8 = 0x04;
const IO_COMPARE: u8 = 0x05;
const IO_WRITE_ZEROES: u8 = 0x08;
const IO_DATASET_MGMT: u8 = 0x09; // TRIM

// Feature IDs
const FEATURE_ARBITRATION: u8 = 0x01;
const FEATURE_POWER_MGMT: u8 = 0x02;
const FEATURE_LBA_RANGE_TYPE: u8 = 0x03;
const FEATURE_TEMP_THRESHOLD: u8 = 0x04;
const FEATURE_ERROR_RECOVERY: u8 = 0x05;
const FEATURE_VOLATILE_WC: u8 = 0x06;
const FEATURE_NUM_QUEUES: u8 = 0x07;
const FEATURE_IRQ_COALESCING: u8 = 0x08;
const FEATURE_IRQ_CONFIG: u8 = 0x09;
const FEATURE_WRITE_ATOMICITY: u8 = 0x0A;
const FEATURE_ASYNC_EVENT_CONFIG: u8 = 0x0B;

// ============================================================================
// PRP List Management
// ============================================================================

/// PRPリストエントリ
/// Physical Region Page - 4KB境界アライン必須
#[repr(C, align(8))]
#[derive(Clone, Copy, Debug, Default)]
pub struct PrpEntry {
    pub addr: u64,
}

/// PRPリスト（4KB超の転送用）
#[repr(C, align(4096))]
pub struct PrpList {
    /// PRPエントリ配列（最大512エントリ = 4096/8）
    entries: [PrpEntry; 512],
    /// 使用中エントリ数
    count: usize,
}

impl PrpList {
    /// 新しいPRPリストを作成
    pub fn new() -> Self {
        Self {
            entries: [PrpEntry::default(); 512],
            count: 0,
        }
    }

    /// エントリを追加
    pub fn add_entry(&mut self, addr: u64) -> Result<(), &'static str> {
        if self.count >= 512 {
            return Err("PRP list full");
        }

        // 4KB境界チェック
        if addr & 0xFFF != 0 {
            return Err("PRP address must be 4KB aligned");
        }

        self.entries[self.count] = PrpEntry { addr };
        self.count += 1;
        Ok(())
    }

    /// リストの物理アドレスを取得
    pub fn phys_addr(&self) -> u64 {
        self.entries.as_ptr() as u64
    }

    /// エントリ数を取得
    pub fn len(&self) -> usize {
        self.count
    }

    /// 空かどうか
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// クリア
    pub fn clear(&mut self) {
        self.count = 0;
    }
}

impl Default for PrpList {
    fn default() -> Self {
        Self::new()
    }
}

/// SGLセグメントタイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SglType {
    DataBlock = 0x00,
    BitBucket = 0x01,
    Segment = 0x02,
    LastSegment = 0x03,
    KeyedDataBlock = 0x04,
    Transport = 0x05,
}

/// SGLディスクリプタ
#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, Default)]
pub struct SglDescriptor {
    /// アドレス
    pub addr: u64,
    /// 長さ
    pub length: u32,
    /// 予約
    _reserved: [u8; 3],
    /// タイプとサブタイプ
    pub type_specific: u8,
}

impl SglDescriptor {
    /// データブロックSGLを作成
    pub fn data_block(addr: u64, length: u32) -> Self {
        Self {
            addr,
            length,
            _reserved: [0; 3],
            type_specific: (SglType::DataBlock as u8) << 4,
        }
    }

    /// ラストセグメントSGLを作成
    pub fn last_segment(addr: u64, length: u32) -> Self {
        Self {
            addr,
            length,
            _reserved: [0; 3],
            type_specific: (SglType::LastSegment as u8) << 4,
        }
    }
}

// ============================================================================
// NVMe Data Structures
// ============================================================================

/// NVMe Submission Queue Entry
#[repr(C, align(64))]
#[derive(Clone, Copy, Debug, Default)]
pub struct NvmeCommand {
    /// Command Dword 0
    pub cdw0: u32,
    /// Namespace ID
    pub nsid: u32,
    /// Reserved
    pub reserved: [u32; 2],
    /// Metadata Pointer
    pub mptr: u64,
    /// Data Pointer (PRP or SGL)
    pub dptr: [u64; 2],
    /// Command Dwords 10-15
    pub cdw10: u32,
    pub cdw11: u32,
    pub cdw12: u32,
    pub cdw13: u32,
    pub cdw14: u32,
    pub cdw15: u32,
}

impl NvmeCommand {
    /// 新しいコマンドを作成
    pub fn new() -> Self {
        Self::default()
    }

    /// オペコードを設定
    pub fn set_opcode(&mut self, opcode: u8) {
        self.cdw0 = (self.cdw0 & !0xFF) | (opcode as u32);
    }

    /// Fused Operation (bits 8:9)
    pub fn set_fused(&mut self, fused: u8) {
        self.cdw0 = (self.cdw0 & !0x300) | (((fused & 0x3) as u32) << 8);
    }

    /// PSDT - PRP or SGL for Data Transfer (bits 14:15)
    pub fn set_psdt(&mut self, psdt: u8) {
        self.cdw0 = (self.cdw0 & !0xC000) | (((psdt & 0x3) as u32) << 14);
    }

    /// コマンドIDを設定
    pub fn set_cid(&mut self, cid: u16) {
        self.cdw0 = (self.cdw0 & 0xFFFF) | ((cid as u32) << 16);
    }

    /// PRPエントリを設定
    pub fn set_prp(&mut self, prp1: u64, prp2: u64) {
        self.dptr[0] = prp1;
        self.dptr[1] = prp2;
    }

    /// SGLを設定
    pub fn set_sgl(&mut self, sgl: &SglDescriptor) {
        self.set_psdt(0x01); // SGL with metadata
        self.dptr[0] = sgl.addr;
        self.dptr[1] = ((sgl.length as u64) << 32) | (sgl.type_specific as u64);
    }

    // ========================================
    // Admin Commands
    // ========================================

    /// Identify Controller コマンドを作成
    pub fn identify_controller(prp1: u64) -> Self {
        let mut cmd = Self::new();
        cmd.set_opcode(ADMIN_IDENTIFY);
        cmd.cdw10 = 0x01; // CNS = 01h: Identify Controller
        cmd.set_prp(prp1, 0);
        cmd
    }

    /// Identify Namespace コマンドを作成
    pub fn identify_namespace(nsid: u32, prp1: u64) -> Self {
        let mut cmd = Self::new();
        cmd.set_opcode(ADMIN_IDENTIFY);
        cmd.nsid = nsid;
        cmd.cdw10 = 0x00; // CNS = 00h: Identify Namespace
        cmd.set_prp(prp1, 0);
        cmd
    }

    /// Create I/O Completion Queue コマンドを作成
    pub fn create_io_cq(
        qid: u16,
        queue_size: u16,
        prp: u64,
        irq_vector: u16,
        irq_enabled: bool,
    ) -> Self {
        let mut cmd = Self::new();
        cmd.set_opcode(ADMIN_CREATE_CQ);
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
    pub fn create_io_sq(qid: u16, queue_size: u16, prp: u64, cqid: u16, priority: u8) -> Self {
        let mut cmd = Self::new();
        cmd.set_opcode(ADMIN_CREATE_SQ);
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
    pub fn delete_io_sq(qid: u16) -> Self {
        let mut cmd = Self::new();
        cmd.set_opcode(ADMIN_DELETE_SQ);
        cmd.cdw10 = qid as u32;
        cmd
    }

    /// Delete I/O Completion Queue コマンドを作成
    pub fn delete_io_cq(qid: u16) -> Self {
        let mut cmd = Self::new();
        cmd.set_opcode(ADMIN_DELETE_CQ);
        cmd.cdw10 = qid as u32;
        cmd
    }

    /// Set Features - Number of Queues コマンドを作成
    pub fn set_features_num_queues(nsq: u16, ncq: u16) -> Self {
        let mut cmd = Self::new();
        cmd.set_opcode(ADMIN_SET_FEATURES);
        cmd.cdw10 = FEATURE_NUM_QUEUES as u32;
        // CDW11: NCQR (31:16) | NSQR (15:0)
        cmd.cdw11 = ((ncq - 1) as u32) << 16 | ((nsq - 1) as u32);
        cmd
    }

    /// Get Features コマンドを作成
    pub fn get_features(fid: u8, nsid: u32) -> Self {
        let mut cmd = Self::new();
        cmd.set_opcode(ADMIN_GET_FEATURES);
        cmd.nsid = nsid;
        cmd.cdw10 = fid as u32;
        cmd
    }

    // ========================================
    // I/O Commands
    // ========================================

    /// 読み取りコマンドを作成
    pub fn read(nsid: u32, lba: u64, blocks: u16, prp1: u64, prp2: u64) -> Self {
        let mut cmd = Self::new();
        cmd.set_opcode(IO_READ);
        cmd.nsid = nsid;
        cmd.cdw10 = lba as u32;
        cmd.cdw11 = (lba >> 32) as u32;
        cmd.cdw12 = (blocks - 1) as u32; // 0-based
        cmd.set_prp(prp1, prp2);
        cmd
    }

    /// 読み取りコマンドを作成（PRPリスト使用）
    pub fn read_with_prp_list(
        nsid: u32,
        lba: u64,
        blocks: u16,
        prp1: u64,
        prp_list: &PrpList,
    ) -> Self {
        let mut cmd = Self::read(nsid, lba, blocks, prp1, 0);
        if prp_list.len() > 0 {
            cmd.dptr[1] = prp_list.phys_addr();
        }
        cmd
    }

    /// 書き込みコマンドを作成
    pub fn write(nsid: u32, lba: u64, blocks: u16, prp1: u64, prp2: u64) -> Self {
        let mut cmd = Self::new();
        cmd.set_opcode(IO_WRITE);
        cmd.nsid = nsid;
        cmd.cdw10 = lba as u32;
        cmd.cdw11 = (lba >> 32) as u32;
        cmd.cdw12 = (blocks - 1) as u32;
        cmd.set_prp(prp1, prp2);
        cmd
    }

    /// 書き込みコマンドを作成（PRPリスト使用）
    pub fn write_with_prp_list(
        nsid: u32,
        lba: u64,
        blocks: u16,
        prp1: u64,
        prp_list: &PrpList,
    ) -> Self {
        let mut cmd = Self::write(nsid, lba, blocks, prp1, 0);
        if prp_list.len() > 0 {
            cmd.dptr[1] = prp_list.phys_addr();
        }
        cmd
    }

    /// フラッシュコマンドを作成
    pub fn flush(nsid: u32) -> Self {
        let mut cmd = Self::new();
        cmd.set_opcode(IO_FLUSH);
        cmd.nsid = nsid;
        cmd
    }

    /// Write Zerosコマンドを作成
    pub fn write_zeroes(nsid: u32, lba: u64, blocks: u16) -> Self {
        let mut cmd = Self::new();
        cmd.set_opcode(IO_WRITE_ZEROES);
        cmd.nsid = nsid;
        cmd.cdw10 = lba as u32;
        cmd.cdw11 = (lba >> 32) as u32;
        cmd.cdw12 = (blocks - 1) as u32;
        cmd
    }

    /// TRIM (Dataset Management) コマンドを作成
    pub fn trim(nsid: u32, ranges_prp: u64, num_ranges: u32) -> Self {
        let mut cmd = Self::new();
        cmd.set_opcode(IO_DATASET_MGMT);
        cmd.nsid = nsid;
        cmd.set_prp(ranges_prp, 0);
        cmd.cdw10 = num_ranges - 1; // 0-based
        cmd.cdw11 = 0x04; // Attribute: Deallocate
        cmd
    }
}

/// NVMe Completion Queue Entry
#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, Default)]
pub struct NvmeCompletion {
    /// Command Specific
    pub dw0: u32,
    /// Reserved
    pub dw1: u32,
    /// SQ Head Pointer
    pub sq_head: u16,
    /// SQ Identifier
    pub sq_id: u16,
    /// Command Identifier
    pub cid: u16,
    /// Status Field
    pub status: u16,
}

impl NvmeCompletion {
    /// フェーズタグを取得
    pub fn phase(&self) -> bool {
        (self.status & 1) != 0
    }

    /// ステータスコードを取得
    pub fn status_code(&self) -> u8 {
        ((self.status >> 1) & 0xFF) as u8
    }

    /// ステータスコードタイプを取得
    pub fn status_code_type(&self) -> u8 {
        ((self.status >> 9) & 0x7) as u8
    }

    /// 成功かどうか
    pub fn is_success(&self) -> bool {
        self.status_code() == 0 && self.status_code_type() == 0
    }
}

// ============================================================================
// Queue Pair
// ============================================================================

/// Submission Queue
pub struct SubmissionQueue {
    /// キューバッファ
    buffer: *mut NvmeCommand,
    /// キュー深度
    depth: u16,
    /// 現在のテール
    tail: AtomicU16,
    /// ドアベルレジスタアドレス
    doorbell: *mut u32,
    /// キューID
    qid: u16,
}

unsafe impl Send for SubmissionQueue {}
unsafe impl Sync for SubmissionQueue {}

impl SubmissionQueue {
    /// 新しいSQを作成
    pub unsafe fn new(buffer: *mut NvmeCommand, depth: u16, doorbell: *mut u32, qid: u16) -> Self {
        Self {
            buffer,
            depth,
            tail: AtomicU16::new(0),
            doorbell,
            qid,
        }
    }

    /// コマンドを送信（ドアベル書き込みあり）
    pub fn submit(&self, cmd: &NvmeCommand) -> Result<u16, &'static str> {
        let cid = self.submit_no_doorbell(cmd)?;
        self.ring_doorbell();
        Ok(cid)
    }

    /// コマンドを送信（ドアベル書き込みなし - バッチ処理用）
    ///
    /// 複数のコマンドをキューに投入してから一度だけドアベルを
    /// 書き込むことで、MMIOオーバーヘッドを削減。
    pub fn submit_no_doorbell(&self, cmd: &NvmeCommand) -> Result<u16, &'static str> {
        let tail = self.tail.load(Ordering::Acquire);
        let next_tail = (tail + 1) % self.depth;

        // キューが満杯の場合はエラー
        // 注：実際にはCQ Headとの比較が必要

        unsafe {
            let entry = self.buffer.add(tail as usize);
            write_volatile(entry, *cmd);

            // メモリバリア（コマンドの書き込みがドアベル前に完了することを保証）
            core::sync::atomic::fence(Ordering::Release);
        }

        self.tail.store(next_tail, Ordering::Release);
        Ok(tail)
    }

    /// ドアベルを鳴らす（コントローラにSQテール更新を通知）
    ///
    /// バッチ処理時は複数コマンド投入後にこれを1回呼ぶ。
    #[inline]
    pub fn ring_doorbell(&self) {
        let tail = self.tail.load(Ordering::Acquire);
        unsafe {
            // MMIO書き込み（高コスト）
            write_volatile(self.doorbell, tail as u32);
        }
    }

    /// キューIDを取得
    pub fn qid(&self) -> u16 {
        self.qid
    }

    /// 現在のテール位置を取得
    pub fn tail(&self) -> u16 {
        self.tail.load(Ordering::Acquire)
    }

    /// キュー深度を取得
    pub fn depth(&self) -> u16 {
        self.depth
    }
}

/// Completion Queue
pub struct CompletionQueue {
    /// キューバッファ
    buffer: *mut NvmeCompletion,
    /// キュー深度
    depth: u16,
    /// 現在のヘッド
    head: AtomicU16,
    /// フェーズビット
    phase: AtomicBool,
    /// ドアベルレジスタアドレス
    doorbell: *mut u32,
    /// キューID
    qid: u16,
}

unsafe impl Send for CompletionQueue {}
unsafe impl Sync for CompletionQueue {}

impl CompletionQueue {
    /// 新しいCQを作成
    pub unsafe fn new(
        buffer: *mut NvmeCompletion,
        depth: u16,
        doorbell: *mut u32,
        qid: u16,
    ) -> Self {
        Self {
            buffer,
            depth,
            head: AtomicU16::new(0),
            phase: AtomicBool::new(true),
            doorbell,
            qid,
        }
    }

    /// 完了をポーリング
    pub fn poll(&self) -> Option<NvmeCompletion> {
        let head = self.head.load(Ordering::Acquire);
        let expected_phase = self.phase.load(Ordering::Acquire);

        let entry = unsafe { read_volatile(self.buffer.add(head as usize)) };

        // フェーズビットをチェック
        if entry.phase() != expected_phase {
            return None;
        }

        // ヘッドを進める
        let next_head = (head + 1) % self.depth;
        self.head.store(next_head, Ordering::Release);

        // ラップアラウンド時にフェーズを反転
        if next_head == 0 {
            self.phase.fetch_xor(true, Ordering::AcqRel);
        }

        Some(entry)
    }

    /// ドアベルを更新（完了処理後に呼ぶ）
    pub fn update_doorbell(&self) {
        let head = self.head.load(Ordering::Acquire);
        unsafe {
            write_volatile(self.doorbell, head as u32);
        }
    }

    /// キューIDを取得
    pub fn qid(&self) -> u16 {
        self.qid
    }
}

/// キューペア（SQ + CQ）
pub struct QueuePair {
    sq: SubmissionQueue,
    cq: CompletionQueue,
    /// 未完了コマンド数
    outstanding: AtomicU32,
}

impl QueuePair {
    /// 新しいキューペアを作成
    pub unsafe fn new(
        sq_buffer: *mut NvmeCommand,
        cq_buffer: *mut NvmeCompletion,
        depth: u16,
        sq_doorbell: *mut u32,
        cq_doorbell: *mut u32,
        qid: u16,
    ) -> Self {
        Self {
            sq: unsafe { SubmissionQueue::new(sq_buffer, depth, sq_doorbell, qid) },
            cq: unsafe { CompletionQueue::new(cq_buffer, depth, cq_doorbell, qid) },
            outstanding: AtomicU32::new(0),
        }
    }

    /// コマンドを送信
    pub fn submit(&self, cmd: &NvmeCommand) -> Result<u16, &'static str> {
        self.outstanding.fetch_add(1, Ordering::AcqRel);
        self.sq.submit(cmd)
    }

    /// 完了をポーリング
    pub fn poll_completion(&self) -> Option<NvmeCompletion> {
        if let Some(cqe) = self.cq.poll() {
            self.outstanding.fetch_sub(1, Ordering::AcqRel);
            self.cq.update_doorbell();
            Some(cqe)
        } else {
            None
        }
    }

    /// 未完了コマンド数を取得
    pub fn outstanding(&self) -> u32 {
        self.outstanding.load(Ordering::Acquire)
    }
}

// ============================================================================
// Per-Core Queue (Lock-free, Cache-line aligned)
// ============================================================================

/// キュー統計（キャッシュライン整列）
#[repr(C, align(64))]
#[derive(Debug, Default)]
pub struct NvmeQueueStats {
    pub commands_submitted: AtomicU64,
    pub commands_completed: AtomicU64,
    pub read_bytes: AtomicU64,
    pub write_bytes: AtomicU64,
    pub errors: AtomicU64,
    pub poll_cycles: AtomicU64,
    pub doorbell_writes: AtomicU64,
    pub batched_commands: AtomicU64,
    _padding: [u8; 0], // 64バイト境界にパディング
}

/// コアごとのNVMeキュー（キャッシュライン整列、ロックフリー）
///
/// 64バイトアラインメントにより、異なるコア間での
/// 偽共有（false sharing）を防止し、キャッシュ効率を最大化。
///
/// UnsafeCellにより、各コアが自身のキューにロックフリーでアクセス可能。
/// （コアアフィニティによりレースコンディションは発生しない）
#[repr(C, align(64))]
pub struct PerCoreNvmeQueue {
    /// キューペア（UnsafeCellでロックフリーアクセス）
    inner: UnsafeCell<Option<QueuePair>>,
    /// コアID
    core_id: u32,
    /// 初期化完了フラグ
    initialized: AtomicBool,
    /// ドアベルバッチカウンタ（保留中のコマンド数）
    pending_commands: AtomicU32,
    /// 統計（別キャッシュライン）
    stats: NvmeQueueStats,
}

// Safety: PerCoreNvmeQueueは各コア固有のキューとして使用され、
// コアアフィニティによりシングルスレッドアクセスが保証される。
// 初期化以外の操作は所有コアからのみ行われる。
unsafe impl Sync for PerCoreNvmeQueue {}
unsafe impl Send for PerCoreNvmeQueue {}

impl PerCoreNvmeQueue {
    /// 新しいコアキューを作成
    pub const fn new(core_id: u32) -> Self {
        Self {
            inner: UnsafeCell::new(None),
            core_id,
            initialized: AtomicBool::new(false),
            pending_commands: AtomicU32::new(0),
            stats: NvmeQueueStats {
                commands_submitted: AtomicU64::new(0),
                commands_completed: AtomicU64::new(0),
                read_bytes: AtomicU64::new(0),
                write_bytes: AtomicU64::new(0),
                errors: AtomicU64::new(0),
                poll_cycles: AtomicU64::new(0),
                doorbell_writes: AtomicU64::new(0),
                batched_commands: AtomicU64::new(0),
                _padding: [],
            },
        }
    }

    /// キューペアを設定（初期化時のみ呼び出し）
    ///
    /// # Safety
    /// 初期化中にのみ呼び出すこと。他のスレッドから同時アクセスがないことを保証。
    pub unsafe fn set_queue_pair(&self, qp: QueuePair) {
        let ptr = self.inner.get();
        unsafe { (*ptr) = Some(qp) };
        self.initialized.store(true, Ordering::Release);
    }

    /// キューが初期化済みかチェック
    #[inline]
    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::Acquire)
    }

    /// ロックフリーでキューペアにアクセス（所有コアのみ）
    ///
    /// # Safety
    /// 現在のコアがこのPerCoreNvmeQueueの所有者であることを呼び出し側が保証。
    #[inline]
    unsafe fn get_queue_pair(&self) -> Option<&QueuePair> {
        unsafe { (*self.inner.get()).as_ref() }
    }

    /// ロックフリーでキューペアに可変アクセス（所有コアのみ）
    ///
    /// # Safety
    /// 現在のコアがこのPerCoreNvmeQueueの所有者であることを呼び出し側が保証。
    #[inline]
    #[allow(dead_code)]
    unsafe fn get_queue_pair_mut(&self) -> Option<&mut QueuePair> {
        unsafe { (*self.inner.get()).as_mut() }
    }

    /// 読み取り操作を発行（ドアベルバッチ対応）
    ///
    /// # Safety
    /// 現在のコアがこのキューの所有者であることを呼び出し側が保証。
    pub unsafe fn read(
        &self,
        nsid: u32,
        lba: u64,
        blocks: u16,
        prp1: u64,
        prp2: u64,
    ) -> Result<u16, &'static str> {
        let qp = unsafe { self.get_queue_pair() }.ok_or("Queue not initialized")?;

        let cmd = NvmeCommand::read(nsid, lba, blocks, prp1, prp2);
        let cid = qp.sq.submit_no_doorbell(&cmd)?;

        self.stats
            .commands_submitted
            .fetch_add(1, Ordering::Relaxed);
        self.stats
            .read_bytes
            .fetch_add((blocks as u64) * (SECTOR_SIZE as u64), Ordering::Relaxed);

        // バッチカウンタをインクリメント
        let pending = self.pending_commands.fetch_add(1, Ordering::Relaxed) + 1;

        // 閾値を超えたらドアベルをフラッシュ
        if pending >= DOORBELL_BATCH_THRESHOLD as u32 {
            unsafe { self.flush_doorbell() };
        }

        Ok(cid)
    }

    /// 読み取り操作を即時発行（ドアベルを即座に書き込み）
    ///
    /// # Safety
    /// 現在のコアがこのキューの所有者であることを呼び出し側が保証。
    pub unsafe fn read_immediate(
        &self,
        nsid: u32,
        lba: u64,
        blocks: u16,
        prp1: u64,
        prp2: u64,
    ) -> Result<u16, &'static str> {
        let qp = unsafe { self.get_queue_pair() }.ok_or("Queue not initialized")?;

        let cmd = NvmeCommand::read(nsid, lba, blocks, prp1, prp2);
        let cid = qp.submit(&cmd)?;

        self.stats
            .commands_submitted
            .fetch_add(1, Ordering::Relaxed);
        self.stats
            .read_bytes
            .fetch_add((blocks as u64) * (SECTOR_SIZE as u64), Ordering::Relaxed);
        self.stats.doorbell_writes.fetch_add(1, Ordering::Relaxed);

        Ok(cid)
    }

    /// 書き込み操作を発行（ドアベルバッチ対応）
    ///
    /// # Safety
    /// 現在のコアがこのキューの所有者であることを呼び出し側が保証。
    pub unsafe fn write(
        &self,
        nsid: u32,
        lba: u64,
        blocks: u16,
        prp1: u64,
        prp2: u64,
    ) -> Result<u16, &'static str> {
        let qp = unsafe { self.get_queue_pair() }.ok_or("Queue not initialized")?;

        let cmd = NvmeCommand::write(nsid, lba, blocks, prp1, prp2);
        let cid = qp.sq.submit_no_doorbell(&cmd)?;

        self.stats
            .commands_submitted
            .fetch_add(1, Ordering::Relaxed);
        self.stats
            .write_bytes
            .fetch_add((blocks as u64) * (SECTOR_SIZE as u64), Ordering::Relaxed);

        // バッチカウンタをインクリメント
        let pending = self.pending_commands.fetch_add(1, Ordering::Relaxed) + 1;

        // 閾値を超えたらドアベルをフラッシュ
        if pending >= DOORBELL_BATCH_THRESHOLD as u32 {
            unsafe { self.flush_doorbell() };
        }

        Ok(cid)
    }

    /// 書き込み操作を即時発行（ドアベルを即座に書き込み）
    ///
    /// # Safety
    /// 現在のコアがこのキューの所有者であることを呼び出し側が保証。
    pub unsafe fn write_immediate(
        &self,
        nsid: u32,
        lba: u64,
        blocks: u16,
        prp1: u64,
        prp2: u64,
    ) -> Result<u16, &'static str> {
        let qp = unsafe { self.get_queue_pair() }.ok_or("Queue not initialized")?;

        let cmd = NvmeCommand::write(nsid, lba, blocks, prp1, prp2);
        let cid = qp.submit(&cmd)?;

        self.stats
            .commands_submitted
            .fetch_add(1, Ordering::Relaxed);
        self.stats
            .write_bytes
            .fetch_add((blocks as u64) * (SECTOR_SIZE as u64), Ordering::Relaxed);
        self.stats.doorbell_writes.fetch_add(1, Ordering::Relaxed);

        Ok(cid)
    }

    /// 保留中のコマンドをフラッシュ（ドアベル書き込み）
    ///
    /// # Safety
    /// 現在のコアがこのキューの所有者であることを呼び出し側が保証。
    pub unsafe fn flush_doorbell(&self) {
        if let Some(qp) = unsafe { self.get_queue_pair() } {
            let pending = self.pending_commands.swap(0, Ordering::Relaxed);
            if pending > 0 {
                qp.sq.ring_doorbell();
                self.stats.doorbell_writes.fetch_add(1, Ordering::Relaxed);
                self.stats
                    .batched_commands
                    .fetch_add(pending as u64, Ordering::Relaxed);
            }
        }
    }

    /// 完了をポーリング
    ///
    /// # Safety
    /// 現在のコアがこのキューの所有者であることを呼び出し側が保証。
    pub unsafe fn poll(&self) -> Option<NvmeCompletion> {
        let qp = unsafe { self.get_queue_pair() }?;

        self.stats.poll_cycles.fetch_add(1, Ordering::Relaxed);

        if let Some(cqe) = qp.poll_completion() {
            self.stats
                .commands_completed
                .fetch_add(1, Ordering::Relaxed);
            if !cqe.is_success() {
                self.stats.errors.fetch_add(1, Ordering::Relaxed);
            }
            Some(cqe)
        } else {
            None
        }
    }

    /// バッチポーリング（複数の完了を一度に処理）
    ///
    /// # Safety
    /// 現在のコアがこのキューの所有者であることを呼び出し側が保証。
    pub unsafe fn poll_batch(&self, max_completions: usize) -> Vec<NvmeCompletion> {
        let mut completions = Vec::with_capacity(max_completions);

        for _ in 0..max_completions {
            if let Some(cqe) = unsafe { self.poll() } {
                completions.push(cqe);
            } else {
                break;
            }
        }

        completions
    }

    /// 高性能ポーリングループ（PAUSE命令による効率化）
    ///
    /// # Safety
    /// 現在のコアがこのキューの所有者であることを呼び出し側が保証。
    pub unsafe fn poll_spin(&self, max_spins: u32) -> Option<NvmeCompletion> {
        for _ in 0..max_spins {
            if let Some(cqe) = unsafe { self.poll() } {
                return Some(cqe);
            }
            // PAUSE命令でCPUリソースを節約
            #[cfg(target_arch = "x86_64")]
            core::arch::x86_64::_mm_pause();
        }
        None
    }

    /// 統計を取得
    pub fn stats(&self) -> &NvmeQueueStats {
        &self.stats
    }

    /// コアIDを取得
    pub fn core_id(&self) -> u32 {
        self.core_id
    }

    /// 保留中のコマンド数を取得
    pub fn pending_commands(&self) -> u32 {
        self.pending_commands.load(Ordering::Relaxed)
    }
}

// ============================================================================
// Polling Driver
// ============================================================================

/// NVMeコントローラ識別データ
#[repr(C, align(4096))]
pub struct NvmeIdentifyController {
    /// PCI Vendor ID
    pub vid: u16,
    /// PCI Subsystem Vendor ID
    pub ssvid: u16,
    /// Serial Number
    pub sn: [u8; 20],
    /// Model Number
    pub mn: [u8; 40],
    /// Firmware Revision
    pub fr: [u8; 8],
    /// Recommended Arbitration Burst
    pub rab: u8,
    /// IEEE OUI Identifier
    pub ieee: [u8; 3],
    /// Controller Multi-Path I/O and Namespace Sharing Capabilities
    pub cmic: u8,
    /// Maximum Data Transfer Size
    pub mdts: u8,
    /// Controller ID
    pub cntlid: u16,
    /// Version
    pub ver: u32,
    /// RTD3 Resume Latency
    pub rtd3r: u32,
    /// RTD3 Entry Latency
    pub rtd3e: u32,
    /// Optional Asynchronous Events Supported
    pub oaes: u32,
    /// Controller Attributes
    pub ctratt: u32,
    /// Read Recovery Levels Supported
    pub rrls: u16,
    /// Reserved
    _reserved1: [u8; 9],
    /// Controller Type
    pub cntrltype: u8,
    /// FRU Globally Unique Identifier
    pub fguid: [u8; 16],
    /// Command Retry Delay Time 1, 2, 3
    pub crdt1: u16,
    pub crdt2: u16,
    pub crdt3: u16,
    /// Reserved
    _reserved2: [u8; 106],
    /// Reserved for Management Interface
    _reserved_mi: [u8; 16],
    /// Optional Admin Command Support
    pub oacs: u16,
    /// Abort Command Limit
    pub acl: u8,
    /// Asynchronous Event Request Limit
    pub aerl: u8,
    /// Firmware Updates
    pub frmw: u8,
    /// Log Page Attributes
    pub lpa: u8,
    /// Error Log Page Entries
    pub elpe: u8,
    /// Number of Power States Support
    pub npss: u8,
    /// Admin Vendor Specific Command Configuration
    pub avscc: u8,
    /// Autonomous Power State Transition Attributes
    pub apsta: u8,
    /// Warning Composite Temperature Threshold
    pub wctemp: u16,
    /// Critical Composite Temperature Threshold
    pub cctemp: u16,
    /// Maximum Time for Firmware Activation
    pub mtfa: u16,
    /// Host Memory Buffer Preferred Size
    pub hmpre: u32,
    /// Host Memory Buffer Minimum Size
    pub hmmin: u32,
    /// Total NVM Capacity
    pub tnvmcap: [u8; 16],
    /// Unallocated NVM Capacity
    pub unvmcap: [u8; 16],
    /// Replay Protected Memory Block Support
    pub rpmbs: u32,
    /// Extended Device Self-test Time
    pub edstt: u16,
    /// Device Self-test Options
    pub dsto: u8,
    /// Firmware Update Granularity
    pub fwug: u8,
    /// Keep Alive Support
    pub kas: u16,
    /// Host Controlled Thermal Management Attributes
    pub hctma: u16,
    /// Minimum Thermal Management Temperature
    pub mntmt: u16,
    /// Maximum Thermal Management Temperature
    pub mxtmt: u16,
    /// Sanitize Capabilities
    pub sanicap: u32,
    /// Host Memory Buffer Minimum Descriptor Entry Size
    pub hmminds: u32,
    /// Host Memory Maximum Descriptors Entries
    pub hmmaxd: u16,
    /// NVM Set Identifier Maximum
    pub nsetidmax: u16,
    /// Endurance Group Identifier Maximum
    pub endgidmax: u16,
    /// ANA Transition Time
    pub anatt: u8,
    /// Asymmetric Namespace Access Capabilities
    pub anacap: u8,
    /// ANA Group Identifier Maximum
    pub anagrpmax: u32,
    /// Number of ANA Group Identifiers
    pub nanagrpid: u32,
    /// Persistent Event Log Size
    pub pels: u32,
    /// Reserved
    _reserved3: [u8; 156],
    /// Submission Queue Entry Size
    pub sqes: u8,
    /// Completion Queue Entry Size
    pub cqes: u8,
    /// Maximum Outstanding Commands
    pub maxcmd: u16,
    /// Number of Namespaces
    pub nn: u32,
    /// Optional NVM Command Support
    pub oncs: u16,
    /// Fused Operation Support
    pub fuses: u16,
    /// Format NVM Attributes
    pub fna: u8,
    /// Volatile Write Cache
    pub vwc: u8,
    /// Atomic Write Unit Normal
    pub awun: u16,
    /// Atomic Write Unit Power Fail
    pub awupf: u16,
    /// NVM Vendor Specific Command Configuration
    pub nvscc: u8,
    /// Namespace Write Protection Capabilities
    pub nwpc: u8,
    /// Atomic Compare & Write Unit
    pub acwu: u16,
    /// Reserved
    _reserved4: [u8; 2],
    /// SGL Support
    pub sgls: u32,
    /// Maximum Number of Allowed Namespaces
    pub mnan: u32,
    /// Reserved
    _reserved5: [u8; 224],
    /// NVM Subsystem NVMe Qualified Name
    pub subnqn: [u8; 256],
    /// Reserved
    _reserved6: [u8; 768],
    /// I/O Queue Command Capsule Supported Size
    pub ioccsz: u32,
    /// I/O Queue Response Capsule Supported Size
    pub iorcsz: u32,
    /// In Capsule Data Offset
    pub icdoff: u16,
    /// Fabrics Controller Attributes
    pub fcatt: u8,
    /// Maximum SGL Data Block Descriptors
    pub msdbd: u8,
    /// Optional Fabric Commands Support
    pub ofcs: u16,
    /// Reserved
    _reserved7: [u8; 242],
    /// Power State Descriptors
    pub psd: [u8; 1024],
    /// Vendor Specific
    pub vs: [u8; 1024],
}

/// NVMeポーリングドライバ
pub struct NvmePollingDriver {
    /// BAR0ベースアドレス
    bar0: u64,
    /// コントローラキャパシティ
    cap: NvmeCapabilities,
    /// ドアベルストライド（バイト単位）
    doorbell_stride: usize,
    /// 管理キュー
    admin_queue: Option<QueuePair>,
    /// コアごとのI/Oキュー
    io_queues: Vec<PerCoreNvmeQueue>,
    /// 名前空間ID
    nsid: u32,
    /// 最大転送サイズ
    max_transfer_size: usize,
    /// 最大キュー深度
    max_queue_depth: u16,
    /// アロケートされたI/Oキュー数
    allocated_sq_count: u16,
    allocated_cq_count: u16,
    /// アクティブフラグ
    active: AtomicBool,
    /// 割り込みモード（falseならポーリング）
    interrupt_mode: bool,
    /// Controller Memory Buffer情報
    cmb_info: Option<CmbInfo>,
    /// CMBを使用するかどうか
    use_cmb: bool,
}

impl NvmePollingDriver {
    /// 新しいドライバを作成
    pub fn new(bar0: u64, num_cores: u32) -> Self {
        let mut io_queues = Vec::new();
        for i in 0..num_cores {
            io_queues.push(PerCoreNvmeQueue::new(i));
        }

        Self {
            bar0,
            cap: NvmeCapabilities::new(0),
            doorbell_stride: 4, // デフォルト
            admin_queue: None,
            io_queues,
            nsid: 1,
            max_transfer_size: MAX_TRANSFER_SIZE,
            max_queue_depth: DEFAULT_QUEUE_DEPTH,
            allocated_sq_count: 0,
            allocated_cq_count: 0,
            active: AtomicBool::new(false),
            interrupt_mode: false, // ポーリングモード
            cmb_info: None,
            use_cmb: true, // デフォルトでCMBを使用（利用可能なら）
        }
    }

    /// レジスタを読む
    unsafe fn read_reg32(&self, offset: usize) -> u32 {
        unsafe { read_volatile((self.bar0 + offset as u64) as *const u32) }
    }

    /// レジスタを書く
    unsafe fn write_reg32(&self, offset: usize, value: u32) {
        unsafe { write_volatile((self.bar0 + offset as u64) as *mut u32, value) }
    }

    /// 64ビットレジスタを読む
    unsafe fn read_reg64(&self, offset: usize) -> u64 {
        unsafe { read_volatile((self.bar0 + offset as u64) as *const u64) }
    }

    /// 64ビットレジスタを書く
    unsafe fn write_reg64(&self, offset: usize, value: u64) {
        unsafe { write_volatile((self.bar0 + offset as u64) as *mut u64, value) }
    }

    /// コントローラステータスを取得
    fn get_status(&self) -> NvmeControllerStatus {
        unsafe { NvmeControllerStatus::new(self.read_reg32(0x1C)) }
    }

    /// ドアベルアドレスを計算
    fn doorbell_address(&self, qid: u16, is_sq: bool) -> *mut u32 {
        // Doorbell register offset: 0x1000 + ((2*y + t) * (4 << CAP.DSTRD))
        // where y = queue ID, t = 0 for SQ, 1 for CQ
        let offset =
            0x1000 + ((2 * qid as usize + if is_sq { 0 } else { 1 }) * self.doorbell_stride);
        (self.bar0 + offset as u64) as *mut u32
    }

    /// コントローラを無効化
    fn disable_controller(&self) -> Result<(), &'static str> {
        unsafe {
            // CC.ENをクリア
            let mut cc = NvmeControllerConfig::from_raw(self.read_reg32(0x14));
            cc.set_enable(false);
            self.write_reg32(0x14, cc.raw());

            // CSTS.RDY = 0 を待つ
            for _ in 0..1000 {
                let status = self.get_status();
                if !status.rdy() {
                    return Ok(());
                }
                // スピン待機（実際にはタイマーを使う）
                core::hint::spin_loop();
            }
        }
        Err("Controller disable timeout")
    }

    /// コントローラを有効化
    fn enable_controller(&self) -> Result<(), &'static str> {
        unsafe {
            // CC設定
            let mut cc = NvmeControllerConfig::new();
            cc.set_enable(true)
                .set_css(0) // NVM Command Set
                .set_mps(0) // 4KB pages
                .set_ams(0) // Round Robin
                .set_iosqes(6) // 64 bytes (2^6)
                .set_iocqes(4); // 16 bytes (2^4)

            self.write_reg32(0x14, cc.raw());

            // CSTS.RDY = 1 を待つ
            let timeout = self.cap.to() as u64 * 500; // ms
            for _ in 0..timeout {
                let status = self.get_status();
                if status.cfs() {
                    return Err("Controller fatal status");
                }
                if status.rdy() {
                    return Ok(());
                }
                // スピン待機
                core::hint::spin_loop();
            }
        }
        Err("Controller enable timeout")
    }

    /// Admin Queueをセットアップ
    unsafe fn setup_admin_queue(
        &mut self,
        asq: u64,
        acq: u64,
        depth: u16,
    ) -> Result<(), &'static str> {
        // AQA設定
        let mut aqa = NvmeAdminQueueAttributes::new();
        aqa.set_asqs(depth - 1).set_acqs(depth - 1);
        unsafe { self.write_reg32(0x24, aqa.raw()) };

        // ASQ設定
        unsafe { self.write_reg64(0x28, asq) };

        // ACQ設定
        unsafe { self.write_reg64(0x30, acq) };

        Ok(())
    }

    /// コントローラを初期化
    pub fn init(&mut self) -> Result<(), &'static str> {
        // CAP レジスタを読む
        let cap_raw = unsafe { self.read_reg64(0x00) };
        self.cap = NvmeCapabilities::new(cap_raw);

        // ドアベルストライドを計算
        self.doorbell_stride = self.cap.doorbell_stride_bytes();
        self.max_queue_depth = self.cap.max_queue_depth().min(MAX_QUEUE_DEPTH);

        // CMB情報を取得
        if self.use_cmb {
            let cmbloc = unsafe { self.read_reg32(0x38) };
            let cmbsz = unsafe { self.read_reg32(0x3C) };
            let cmb_info = CmbInfo::from_registers(self.bar0, cmbloc, cmbsz, &self.cap);

            if cmb_info.supported {
                // CMBメモリ空間を有効化（CMBMSC.CREを設定）
                if cmb_info.base_addr != 0 {
                    // CMBMSC (offset 0x50) のCRE（bit 0）を設定
                    let cmbmsc = unsafe { self.read_reg64(0x50) };
                    unsafe { self.write_reg64(0x50, cmbmsc | 1) };
                }
                self.cmb_info = Some(cmb_info);
            }
        }

        // コントローラを無効化
        self.disable_controller()?;

        // Admin Queueのセットアップ
        let admin_depth = DEFAULT_QUEUE_DEPTH.min(self.cap.max_queue_depth());
        self.init_admin_queue(admin_depth)?;

        // コントローラを有効化
        self.enable_controller()?;

        // Identify Controllerコマンド発行（オプション）
        // self.identify_controller()?;

        self.active.store(true, Ordering::Release);
        Ok(())
    }
    
    /// Admin Queueを初期化
    /// 
    /// NVMe仕様に基づき、Admin Submission Queue (ASQ) と
    /// Admin Completion Queue (ACQ) を設定する
    fn init_admin_queue(&mut self, depth: u16) -> Result<(), &'static str> {
        // Admin Queueメモリを割り当て
        // 実際の実装ではDMA可能な物理連続メモリが必要
        // ここでは静的バッファを使用（実運用では動的割り当て推奨）
        
        let sq_size = (depth as usize) * QUEUE_ENTRY_SIZE;
        let cq_size = (depth as usize) * CQ_ENTRY_SIZE;
        
        // メモリ割り当て（簡略化：実際にはDMA対応メモリアロケータを使用）
        // NOTE: 実際の実装では以下のようにする
        // let asq_buffer = dma_alloc(sq_size, PAGE_SIZE);
        // let acq_buffer = dma_alloc(cq_size, PAGE_SIZE);
        
        // 静的バッファを使用（デモ用）
        static mut ASQ_BUFFER: [u8; 16384] = [0; 16384]; // 256 * 64
        static mut ACQ_BUFFER: [u8; 4096] = [0; 4096];   // 256 * 16
        
        let asq_ptr = unsafe { core::ptr::addr_of!(ASQ_BUFFER) as u64 };
        let acq_ptr = unsafe { core::ptr::addr_of!(ACQ_BUFFER) as u64 };
        
        // 4KB境界チェック（NVMe仕様要件）
        if asq_ptr & 0xFFF != 0 || acq_ptr & 0xFFF != 0 {
            // 静的バッファがアラインされていない場合は調整
            // 実際の実装ではアラインドアロケータを使用
        }
        
        // Admin Queue Attributesを設定
        unsafe {
            self.setup_admin_queue(asq_ptr, acq_ptr, depth)?;
        }
        
        // Admin QueuePairを作成
        let sq_doorbell = (self.bar0 + 0x1000) as *mut u32; // Admin SQ doorbell at offset 0x1000
        let cq_doorbell = (self.bar0 + 0x1000 + self.doorbell_stride as u64) as *mut u32;
        
        let admin_qp = unsafe {
            QueuePair::new(
                asq_ptr as *mut NvmeCommand,
                acq_ptr as *mut NvmeCompletion,
                depth,
                sq_doorbell,
                cq_doorbell,
                0, // Admin Queue ID = 0
            )
        };
        
        self.admin_queue = Some(admin_qp);
        
        Ok(())
    }
    
    /// Identify Controllerコマンドを発行
    #[allow(dead_code)]
    fn identify_controller(&mut self) -> Result<(), &'static str> {
        let admin_queue = self.admin_queue.as_ref()
            .ok_or("Admin queue not initialized")?;
        
        // Identify用データバッファを用意（4KBページ）
        static mut IDENTIFY_BUFFER: [u8; 4096] = [0; 4096];
        let buffer_ptr = unsafe { core::ptr::addr_of!(IDENTIFY_BUFFER) as u64 };
        
        // Identify Controllerコマンド (CNS=1)
        let mut cmd = NvmeCommand::default();
        cmd.set_opcode(ADMIN_IDENTIFY);
        cmd.set_cid(0);
        cmd.nsid = 0;
        cmd.set_prp(buffer_ptr, 0);
        cmd.cdw10 = 1; // CNS = 1 (Identify Controller)
        
        // コマンド発行
        admin_queue.submit(&cmd)?;
        
        // 完了待ち（ポーリング）
        for _ in 0..10000 {
            if let Some(cqe) = admin_queue.poll_completion() {
                // ステータスチェック
                let status = cqe.status >> 1;
                if status != 0 {
                    return Err("Identify Controller command failed");
                }
                return Ok(());
            }
            core::hint::spin_loop();
        }
        
        Err("Identify Controller timeout")
    }
    
    /// Set Features - Number of Queuesを設定
    #[allow(dead_code)]
    fn set_num_queues(&mut self, num_sq: u16, num_cq: u16) -> Result<(u16, u16), &'static str> {
        let admin_queue = self.admin_queue.as_ref()
            .ok_or("Admin queue not initialized")?;
        
        // Set Features コマンド
        let mut cmd = NvmeCommand::default();
        cmd.set_opcode(ADMIN_SET_FEATURES);
        cmd.set_cid(1);
        cmd.cdw10 = 0x07; // Feature ID = Number of Queues
        cmd.cdw11 = ((num_cq.saturating_sub(1) as u32) << 16) | (num_sq.saturating_sub(1) as u32);
        
        admin_queue.submit(&cmd)?;
        
        // 完了待ち
        for _ in 0..10000 {
            if let Some(cqe) = admin_queue.poll_completion() {
                let status = cqe.status >> 1;
                if status != 0 {
                    return Err("Set Features failed");
                }
                // 返されたキュー数を取得
                let allocated_sq = ((cqe.dw0 & 0xFFFF) + 1) as u16;
                let allocated_cq = (((cqe.dw0 >> 16) & 0xFFFF) + 1) as u16;
                return Ok((allocated_sq, allocated_cq));
            }
            core::hint::spin_loop();
        }
        
        Err("Set Features timeout")
    }

    /// CMBからSQバッファを割り当て（利用可能な場合）
    pub fn allocate_sq_from_cmb(&mut self, depth: u16) -> Option<u64> {
        self.cmb_info
            .as_mut()
            .and_then(|cmb| cmb.allocate_sq(depth))
    }

    /// CMBからCQバッファを割り当て（利用可能な場合）
    pub fn allocate_cq_from_cmb(&mut self, depth: u16) -> Option<u64> {
        self.cmb_info
            .as_mut()
            .and_then(|cmb| cmb.allocate_cq(depth))
    }

    /// CMBがサポートされているか
    pub fn has_cmb(&self) -> bool {
        self.cmb_info.as_ref().map_or(false, |cmb| cmb.supported)
    }

    /// CMB情報を取得
    pub fn cmb_info(&self) -> Option<&CmbInfo> {
        self.cmb_info.as_ref()
    }

    /// CMBを使用してI/Oキューを作成（高速版）
    ///
    /// CMBが利用可能な場合、SQをCMB上に配置することで
    /// コマンド書き込みのレイテンシを大幅に削減。
    pub fn create_io_queue_with_cmb(
        &mut self,
        core_id: u32,
        cq_buffer: *mut NvmeCompletion,
        cq_phys: u64,
        depth: u16,
    ) -> Result<(u16, Option<u64>), &'static str> {
        // CMBからSQバッファを割り当て
        let cmb_sq_addr = self.allocate_sq_from_cmb(depth);

        if let Some(sq_addr) = cmb_sq_addr {
            // CMB上のSQを使用（超低レイテンシ）
            // CMBアドレスはコントローラから見た物理アドレス
            let qid = self.create_io_queue_pair_internal(
                core_id,
                sq_addr as *mut NvmeCommand,
                cq_buffer,
                sq_addr, // CMBアドレスはそのまま使える
                cq_phys,
                depth,
            )?;
            Ok((qid, Some(sq_addr)))
        } else {
            // CMBが使えない場合は通常のDRAM上のSQを使用
            // 呼び出し側でSQバッファを確保して通常のcreate_io_queue_pairを使う
            Err("CMB not available for SQ allocation")
        }
    }

    /// 内部用：I/Oキューペアを作成
    fn create_io_queue_pair_internal(
        &mut self,
        core_id: u32,
        sq_buffer: *mut NvmeCommand,
        cq_buffer: *mut NvmeCompletion,
        sq_phys: u64,
        cq_phys: u64,
        depth: u16,
    ) -> Result<u16, &'static str> {
        let admin_queue = self
            .admin_queue
            .as_ref()
            .ok_or("Admin queue not initialized")?;

        // QID = core_id + 1 (0 is admin queue)
        let qid = (core_id + 1) as u16;

        // Create I/O Completion Queue
        let create_cq_cmd = NvmeCommand::create_io_cq(
            qid,
            depth,
            cq_phys,
            0,                   // IRQ vector (unused in polling mode)
            self.interrupt_mode, // IRQ enabled
        );
        admin_queue.submit(&create_cq_cmd)?;

        // Admin完了を待つ
        self.poll_admin_completion()?;

        // Create I/O Submission Queue
        let create_sq_cmd = NvmeCommand::create_io_sq(
            qid, depth, sq_phys, qid, // Associated CQ ID
            0,   // Priority (urgent)
        );
        admin_queue.submit(&create_sq_cmd)?;

        // Admin完了を待つ
        self.poll_admin_completion()?;

        // キューペアを設定
        let qp = unsafe {
            QueuePair::new(
                sq_buffer,
                cq_buffer,
                depth,
                self.doorbell_address(qid, true),
                self.doorbell_address(qid, false),
                qid,
            )
        };

        if let Some(queue) = self.io_queues.get(core_id as usize) {
            unsafe { queue.set_queue_pair(qp) };
        }

        self.allocated_sq_count += 1;
        self.allocated_cq_count += 1;

        Ok(qid)
    }

    /// I/Oキューペアを作成（公開API）
    pub fn create_io_queue_pair(
        &mut self,
        core_id: u32,
        sq_buffer: *mut NvmeCommand,
        cq_buffer: *mut NvmeCompletion,
        sq_phys: u64,
        cq_phys: u64,
        depth: u16,
    ) -> Result<u16, &'static str> {
        self.create_io_queue_pair_internal(core_id, sq_buffer, cq_buffer, sq_phys, cq_phys, depth)
    }

    /// Admin完了をポーリング
    fn poll_admin_completion(&self) -> Result<NvmeCompletion, &'static str> {
        let admin_queue = self
            .admin_queue
            .as_ref()
            .ok_or("Admin queue not initialized")?;

        for _ in 0..100000 {
            if let Some(cqe) = admin_queue.poll_completion() {
                if cqe.is_success() {
                    return Ok(cqe);
                } else {
                    return Err("Admin command failed");
                }
            }
            // PAUSE命令によるスピン待機の最適化
            cpu_pause();
        }
        Err("Admin command timeout")
    }

    /// I/Oキューを設定（レガシーAPI）
    ///
    /// # Safety
    /// 初期化中にのみ呼び出すこと。
    pub unsafe fn setup_io_queue(&self, core_id: u32, qp: QueuePair) {
        if let Some(queue) = self.io_queues.get(core_id as usize) {
            unsafe { queue.set_queue_pair(qp) };
        }
    }

    /// コアのキューを取得
    pub fn get_queue(&self, core_id: u32) -> Option<&PerCoreNvmeQueue> {
        self.io_queues.get(core_id as usize)
    }

    /// ポーリングループを実行（最適化版）
    ///
    /// # Safety
    /// 現在のコアIDが正しいことを呼び出し側が保証。
    pub unsafe fn poll_loop(&self, core_id: u32) -> usize {
        let queue = match self.get_queue(core_id) {
            Some(q) => q,
            None => return 0,
        };

        let mut completed = 0;

        // バッチ処理で複数の完了を一度に処理
        for _ in 0..POLL_BATCH_SIZE {
            if let Some(_cqe) = unsafe { queue.poll() } {
                completed += 1;
            } else {
                break;
            }
        }

        // 完了がなかった場合はPAUSE命令でCPUを休ませる
        if completed == 0 {
            cpu_pause();
        }

        completed
    }

    /// バッチポーリング（高スループット用）
    ///
    /// # Safety
    /// 現在のコアIDが正しいことを呼び出し側が保証。
    pub unsafe fn poll_batch(&self, core_id: u32, completions: &mut [NvmeCompletion]) -> usize {
        let queue = match self.get_queue(core_id) {
            Some(q) => q,
            None => return 0,
        };

        let mut count = 0;
        for slot in completions.iter_mut() {
            if let Some(cqe) = unsafe { queue.poll() } {
                *slot = cqe;
                count += 1;
            } else {
                break;
            }
        }

        count
    }

    /// アダプティブポーリング（負荷に応じて調整）
    ///
    /// # Safety
    /// 現在のコアIDが正しいことを呼び出し側が保証。
    pub unsafe fn adaptive_poll(&self, core_id: u32, idle_count: &mut u32) -> usize {
        let completed = unsafe { self.poll_loop(core_id) };

        if completed > 0 {
            *idle_count = 0;
        } else {
            *idle_count += 1;
            // アイドル期間が長い場合はより長く休む
            if *idle_count > 100 {
                for _ in 0..10 {
                    cpu_pause();
                }
            }
        }

        completed
    }

    /// アクティブかどうか
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }

    /// 最大転送サイズを取得
    pub fn max_transfer_size(&self) -> usize {
        self.max_transfer_size
    }

    /// 統計を収集
    pub fn collect_stats(&self) -> NvmeDriverStats {
        let mut stats = NvmeDriverStats::default();

        for queue in &self.io_queues {
            let qs = queue.stats();
            stats.total_commands_submitted += qs.commands_submitted.load(Ordering::Relaxed);
            stats.total_commands_completed += qs.commands_completed.load(Ordering::Relaxed);
            stats.total_read_bytes += qs.read_bytes.load(Ordering::Relaxed);
            stats.total_write_bytes += qs.write_bytes.load(Ordering::Relaxed);
            stats.total_errors += qs.errors.load(Ordering::Relaxed);
            stats.total_poll_cycles += qs.poll_cycles.load(Ordering::Relaxed);
        }

        stats
    }
}

/// ドライバ全体の統計
#[derive(Debug, Default)]
pub struct NvmeDriverStats {
    pub total_commands_submitted: u64,
    pub total_commands_completed: u64,
    pub total_read_bytes: u64,
    pub total_write_bytes: u64,
    pub total_errors: u64,
    pub total_poll_cycles: u64,
}

/// CPU PAUSE命令（スピン待機の電力効率化）
#[inline(always)]
fn cpu_pause() {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::x86_64::_mm_pause();
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        core::hint::spin_loop();
    }
}

// ============================================================================
// Async I/O Request
// ============================================================================

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};

/// I/Oリクエストの状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoRequestState {
    Pending,
    Submitted,
    Completed,
    Error,
    Cancelled,
}

/// 非同期I/Oリクエスト
pub struct AsyncIoRequest {
    /// コマンドID
    cid: u16,
    /// キューID
    qid: u16,
    /// 状態
    state: IoRequestState,
    /// 完了結果
    result: Option<NvmeCompletion>,
    /// Waker
    waker: Option<Waker>,
    /// 開始時刻（サイクルカウンタ）
    start_tsc: u64,
}

impl AsyncIoRequest {
    pub fn new(cid: u16, qid: u16) -> Self {
        Self {
            cid,
            qid,
            state: IoRequestState::Pending,
            result: None,
            waker: None,
            start_tsc: read_tsc(),
        }
    }

    /// 状態を取得
    pub fn state(&self) -> IoRequestState {
        self.state
    }

    /// 完了かどうか
    pub fn is_complete(&self) -> bool {
        matches!(
            self.state,
            IoRequestState::Completed | IoRequestState::Error
        )
    }

    /// 結果を取得
    pub fn result(&self) -> Option<&NvmeCompletion> {
        self.result.as_ref()
    }

    /// 経過時間（サイクル数）
    pub fn elapsed_cycles(&self) -> u64 {
        read_tsc().saturating_sub(self.start_tsc)
    }

    /// 完了を設定
    pub fn complete(&mut self, cqe: NvmeCompletion) {
        self.result = Some(cqe);
        self.state = if cqe.is_success() {
            IoRequestState::Completed
        } else {
            IoRequestState::Error
        };

        if let Some(waker) = self.waker.take() {
            waker.wake();
        }
    }

    /// キャンセル
    pub fn cancel(&mut self) {
        self.state = IoRequestState::Cancelled;
        if let Some(waker) = self.waker.take() {
            waker.wake();
        }
    }
}

/// ペンディングリクエストトラッカー
pub struct PendingRequests {
    /// リクエストマップ（CID -> Request）
    requests: [Option<AsyncIoRequest>; 256],
    /// アクティブなリクエスト数
    active_count: AtomicU32,
}

impl PendingRequests {
    pub const fn new() -> Self {
        const NONE: Option<AsyncIoRequest> = None;
        Self {
            requests: [NONE; 256],
            active_count: AtomicU32::new(0),
        }
    }

    /// リクエストを登録
    pub fn register(&mut self, cid: u16, qid: u16) -> Result<(), &'static str> {
        let idx = (cid as usize) % 256;
        if self.requests[idx].is_some() {
            return Err("CID slot already in use");
        }
        self.requests[idx] = Some(AsyncIoRequest::new(cid, qid));
        self.active_count.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// リクエストを完了
    pub fn complete(&mut self, cid: u16, cqe: NvmeCompletion) -> bool {
        let idx = (cid as usize) % 256;
        if let Some(ref mut req) = self.requests[idx] {
            if req.cid == cid {
                req.complete(cqe);
                return true;
            }
        }
        false
    }

    /// リクエストを削除して取得
    pub fn take(&mut self, cid: u16) -> Option<AsyncIoRequest> {
        let idx = (cid as usize) % 256;
        if let Some(ref req) = self.requests[idx] {
            if req.cid == cid {
                self.active_count.fetch_sub(1, Ordering::Relaxed);
                return self.requests[idx].take();
            }
        }
        None
    }

    /// Wakerを設定
    pub fn set_waker(&mut self, cid: u16, waker: Waker) {
        let idx = (cid as usize) % 256;
        if let Some(ref mut req) = self.requests[idx] {
            if req.cid == cid {
                req.waker = Some(waker);
            }
        }
    }

    /// アクティブなリクエスト数
    pub fn active_count(&self) -> u32 {
        self.active_count.load(Ordering::Relaxed)
    }
}

/// 非同期読み取りFuture
pub struct ReadFuture<'a> {
    driver: &'a NvmePollingDriver,
    core_id: u32,
    cid: u16,
    submitted: bool,
}

impl<'a> ReadFuture<'a> {
    pub fn new(driver: &'a NvmePollingDriver, core_id: u32, cid: u16) -> Self {
        Self {
            driver,
            core_id,
            cid,
            submitted: true,
        }
    }
}

impl<'a> Future for ReadFuture<'a> {
    type Output = Result<NvmeCompletion, NvmeError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // ポーリングして完了を確認
        if let Some(queue) = self.driver.get_queue(self.core_id) {
            // バッチでポーリング
            for _ in 0..POLL_BATCH_SIZE {
                // Safety: Futureは生成元のコアでのみpolledされると仮定
                if let Some(cqe) = unsafe { queue.poll() } {
                    if cqe.cid == self.cid {
                        if cqe.is_success() {
                            return Poll::Ready(Ok(cqe));
                        } else {
                            return Poll::Ready(Err(NvmeError::CommandError(cqe)));
                        }
                    }
                    // 他のCIDの完了 - 対応するwakerを起こす必要がある
                    // 実際の実装ではPendingRequestsと連携
                } else {
                    break;
                }
            }
        } else {
            return Poll::Ready(Err(NvmeError::QueueNotFound));
        }

        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

/// 非同期書き込みFuture
pub struct WriteFuture<'a> {
    driver: &'a NvmePollingDriver,
    core_id: u32,
    cid: u16,
}

impl<'a> WriteFuture<'a> {
    pub fn new(driver: &'a NvmePollingDriver, core_id: u32, cid: u16) -> Self {
        Self {
            driver,
            core_id,
            cid,
        }
    }
}

impl<'a> Future for WriteFuture<'a> {
    type Output = Result<NvmeCompletion, NvmeError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if let Some(queue) = self.driver.get_queue(self.core_id) {
            for _ in 0..POLL_BATCH_SIZE {
                // Safety: Futureは生成元のコアでのみpolledされると仮定
                if let Some(cqe) = unsafe { queue.poll() } {
                    if cqe.cid == self.cid {
                        if cqe.is_success() {
                            return Poll::Ready(Ok(cqe));
                        } else {
                            return Poll::Ready(Err(NvmeError::CommandError(cqe)));
                        }
                    }
                } else {
                    break;
                }
            }
        } else {
            return Poll::Ready(Err(NvmeError::QueueNotFound));
        }

        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

/// NVMeエラー型
#[derive(Debug, Clone)]
pub enum NvmeError {
    /// コマンドエラー
    CommandError(NvmeCompletion),
    /// キューが見つからない
    QueueNotFound,
    /// タイムアウト
    Timeout,
    /// キューがフル
    QueueFull,
    /// 未初期化
    NotInitialized,
    /// 無効なパラメータ
    InvalidParameter,
}

impl core::fmt::Display for NvmeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            NvmeError::CommandError(cqe) => write!(
                f,
                "NVMe command error: SCT={}, SC={}",
                cqe.status_code_type(),
                cqe.status_code()
            ),
            NvmeError::QueueNotFound => write!(f, "NVMe queue not found"),
            NvmeError::Timeout => write!(f, "NVMe command timeout"),
            NvmeError::QueueFull => write!(f, "NVMe queue full"),
            NvmeError::NotInitialized => write!(f, "NVMe not initialized"),
            NvmeError::InvalidParameter => write!(f, "Invalid parameter"),
        }
    }
}

/// TSCを読む（タイムスタンプカウンタ）
#[inline(always)]
fn read_tsc() -> u64 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::x86_64::_rdtsc()
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        0
    }
}

// ============================================================================
// High-Level Async API
// ============================================================================

/// 非同期読み取り
///
/// # Safety
/// 現在のコアIDが正しいことを呼び出し側が保証。
pub async unsafe fn async_read(
    driver: &NvmePollingDriver,
    core_id: u32,
    nsid: u32,
    lba: u64,
    blocks: u16,
    prp1: u64,
    prp2: u64,
) -> Result<NvmeCompletion, NvmeError> {
    let queue = driver.get_queue(core_id).ok_or(NvmeError::QueueNotFound)?;

    // Safety: 呼び出し元が正しいcore_idを保証
    let cid =
        unsafe { queue.read(nsid, lba, blocks, prp1, prp2) }.map_err(|_| NvmeError::QueueFull)?;

    ReadFuture::new(driver, core_id, cid).await
}

/// 非同期書き込み
///
/// # Safety
/// 現在のコアIDが正しいことを呼び出し側が保証。
pub async unsafe fn async_write(
    driver: &NvmePollingDriver,
    core_id: u32,
    nsid: u32,
    lba: u64,
    blocks: u16,
    prp1: u64,
    prp2: u64,
) -> Result<NvmeCompletion, NvmeError> {
    let queue = driver.get_queue(core_id).ok_or(NvmeError::QueueNotFound)?;

    // Safety: 呼び出し元が正しいcore_idを保証
    let cid =
        unsafe { queue.write(nsid, lba, blocks, prp1, prp2) }.map_err(|_| NvmeError::QueueFull)?;

    WriteFuture::new(driver, core_id, cid).await
}

// ============================================================================
// Global Instance
// ============================================================================

static NVME_DRIVER: Mutex<Option<NvmePollingDriver>> = Mutex::new(None);

/// NVMeドライバを初期化
pub fn init(bar0: u64, num_cores: u32) -> Result<(), &'static str> {
    let mut driver = NvmePollingDriver::new(bar0, num_cores);
    driver.init()?;
    *NVME_DRIVER.lock() = Some(driver);
    Ok(())
}

/// NVMeドライバにアクセス
pub fn with_driver<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&NvmePollingDriver) -> R,
{
    NVME_DRIVER.lock().as_ref().map(f)
}

/// NVMeドライバに可変アクセス
pub fn with_driver_mut<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&mut NvmePollingDriver) -> R,
{
    NVME_DRIVER.lock().as_mut().map(f)
}

/// ポーリングを実行
///
/// # Safety
/// 現在のコアIDが正しいことを呼び出し側が保証。
pub unsafe fn poll(core_id: u32) -> usize {
    with_driver(|d| unsafe { d.poll_loop(core_id) }).unwrap_or(0)
}

/// バッチポーリングを実行
///
/// # Safety
/// 現在のコアIDが正しいことを呼び出し側が保証。
pub unsafe fn poll_batch(core_id: u32, completions: &mut [NvmeCompletion]) -> usize {
    with_driver(|d| unsafe { d.poll_batch(core_id, completions) }).unwrap_or(0)
}

/// 統計を取得
pub fn get_stats() -> Option<NvmeDriverStats> {
    with_driver(|d| d.collect_stats())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nvme_command_read() {
        let cmd = NvmeCommand::read(1, 0, 8, 0x1000, 0);
        assert_eq!(cmd.nsid, 1);
        assert_eq!(cmd.cdw10, 0);
        assert_eq!(cmd.cdw12, 7); // 8-1
    }

    #[test]
    fn test_nvme_command_write() {
        let cmd = NvmeCommand::write(1, 100, 16, 0x2000, 0);
        assert_eq!(cmd.nsid, 1);
        assert_eq!(cmd.cdw10, 100);
        assert_eq!(cmd.cdw12, 15); // 16-1
    }

    #[test]
    fn test_nvme_command_create_cq() {
        let cmd = NvmeCommand::create_io_cq(1, 256, 0x10000, 0, false);
        assert_eq!(cmd.cdw10, (1 << 16) | 255);
        assert_eq!(cmd.cdw11, 0x01); // PC=1, IEN=0
    }

    #[test]
    fn test_nvme_command_create_sq() {
        let cmd = NvmeCommand::create_io_sq(1, 256, 0x20000, 1, 0);
        assert_eq!(cmd.cdw10, (1 << 16) | 255);
        assert_eq!(cmd.cdw11, (1 << 16) | 0x01); // CQID=1, PC=1
    }

    #[test]
    fn test_nvme_completion_status() {
        let mut cqe = NvmeCompletion::default();
        cqe.status = 0x0001; // Phase bit set, success
        assert!(cqe.phase());
        assert!(cqe.is_success());
    }

    #[test]
    fn test_nvme_completion_error() {
        let mut cqe = NvmeCompletion::default();
        cqe.status = 0x0103; // SC=1, SCT=0, Phase=1
        assert!(cqe.phase());
        assert!(!cqe.is_success());
        assert_eq!(cqe.status_code(), 1);
    }

    #[test]
    fn test_io_request_state() {
        let req = AsyncIoRequest::new(42, 1);
        assert_eq!(req.state, IoRequestState::Pending);
        assert!(!req.is_complete());
    }

    #[test]
    fn test_capabilities() {
        let cap = NvmeCapabilities::new(0x00FF_2003_0020_FFFF);
        assert_eq!(cap.mqes(), 0xFFFF);
        assert_eq!(cap.dstrd(), 2);
        assert_eq!(cap.doorbell_stride_bytes(), 16);
        assert_eq!(cap.max_queue_depth(), 0x10000);
    }

    #[test]
    fn test_controller_config() {
        let mut cc = NvmeControllerConfig::new();
        cc.set_enable(true)
            .set_css(0)
            .set_mps(0)
            .set_iosqes(6)
            .set_iocqes(4);

        assert!(cc.is_enabled());
        assert_eq!(cc.raw() & 0xF0000, 6 << 16); // IOSQES
        assert_eq!(cc.raw() & 0xF00000, 4 << 20); // IOCQES
    }

    #[test]
    fn test_prp_list() {
        let mut prp_list = PrpList::new();
        assert!(prp_list.is_empty());

        assert!(prp_list.add_entry(0x1000).is_ok());
        assert!(prp_list.add_entry(0x2000).is_ok());
        assert_eq!(prp_list.len(), 2);

        // Non-aligned address should fail
        assert!(prp_list.add_entry(0x1001).is_err());
    }

    #[test]
    fn test_pending_requests() {
        let mut pending = PendingRequests::new();

        assert!(pending.register(0, 1).is_ok());
        assert_eq!(pending.active_count(), 1);

        // Complete the request
        let cqe = NvmeCompletion {
            cid: 0,
            status: 0x0001, // success with phase
            ..Default::default()
        };
        assert!(pending.complete(0, cqe));

        // Take the completed request
        let req = pending.take(0);
        assert!(req.is_some());
        assert!(req.unwrap().is_complete());
        assert_eq!(pending.active_count(), 0);
    }
}
