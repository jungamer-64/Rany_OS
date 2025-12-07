// ============================================================================
// src/io/nvme/defs.rs - NVMe Common Definitions
// ============================================================================
//!
//! NVMe共通定数・構造体定義
//!
//! NVMe Base Specification 2.0に基づく共通定義を提供。

#![allow(dead_code)]

// ============================================================================
// NVMe Constants
// ============================================================================

/// キャッシュラインサイズ（x86_64標準）
pub const CACHE_LINE_SIZE: usize = 64;

/// Submission Queueエントリサイズ（64バイト）
pub const SQE_SIZE: usize = 64;

/// Completion Queueエントリサイズ（16バイト）
pub const CQE_SIZE: usize = 16;

/// 最大キュー深度
pub const MAX_QUEUE_DEPTH: u16 = 1024;

/// デフォルトキュー深度
pub const DEFAULT_QUEUE_DEPTH: u16 = 256;

/// Admin Queueデフォルト深度
pub const ADMIN_QUEUE_DEPTH: u16 = 32;

/// セクタサイズ
pub const SECTOR_SIZE: usize = 512;

/// ページサイズ（4KB）
pub const PAGE_SIZE: usize = 4096;

/// 最大転送サイズ（128KB）
pub const MAX_TRANSFER_SIZE: usize = 128 * 1024;

/// ポーリングバッチサイズ
pub const POLL_BATCH_SIZE: usize = 16;

/// ドアベルバッチ閾値
pub const DOORBELL_BATCH_THRESHOLD: usize = 8;

/// コントローラレディタイムアウト（ミリ秒）
pub const CONTROLLER_READY_TIMEOUT_MS: u64 = 5000;

// ============================================================================
// NVMe Admin Opcodes
// ============================================================================

/// NVMe Admin Command Opcodes
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdminOpcode {
    DeleteIOSQ = 0x00,
    CreateIOSQ = 0x01,
    GetLogPage = 0x02,
    DeleteIOCQ = 0x04,
    CreateIOCQ = 0x05,
    Identify = 0x06,
    Abort = 0x08,
    SetFeatures = 0x09,
    GetFeatures = 0x0A,
    AsyncEventRequest = 0x0C,
    NamespaceManagement = 0x0D,
    FirmwareCommit = 0x10,
    FirmwareImageDownload = 0x11,
    NamespaceAttachment = 0x15,
}

/// Admin Opcode定数（互換性のため）
pub mod admin_opcodes {
    pub const DELETE_SQ: u8 = 0x00;
    pub const CREATE_SQ: u8 = 0x01;
    pub const GET_LOG_PAGE: u8 = 0x02;
    pub const DELETE_CQ: u8 = 0x04;
    pub const CREATE_CQ: u8 = 0x05;
    pub const IDENTIFY: u8 = 0x06;
    pub const ABORT: u8 = 0x08;
    pub const SET_FEATURES: u8 = 0x09;
    pub const GET_FEATURES: u8 = 0x0A;
    pub const ASYNC_EVENT_REQ: u8 = 0x0C;
    pub const NS_MGMT: u8 = 0x0D;
    pub const FW_COMMIT: u8 = 0x10;
    pub const FW_DOWNLOAD: u8 = 0x11;
}

// ============================================================================
// NVMe I/O Opcodes
// ============================================================================

/// NVMe I/O Command Opcodes
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IoOpcode {
    Flush = 0x00,
    Write = 0x01,
    Read = 0x02,
    WriteUncorrectable = 0x04,
    Compare = 0x05,
    WriteZeroes = 0x08,
    DatasetManagement = 0x09,
    Verify = 0x0C,
    ReservationRegister = 0x0D,
    ReservationReport = 0x0E,
    ReservationAcquire = 0x11,
    ReservationRelease = 0x15,
}

/// I/O Opcode定数（互換性のため）
pub mod io_opcodes {
    pub const FLUSH: u8 = 0x00;
    pub const WRITE: u8 = 0x01;
    pub const READ: u8 = 0x02;
    pub const WRITE_UNCORRECTABLE: u8 = 0x04;
    pub const COMPARE: u8 = 0x05;
    pub const WRITE_ZEROES: u8 = 0x08;
    pub const DATASET_MGMT: u8 = 0x09;
}

// ============================================================================
// Feature IDs
// ============================================================================

/// NVMe Feature IDs
pub mod feature_ids {
    pub const ARBITRATION: u8 = 0x01;
    pub const POWER_MGMT: u8 = 0x02;
    pub const LBA_RANGE_TYPE: u8 = 0x03;
    pub const TEMP_THRESHOLD: u8 = 0x04;
    pub const ERROR_RECOVERY: u8 = 0x05;
    pub const VOLATILE_WC: u8 = 0x06;
    pub const NUM_QUEUES: u8 = 0x07;
    pub const IRQ_COALESCING: u8 = 0x08;
    pub const IRQ_CONFIG: u8 = 0x09;
    pub const WRITE_ATOMICITY: u8 = 0x0A;
    pub const ASYNC_EVENT_CONFIG: u8 = 0x0B;
}

// ============================================================================
// NVMe Status Codes
// ============================================================================

/// NVMe Status Codes
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NvmeStatus {
    /// 成功
    Success = 0x00,
    /// 無効なコマンドオペコード
    InvalidCommandOpcode = 0x01,
    /// コマンドフィールドが無効
    InvalidFieldInCommand = 0x02,
    /// コマンドID競合
    CommandIdConflict = 0x03,
    /// データ転送エラー
    DataTransferError = 0x04,
    /// 電源喪失によるコマンド中止
    CommandsAbortedPowerLoss = 0x05,
    /// 内部エラー
    InternalError = 0x06,
    /// コマンド中止要求
    CommandAbortRequested = 0x07,
    /// SQ削除によるコマンド中止
    CommandAbortedSqDeletion = 0x08,
    /// Fused操作失敗
    CommandAbortedFailedFuse = 0x09,
    /// Fused操作欠落
    CommandAbortedMissingFuse = 0x0A,
    /// 無効なネームスペースまたはフォーマット
    InvalidNamespaceOrFormat = 0x0B,
    /// コマンドシーケンスエラー
    CommandSequenceError = 0x0C,
    /// 書き込み保護
    WriteProtected = 0x82,
    /// 不明なエラー
    Unknown = 0xFF,
}

impl From<u16> for NvmeStatus {
    fn from(value: u16) -> Self {
        let sc = ((value >> 1) & 0xFF) as u8;
        match sc {
            0x00 => NvmeStatus::Success,
            0x01 => NvmeStatus::InvalidCommandOpcode,
            0x02 => NvmeStatus::InvalidFieldInCommand,
            0x03 => NvmeStatus::CommandIdConflict,
            0x04 => NvmeStatus::DataTransferError,
            0x05 => NvmeStatus::CommandsAbortedPowerLoss,
            0x06 => NvmeStatus::InternalError,
            0x07 => NvmeStatus::CommandAbortRequested,
            0x08 => NvmeStatus::CommandAbortedSqDeletion,
            0x09 => NvmeStatus::CommandAbortedFailedFuse,
            0x0A => NvmeStatus::CommandAbortedMissingFuse,
            0x0B => NvmeStatus::InvalidNamespaceOrFormat,
            0x0C => NvmeStatus::CommandSequenceError,
            0x82 => NvmeStatus::WriteProtected,
            _ => NvmeStatus::Unknown,
        }
    }
}

impl NvmeStatus {
    /// 成功かどうか
    pub fn is_success(&self) -> bool {
        matches!(self, NvmeStatus::Success)
    }
}

// ============================================================================
// NVMe Error Type
// ============================================================================

/// NVMeエラー型
#[derive(Clone, Debug)]
pub enum NvmeError {
    /// コントローラ初期化失敗
    InitializationFailed(&'static str),
    /// タイムアウト
    Timeout,
    /// キューがフル
    QueueFull,
    /// 無効なパラメータ
    InvalidParameter(&'static str),
    /// コマンド失敗
    CommandFailed(NvmeStatus),
    /// メモリ割り当て失敗
    OutOfMemory,
    /// デバイスが見つからない
    DeviceNotFound,
    /// 致命的なコントローラエラー
    ControllerFatalError,
    /// I/Oエラー
    IoError(&'static str),
}

impl From<NvmeStatus> for NvmeError {
    fn from(status: NvmeStatus) -> Self {
        NvmeError::CommandFailed(status)
    }
}

// ============================================================================
// PRP/SGL Definitions
// ============================================================================

/// PRPエントリ（Physical Region Page）
/// 8バイトアラインメント必須
#[repr(C, align(8))]
#[derive(Clone, Copy, Debug, Default)]
pub struct PrpEntry {
    /// 物理アドレス（4KB境界アライン必須）
    pub addr: u64,
}

impl PrpEntry {
    /// 新しいPRPエントリを作成
    pub fn new(addr: u64) -> Self {
        Self { addr }
    }

    /// アドレスが有効か（4KB境界）
    pub fn is_aligned(&self) -> bool {
        self.addr & 0xFFF == 0
    }
}

/// PRPリスト（4KB超の転送用）
#[repr(C, align(4096))]
pub struct PrpList {
    /// PRPエントリ配列（最大512エントリ = 4096/8）
    pub entries: [PrpEntry; 512],
    /// 使用中エントリ数
    pub count: usize,
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
        if addr & 0xFFF != 0 {
            return Err("PRP address must be 4KB aligned");
        }
        self.entries[self.count] = PrpEntry::new(addr);
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

// ============================================================================
// SGL Definitions
// ============================================================================

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

/// SGLディスクリプタ（16バイト）
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

// Note: Identify structures (IdentifyController, IdentifyNamespace, LbaFormat)
// are now in identify.rs to avoid duplication
