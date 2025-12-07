// ============================================================================
// src/io/usb/class/msc.rs - USB Mass Storage Class Driver
// ============================================================================
//!
//! # USB Mass Storage クラスドライバ
//!
//! USBメモリ、外付けHDD/SSD等のストレージデバイスをサポート。
//!
//! ## サポートプロトコル
//! - Bulk-Only Transport (BBB)
//! - SCSI Transparent Command Set
//!
//! ## 参照仕様
//! - USB Mass Storage Class Specification Overview 1.4
//! - USB Mass Storage Class Bulk-Only Transport 1.0
//! - SCSI Primary Commands (SPC)
//! - SCSI Block Commands (SBC)

#![allow(dead_code)]

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering};
use spin::Mutex;

use super::{
    ClassDriverError, ClassDriverEvent, SetupPacket, TransferStatus, UsbClass, UsbClassDriver,
    REQUEST_DIR_IN, REQUEST_DIR_OUT, REQUEST_TYPE_CLASS_INTERFACE,
};

// ============================================================================
// MSC Constants
// ============================================================================

/// Mass Storage クラスコード
pub const MSC_CLASS: u8 = 0x08;

/// MSC サブクラス: RBC (Reduced Block Commands)
pub const MSC_SUBCLASS_RBC: u8 = 0x01;
/// MSC サブクラス: MMC-5 (CD/DVD)
pub const MSC_SUBCLASS_MMC5: u8 = 0x02;
/// MSC サブクラス: UFI (Floppy)
pub const MSC_SUBCLASS_UFI: u8 = 0x04;
/// MSC サブクラス: SCSI Transparent
pub const MSC_SUBCLASS_SCSI: u8 = 0x06;
/// MSC サブクラス: LSD FS
pub const MSC_SUBCLASS_LSDFS: u8 = 0x07;
/// MSC サブクラス: IEEE 1667
pub const MSC_SUBCLASS_IEEE1667: u8 = 0x08;

/// MSC プロトコル: CBI (Control/Bulk/Interrupt) with completion interrupt
pub const MSC_PROTOCOL_CBI_INT: u8 = 0x00;
/// MSC プロトコル: CBI without completion interrupt
pub const MSC_PROTOCOL_CBI: u8 = 0x01;
/// MSC プロトコル: BBB (Bulk-Only)
pub const MSC_PROTOCOL_BBB: u8 = 0x50;
/// MSC プロトコル: UAS (USB Attached SCSI)
pub const MSC_PROTOCOL_UAS: u8 = 0x62;

// ============================================================================
// MSC Request Codes
// ============================================================================

/// Mass Storage Reset
pub const MSC_RESET: u8 = 0xFF;
/// Get Max LUN
pub const MSC_GET_MAX_LUN: u8 = 0xFE;

// ============================================================================
// CBW/CSW
// ============================================================================

/// CBW (Command Block Wrapper) シグネチャ
pub const CBW_SIGNATURE: u32 = 0x43425355; // "USBC"
/// CSW (Command Status Wrapper) シグネチャ
pub const CSW_SIGNATURE: u32 = 0x53425355; // "USBS"

/// CBW サイズ
pub const CBW_SIZE: usize = 31;
/// CSW サイズ
pub const CSW_SIZE: usize = 13;

/// CBW 方向: Device to Host
pub const CBW_DIR_IN: u8 = 0x80;
/// CBW 方向: Host to Device
pub const CBW_DIR_OUT: u8 = 0x00;

/// CSW ステータス: コマンド成功
pub const CSW_STATUS_PASSED: u8 = 0x00;
/// CSW ステータス: コマンド失敗
pub const CSW_STATUS_FAILED: u8 = 0x01;
/// CSW ステータス: Phase Error
pub const CSW_STATUS_PHASE_ERROR: u8 = 0x02;

// ============================================================================
// MSC Subclass / Protocol Enums
// ============================================================================

/// MSC サブクラス
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MscSubclass {
    /// RBC (Reduced Block Commands)
    Rbc,
    /// MMC-5 (CD/DVD)
    Mmc5,
    /// UFI (Floppy)
    Ufi,
    /// SCSI Transparent
    Scsi,
    /// 不明
    Unknown(u8),
}

impl MscSubclass {
    pub fn from_u8(value: u8) -> Self {
        match value {
            0x01 => Self::Rbc,
            0x02 => Self::Mmc5,
            0x04 => Self::Ufi,
            0x06 => Self::Scsi,
            v => Self::Unknown(v),
        }
    }
}

/// MSC プロトコル
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MscProtocol {
    /// CBI with interrupt
    CbiWithInterrupt,
    /// CBI
    Cbi,
    /// BBB (Bulk-Only)
    BulkOnly,
    /// UAS
    Uas,
    /// 不明
    Unknown(u8),
}

impl MscProtocol {
    pub fn from_u8(value: u8) -> Self {
        match value {
            0x00 => Self::CbiWithInterrupt,
            0x01 => Self::Cbi,
            0x50 => Self::BulkOnly,
            0x62 => Self::Uas,
            v => Self::Unknown(v),
        }
    }
}

// ============================================================================
// CBW/CSW Structures
// ============================================================================

/// Command Block Wrapper
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct CommandBlockWrapper {
    /// シグネチャ (0x43425355)
    pub signature: u32,
    /// タグ（ホストが任意に設定）
    pub tag: u32,
    /// 転送データ長
    pub data_transfer_length: u32,
    /// フラグ（方向ビット含む）
    pub flags: u8,
    /// LUN（下位4ビット）
    pub lun: u8,
    /// コマンド長（1-16）
    pub cb_length: u8,
    /// コマンドブロック
    pub cb: [u8; 16],
}

impl CommandBlockWrapper {
    /// 新しいCBWを作成
    pub fn new(tag: u32, data_length: u32, direction_in: bool, lun: u8, command: &[u8]) -> Self {
        let mut cbw = Self {
            signature: CBW_SIGNATURE,
            tag,
            data_transfer_length: data_length,
            flags: if direction_in { CBW_DIR_IN } else { CBW_DIR_OUT },
            lun: lun & 0x0F,
            cb_length: command.len().min(16) as u8,
            cb: [0; 16],
        };
        cbw.cb[..command.len().min(16)].copy_from_slice(&command[..command.len().min(16)]);
        cbw
    }
    
    /// バイト配列に変換
    pub fn to_bytes(&self) -> [u8; CBW_SIZE] {
        let mut bytes = [0u8; CBW_SIZE];
        bytes[0..4].copy_from_slice(&self.signature.to_le_bytes());
        bytes[4..8].copy_from_slice(&self.tag.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.data_transfer_length.to_le_bytes());
        bytes[12] = self.flags;
        bytes[13] = self.lun;
        bytes[14] = self.cb_length;
        bytes[15..31].copy_from_slice(&self.cb);
        bytes
    }
}

/// Command Status Wrapper
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct CommandStatusWrapper {
    /// シグネチャ (0x53425355)
    pub signature: u32,
    /// タグ（CBWと一致すべき）
    pub tag: u32,
    /// 残りデータ長
    pub data_residue: u32,
    /// ステータス
    pub status: u8,
}

impl CommandStatusWrapper {
    /// バイト配列から作成
    pub fn from_bytes(bytes: &[u8; CSW_SIZE]) -> Self {
        Self {
            signature: u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            tag: u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            data_residue: u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
            status: bytes[12],
        }
    }
    
    /// シグネチャを検証
    pub fn is_valid(&self) -> bool {
        self.signature == CSW_SIGNATURE
    }
    
    /// 成功かどうか
    pub fn is_success(&self) -> bool {
        self.status == CSW_STATUS_PASSED
    }
}

// ============================================================================
// SCSI Commands
// ============================================================================

/// SCSI コマンドコード
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ScsiCommand {
    /// TEST UNIT READY
    TestUnitReady = 0x00,
    /// REQUEST SENSE
    RequestSense = 0x03,
    /// INQUIRY
    Inquiry = 0x12,
    /// MODE SENSE (6)
    ModeSense6 = 0x1A,
    /// START STOP UNIT
    StartStopUnit = 0x1B,
    /// PREVENT ALLOW MEDIUM REMOVAL
    PreventAllowMediumRemoval = 0x1E,
    /// READ CAPACITY (10)
    ReadCapacity10 = 0x25,
    /// READ (10)
    Read10 = 0x28,
    /// WRITE (10)
    Write10 = 0x2A,
    /// SYNCHRONIZE CACHE (10)
    SynchronizeCache10 = 0x35,
    /// READ CAPACITY (16)
    ReadCapacity16 = 0x9E,
    /// READ (16)
    Read16 = 0x88,
    /// WRITE (16)
    Write16 = 0x8A,
}

/// SCSI Sense Key
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SenseKey {
    NoSense = 0x00,
    RecoveredError = 0x01,
    NotReady = 0x02,
    MediumError = 0x03,
    HardwareError = 0x04,
    IllegalRequest = 0x05,
    UnitAttention = 0x06,
    DataProtect = 0x07,
    BlankCheck = 0x08,
    VendorSpecific = 0x09,
    CopyAborted = 0x0A,
    AbortedCommand = 0x0B,
    VolumeOverflow = 0x0D,
    Miscompare = 0x0E,
}

impl SenseKey {
    pub fn from_u8(value: u8) -> Self {
        match value & 0x0F {
            0x00 => Self::NoSense,
            0x01 => Self::RecoveredError,
            0x02 => Self::NotReady,
            0x03 => Self::MediumError,
            0x04 => Self::HardwareError,
            0x05 => Self::IllegalRequest,
            0x06 => Self::UnitAttention,
            0x07 => Self::DataProtect,
            0x08 => Self::BlankCheck,
            0x09 => Self::VendorSpecific,
            0x0A => Self::CopyAborted,
            0x0B => Self::AbortedCommand,
            0x0D => Self::VolumeOverflow,
            0x0E => Self::Miscompare,
            _ => Self::NoSense,
        }
    }
}

/// SCSI Sense Data
#[derive(Debug, Clone)]
pub struct ScsiSense {
    /// Sense Key
    pub sense_key: SenseKey,
    /// Additional Sense Code
    pub asc: u8,
    /// Additional Sense Code Qualifier
    pub ascq: u8,
}

impl ScsiSense {
    /// 固定フォーマットSenseデータから作成
    pub fn from_fixed_format(data: &[u8]) -> Option<Self> {
        if data.len() < 14 {
            return None;
        }
        
        Some(Self {
            sense_key: SenseKey::from_u8(data[2]),
            asc: data[12],
            ascq: data[13],
        })
    }
}

// ============================================================================
// SCSI Command Builders
// ============================================================================

/// SCSI コマンドビルダー
pub struct ScsiCommandBuilder;

impl ScsiCommandBuilder {
    /// TEST UNIT READY を構築
    pub fn test_unit_ready() -> [u8; 6] {
        [0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    }
    
    /// REQUEST SENSE を構築
    pub fn request_sense(allocation_length: u8) -> [u8; 6] {
        [0x03, 0x00, 0x00, 0x00, allocation_length, 0x00]
    }
    
    /// INQUIRY を構築
    pub fn inquiry(allocation_length: u8) -> [u8; 6] {
        [0x12, 0x00, 0x00, 0x00, allocation_length, 0x00]
    }
    
    /// READ CAPACITY (10) を構築
    pub fn read_capacity_10() -> [u8; 10] {
        [0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    }
    
    /// READ (10) を構築
    pub fn read_10(lba: u32, block_count: u16) -> [u8; 10] {
        let lba_bytes = lba.to_be_bytes();
        let count_bytes = block_count.to_be_bytes();
        [
            0x28, 0x00,
            lba_bytes[0], lba_bytes[1], lba_bytes[2], lba_bytes[3],
            0x00,
            count_bytes[0], count_bytes[1],
            0x00,
        ]
    }
    
    /// WRITE (10) を構築
    pub fn write_10(lba: u32, block_count: u16) -> [u8; 10] {
        let lba_bytes = lba.to_be_bytes();
        let count_bytes = block_count.to_be_bytes();
        [
            0x2A, 0x00,
            lba_bytes[0], lba_bytes[1], lba_bytes[2], lba_bytes[3],
            0x00,
            count_bytes[0], count_bytes[1],
            0x00,
        ]
    }
    
    /// READ (16) を構築（大容量デバイス用）
    pub fn read_16(lba: u64, block_count: u32) -> [u8; 16] {
        let lba_bytes = lba.to_be_bytes();
        let count_bytes = block_count.to_be_bytes();
        [
            0x88, 0x00,
            lba_bytes[0], lba_bytes[1], lba_bytes[2], lba_bytes[3],
            lba_bytes[4], lba_bytes[5], lba_bytes[6], lba_bytes[7],
            count_bytes[0], count_bytes[1], count_bytes[2], count_bytes[3],
            0x00, 0x00,
        ]
    }
    
    /// WRITE (16) を構築（大容量デバイス用）
    pub fn write_16(lba: u64, block_count: u32) -> [u8; 16] {
        let lba_bytes = lba.to_be_bytes();
        let count_bytes = block_count.to_be_bytes();
        [
            0x8A, 0x00,
            lba_bytes[0], lba_bytes[1], lba_bytes[2], lba_bytes[3],
            lba_bytes[4], lba_bytes[5], lba_bytes[6], lba_bytes[7],
            count_bytes[0], count_bytes[1], count_bytes[2], count_bytes[3],
            0x00, 0x00,
        ]
    }
    
    /// SYNCHRONIZE CACHE (10) を構築
    pub fn synchronize_cache_10() -> [u8; 10] {
        [0x35, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    }
    
    /// START STOP UNIT を構築
    pub fn start_stop_unit(start: bool, eject: bool) -> [u8; 6] {
        let flags = (if start { 0x01 } else { 0x00 }) | (if eject { 0x02 } else { 0x00 });
        [0x1B, 0x00, 0x00, 0x00, flags, 0x00]
    }
}

// ============================================================================
// MSC Device
// ============================================================================

/// Mass Storage デバイス
pub struct MscDevice {
    /// スロットID
    slot_id: AtomicU8,
    /// インターフェース番号
    interface: u8,
    /// サブクラス
    subclass: MscSubclass,
    /// プロトコル
    protocol: MscProtocol,
    /// Bulk IN エンドポイント
    bulk_in: u8,
    /// Bulk OUT エンドポイント
    bulk_out: u8,
    /// 最大LUN
    max_lun: AtomicU8,
    /// 現在のコマンドタグ
    current_tag: AtomicU32,
    /// 初期化済みフラグ
    initialized: AtomicBool,
    /// デバイス情報
    device_info: Mutex<Option<MscDeviceInfo>>,
}

/// MSC デバイス情報
#[derive(Debug, Clone)]
pub struct MscDeviceInfo {
    /// ベンダーID文字列
    pub vendor: String,
    /// プロダクトID文字列
    pub product: String,
    /// リビジョン
    pub revision: String,
    /// 総ブロック数
    pub total_blocks: u64,
    /// ブロックサイズ
    pub block_size: u32,
    /// 総容量（バイト）
    pub capacity: u64,
    /// リムーバブルメディアか
    pub removable: bool,
}

impl MscDevice {
    /// 新しい MSC デバイスを作成
    pub fn new(
        interface: u8,
        subclass: MscSubclass,
        protocol: MscProtocol,
        bulk_in: u8,
        bulk_out: u8,
    ) -> Self {
        Self {
            slot_id: AtomicU8::new(0),
            interface,
            subclass,
            protocol,
            bulk_in,
            bulk_out,
            max_lun: AtomicU8::new(0),
            current_tag: AtomicU32::new(1),
            initialized: AtomicBool::new(false),
            device_info: Mutex::new(None),
        }
    }
    
    /// 次のコマンドタグを取得
    fn next_tag(&self) -> u32 {
        self.current_tag.fetch_add(1, Ordering::SeqCst)
    }
    
    /// 最大LUNを取得
    pub fn max_lun(&self) -> u8 {
        self.max_lun.load(Ordering::SeqCst)
    }
    
    /// デバイス情報を取得
    pub fn device_info(&self) -> Option<MscDeviceInfo> {
        self.device_info.lock().clone()
    }
    
    /// GET MAX LUN リクエストを構築
    pub fn build_get_max_lun(interface: u8) -> SetupPacket {
        SetupPacket {
            request_type: REQUEST_TYPE_CLASS_INTERFACE | REQUEST_DIR_IN,
            request: MSC_GET_MAX_LUN,
            value: 0,
            index: interface as u16,
            length: 1,
        }
    }
    
    /// Bulk-Only Mass Storage Reset を構築
    pub fn build_reset(interface: u8) -> SetupPacket {
        SetupPacket {
            request_type: REQUEST_TYPE_CLASS_INTERFACE | REQUEST_DIR_OUT,
            request: MSC_RESET,
            value: 0,
            index: interface as u16,
            length: 0,
        }
    }
    
    // ========================================================================
    // Bulk-Only Transport Operations
    // ========================================================================
    
    /// CBWを作成してコマンドを実行（実際の転送はドライバ側で行う）
    pub fn prepare_command(&self, command: &[u8], data_length: u32, direction_in: bool, lun: u8) -> CommandBlockWrapper {
        CommandBlockWrapper::new(
            self.next_tag(),
            data_length,
            direction_in,
            lun,
            command,
        )
    }
    
    /// TEST UNIT READY コマンドを準備
    pub fn prepare_test_unit_ready(&self, lun: u8) -> CommandBlockWrapper {
        let cmd = ScsiCommandBuilder::test_unit_ready();
        self.prepare_command(&cmd, 0, false, lun)
    }
    
    /// INQUIRY コマンドを準備
    pub fn prepare_inquiry(&self, lun: u8) -> CommandBlockWrapper {
        let cmd = ScsiCommandBuilder::inquiry(36);
        self.prepare_command(&cmd, 36, true, lun)
    }
    
    /// READ CAPACITY (10) コマンドを準備
    pub fn prepare_read_capacity(&self, lun: u8) -> CommandBlockWrapper {
        let cmd = ScsiCommandBuilder::read_capacity_10();
        self.prepare_command(&cmd, 8, true, lun)
    }
    
    /// READ (10) コマンドを準備
    pub fn prepare_read(&self, lun: u8, lba: u32, block_count: u16, block_size: u32) -> CommandBlockWrapper {
        let cmd = ScsiCommandBuilder::read_10(lba, block_count);
        let data_length = (block_count as u32) * block_size;
        self.prepare_command(&cmd, data_length, true, lun)
    }
    
    /// WRITE (10) コマンドを準備
    pub fn prepare_write(&self, lun: u8, lba: u32, block_count: u16, block_size: u32) -> CommandBlockWrapper {
        let cmd = ScsiCommandBuilder::write_10(lba, block_count);
        let data_length = (block_count as u32) * block_size;
        self.prepare_command(&cmd, data_length, false, lun)
    }
    
    /// REQUEST SENSE コマンドを準備
    pub fn prepare_request_sense(&self, lun: u8) -> CommandBlockWrapper {
        let cmd = ScsiCommandBuilder::request_sense(18);
        self.prepare_command(&cmd, 18, true, lun)
    }
    
    /// SYNCHRONIZE CACHE コマンドを準備
    pub fn prepare_sync_cache(&self, lun: u8) -> CommandBlockWrapper {
        let cmd = ScsiCommandBuilder::synchronize_cache_10();
        self.prepare_command(&cmd, 0, false, lun)
    }
    
    // ========================================================================
    // Response Parsing
    // ========================================================================
    
    /// INQUIRY レスポンスをパース
    pub fn parse_inquiry_response(data: &[u8]) -> Option<(String, String, String, bool)> {
        if data.len() < 36 {
            return None;
        }
        
        let removable = (data[1] & 0x80) != 0;
        
        // Vendor ID (8 bytes at offset 8)
        let vendor = alloc::string::String::from(
            core::str::from_utf8(&data[8..16])
                .unwrap_or("")
                .trim()
        );
        
        // Product ID (16 bytes at offset 16)
        let product = alloc::string::String::from(
            core::str::from_utf8(&data[16..32])
                .unwrap_or("")
                .trim()
        );
        
        // Revision (4 bytes at offset 32)
        let revision = alloc::string::String::from(
            core::str::from_utf8(&data[32..36])
                .unwrap_or("")
                .trim()
        );
        
        Some((vendor, product, revision, removable))
    }
    
    /// READ CAPACITY (10) レスポンスをパース
    pub fn parse_read_capacity_10(data: &[u8]) -> Option<(u32, u32)> {
        if data.len() < 8 {
            return None;
        }
        
        let last_lba = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let block_size = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        
        Some((last_lba + 1, block_size))
    }
    
    /// デバイス情報を更新
    pub fn update_device_info(&self, info: MscDeviceInfo) {
        *self.device_info.lock() = Some(info);
    }
}

impl UsbClassDriver for MscDevice {
    fn name(&self) -> &'static str {
        "USB Mass Storage Device"
    }
    
    fn class_code(&self) -> UsbClass {
        UsbClass::MassStorage
    }
    
    fn probe(&self, class: u8, subclass: u8, protocol: u8) -> bool {
        class == MSC_CLASS
            && (subclass == MSC_SUBCLASS_SCSI || subclass == MSC_SUBCLASS_RBC)
            && protocol == MSC_PROTOCOL_BBB
    }
    
    fn init(&mut self, slot_id: u8) -> Result<(), ClassDriverError> {
        self.slot_id.store(slot_id, Ordering::SeqCst);
        
        // 1. GET MAX LUN を取得
        // 2. TEST UNIT READY を実行
        // 3. INQUIRY でデバイス情報を取得
        // 4. READ CAPACITY で容量を取得
        
        self.initialized.store(true, Ordering::SeqCst);
        Ok(())
    }
    
    fn release(&mut self) -> Result<(), ClassDriverError> {
        // SYNCHRONIZE CACHE を実行
        // START STOP UNIT (eject) を実行（リムーバブルメディアの場合）
        
        self.initialized.store(false, Ordering::SeqCst);
        Ok(())
    }
    
    fn poll(&mut self) -> Result<(), ClassDriverError> {
        // Bulk転送はポーリング不要
        Ok(())
    }
    
    fn on_event(&mut self, event: ClassDriverEvent) {
        if let ClassDriverEvent::TransferComplete { endpoint, status, bytes_transferred } = event {
            if endpoint == self.bulk_in && status == TransferStatus::Success {
                let _ = bytes_transferred;
            }
        }
    }
}

// ============================================================================
// Block Device Interface
// ============================================================================

/// ブロックデバイスインターフェース（ファイルシステム連携用）
pub trait BlockDevice: Send + Sync {
    /// ブロックサイズを取得
    fn block_size(&self) -> u32;
    
    /// 総ブロック数を取得
    fn total_blocks(&self) -> u64;
    
    /// ブロックを読み取り
    fn read_blocks(&self, start_lba: u64, count: u32, buffer: &mut [u8]) -> Result<(), ClassDriverError>;
    
    /// ブロックを書き込み
    fn write_blocks(&self, start_lba: u64, count: u32, buffer: &[u8]) -> Result<(), ClassDriverError>;
    
    /// キャッシュをフラッシュ
    fn flush(&self) -> Result<(), ClassDriverError>;
}
