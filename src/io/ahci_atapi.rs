// ============================================================================
// src/io/ahci_atapi.rs - AHCI ATAPI (CD/DVD) Support
// ============================================================================
//!
//! # ATAPI サポート
//!
//! SATA接続の光学ドライブ（CD/DVD）をAHCI経由で制御。
//! SCSI Packet Commandを使用してメディアへのアクセスを提供。
//!
//! ## 機能
//! - ATAPI IDENTIFY
//! - SCSI Packet Command発行
//! - CD/DVDセクタ読み取り
//! - TOC読み取り
//! - メディア情報取得
//!
//! ## 参考
//! - ATA/ATAPI-8 仕様
//! - MMC-6 (Multi-Media Commands)

#![allow(dead_code)]

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::ptr;

use super::ahci::{
    AhciError, AhciResult, CommandHeader, CommandTable, DeviceType, FisRegH2D, FisType, Lba,
    PhysicalRegionDescriptor, PortNumber, SlotNumber,
};

// AHCI port register offsets (duplicated from ahci.rs as they are private)
const PX_IS: u32 = 0x10;
const PX_TFD: u32 = 0x20;
const PX_CI: u32 = 0x38;

// ============================================================================
// ATAPI Constants
// ============================================================================

/// ATAPIコマンド
const ATA_CMD_PACKET: u8 = 0xA0;
const ATA_CMD_IDENTIFY_PACKET: u8 = 0xA1;

/// SCSI コマンドコード
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScsiOpcode {
    /// Test Unit Ready
    TestUnitReady = 0x00,
    /// Request Sense
    RequestSense = 0x03,
    /// Inquiry
    Inquiry = 0x12,
    /// Mode Sense (6)
    ModeSense6 = 0x1A,
    /// Start/Stop Unit
    StartStopUnit = 0x1B,
    /// Prevent/Allow Medium Removal
    PreventAllow = 0x1E,
    /// Read Capacity
    ReadCapacity = 0x25,
    /// Read (10)
    Read10 = 0x28,
    /// Read (12)
    Read12 = 0xA8,
    /// Read TOC/PMA/ATIP
    ReadTocPmaAtip = 0x43,
    /// Get Configuration
    GetConfiguration = 0x46,
    /// Get Event/Status Notification
    GetEventStatus = 0x4A,
    /// Read Disc Information
    ReadDiscInfo = 0x51,
    /// Mode Sense (10)
    ModeSense10 = 0x5A,
    /// Read CD
    ReadCd = 0xBE,
}

/// セクタサイズ
pub const CD_SECTOR_SIZE: u32 = 2048;
pub const CD_AUDIO_SECTOR_SIZE: u32 = 2352;

// ============================================================================
// SCSI Command Descriptor Block (CDB)
// ============================================================================

/// SCSI CDB (12バイト固定)
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ScsiCdb12 {
    pub opcode: u8,
    pub flags: u8,
    pub lba_hi: u8,
    pub lba_mid_hi: u8,
    pub lba_mid_lo: u8,
    pub lba_lo: u8,
    pub length_hi: u8,
    pub length_mid_hi: u8,
    pub length_mid_lo: u8,
    pub length_lo: u8,
    pub reserved: u8,
    pub control: u8,
}

impl ScsiCdb12 {
    /// Test Unit Ready コマンド
    pub fn test_unit_ready() -> Self {
        Self {
            opcode: ScsiOpcode::TestUnitReady as u8,
            ..Default::default()
        }
    }

    /// Inquiry コマンド
    pub fn inquiry(allocation_length: u8) -> Self {
        Self {
            opcode: ScsiOpcode::Inquiry as u8,
            length_lo: allocation_length,
            ..Default::default()
        }
    }

    /// Request Sense コマンド
    pub fn request_sense(allocation_length: u8) -> Self {
        Self {
            opcode: ScsiOpcode::RequestSense as u8,
            length_lo: allocation_length,
            ..Default::default()
        }
    }

    /// Read Capacity コマンド
    pub fn read_capacity() -> Self {
        Self {
            opcode: ScsiOpcode::ReadCapacity as u8,
            ..Default::default()
        }
    }

    /// Read (10) コマンド
    pub fn read10(lba: u32, block_count: u16) -> Self {
        Self {
            opcode: ScsiOpcode::Read10 as u8,
            lba_hi: ((lba >> 24) & 0xFF) as u8,
            lba_mid_hi: ((lba >> 16) & 0xFF) as u8,
            lba_mid_lo: ((lba >> 8) & 0xFF) as u8,
            lba_lo: (lba & 0xFF) as u8,
            length_mid_lo: ((block_count >> 8) & 0xFF) as u8,
            length_lo: (block_count & 0xFF) as u8,
            ..Default::default()
        }
    }

    /// Read (12) コマンド
    pub fn read12(lba: u32, block_count: u32) -> Self {
        Self {
            opcode: ScsiOpcode::Read12 as u8,
            lba_hi: ((lba >> 24) & 0xFF) as u8,
            lba_mid_hi: ((lba >> 16) & 0xFF) as u8,
            lba_mid_lo: ((lba >> 8) & 0xFF) as u8,
            lba_lo: (lba & 0xFF) as u8,
            length_hi: ((block_count >> 24) & 0xFF) as u8,
            length_mid_hi: ((block_count >> 16) & 0xFF) as u8,
            length_mid_lo: ((block_count >> 8) & 0xFF) as u8,
            length_lo: (block_count & 0xFF) as u8,
            ..Default::default()
        }
    }

    /// Read TOC コマンド
    pub fn read_toc(format: TocFormat, track: u8, allocation_length: u16) -> Self {
        Self {
            opcode: ScsiOpcode::ReadTocPmaAtip as u8,
            flags: (format as u8) << 1,
            lba_lo: track,
            length_mid_lo: ((allocation_length >> 8) & 0xFF) as u8,
            length_lo: (allocation_length & 0xFF) as u8,
            ..Default::default()
        }
    }

    /// Start/Stop Unit コマンド
    pub fn start_stop_unit(start: bool, load_eject: bool) -> Self {
        let mut flags = 0u8;
        if start {
            flags |= 0x01;
        }
        if load_eject {
            flags |= 0x02;
        }
        Self {
            opcode: ScsiOpcode::StartStopUnit as u8,
            length_lo: flags,
            ..Default::default()
        }
    }

    /// Get Configuration コマンド
    pub fn get_configuration(feature: u16, allocation_length: u16) -> Self {
        Self {
            opcode: ScsiOpcode::GetConfiguration as u8,
            flags: 0x02, // RT = 10b (one feature at specified starting feature number)
            lba_hi: ((feature >> 8) & 0xFF) as u8,
            lba_mid_hi: (feature & 0xFF) as u8,
            length_mid_lo: ((allocation_length >> 8) & 0xFF) as u8,
            length_lo: (allocation_length & 0xFF) as u8,
            ..Default::default()
        }
    }
}

/// TOCフォーマット
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TocFormat {
    /// Formatted TOC
    FormattedToc = 0,
    /// Multi-session info
    MultiSession = 1,
    /// Raw TOC
    RawToc = 2,
    /// PMA
    Pma = 3,
    /// ATIP
    Atip = 4,
    /// CD-TEXT
    CdText = 5,
}

// ============================================================================
// ATAPI Response Structures
// ============================================================================

/// SCSI Inquiry Response
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default)]
pub struct InquiryResponse {
    /// Peripheral device type (bits 0-4), Peripheral qualifier (bits 5-7)
    pub peripheral: u8,
    /// Removable media (bit 7)
    pub rmb: u8,
    /// Version
    pub version: u8,
    /// Response data format
    pub response_format: u8,
    /// Additional length
    pub additional_length: u8,
    pub reserved: [u8; 3],
    /// Vendor identification
    pub vendor: [u8; 8],
    /// Product identification
    pub product: [u8; 16],
    /// Product revision level
    pub revision: [u8; 4],
}

impl InquiryResponse {
    /// デバイスタイプを取得
    pub fn device_type(&self) -> AtapiDeviceType {
        AtapiDeviceType::from_code(self.peripheral & 0x1F)
    }

    /// リムーバブルか
    pub fn is_removable(&self) -> bool {
        (self.rmb & 0x80) != 0
    }

    /// ベンダー名を取得
    pub fn vendor_string(&self) -> String {
        String::from_utf8_lossy(&self.vendor).trim().to_string()
    }

    /// プロダクト名を取得
    pub fn product_string(&self) -> String {
        String::from_utf8_lossy(&self.product).trim().to_string()
    }

    /// リビジョンを取得
    pub fn revision_string(&self) -> String {
        String::from_utf8_lossy(&self.revision).trim().to_string()
    }
}

/// ATAPIデバイスタイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtapiDeviceType {
    /// Direct-access block device (SBC)
    DirectAccess,
    /// Sequential-access device (tape)
    SequentialAccess,
    /// CD/DVD-ROM
    CdDvd,
    /// Optical memory device
    OpticalMemory,
    /// Media changer
    MediaChanger,
    /// Unknown
    Unknown(u8),
}

impl AtapiDeviceType {
    fn from_code(code: u8) -> Self {
        match code {
            0x00 => AtapiDeviceType::DirectAccess,
            0x01 => AtapiDeviceType::SequentialAccess,
            0x05 => AtapiDeviceType::CdDvd,
            0x07 => AtapiDeviceType::OpticalMemory,
            0x08 => AtapiDeviceType::MediaChanger,
            _ => AtapiDeviceType::Unknown(code),
        }
    }
}

/// Read Capacity Response
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ReadCapacityResponse {
    /// Last Logical Block Address (Big Endian)
    pub last_lba_be: u32,
    /// Block Length (Big Endian)
    pub block_length_be: u32,
}

impl ReadCapacityResponse {
    /// 最終LBAを取得
    pub fn last_lba(&self) -> u32 {
        u32::from_be(self.last_lba_be)
    }

    /// ブロック長を取得
    pub fn block_length(&self) -> u32 {
        u32::from_be(self.block_length_be)
    }

    /// 総ブロック数を取得
    pub fn total_blocks(&self) -> u64 {
        self.last_lba() as u64 + 1
    }

    /// 総容量（バイト）
    pub fn total_bytes(&self) -> u64 {
        self.total_blocks() * self.block_length() as u64
    }
}

/// Request Sense Response
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SenseData {
    /// Error code (bits 0-6), Valid (bit 7)
    pub error_code: u8,
    pub segment_number: u8,
    /// Sense Key (bits 0-3), ILI (bit 5), EOM (bit 6), Filemark (bit 7)
    pub flags: u8,
    pub information: [u8; 4],
    pub additional_length: u8,
    pub command_specific: [u8; 4],
    /// Additional Sense Code
    pub asc: u8,
    /// Additional Sense Code Qualifier
    pub ascq: u8,
    pub fru_code: u8,
    pub sense_key_specific: [u8; 3],
}

impl SenseData {
    /// Sense Keyを取得
    pub fn sense_key(&self) -> SenseKey {
        SenseKey::from_code(self.flags & 0x0F)
    }

    /// ASC/ASCQを取得
    pub fn asc_ascq(&self) -> (u8, u8) {
        (self.asc, self.ascq)
    }

    /// エラー説明を取得
    pub fn error_description(&self) -> &'static str {
        match (self.sense_key(), self.asc, self.ascq) {
            (SenseKey::NoSense, _, _) => "No sense",
            (SenseKey::NotReady, 0x04, 0x01) => "Becoming ready",
            (SenseKey::NotReady, 0x04, 0x02) => "Need START command",
            (SenseKey::NotReady, 0x3A, _) => "Medium not present",
            (SenseKey::MediumError, _, _) => "Medium error",
            (SenseKey::HardwareError, _, _) => "Hardware error",
            (SenseKey::IllegalRequest, _, _) => "Illegal request",
            (SenseKey::UnitAttention, 0x28, _) => "Medium changed",
            (SenseKey::UnitAttention, 0x29, _) => "Reset occurred",
            (SenseKey::DataProtect, _, _) => "Data protect",
            (SenseKey::AbortedCommand, _, _) => "Aborted command",
            _ => "Unknown error",
        }
    }
}

/// SCSI Sense Key
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SenseKey {
    NoSense,
    RecoveredError,
    NotReady,
    MediumError,
    HardwareError,
    IllegalRequest,
    UnitAttention,
    DataProtect,
    BlankCheck,
    VendorSpecific,
    CopyAborted,
    AbortedCommand,
    Obsolete,
    VolumeOverflow,
    Miscompare,
    Reserved,
}

impl SenseKey {
    fn from_code(code: u8) -> Self {
        match code {
            0x0 => SenseKey::NoSense,
            0x1 => SenseKey::RecoveredError,
            0x2 => SenseKey::NotReady,
            0x3 => SenseKey::MediumError,
            0x4 => SenseKey::HardwareError,
            0x5 => SenseKey::IllegalRequest,
            0x6 => SenseKey::UnitAttention,
            0x7 => SenseKey::DataProtect,
            0x8 => SenseKey::BlankCheck,
            0x9 => SenseKey::VendorSpecific,
            0xA => SenseKey::CopyAborted,
            0xB => SenseKey::AbortedCommand,
            0xC => SenseKey::Obsolete,
            0xD => SenseKey::VolumeOverflow,
            0xE => SenseKey::Miscompare,
            _ => SenseKey::Reserved,
        }
    }
}

// ============================================================================
// TOC Structures
// ============================================================================

/// TOCヘッダ
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default)]
pub struct TocHeader {
    /// Data length (Big Endian)
    pub data_length_be: u16,
    /// First track number
    pub first_track: u8,
    /// Last track number
    pub last_track: u8,
}

impl TocHeader {
    pub fn data_length(&self) -> u16 {
        u16::from_be(self.data_length_be)
    }
}

/// TOCトラック記述子
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default)]
pub struct TocTrackDescriptor {
    pub reserved1: u8,
    /// ADR (bits 4-7), Control (bits 0-3)
    pub adr_control: u8,
    /// Track number
    pub track_number: u8,
    pub reserved2: u8,
    /// Track start address (Big Endian)
    pub track_start_be: u32,
}

impl TocTrackDescriptor {
    /// トラック開始位置（LBA）
    pub fn track_start(&self) -> u32 {
        u32::from_be(self.track_start_be)
    }

    /// データトラックか
    pub fn is_data_track(&self) -> bool {
        (self.adr_control & 0x04) != 0
    }

    /// オーディオトラックか
    pub fn is_audio_track(&self) -> bool {
        !self.is_data_track()
    }
}

/// TOC全体
pub struct TableOfContents {
    pub first_track: u8,
    pub last_track: u8,
    pub tracks: Vec<TocTrackDescriptor>,
}

impl TableOfContents {
    /// トラック数を取得
    pub fn track_count(&self) -> u8 {
        if self.last_track >= self.first_track {
            self.last_track - self.first_track + 1
        } else {
            0
        }
    }

    /// 指定トラックを取得
    pub fn get_track(&self, number: u8) -> Option<&TocTrackDescriptor> {
        self.tracks.iter().find(|t| t.track_number == number)
    }

    /// Lead-outトラック（0xAA）を取得
    pub fn lead_out(&self) -> Option<&TocTrackDescriptor> {
        self.tracks.iter().find(|t| t.track_number == 0xAA)
    }

    /// 総再生時間（秒）
    pub fn total_length_seconds(&self) -> u32 {
        if let Some(lead_out) = self.lead_out() {
            // 75フレーム/秒
            lead_out.track_start() / 75
        } else {
            0
        }
    }
}

// ============================================================================
// ATAPI Port Extension
// ============================================================================

/// AHCIポートのATAPI拡張
pub struct AtapiPort {
    /// ポート番号
    port: PortNumber,
    /// ベースアドレス
    base: u64,
    /// ポートベースアドレス
    port_base: u64,
    /// コマンドリスト
    command_list: Box<[CommandHeader; 32]>,
    /// コマンドテーブル
    command_tables: [Option<Box<CommandTable>>; 32],
    /// Inquiry情報（キャッシュ）
    inquiry_cache: Option<InquiryResponse>,
}

impl AtapiPort {
    /// 新しいATAPIポートを作成
    pub fn new(base: u64, port: PortNumber) -> Self {
        let port_base = base + 0x100 + (port.as_u8() as u64 * 0x80);

        Self {
            port,
            base,
            port_base,
            command_list: Box::new([CommandHeader::default(); 32]),
            command_tables: Default::default(),
            inquiry_cache: None,
        }
    }

    /// ATAPI PACKETコマンドを発行
    pub fn packet_command(
        &mut self,
        cdb: &ScsiCdb12,
        buffer: &mut [u8],
        write: bool,
    ) -> AhciResult<usize> {
        let slot = self.find_slot().ok_or(AhciError::NoCommandSlot)?;

        // コマンドテーブルを準備
        let mut cmd_table = Box::new(CommandTable::default());
        let cmd_table_addr = cmd_table.as_ref() as *const _ as u64;

        // PACKET FISを設定
        let fis = FisRegH2D {
            fis_type: FisType::RegH2D as u8,
            flags: 0x80, // Command
            command: ATA_CMD_PACKET,
            feature_lo: if write { 0x00 } else { 0x00 },
            lba1: (buffer.len() & 0xFF) as u8,        // Byte count low
            lba2: ((buffer.len() >> 8) & 0xFF) as u8, // Byte count high
            device: 0,
            ..Default::default()
        };

        unsafe {
            ptr::copy_nonoverlapping(
                &fis as *const _ as *const u8,
                cmd_table.cfis.as_mut_ptr(),
                core::mem::size_of::<FisRegH2D>(),
            );
        }

        // ATAPI CDBを設定
        unsafe {
            ptr::copy_nonoverlapping(
                cdb as *const _ as *const u8,
                cmd_table.acmd.as_mut_ptr(),
                12,
            );
        }

        // PRDTを設定
        if !buffer.is_empty() {
            let buffer_addr = buffer.as_ptr() as u64;
            cmd_table.prdt[0] =
                PhysicalRegionDescriptor::new(buffer_addr, buffer.len() as u32, true);
        }

        // コマンドヘッダを設定
        let header = &mut self.command_list[slot.as_usize()];
        header.set_flags(5, write, true, false); // A=1 for ATAPI
        header.prdtl = if buffer.is_empty() { 0 } else { 1 };
        header.prdbc = 0;
        header.set_ctba(cmd_table_addr);

        self.command_tables[slot.as_usize()] = Some(cmd_table);

        // コマンドを発行
        self.write_port(PX_CI, 1 << slot.as_u8());

        // 完了を待機
        self.wait_completion(slot)?;

        // 転送バイト数を取得
        let transferred = self.command_list[slot.as_usize()].prdbc;
        Ok(transferred as usize)
    }

    /// Test Unit Readyを実行
    pub fn test_unit_ready(&mut self) -> AhciResult<bool> {
        let cdb = ScsiCdb12::test_unit_ready();
        let mut buffer = [];

        match self.packet_command(&cdb, &mut buffer, false) {
            Ok(_) => Ok(true),
            Err(AhciError::TaskFileError(_)) => {
                // Sense情報を取得
                Ok(false)
            }
            Err(e) => Err(e),
        }
    }

    /// Inquiryを実行
    pub fn inquiry(&mut self) -> AhciResult<InquiryResponse> {
        if let Some(cached) = &self.inquiry_cache {
            return Ok(*cached);
        }

        let cdb = ScsiCdb12::inquiry(36);
        let mut buffer = [0u8; 36];

        self.packet_command(&cdb, &mut buffer, false)?;

        let response = unsafe { ptr::read_unaligned(buffer.as_ptr() as *const InquiryResponse) };
        self.inquiry_cache = Some(response);

        Ok(response)
    }

    /// Request Senseを実行
    pub fn request_sense(&mut self) -> AhciResult<SenseData> {
        let cdb = ScsiCdb12::request_sense(18);
        let mut buffer = [0u8; 18];

        self.packet_command(&cdb, &mut buffer, false)?;

        Ok(unsafe { ptr::read_unaligned(buffer.as_ptr() as *const SenseData) })
    }

    /// Read Capacityを実行
    pub fn read_capacity(&mut self) -> AhciResult<ReadCapacityResponse> {
        let cdb = ScsiCdb12::read_capacity();
        let mut buffer = [0u8; 8];

        self.packet_command(&cdb, &mut buffer, false)?;

        Ok(unsafe { ptr::read_unaligned(buffer.as_ptr() as *const ReadCapacityResponse) })
    }

    /// セクタを読み取り
    pub fn read_sectors(
        &mut self,
        lba: u32,
        count: u16,
        buffer: &mut [u8],
    ) -> AhciResult<usize> {
        let expected = count as usize * CD_SECTOR_SIZE as usize;
        if buffer.len() < expected {
            return Err(AhciError::InvalidParameter);
        }

        let cdb = ScsiCdb12::read10(lba, count);
        self.packet_command(&cdb, &mut buffer[..expected], false)
    }

    /// 大量セクタを読み取り（Read 12）
    pub fn read_sectors_large(
        &mut self,
        lba: u32,
        count: u32,
        buffer: &mut [u8],
    ) -> AhciResult<usize> {
        let expected = count as usize * CD_SECTOR_SIZE as usize;
        if buffer.len() < expected {
            return Err(AhciError::InvalidParameter);
        }

        let cdb = ScsiCdb12::read12(lba, count);
        self.packet_command(&cdb, &mut buffer[..expected], false)
    }

    /// TOCを読み取り
    pub fn read_toc(&mut self) -> AhciResult<TableOfContents> {
        // まずTOCヘッダを読み取り
        let cdb = ScsiCdb12::read_toc(TocFormat::FormattedToc, 0, 4);
        let mut header_buf = [0u8; 4];
        self.packet_command(&cdb, &mut header_buf, false)?;

        let header =
            unsafe { ptr::read_unaligned(header_buf.as_ptr() as *const TocHeader) };
        let data_length = header.data_length();

        // 全TOCデータを読み取り
        let total_length = (data_length + 2) as usize;
        let mut toc_buf = alloc::vec![0u8; total_length];

        let cdb = ScsiCdb12::read_toc(TocFormat::FormattedToc, 0, total_length as u16);
        self.packet_command(&cdb, &mut toc_buf, false)?;

        // TOCをパース
        let header =
            unsafe { ptr::read_unaligned(toc_buf.as_ptr() as *const TocHeader) };

        let track_data = &toc_buf[4..];
        let track_count = track_data.len() / 8;
        let mut tracks = Vec::with_capacity(track_count);

        for i in 0..track_count {
            let offset = i * 8;
            let track = unsafe {
                ptr::read_unaligned(
                    track_data[offset..].as_ptr() as *const TocTrackDescriptor
                )
            };
            tracks.push(track);
        }

        Ok(TableOfContents {
            first_track: header.first_track,
            last_track: header.last_track,
            tracks,
        })
    }

    /// トレイをイジェクト
    pub fn eject(&mut self) -> AhciResult<()> {
        let cdb = ScsiCdb12::start_stop_unit(false, true);
        let mut buffer = [];
        self.packet_command(&cdb, &mut buffer, false)?;
        Ok(())
    }

    /// トレイをロード
    pub fn load(&mut self) -> AhciResult<()> {
        let cdb = ScsiCdb12::start_stop_unit(true, true);
        let mut buffer = [];
        self.packet_command(&cdb, &mut buffer, false)?;
        Ok(())
    }

    /// スピンアップ
    pub fn spin_up(&mut self) -> AhciResult<()> {
        let cdb = ScsiCdb12::start_stop_unit(true, false);
        let mut buffer = [];
        self.packet_command(&cdb, &mut buffer, false)?;
        Ok(())
    }

    // ========================================================================
    // Internal Methods
    // ========================================================================

    fn find_slot(&self) -> Option<SlotNumber> {
        let sact = self.read_port(0x34);
        let ci = self.read_port(PX_CI);
        let busy = sact | ci;

        for i in 0..32 {
            if (busy & (1 << i)) == 0 {
                return Some(SlotNumber(i));
            }
        }

        None
    }

    fn wait_completion(&self, slot: SlotNumber) -> AhciResult<()> {
        let slot_mask = 1u32 << slot.as_u8();

        for _ in 0..100000 {
            let ci = self.read_port(PX_CI);
            if (ci & slot_mask) == 0 {
                let tfd = self.read_port(PX_TFD);
                let status = (tfd & 0xFF) as u8;
                let error = ((tfd >> 8) & 0xFF) as u8;

                if (status & 0x01) != 0 {
                    return Err(AhciError::TaskFileError(error));
                }

                return Ok(());
            }

            let is = self.read_port(PX_IS);
            if (is & (1 << 30)) != 0 {
                let tfd = self.read_port(PX_TFD);
                let error = ((tfd >> 8) & 0xFF) as u8;
                return Err(AhciError::TaskFileError(error));
            }
        }

        Err(AhciError::Timeout)
    }

    fn read_port(&self, offset: u32) -> u32 {
        unsafe { ptr::read_volatile((self.port_base + offset as u64) as *const u32) }
    }

    fn write_port(&self, offset: u32, value: u32) {
        unsafe { ptr::write_volatile((self.port_base + offset as u64) as *mut u32, value) }
    }
}

// ============================================================================
// CD/DVD Drive Abstraction
// ============================================================================

/// CD/DVDドライブ情報
#[derive(Debug, Clone)]
pub struct CdDvdDriveInfo {
    /// ベンダー名
    pub vendor: String,
    /// プロダクト名
    pub product: String,
    /// リビジョン
    pub revision: String,
    /// デバイスタイプ
    pub device_type: AtapiDeviceType,
    /// リムーバブル
    pub removable: bool,
}

/// CD/DVDドライブ
pub struct CdDvdDrive {
    port: AtapiPort,
    info: Option<CdDvdDriveInfo>,
}

impl CdDvdDrive {
    /// 新しいCD/DVDドライブを作成
    pub fn new(base: u64, port_number: PortNumber) -> Self {
        Self {
            port: AtapiPort::new(base, port_number),
            info: None,
        }
    }

    /// ドライブを初期化
    pub fn init(&mut self) -> AhciResult<()> {
        // Inquiryでデバイス情報を取得
        let inquiry = self.port.inquiry()?;

        self.info = Some(CdDvdDriveInfo {
            vendor: inquiry.vendor_string(),
            product: inquiry.product_string(),
            revision: inquiry.revision_string(),
            device_type: inquiry.device_type(),
            removable: inquiry.is_removable(),
        });

        Ok(())
    }

    /// ドライブ情報を取得
    pub fn info(&self) -> Option<&CdDvdDriveInfo> {
        self.info.as_ref()
    }

    /// メディアが挿入されているか確認
    pub fn is_media_present(&mut self) -> bool {
        self.port.test_unit_ready().unwrap_or(false)
    }

    /// メディア容量を取得
    pub fn media_capacity(&mut self) -> AhciResult<(u64, u32)> {
        let cap = self.port.read_capacity()?;
        Ok((cap.total_blocks(), cap.block_length()))
    }

    /// セクタを読み取り
    pub fn read(&mut self, lba: u32, count: u16, buffer: &mut [u8]) -> AhciResult<usize> {
        self.port.read_sectors(lba, count, buffer)
    }

    /// TOCを読み取り
    pub fn read_toc(&mut self) -> AhciResult<TableOfContents> {
        self.port.read_toc()
    }

    /// トレイをイジェクト
    pub fn eject(&mut self) -> AhciResult<()> {
        self.port.eject()
    }

    /// トレイをロード
    pub fn load(&mut self) -> AhciResult<()> {
        self.port.load()
    }

    /// 最後のエラー情報を取得
    pub fn last_error(&mut self) -> AhciResult<SenseData> {
        self.port.request_sense()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cdb_read10() {
        let cdb = ScsiCdb12::read10(0x12345678, 256);
        assert_eq!(cdb.opcode, ScsiOpcode::Read10 as u8);
        assert_eq!(cdb.lba_hi, 0x12);
        assert_eq!(cdb.lba_mid_hi, 0x34);
        assert_eq!(cdb.lba_mid_lo, 0x56);
        assert_eq!(cdb.lba_lo, 0x78);
        assert_eq!(cdb.length_mid_lo, 0x01);
        assert_eq!(cdb.length_lo, 0x00);
    }

    #[test]
    fn test_sense_key() {
        assert_eq!(SenseKey::from_code(0x00), SenseKey::NoSense);
        assert_eq!(SenseKey::from_code(0x02), SenseKey::NotReady);
        assert_eq!(SenseKey::from_code(0x05), SenseKey::IllegalRequest);
    }

    #[test]
    fn test_read_capacity_endianness() {
        let response = ReadCapacityResponse {
            last_lba_be: 0x01020304u32.to_be(),
            block_length_be: 0x00000800u32.to_be(), // 2048
        };
        assert_eq!(response.last_lba(), 0x01020304);
        assert_eq!(response.block_length(), 2048);
    }
}
