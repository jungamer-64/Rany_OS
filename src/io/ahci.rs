// ============================================================================
// src/io/ahci.rs - AHCI (Advanced Host Controller Interface) Driver
// ============================================================================
//!
//! # AHCI ドライバ
//!
//! SATA デバイス用の AHCI コントローラドライバ。
//!
//! ## アーキテクチャ
//! - HBA (Host Bus Adapter) 制御
//! - ポートごとのコマンド発行
//! - FIS (Frame Information Structure) ベースの通信
//!
//! ## 型安全性
//! - Newtype パターンによるポート/スロット管理
//! - 状態機械による安全な状態遷移
//! - SafePackedRead による構造体アクセス

#![allow(dead_code)]

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ptr;
use core::sync::atomic::AtomicU32;
use spin::Mutex;

// ============================================================================
// Type-Safe Identifiers
// ============================================================================

/// AHCIポート番号（型安全）
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PortNumber(pub u8);

impl PortNumber {
    pub const MAX_PORTS: u8 = 32;

    pub fn is_valid(&self) -> bool {
        self.0 < Self::MAX_PORTS
    }

    pub fn as_u8(&self) -> u8 {
        self.0
    }

    pub fn as_usize(&self) -> usize {
        self.0 as usize
    }
}

/// コマンドスロット番号（型安全）
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SlotNumber(pub u8);

impl SlotNumber {
    pub const MAX_SLOTS: u8 = 32;

    pub fn is_valid(&self) -> bool {
        self.0 < Self::MAX_SLOTS
    }

    pub fn as_u8(&self) -> u8 {
        self.0
    }

    pub fn as_usize(&self) -> usize {
        self.0 as usize
    }
}

/// LBA（Logical Block Address）（型安全）
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Lba(pub u64);

impl Lba {
    pub fn as_u64(&self) -> u64 {
        self.0
    }

    /// セクタオフセットを加算
    pub fn offset(&self, sectors: u64) -> Self {
        Lba(self.0 + sectors)
    }
}

impl core::ops::Add<u64> for Lba {
    type Output = Lba;
    fn add(self, rhs: u64) -> Self::Output {
        Lba(self.0 + rhs)
    }
}

/// セクタ数（型安全）
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SectorCount(pub u32);

impl SectorCount {
    pub fn as_u32(&self) -> u32 {
        self.0
    }

    /// バイト数に変換（512バイト/セクタ）
    pub fn to_bytes(&self) -> u64 {
        (self.0 as u64) * 512
    }
}

// ============================================================================
// AHCI Constants
// ============================================================================

/// GHC (Global Host Control) オフセット
const GHC_CAP: u32 = 0x00; // HBA Capabilities
const GHC_GHC: u32 = 0x04; // Global HBA Control
const GHC_IS: u32 = 0x08; // Interrupt Status
const GHC_PI: u32 = 0x0C; // Ports Implemented
const GHC_VS: u32 = 0x10; // Version
const GHC_CCC_CTL: u32 = 0x14; // Command Completion Coalescing Control
const GHC_CCC_PORTS: u32 = 0x18; // Command Completion Coalescing Ports
const GHC_CAP2: u32 = 0x24; // HBA Capabilities Extended
const GHC_BOHC: u32 = 0x28; // BIOS/OS Handoff Control

/// GHC ビット
const GHC_AE: u32 = 1 << 31; // AHCI Enable
const GHC_IE: u32 = 1 << 1; // Interrupt Enable
const GHC_HR: u32 = 1 << 0; // HBA Reset

/// ポートレジスタオフセット（ポート0の開始）
const PORT_BASE: u32 = 0x100;
const PORT_SIZE: u32 = 0x80;

/// ポートレジスタ
const PX_CLB: u32 = 0x00; // Command List Base Address
const PX_CLBU: u32 = 0x04; // Command List Base Address Upper
const PX_FB: u32 = 0x08; // FIS Base Address
const PX_FBU: u32 = 0x0C; // FIS Base Address Upper
const PX_IS: u32 = 0x10; // Interrupt Status
const PX_IE: u32 = 0x14; // Interrupt Enable
const PX_CMD: u32 = 0x18; // Command and Status
const PX_TFD: u32 = 0x20; // Task File Data
const PX_SIG: u32 = 0x24; // Signature
const PX_SSTS: u32 = 0x28; // SATA Status
const PX_SCTL: u32 = 0x2C; // SATA Control
const PX_SERR: u32 = 0x30; // SATA Error
const PX_SACT: u32 = 0x34; // SATA Active
const PX_CI: u32 = 0x38; // Command Issue
const PX_SNTF: u32 = 0x3C; // SATA Notification
const PX_FBS: u32 = 0x40; // FIS-based Switching Control

/// PxCMD ビット
const PX_CMD_ST: u32 = 1 << 0; // Start
const PX_CMD_SUD: u32 = 1 << 1; // Spin-Up Device
const PX_CMD_POD: u32 = 1 << 2; // Power On Device
const PX_CMD_FRE: u32 = 1 << 4; // FIS Receive Enable
const PX_CMD_FR: u32 = 1 << 14; // FIS Receive Running
const PX_CMD_CR: u32 = 1 << 15; // Command List Running

/// PxIS ビット
const PX_IS_DHRS: u32 = 1 << 0; // Device to Host Register FIS
const PX_IS_PSS: u32 = 1 << 1; // PIO Setup FIS
const PX_IS_DSS: u32 = 1 << 2; // DMA Setup FIS
const PX_IS_SDBS: u32 = 1 << 3; // Set Device Bits
const PX_IS_TFES: u32 = 1 << 30; // Task File Error

/// デバイスシグネチャ
const SATA_SIG_ATA: u32 = 0x00000101;
const SATA_SIG_ATAPI: u32 = 0xEB140101;
const SATA_SIG_SEMB: u32 = 0xC33C0101;
const SATA_SIG_PM: u32 = 0x96690101;

// ============================================================================
// FIS Types
// ============================================================================

/// FIS タイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FisType {
    /// Register FIS - Host to Device
    RegH2D = 0x27,
    /// Register FIS - Device to Host
    RegD2H = 0x34,
    /// DMA Activate FIS
    DmaActivate = 0x39,
    /// DMA Setup FIS
    DmaSetup = 0x41,
    /// Data FIS
    Data = 0x46,
    /// BIST Activate FIS
    Bist = 0x58,
    /// PIO Setup FIS
    PioSetup = 0x5F,
    /// Set Device Bits FIS
    DevBits = 0xA1,
}

/// Register FIS - Host to Device (20バイト)
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default)]
pub struct FisRegH2D {
    /// FIS Type (0x27)
    pub fis_type: u8,
    /// PM Port | C bit (0x80 = command)
    pub flags: u8,
    /// Command register
    pub command: u8,
    /// Feature register (lower)
    pub feature_lo: u8,

    /// LBA low
    pub lba0: u8,
    /// LBA mid
    pub lba1: u8,
    /// LBA high
    pub lba2: u8,
    /// Device register
    pub device: u8,

    /// LBA register, 31:24
    pub lba3: u8,
    /// LBA register, 39:32
    pub lba4: u8,
    /// LBA register, 47:40
    pub lba5: u8,
    /// Feature register (upper)
    pub feature_hi: u8,

    /// Count register (lower)
    pub count_lo: u8,
    /// Count register (upper)
    pub count_hi: u8,
    /// Isochronous command completion
    pub icc: u8,
    /// Control register
    pub control: u8,

    /// Reserved
    pub reserved: [u8; 4],
}

impl FisRegH2D {
    /// ATA IDENTIFYコマンド用FISを作成
    pub fn identify() -> Self {
        Self {
            fis_type: FisType::RegH2D as u8,
            flags: 0x80, // Command
            command: ATA_CMD_IDENTIFY,
            device: 0,
            ..Default::default()
        }
    }

    /// ATA READ DMA EXTコマンド用FISを作成
    pub fn read_dma_ext(lba: Lba, count: SectorCount) -> Self {
        let lba_val = lba.as_u64();
        let count_val = count.as_u32() as u16;

        Self {
            fis_type: FisType::RegH2D as u8,
            flags: 0x80,
            command: ATA_CMD_READ_DMA_EXT,
            device: 0x40, // LBA mode
            lba0: (lba_val & 0xFF) as u8,
            lba1: ((lba_val >> 8) & 0xFF) as u8,
            lba2: ((lba_val >> 16) & 0xFF) as u8,
            lba3: ((lba_val >> 24) & 0xFF) as u8,
            lba4: ((lba_val >> 32) & 0xFF) as u8,
            lba5: ((lba_val >> 40) & 0xFF) as u8,
            count_lo: (count_val & 0xFF) as u8,
            count_hi: ((count_val >> 8) & 0xFF) as u8,
            ..Default::default()
        }
    }

    /// ATA WRITE DMA EXTコマンド用FISを作成
    pub fn write_dma_ext(lba: Lba, count: SectorCount) -> Self {
        let lba_val = lba.as_u64();
        let count_val = count.as_u32() as u16;

        Self {
            fis_type: FisType::RegH2D as u8,
            flags: 0x80,
            command: ATA_CMD_WRITE_DMA_EXT,
            device: 0x40, // LBA mode
            lba0: (lba_val & 0xFF) as u8,
            lba1: ((lba_val >> 8) & 0xFF) as u8,
            lba2: ((lba_val >> 16) & 0xFF) as u8,
            lba3: ((lba_val >> 24) & 0xFF) as u8,
            lba4: ((lba_val >> 32) & 0xFF) as u8,
            lba5: ((lba_val >> 40) & 0xFF) as u8,
            count_lo: (count_val & 0xFF) as u8,
            count_hi: ((count_val >> 8) & 0xFF) as u8,
            ..Default::default()
        }
    }
}

/// ATAコマンド
const ATA_CMD_IDENTIFY: u8 = 0xEC;
const ATA_CMD_IDENTIFY_PACKET: u8 = 0xA1;
const ATA_CMD_READ_DMA: u8 = 0xC8;
const ATA_CMD_READ_DMA_EXT: u8 = 0x25;
const ATA_CMD_WRITE_DMA: u8 = 0xCA;
const ATA_CMD_WRITE_DMA_EXT: u8 = 0x35;
const ATA_CMD_FLUSH_CACHE: u8 = 0xE7;
const ATA_CMD_FLUSH_CACHE_EXT: u8 = 0xEA;

// ============================================================================
// Command Structures
// ============================================================================

/// Command Header (32バイト)
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default)]
pub struct CommandHeader {
    /// DW0: CFL, A, W, P, R, B, C, PMP
    pub flags: u16,
    /// Physical Region Descriptor Table Length
    pub prdtl: u16,
    /// PRD Byte Count
    pub prdbc: u32,
    /// Command Table Base Address
    pub ctba: u32,
    /// Command Table Base Address Upper
    pub ctbau: u32,
    /// Reserved
    pub reserved: [u32; 4],
}

impl CommandHeader {
    /// フラグを設定
    pub fn set_flags(&mut self, cfl: u8, write: bool, atapi: bool, prefetch: bool) {
        let mut flags = (cfl & 0x1F) as u16;
        if write {
            flags |= 1 << 6; // W bit
        }
        if atapi {
            flags |= 1 << 5; // A bit
        }
        if prefetch {
            flags |= 1 << 7; // P bit
        }
        self.flags = flags;
    }

    /// Command Table アドレスを設定
    pub fn set_ctba(&mut self, addr: u64) {
        self.ctba = addr as u32;
        self.ctbau = (addr >> 32) as u32;
    }
}

/// Physical Region Descriptor (16バイト)
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default)]
pub struct PhysicalRegionDescriptor {
    /// Data Base Address
    pub dba: u32,
    /// Data Base Address Upper
    pub dbau: u32,
    /// Reserved
    pub reserved: u32,
    /// Data Byte Count | Interrupt on Completion
    pub dbc: u32,
}

impl PhysicalRegionDescriptor {
    /// 新しいPRDを作成
    pub fn new(addr: u64, byte_count: u32, interrupt: bool) -> Self {
        let dbc = ((byte_count - 1) & 0x3FFFFF) | if interrupt { 1 << 31 } else { 0 };
        Self {
            dba: addr as u32,
            dbau: (addr >> 32) as u32,
            reserved: 0,
            dbc,
        }
    }
}

/// Command Table
#[repr(C, align(128))]
pub struct CommandTable {
    /// Command FIS (64バイト)
    pub cfis: [u8; 64],
    /// ATAPI Command (16バイト)
    pub acmd: [u8; 16],
    /// Reserved (48バイト)
    pub reserved: [u8; 48],
    /// Physical Region Descriptor Table
    pub prdt: [PhysicalRegionDescriptor; 8],
}

impl Default for CommandTable {
    fn default() -> Self {
        Self {
            cfis: [0; 64],
            acmd: [0; 16],
            reserved: [0; 48],
            prdt: [PhysicalRegionDescriptor::default(); 8],
        }
    }
}

// ============================================================================
// Received FIS Structure
// ============================================================================

/// Received FIS Structure (256バイト)
#[repr(C, align(256))]
#[derive(Clone, Copy)]
pub struct ReceivedFis {
    /// DMA Setup FIS
    pub dsfis: [u8; 28],
    pub reserved0: [u8; 4],
    /// PIO Setup FIS
    pub psfis: [u8; 20],
    pub reserved1: [u8; 12],
    /// D2H Register FIS
    pub rfis: [u8; 20],
    pub reserved2: [u8; 4],
    /// Set Device Bits FIS
    pub sdbfis: [u8; 8],
    /// Unknown FIS
    pub ufis: [u8; 64],
    pub reserved3: [u8; 96],
}

// ============================================================================
// Device Types
// ============================================================================

/// AHCIデバイスタイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceType {
    /// No device
    None,
    /// SATA drive
    Sata,
    /// SATAPI device (CD/DVD)
    Satapi,
    /// Enclosure management bridge
    Semb,
    /// Port multiplier
    PortMultiplier,
}

impl DeviceType {
    fn from_signature(sig: u32) -> Self {
        match sig {
            SATA_SIG_ATA => DeviceType::Sata,
            SATA_SIG_ATAPI => DeviceType::Satapi,
            SATA_SIG_SEMB => DeviceType::Semb,
            SATA_SIG_PM => DeviceType::PortMultiplier,
            _ => DeviceType::None,
        }
    }
}

// ============================================================================
// AHCI Error Types
// ============================================================================

/// AHCIエラー
#[derive(Debug, Clone)]
pub enum AhciError {
    /// ポートが利用不可
    PortNotAvailable,
    /// デバイスが接続されていない
    NoDevice,
    /// コマンドスロットが利用不可
    NoCommandSlot,
    /// タイムアウト
    Timeout,
    /// タスクファイルエラー
    TaskFileError(u8),
    /// DMAエラー
    DmaError,
    /// 無効なパラメータ
    InvalidParameter,
    /// その他
    Other(String),
}

pub type AhciResult<T> = Result<T, AhciError>;

// ============================================================================
// AHCI Port
// ============================================================================

/// AHCIポート
pub struct AhciPort {
    /// ポート番号
    port: PortNumber,
    /// ベースアドレス
    base: u64,
    /// ポートベースアドレス
    port_base: u64,
    /// デバイスタイプ
    device_type: DeviceType,
    /// コマンドリスト
    command_list: Box<[CommandHeader; 32]>,
    /// Received FIS
    received_fis: Box<ReceivedFis>,
    /// コマンドテーブル
    command_tables: [Option<Box<CommandTable>>; 32],
    /// アクティブなコマンド
    active_commands: AtomicU32,
}

impl AhciPort {
    /// 新しいポートを作成
    pub fn new(base: u64, port: PortNumber) -> Self {
        let port_base = base + PORT_BASE as u64 + (port.as_u8() as u64 * PORT_SIZE as u64);

        Self {
            port,
            base,
            port_base,
            device_type: DeviceType::None,
            command_list: Box::new([CommandHeader::default(); 32]),
            received_fis: Box::new(unsafe { core::mem::zeroed() }),
            command_tables: Default::default(),
            active_commands: AtomicU32::new(0),
        }
    }

    /// ポートを初期化
    pub fn init(&mut self) -> AhciResult<()> {
        // ポートを停止
        self.stop()?;

        // コマンドリストとFISのアドレスを設定
        let clb = self.command_list.as_ptr() as u64;
        let fb = self.received_fis.as_ref() as *const _ as u64;

        self.write_port(PX_CLB, clb as u32);
        self.write_port(PX_CLBU, (clb >> 32) as u32);
        self.write_port(PX_FB, fb as u32);
        self.write_port(PX_FBU, (fb >> 32) as u32);

        // SATAエラーをクリア
        self.write_port(PX_SERR, 0xFFFFFFFF);

        // 割り込みをクリア
        self.write_port(PX_IS, 0xFFFFFFFF);

        // 割り込みを有効化
        self.write_port(
            PX_IE,
            PX_IS_DHRS | PX_IS_PSS | PX_IS_DSS | PX_IS_SDBS | PX_IS_TFES,
        );

        // ポートを開始
        self.start()?;

        // デバイスシグネチャを確認
        let sig = self.read_port(PX_SIG);
        self.device_type = DeviceType::from_signature(sig);

        // log::info!("AHCI port {} initialized, device type: {:?}", self.port.as_u8(), self.device_type);

        Ok(())
    }

    /// ポートを開始
    fn start(&self) -> AhciResult<()> {
        // FIS受信を有効化
        let mut cmd = self.read_port(PX_CMD);
        cmd |= PX_CMD_FRE;
        self.write_port(PX_CMD, cmd);

        // コマンド実行を有効化
        cmd = self.read_port(PX_CMD);
        cmd |= PX_CMD_ST;
        self.write_port(PX_CMD, cmd);

        Ok(())
    }

    /// ポートを停止
    fn stop(&self) -> AhciResult<()> {
        // コマンド実行を停止
        let mut cmd = self.read_port(PX_CMD);
        cmd &= !PX_CMD_ST;
        self.write_port(PX_CMD, cmd);

        // CRビットがクリアされるまで待機
        for _ in 0..500 {
            let cmd = self.read_port(PX_CMD);
            if (cmd & PX_CMD_CR) == 0 {
                break;
            }
        }

        // FIS受信を停止
        cmd = self.read_port(PX_CMD);
        cmd &= !PX_CMD_FRE;
        self.write_port(PX_CMD, cmd);

        // FRビットがクリアされるまで待機
        for _ in 0..500 {
            let cmd = self.read_port(PX_CMD);
            if (cmd & PX_CMD_FR) == 0 {
                return Ok(());
            }
        }

        Err(AhciError::Timeout)
    }

    /// 空きコマンドスロットを見つける
    fn find_slot(&self) -> Option<SlotNumber> {
        let sact = self.read_port(PX_SACT);
        let ci = self.read_port(PX_CI);
        let busy = sact | ci;

        for i in 0..32 {
            if (busy & (1 << i)) == 0 {
                return Some(SlotNumber(i));
            }
        }

        None
    }

    /// IDENTIFYコマンドを実行
    pub fn identify(&mut self) -> AhciResult<IdentifyData> {
        let slot = self.find_slot().ok_or(AhciError::NoCommandSlot)?;

        // コマンドテーブルを準備
        let cmd_table = Box::new(CommandTable::default());
        let cmd_table_addr = cmd_table.as_ref() as *const _ as u64;

        // FISを設定
        let fis = FisRegH2D::identify();
        unsafe {
            ptr::copy_nonoverlapping(
                &fis as *const _ as *const u8,
                cmd_table.cfis.as_ptr() as *mut u8,
                core::mem::size_of::<FisRegH2D>(),
            );
        }

        // 結果バッファを用意
        let identify_buffer = Box::new([0u16; 256]);
        let buffer_addr = identify_buffer.as_ptr() as u64;

        // PRDTを設定
        unsafe {
            let prdt_ptr = cmd_table.prdt.as_ptr() as *mut PhysicalRegionDescriptor;
            *prdt_ptr = PhysicalRegionDescriptor::new(buffer_addr, 512, true);
        }

        // コマンドヘッダを設定
        let header = &mut self.command_list[slot.as_usize()];
        header.set_flags(5, false, false, false); // CFL = 5 dwords
        header.prdtl = 1;
        header.prdbc = 0;
        header.set_ctba(cmd_table_addr);

        // コマンドテーブルを保存
        self.command_tables[slot.as_usize()] = Some(cmd_table);

        // コマンドを発行
        self.write_port(PX_CI, 1 << slot.as_u8());

        // 完了を待機
        self.wait_completion(slot)?;

        // 結果を取得
        Ok(IdentifyData::from_words(&identify_buffer))
    }

    /// セクタを読み取り
    pub fn read_sectors(
        &mut self,
        lba: Lba,
        count: SectorCount,
        buffer: &mut [u8],
    ) -> AhciResult<()> {
        if buffer.len() < count.to_bytes() as usize {
            return Err(AhciError::InvalidParameter);
        }

        let slot = self.find_slot().ok_or(AhciError::NoCommandSlot)?;

        // コマンドテーブルを準備
        let mut cmd_table = Box::new(CommandTable::default());
        let cmd_table_addr = cmd_table.as_ref() as *const _ as u64;

        // FISを設定
        let fis = FisRegH2D::read_dma_ext(lba, count);
        unsafe {
            ptr::copy_nonoverlapping(
                &fis as *const _ as *const u8,
                cmd_table.cfis.as_mut_ptr(),
                core::mem::size_of::<FisRegH2D>(),
            );
        }

        // PRDTを設定
        let buffer_addr = buffer.as_ptr() as u64;
        cmd_table.prdt[0] =
            PhysicalRegionDescriptor::new(buffer_addr, count.to_bytes() as u32, true);

        // コマンドヘッダを設定
        let header = &mut self.command_list[slot.as_usize()];
        header.set_flags(5, false, false, false);
        header.prdtl = 1;
        header.prdbc = 0;
        header.set_ctba(cmd_table_addr);

        self.command_tables[slot.as_usize()] = Some(cmd_table);

        // コマンドを発行
        self.write_port(PX_CI, 1 << slot.as_u8());

        // 完了を待機
        self.wait_completion(slot)
    }

    /// セクタを書き込み
    pub fn write_sectors(&mut self, lba: Lba, count: SectorCount, buffer: &[u8]) -> AhciResult<()> {
        if buffer.len() < count.to_bytes() as usize {
            return Err(AhciError::InvalidParameter);
        }

        let slot = self.find_slot().ok_or(AhciError::NoCommandSlot)?;

        // コマンドテーブルを準備
        let mut cmd_table = Box::new(CommandTable::default());
        let cmd_table_addr = cmd_table.as_ref() as *const _ as u64;

        // FISを設定
        let fis = FisRegH2D::write_dma_ext(lba, count);
        unsafe {
            ptr::copy_nonoverlapping(
                &fis as *const _ as *const u8,
                cmd_table.cfis.as_mut_ptr(),
                core::mem::size_of::<FisRegH2D>(),
            );
        }

        // PRDTを設定
        let buffer_addr = buffer.as_ptr() as u64;
        cmd_table.prdt[0] =
            PhysicalRegionDescriptor::new(buffer_addr, count.to_bytes() as u32, true);

        // コマンドヘッダを設定
        let header = &mut self.command_list[slot.as_usize()];
        header.set_flags(5, true, false, false); // W=1 for write
        header.prdtl = 1;
        header.prdbc = 0;
        header.set_ctba(cmd_table_addr);

        self.command_tables[slot.as_usize()] = Some(cmd_table);

        // コマンドを発行
        self.write_port(PX_CI, 1 << slot.as_u8());

        // 完了を待機
        self.wait_completion(slot)
    }

    /// コマンド完了を待機
    fn wait_completion(&self, slot: SlotNumber) -> AhciResult<()> {
        let slot_mask = 1u32 << slot.as_u8();

        for _ in 0..100000 {
            let ci = self.read_port(PX_CI);
            if (ci & slot_mask) == 0 {
                // 完了
                let tfd = self.read_port(PX_TFD);
                let status = (tfd & 0xFF) as u8;
                let error = ((tfd >> 8) & 0xFF) as u8;

                if (status & 0x01) != 0 {
                    // エラーステータス
                    return Err(AhciError::TaskFileError(error));
                }

                return Ok(());
            }

            // タスクファイルエラーを確認
            let is = self.read_port(PX_IS);
            if (is & PX_IS_TFES) != 0 {
                let tfd = self.read_port(PX_TFD);
                let error = ((tfd >> 8) & 0xFF) as u8;
                return Err(AhciError::TaskFileError(error));
            }
        }

        Err(AhciError::Timeout)
    }

    /// デバイスタイプを取得
    pub fn device_type(&self) -> DeviceType {
        self.device_type
    }

    /// ポートレジスタを読み取り
    fn read_port(&self, offset: u32) -> u32 {
        unsafe { ptr::read_volatile((self.port_base + offset as u64) as *const u32) }
    }

    /// ポートレジスタを書き込み
    fn write_port(&self, offset: u32, value: u32) {
        unsafe { ptr::write_volatile((self.port_base + offset as u64) as *mut u32, value) }
    }
}

// ============================================================================
// Identify Data
// ============================================================================

/// ATA IDENTIFY データ
#[derive(Debug, Clone)]
pub struct IdentifyData {
    /// モデル名
    pub model: String,
    /// シリアル番号
    pub serial: String,
    /// ファームウェアリビジョン
    pub firmware: String,
    /// 総セクタ数（LBA48）
    pub total_sectors: u64,
    /// セクタサイズ（バイト）
    pub sector_size: u32,
    /// 48-bit LBA対応
    pub lba48_supported: bool,
    /// NCQ対応
    pub ncq_supported: bool,
    /// NCQキュー深度
    pub ncq_queue_depth: u8,
}

impl IdentifyData {
    /// ワード配列からパース
    fn from_words(words: &[u16; 256]) -> Self {
        // モデル名（ワード27-46）
        let model = Self::parse_string(&words[27..47]);
        // シリアル番号（ワード10-19）
        let serial = Self::parse_string(&words[10..20]);
        // ファームウェア（ワード23-26）
        let firmware = Self::parse_string(&words[23..27]);

        // 総セクタ数
        let total_sectors = if (words[83] & (1 << 10)) != 0 {
            // LBA48対応
            (words[100] as u64)
                | ((words[101] as u64) << 16)
                | ((words[102] as u64) << 32)
                | ((words[103] as u64) << 48)
        } else {
            // LBA28
            (words[60] as u64) | ((words[61] as u64) << 16)
        };

        // セクタサイズ
        let sector_size = if (words[106] & (1 << 12)) != 0 {
            // 論理セクタサイズが設定されている
            ((words[117] as u32) | ((words[118] as u32) << 16)) * 2
        } else {
            512
        };

        let lba48_supported = (words[83] & (1 << 10)) != 0;
        let ncq_supported = (words[76] & (1 << 8)) != 0;
        let ncq_queue_depth = if ncq_supported {
            (words[75] & 0x1F) as u8 + 1
        } else {
            0
        };

        Self {
            model,
            serial,
            firmware,
            total_sectors,
            sector_size,
            lba48_supported,
            ncq_supported,
            ncq_queue_depth,
        }
    }

    /// ATA文字列をパース（バイトスワップ）
    fn parse_string(words: &[u16]) -> String {
        let mut bytes = Vec::with_capacity(words.len() * 2);
        for &word in words {
            bytes.push((word >> 8) as u8);
            bytes.push((word & 0xFF) as u8);
        }

        // 末尾のスペースを削除
        while bytes.last() == Some(&0x20) || bytes.last() == Some(&0x00) {
            bytes.pop();
        }

        String::from_utf8_lossy(&bytes).to_string()
    }

    /// 容量を取得（バイト）
    pub fn capacity_bytes(&self) -> u64 {
        self.total_sectors * self.sector_size as u64
    }

    /// 容量を取得（GB）
    pub fn capacity_gb(&self) -> f64 {
        self.capacity_bytes() as f64 / (1024.0 * 1024.0 * 1024.0)
    }
}

// ============================================================================
// AHCI Controller
// ============================================================================

/// AHCIコントローラ
pub struct AhciController {
    /// ベースアドレス
    base: u64,
    /// 利用可能なポートのビットマップ
    ports_implemented: u32,
    /// ポート
    ports: Mutex<[Option<Box<AhciPort>>; 32]>,
    /// バージョン
    version: u32,
    /// コマンドスロット数
    command_slots: u8,
}

impl AhciController {
    /// 新しいコントローラを作成
    pub fn new(base: u64) -> AhciResult<Self> {
        let cap = unsafe { ptr::read_volatile((base + GHC_CAP as u64) as *const u32) };
        let pi = unsafe { ptr::read_volatile((base + GHC_PI as u64) as *const u32) };
        let vs = unsafe { ptr::read_volatile((base + GHC_VS as u64) as *const u32) };

        let command_slots = ((cap >> 8) & 0x1F) as u8 + 1;
        let _version_major = (vs >> 16) & 0xFFFF;
        let _version_minor = vs & 0xFFFF;

        // log::info!("AHCI version {}.{}, {} command slots, ports implemented: {:#010x}",
        //            version_major, version_minor, command_slots, pi);

        const NONE_PORT: Option<Box<AhciPort>> = None;

        Ok(Self {
            base,
            ports_implemented: pi,
            ports: Mutex::new([NONE_PORT; 32]),
            version: vs,
            command_slots,
        })
    }

    /// コントローラを初期化
    pub fn init(&mut self) -> AhciResult<()> {
        // AHCIを有効化
        let mut ghc = self.read_ghc(GHC_GHC);
        ghc |= GHC_AE;
        self.write_ghc(GHC_GHC, ghc);

        // 実装されているポートを初期化
        let mut ports = self.ports.lock();
        for i in 0..32 {
            if (self.ports_implemented & (1 << i)) != 0 {
                let port = PortNumber(i);
                let mut ahci_port = Box::new(AhciPort::new(self.base, port));

                // ポートステータスを確認
                let ssts = self.read_port_reg(port, PX_SSTS);
                let det = ssts & 0x0F;

                if det == 3 {
                    // デバイスが接続されている
                    if let Err(_e) = ahci_port.init() {
                        // log::warn!("Failed to initialize AHCI port {}: {:?}", i, e);
                    } else {
                        // log::info!("AHCI port {} initialized: {:?}", i, ahci_port.device_type());
                    }
                }

                ports[i as usize] = Some(ahci_port);
            }
        }

        // 割り込みを有効化
        ghc = self.read_ghc(GHC_GHC);
        ghc |= GHC_IE;
        self.write_ghc(GHC_GHC, ghc);

        // log::info!("AHCI controller initialized");
        Ok(())
    }

    /// ポートを取得
    pub fn port(&self, port: PortNumber) -> Option<&AhciPort> {
        if !port.is_valid() {
            return None;
        }
        if (self.ports_implemented & (1 << port.as_u8())) == 0 {
            return None;
        }

        // Note: 実際の実装では適切なライフタイム管理が必要
        None
    }

    /// GHCレジスタを読み取り
    fn read_ghc(&self, offset: u32) -> u32 {
        unsafe { ptr::read_volatile((self.base + offset as u64) as *const u32) }
    }

    /// GHCレジスタを書き込み
    fn write_ghc(&self, offset: u32, value: u32) {
        unsafe { ptr::write_volatile((self.base + offset as u64) as *mut u32, value) }
    }

    /// ポートレジスタを読み取り
    fn read_port_reg(&self, port: PortNumber, offset: u32) -> u32 {
        let addr =
            self.base + PORT_BASE as u64 + (port.as_u8() as u64 * PORT_SIZE as u64) + offset as u64;
        unsafe { ptr::read_volatile(addr as *const u32) }
    }
}

// ============================================================================
// AHCI Initialization from PCI
// ============================================================================

/// PCIデバイスからAHCIを初期化
pub fn init_from_pci(base_addr: u64) -> AhciResult<Arc<Mutex<AhciController>>> {
    let mut controller = AhciController::new(base_addr)?;
    controller.init()?;
    Ok(Arc::new(Mutex::new(controller)))
}

// Default実装
impl Default for AhciPort {
    fn default() -> Self {
        Self {
            port: PortNumber(0),
            base: 0,
            port_base: 0,
            device_type: DeviceType::None,
            command_list: Box::new([CommandHeader::default(); 32]),
            received_fis: Box::new(unsafe { core::mem::zeroed() }),
            command_tables: Default::default(),
            active_commands: AtomicU32::new(0),
        }
    }
}
