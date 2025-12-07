//! AHCI型定義とエラー型
//!
//! 型安全なID、定数、エラー型を定義

use alloc::string::String;

// ============================================================================
// GHC (Generic Host Control) レジスタオフセット
// ============================================================================

/// Host Capabilities
pub const GHC_CAP: u32 = 0x00;
/// Global Host Control
pub const GHC_GHC: u32 = 0x04;
/// Interrupt Status
pub const GHC_IS: u32 = 0x08;
/// Ports Implemented
pub const GHC_PI: u32 = 0x0C;
/// Version
pub const GHC_VS: u32 = 0x10;

// GHC_GHC bits
/// AHCI Enable
pub const GHC_AE: u32 = 1 << 31;
/// Interrupt Enable
pub const GHC_IE: u32 = 1 << 1;
/// HBA Reset
pub const GHC_HR: u32 = 1 << 0;

// ============================================================================
// ポートレジスタオフセット
// ============================================================================

/// Port registers base offset
pub const PORT_BASE: u32 = 0x100;
/// Size of each port register set
pub const PORT_SIZE: u32 = 0x80;

/// Command List Base Address
pub const PX_CLB: u32 = 0x00;
/// Command List Base Address Upper
pub const PX_CLBU: u32 = 0x04;
/// FIS Base Address
pub const PX_FB: u32 = 0x08;
/// FIS Base Address Upper
pub const PX_FBU: u32 = 0x0C;
/// Interrupt Status
pub const PX_IS: u32 = 0x10;
/// Interrupt Enable
pub const PX_IE: u32 = 0x14;
/// Command and Status
pub const PX_CMD: u32 = 0x18;
/// Task File Data
pub const PX_TFD: u32 = 0x20;
/// Signature
pub const PX_SIG: u32 = 0x24;
/// SATA Status
pub const PX_SSTS: u32 = 0x28;
/// SATA Control
pub const PX_SCTL: u32 = 0x2C;
/// SATA Error
pub const PX_SERR: u32 = 0x30;
/// SATA Active
pub const PX_SACT: u32 = 0x34;
/// Command Issue
pub const PX_CI: u32 = 0x38;

// PX_CMD bits
/// Start
pub const PX_CMD_ST: u32 = 1 << 0;
/// FIS Receive Enable
pub const PX_CMD_FRE: u32 = 1 << 4;
/// FIS Receive Running
pub const PX_CMD_FR: u32 = 1 << 14;
/// Command List Running
pub const PX_CMD_CR: u32 = 1 << 15;

// PX_IS bits
/// Device to Host Register FIS Interrupt
pub const PX_IS_DHRS: u32 = 1 << 0;
/// PIO Setup FIS Interrupt
pub const PX_IS_PSS: u32 = 1 << 1;
/// DMA Setup FIS Interrupt
pub const PX_IS_DSS: u32 = 1 << 2;
/// Set Device Bits Interrupt
pub const PX_IS_SDBS: u32 = 1 << 3;
/// Task File Error Status
pub const PX_IS_TFES: u32 = 1 << 30;

/// セクタサイズ（バイト）
pub const SECTOR_SIZE: usize = 512;

// ============================================================================
// 型安全なID
// ============================================================================

/// ポート番号（0-31）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PortNumber(pub u8);

impl PortNumber {
    /// ポート番号を取得
    pub fn as_u8(&self) -> u8 {
        self.0
    }

    /// usizeに変換
    pub fn as_usize(&self) -> usize {
        self.0 as usize
    }

    /// 有効なポート番号かチェック
    pub fn is_valid(&self) -> bool {
        self.0 < 32
    }
}

/// コマンドスロット番号（0-31）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlotNumber(pub u8);

impl SlotNumber {
    /// スロット番号を取得
    pub fn as_u8(&self) -> u8 {
        self.0
    }

    /// usizeに変換
    pub fn as_usize(&self) -> usize {
        self.0 as usize
    }

    /// 有効なスロット番号かチェック
    pub fn is_valid(&self) -> bool {
        self.0 < 32
    }
}

/// LBAアドレス
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lba(pub u64);

impl Lba {
    /// LBA値を取得
    pub fn as_u64(&self) -> u64 {
        self.0
    }

    /// LBA48範囲内かチェック
    pub fn is_lba48(&self) -> bool {
        self.0 >= (1 << 28)
    }

    /// 下位24ビット
    pub fn low24(&self) -> u32 {
        (self.0 & 0x00FF_FFFF) as u32
    }

    /// 上位24ビット（LBA48用）
    pub fn high24(&self) -> u32 {
        ((self.0 >> 24) & 0x00FF_FFFF) as u32
    }
}

/// セクタ数
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SectorCount(pub u16);

impl SectorCount {
    /// セクタ数を取得
    pub fn as_u16(&self) -> u16 {
        self.0
    }

    /// バイト数に変換
    pub fn to_bytes(&self) -> u32 {
        self.0 as u32 * SECTOR_SIZE as u32
    }
}

// ============================================================================
// デバイスタイプ
// ============================================================================

/// デバイスタイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceType {
    /// デバイスなし
    None,
    /// SATAデバイス
    Sata,
    /// SATAPIデバイス（CD/DVD等）
    Satapi,
    /// Enclosure Management Bridge
    Semb,
    /// Port Multiplier
    PortMultiplier,
}

impl DeviceType {
    /// シグネチャからデバイスタイプを判定
    pub fn from_signature(sig: u32) -> Self {
        match sig {
            0x00000101 => Self::Sata,
            0xEB140101 => Self::Satapi,
            0xC33C0101 => Self::Semb,
            0x96690101 => Self::PortMultiplier,
            _ => Self::None,
        }
    }

    /// SATAデバイスかどうか
    pub fn is_sata(&self) -> bool {
        matches!(self, Self::Sata | Self::Satapi)
    }
}

// ============================================================================
// エラー型
// ============================================================================

/// AHCIエラー
#[derive(Debug, Clone)]
pub enum AhciError {
    /// ポートが利用不可
    PortNotAvailable,
    /// デバイスが接続されていない
    NoDevice,
    /// 空きコマンドスロットがない
    NoCommandSlot,
    /// タイムアウト
    Timeout,
    /// タスクファイルエラー
    TaskFileError(u8),
    /// 無効なパラメータ
    InvalidParameter,
    /// メモリ割り当てエラー
    AllocationError,
    /// PCI設定エラー
    PciError(String),
    /// DMAエラー
    DmaError,
    /// その他のエラー
    Other(String),
}

/// AHCIの結果型
pub type AhciResult<T> = Result<T, AhciError>;
