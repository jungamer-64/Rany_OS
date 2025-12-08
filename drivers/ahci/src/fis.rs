//! FIS (Frame Information Structure) 関連
//!
//! SATA通信で使用されるFIS構造体とATAコマンド定数

use super::types::{Lba, SectorCount};

// ============================================================================
// ATAコマンド
// ============================================================================

/// ATA IDENTIFY DEVICE コマンド
pub const ATA_CMD_IDENTIFY: u8 = 0xEC;
/// ATA READ DMA EXT コマンド（LBA48）
pub const ATA_CMD_READ_DMA_EXT: u8 = 0x25;
/// ATA WRITE DMA EXT コマンド（LBA48）
pub const ATA_CMD_WRITE_DMA_EXT: u8 = 0x35;
/// ATA FLUSH CACHE コマンド
pub const ATA_CMD_FLUSH_CACHE: u8 = 0xE7;
/// ATA FLUSH CACHE EXT コマンド
pub const ATA_CMD_FLUSH_CACHE_EXT: u8 = 0xEA;

// ============================================================================
// FISタイプ
// ============================================================================

/// FISタイプ
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FisType {
    /// Register Host to Device
    RegH2D = 0x27,
    /// Register Device to Host
    RegD2H = 0x34,
    /// DMA Activate
    DmaActivate = 0x39,
    /// DMA Setup
    DmaSetup = 0x41,
    /// Data
    Data = 0x46,
    /// BIST Activate
    BistActivate = 0x58,
    /// PIO Setup
    PioSetup = 0x5F,
    /// Set Device Bits
    SetDeviceBits = 0xA1,
}

// ============================================================================
// Register FIS - Host to Device
// ============================================================================

/// Register FIS - Host to Device
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct FisRegH2D {
    /// FIS type (0x27)
    pub fis_type: u8,
    /// Port multiplier + command bit (flags)
    pub flags: u8,
    /// Command register
    pub command: u8,
    /// Features register (7:0)
    pub feature_lo: u8,
    /// LBA (7:0)
    pub lba0: u8,
    /// LBA (15:8)
    pub lba1: u8,
    /// LBA (23:16)
    pub lba2: u8,
    /// Device register
    pub device: u8,
    /// LBA (31:24)
    pub lba3: u8,
    /// LBA (39:32)
    pub lba4: u8,
    /// LBA (47:40)
    pub lba5: u8,
    /// Features register (15:8)
    pub feature_hi: u8,
    /// Count (7:0)
    pub count_low: u8,
    /// Count (15:8)
    pub count_high: u8,
    /// Isochronous Command Completion
    pub icc: u8,
    /// Control register
    pub control: u8,
    /// Reserved
    pub reserved: [u8; 4],
}

impl Default for FisRegH2D {
    fn default() -> Self {
        Self {
            fis_type: FisType::RegH2D as u8,
            flags: 0,
            command: 0,
            feature_lo: 0,
            lba0: 0,
            lba1: 0,
            lba2: 0,
            device: 0,
            lba3: 0,
            lba4: 0,
            lba5: 0,
            feature_hi: 0,
            count_low: 0,
            count_high: 0,
            icc: 0,
            control: 0,
            reserved: [0; 4],
        }
    }
}

impl FisRegH2D {
    /// IDENTIFYコマンド用FISを作成
    pub fn identify() -> Self {
        Self {
            fis_type: FisType::RegH2D as u8,
            flags: 0x80, // Command bit set
            command: ATA_CMD_IDENTIFY,
            feature_lo: 0,
            lba0: 0,
            lba1: 0,
            lba2: 0,
            device: 0,
            lba3: 0,
            lba4: 0,
            lba5: 0,
            feature_hi: 0,
            count_low: 0,
            count_high: 0,
            icc: 0,
            control: 0,
            reserved: [0; 4],
        }
    }

    /// READ DMA EXT用FISを作成
    pub fn read_dma_ext(lba: Lba, count: SectorCount) -> Self {
        Self {
            fis_type: FisType::RegH2D as u8,
            flags: 0x80,
            command: ATA_CMD_READ_DMA_EXT,
            feature_lo: 0,
            lba0: lba.as_u64() as u8,
            lba1: (lba.as_u64() >> 8) as u8,
            lba2: (lba.as_u64() >> 16) as u8,
            device: 0x40, // LBA mode
            lba3: (lba.as_u64() >> 24) as u8,
            lba4: (lba.as_u64() >> 32) as u8,
            lba5: (lba.as_u64() >> 40) as u8,
            feature_hi: 0,
            count_low: count.as_u16() as u8,
            count_high: (count.as_u16() >> 8) as u8,
            icc: 0,
            control: 0,
            reserved: [0; 4],
        }
    }

    /// WRITE DMA EXT用FISを作成
    pub fn write_dma_ext(lba: Lba, count: SectorCount) -> Self {
        Self {
            fis_type: FisType::RegH2D as u8,
            flags: 0x80,
            command: ATA_CMD_WRITE_DMA_EXT,
            feature_lo: 0,
            lba0: lba.as_u64() as u8,
            lba1: (lba.as_u64() >> 8) as u8,
            lba2: (lba.as_u64() >> 16) as u8,
            device: 0x40,
            lba3: (lba.as_u64() >> 24) as u8,
            lba4: (lba.as_u64() >> 32) as u8,
            lba5: (lba.as_u64() >> 40) as u8,
            feature_hi: 0,
            count_low: count.as_u16() as u8,
            count_high: (count.as_u16() >> 8) as u8,
            icc: 0,
            control: 0,
            reserved: [0; 4],
        }
    }
}
