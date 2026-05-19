#![no_std]
// Allow common patterns in IDE driver code
#![allow(clippy::cast_possible_truncation)] // LBA byte splitting
#![allow(clippy::unreadable_literal)] // ATA addresses and constants
#![allow(clippy::must_use_candidate)] // Hardware accessor methods
#![allow(clippy::missing_const_for_fn)] // Functions use spin lock
#![allow(clippy::cast_lossless)] // u16->u32, u32->u64 for LBA calculations
#![allow(clippy::needless_range_loop)] // Index loops for buffer filling
#![allow(clippy::cast_ptr_alignment)] // u8 buffer cast to u16 for sector I/O
#![allow(clippy::ptr_as_ptr)] // Pointer casts for buffer operations
#![allow(clippy::bool_to_int_with_if)] // Drive index from DriveSel comparison
#![allow(clippy::missing_safety_doc)] // Unsafe fn docs
#![allow(clippy::missing_errors_doc)] // Error documentation for driver functions

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use hal::port_io::{PortU8, PortU16};
use spin::Mutex;

// ============================================================================
// IDE Constants
// ============================================================================

/// IDEコントローラタイプ
mod error;
pub use error::*;
mod channel;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdeController {
    Primary,
    Secondary,
}

impl IdeController {
    /// ベースI/Oポート
    pub const fn io_base(self) -> u16 {
        match self {
            Self::Primary => 0x1F0,
            Self::Secondary => 0x170,
        }
    }

    /// コントロールポート
    pub const fn control_base(self) -> u16 {
        match self {
            Self::Primary => 0x3F6,
            Self::Secondary => 0x376,
        }
    }
}

/// ドライブセレクト
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DriveSel {
    Master,
    Slave,
}

impl DriveSel {
    pub const fn value(self) -> u8 {
        match self {
            Self::Master => 0xA0,
            Self::Slave => 0xB0,
        }
    }
}

/// IDEレジスタオフセット
pub mod regs {
    pub const DATA: u16 = 0; // R/W データ
    pub const ERROR: u16 = 1; // R エラー
    pub const FEATURES: u16 = 1; // W フィーチャー
    pub const SECTOR_COUNT: u16 = 2; // R/W セクタカウント
    pub const LBA_LOW: u16 = 3; // R/W LBA[0:7]
    pub const LBA_MID: u16 = 4; // R/W LBA[8:15]
    pub const LBA_HIGH: u16 = 5; // R/W LBA[16:23]
    pub const DRIVE: u16 = 6; // R/W ドライブ/ヘッド
    pub const STATUS: u16 = 7; // R ステータス
    pub const COMMAND: u16 = 7; // W コマンド
}

/// ステータスビット
pub mod status {
    pub const ERR: u8 = 0x01; // エラー
    pub const IDX: u8 = 0x02; // インデックス
    pub const CORR: u8 = 0x04; // 訂正データ
    pub const DRQ: u8 = 0x08; // データ要求
    pub const SRV: u8 = 0x10; // サービス
    pub const DF: u8 = 0x20; // ドライブ障害
    pub const RDY: u8 = 0x40; // 準備完了
    pub const BSY: u8 = 0x80; // ビジー
}

/// ATAコマンド
pub mod commands {
    pub const IDENTIFY: u8 = 0xEC; // IDENTIFY DEVICE
    pub const IDENTIFY_PACKET: u8 = 0xA1; // IDENTIFY PACKET DEVICE
    pub const READ_SECTORS: u8 = 0x20; // READ SECTORS
    pub const READ_SECTORS_EXT: u8 = 0x24; // READ SECTORS EXT (48-bit LBA)
    pub const WRITE_SECTORS: u8 = 0x30; // WRITE SECTORS
    pub const WRITE_SECTORS_EXT: u8 = 0x34; // WRITE SECTORS EXT (48-bit LBA)
    pub const READ_DMA: u8 = 0xC8; // READ DMA
    pub const READ_DMA_EXT: u8 = 0x25; // READ DMA EXT
    pub const WRITE_DMA: u8 = 0xCA; // WRITE DMA
    pub const WRITE_DMA_EXT: u8 = 0x35; // WRITE DMA EXT
    pub const CACHE_FLUSH: u8 = 0xE7; // CACHE FLUSH
    pub const CACHE_FLUSH_EXT: u8 = 0xEA; // CACHE FLUSH EXT
    pub const PACKET: u8 = 0xA0; // PACKET (ATAPI)
    pub const SET_FEATURES: u8 = 0xEF; // SET FEATURES
}

// ============================================================================
// Device Identification
// ============================================================================

/// デバイスタイプ
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceType {
    Unknown,
    Ata,
    Atapi,
}

/// IDENTIFY DATAから取得した情報
#[derive(Clone, Debug)]
pub struct IdentifyData {
    /// デバイスタイプ
    pub device_type: DeviceType,
    /// モデル名
    pub model: String,
    /// シリアル番号
    pub serial: String,
    /// ファームウェアリビジョン
    pub firmware: String,
    /// 総セクタ数（28-bit）
    pub sectors_28: u32,
    /// 総セクタ数（48-bit）
    pub sectors_48: u64,
    /// LBA48サポート
    pub lba48_supported: bool,
    /// DMAサポート
    pub dma_supported: bool,
    /// UDMAモード
    pub udma_mode: Option<u8>,
    /// セクタサイズ
    pub sector_size: u32,
}

impl IdentifyData {
    /// 生データからパース
    pub fn from_words(words: &[u16; 256]) -> Self {
        // モデル名（ワード27-46）
        let model = Self::extract_string(words, 27, 46);
        // シリアル番号（ワード10-19）
        let serial = Self::extract_string(words, 10, 19);
        // ファームウェア（ワード23-26）
        let firmware = Self::extract_string(words, 23, 26);

        // 総セクタ数
        let sectors_28 = (words[60] as u32) | ((words[61] as u32) << 16);
        let sectors_48 = (words[100] as u64)
            | ((words[101] as u64) << 16)
            | ((words[102] as u64) << 32)
            | ((words[103] as u64) << 48);

        // 機能サポート
        let lba48_supported = (words[83] & (1 << 10)) != 0;
        let dma_supported = (words[49] & (1 << 8)) != 0;

        // UDMAモード
        let udma_mode = if words[88] != 0 {
            // 最高サポートモードを検索
            let supported = words[88] & 0x3F;
            let active = (words[88] >> 8) & 0x3F;
            if active != 0 {
                Some((active.trailing_zeros()) as u8)
            } else if supported != 0 {
                Some((supported.trailing_zeros()) as u8)
            } else {
                None
            }
        } else {
            None
        };

        // セクタサイズ
        let sector_size = if (words[106] & 0x4000) != 0 && (words[106] & 0x1000) != 0 {
            // ラージセクタ
            ((words[117] as u32) | ((words[118] as u32) << 16)) * 2
        } else {
            512
        };

        Self {
            device_type: DeviceType::Ata,
            model,
            serial,
            firmware,
            sectors_28,
            sectors_48,
            lba48_supported,
            dma_supported,
            udma_mode,
            sector_size,
        }
    }

    /// ATA文字列を抽出（バイトスワップ）
    fn extract_string(words: &[u16; 256], start: usize, end: usize) -> String {
        let mut bytes = Vec::new();
        for i in start..=end {
            bytes.push((words[i] >> 8) as u8);
            bytes.push((words[i] & 0xFF) as u8);
        }
        // 末尾スペースを削除
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while bytes.last() == Some(&b' ') {
            bytes.pop();
        }
        String::from_utf8_lossy(&bytes).into_owned()
    }

    /// 総容量（バイト）
    pub fn capacity(&self) -> u64 {
        let sectors = if self.lba48_supported && self.sectors_48 > 0 {
            self.sectors_48
        } else {
            self.sectors_28 as u64
        };
        sectors * self.sector_size as u64
    }
}

// ============================================================================
// IDE Channel
// ============================================================================

/// IDEチャネル
pub struct IdeChannel {
    /// ベースI/Oポート
    io_base: u16,
    /// コントロールポート
    control_base: u16,
    /// 接続されたデバイス
    devices: [Option<IdentifyData>; 2],
}
