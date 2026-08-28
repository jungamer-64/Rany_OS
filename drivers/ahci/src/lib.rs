//! AHCI (Advanced Host Controller Interface) ドライバ
//!
//! SATAデバイスを制御するためのAHCIコントローラドライバ
//!
//! # モジュール構成
//!
//! - `types` - 型安全なID、定数、エラー型
//! - `fis` - FIS (Frame Information Structure) 関連
//! - `command` - 検証済み ATA command と lease 由来の wire encoding
//! - `identify` - ATA IDENTIFY データ構造体
//! - `port` - AHCIポート実装
//! - `controller` - AHCIコントローラ実装

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
#![allow(clippy::derivable_impls)] // Explicit Default impl for packed struct clarity
#![allow(clippy::must_use_candidate)] // Hardware accessor methods

extern crate alloc;

mod command;
pub mod fis;
pub mod identify;
pub mod types;

pub mod atapi;
pub mod controller;
pub mod port;

// 主要な型を再エクスポート
pub use command::{AtaCommand, CommandError, DmaAddressWidth, PORT_DMA_BYTES};
pub use fis::{
    ATA_CMD_FLUSH_CACHE, ATA_CMD_FLUSH_CACHE_EXT, ATA_CMD_IDENTIFY, ATA_CMD_READ_DMA_EXT,
    ATA_CMD_WRITE_DMA_EXT, FisRegH2D, FisType,
};
pub use identify::IdentifyData;
pub use types::{
    AhciError,
    AhciResult,
    DeviceType,
    // レジスタ定数
    GHC_AE,
    GHC_CAP,
    GHC_GHC,
    GHC_HR,
    GHC_IE,
    GHC_IS,
    GHC_PI,
    GHC_VS,
    Lba,
    PORT_BASE,
    PORT_SIZE,
    PX_CI,
    PX_CLB,
    PX_CLBU,
    PX_CMD,
    PX_CMD_CR,
    PX_CMD_FR,
    PX_CMD_FRE,
    PX_CMD_ST,
    PX_FB,
    PX_FBU,
    PX_IE,
    PX_IS,
    PX_IS_DHRS,
    PX_IS_DSS,
    PX_IS_PSS,
    PX_IS_SDBS,
    PX_IS_TFES,
    PX_SACT,
    PX_SCTL,
    PX_SERR,
    PX_SIG,
    PX_SSTS,
    PX_TFD,
    PortNumber,
    SECTOR_SIZE,
    SectorCount,
    SlotNumber,
};
