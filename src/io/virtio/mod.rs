// ============================================================================
// src/io/virtio/mod.rs - VirtIO Common Definitions and Core Implementation
// ============================================================================
//!
//! # VirtIO共通モジュール
//!
//! VirtIO仕様に基づく共通定義とVirtQueue実装を提供。
//! 各デバイスドライバ（block, net等）はこのモジュールの定義を使用する。
//!
//! ## モジュール構成
//! - `core`: VirtQueueの基本実装
//! - `defs`: 共通定数構造体定義
//! - `transport`: トランスポート層抽象化（MMIO/PCI）
//! - `net`: VirtIO-Netドライバ
//! - `blk`: VirtIO-Blkドライバ

#![allow(dead_code)]

pub mod core;
pub mod defs;
pub mod transport;
pub mod net;
pub mod blk;

// Re-export common types
pub use self::core::*;
pub use self::defs::*;

// Re-exports for Transport
pub use transport::{
    VirtioTransport,
    VirtioMmioTransport,
    VirtioPciTransport,
    TransportType,
    TransportError,
    TransportResult,
    VirtioDeviceInit,
};

// Re-exports for VirtIO-Net
pub use net::{
    VirtioNetDevice,
    VirtioNetHeader,
    VirtioNetStats,
    VirtioNetConfig,
    NetVirtQueue,
    VringDesc,
    init_virtio_net,
    handle_virtio_net_interrupt,
    with_virtio_net,
    features as net_features,
};

// Re-exports for VirtIO-Blk
pub use blk::{
    VirtioBlkDevice,
    VirtQueue as BlkVirtQueue,
    VringDesc as BlkVringDesc,
    AsyncBlockDevice,
    BlockDeviceConfig,
    BlockError,
    init_virtio_blk,
    handle_virtio_blk_interrupt,
    features as blk_features,
};
