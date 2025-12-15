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

pub mod blk;
pub mod net;

// Re-export defs from virtio_driver crate
pub use virtio_driver::defs;
pub use virtio_driver::core;
pub use virtio_driver::transport;

// Re-export common types
pub use virtio_driver::core::*;
pub use virtio_driver::defs::*;

// Re-exports for Transport
pub use virtio_driver::transport::{
    TransportError, TransportResult, TransportType, VirtioDeviceInit, VirtioMmioTransport,
    VirtioPciTransport, VirtioTransport,
};

// Re-exports for VirtIO-Net
pub use net::{
    NetVirtQueue, VirtioNetConfig, VirtioNetDevice, VirtioNetHeader, VirtioNetStats, VringDesc,
    features as net_features, handle_virtio_net_interrupt, init_virtio_net, with_virtio_net,
};

// Re-exports for VirtIO-Blk
pub use blk::{
    AsyncBlockDevice, BlockDeviceConfig, BlockError, VirtQueue as BlkVirtQueue, VirtioBlkDevice,
    VringDesc as BlkVringDesc, features as blk_features, handle_virtio_blk_interrupt,
    init_virtio_blk,
};
