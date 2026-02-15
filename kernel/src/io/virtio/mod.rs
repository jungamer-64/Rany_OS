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
//! - `console`: VirtIO-Consoleドライバ
//! - `input`: VirtIO-Inputドライバ
//! - `balloon`: VirtIO-Balloonドライバ

#![allow(dead_code)]

pub mod blk;
pub mod blk_driver;
pub mod net;
pub mod console;
pub mod console_driver;
pub mod input;
pub mod input_driver;
pub mod balloon;
pub mod balloon_driver;

// Re-export defs from virtio_driver crate
pub use virtio_driver::core;
pub use virtio_driver::defs;
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
    features as net_features, handle_virtio_net_interrupt, init_virtio_net,
    init_virtio_net_for_device, init_virtio_net_with_transport, with_virtio_net,
};

// Re-exports for VirtIO-Blk
pub use blk::{
    AsyncBlockDevice, BlockDeviceConfig, BlockError, VirtQueue as BlkVirtQueue, VirtioBlkDevice,
    VringDesc as BlkVringDesc, features as blk_features, handle_virtio_blk_interrupt,
    init_virtio_blk, init_virtio_blk_for_device, init_virtio_blk_with_transport,
};
pub use blk_driver::VirtioBlkDriver;

// Re-exports for VirtIO-Console
pub use console::{
    VirtioConsoleDevice, handle_virtio_console_interrupt,
    init_virtio_console, init_virtio_console_for_device, init_virtio_console_with_transport,
    get_virtio_console_device, features as console_features,
};
pub use console_driver::VirtioConsoleDriver;

// Re-exports for VirtIO-Input
pub use input::{
    VirtioInputDevice, VirtioInputEvent, handle_virtio_input_interrupt,
    init_virtio_input, init_virtio_input_for_device, init_virtio_input_with_transport,
    get_virtio_input_device,
};
pub use input_driver::VirtioInputDriver;

// Re-exports for VirtIO-Balloon
pub use balloon::{
    VirtioBalloonDevice, handle_virtio_balloon_interrupt,
    init_virtio_balloon, init_virtio_balloon_for_device, init_virtio_balloon_with_transport,
    get_virtio_balloon_device, features as balloon_features,
};
pub use balloon_driver::VirtioBalloonDriver;
