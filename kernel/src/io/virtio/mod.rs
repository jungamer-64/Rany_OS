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
//!
//! ## VirtIO-Net IoScheduler opt-in
//! - 公式入口は `io::virtio::register_virtio_net_with_io_scheduler(index)`。
//! - `system_impl` からは自動登録しないため、利用時は明示的に opt-in する。
//! - 送受信は `IoCommand::Ioctl` + `VIRTIO_NET_IOCTL_TX/RX` を使用する。

#![allow(dead_code)]

pub mod blk;
pub mod blk_driver;
pub mod blk_scheduler;
pub mod net;

pub mod virtqueue;
pub use virtqueue::*;

pub mod balloon;
pub mod balloon_driver;
pub mod console;
pub mod console_driver;
pub mod dma;
pub mod input;
pub mod input_driver;

// Re-export common types from virtio_driver, but exclude conflicting ring/desc definitions
// which are now unified in our local virtqueue.rs
pub use virtio_driver::defs::{VirtioDeviceStatus, VirtioDeviceType, status};
pub mod defs {
    pub use super::virtqueue::{VringAvail, VringDesc, VringUsed};
    pub use virtio_driver::defs::*;
}

pub mod transport {
    pub use virtio_driver::transport::*;
}

// Re-exports for Transport
pub use virtio_driver::transport::{
    TransportError, TransportResult, TransportType, VirtioDeviceInit, VirtioMmioTransport,
    VirtioPciTransport, VirtioTransport,
};

// Re-exports for VirtIO-Net
#[cfg(test)]
pub use net::init_virtio_net_at_index;
pub use net::{
    NetVirtQueue, VIRTIO_NET_IOCTL_RX, VIRTIO_NET_IOCTL_TX, VirtioNetConfig, VirtioNetDevice,
    VirtioNetHeader, VirtioNetOps, VirtioNetStats, features as net_features, for_each_virtio_net,
    get_poll_handler, init_virtio_net_for_device_at_index, init_virtio_net_with_transport_at_index,
    register_virtio_net_with_io_scheduler, virtio_net_driver_adapter, with_virtio_net_at_index,
};
pub use virtqueue::{VringAvail, VringDesc, VringUsed};

// Re-exports for VirtIO-Blk
#[cfg(test)]
pub use blk::init_virtio_blk_at_index;
pub use blk::{
    AsyncBlockDevice, BlockError, VirtioBlkConfig, VirtioBlkDevice, features as blk_features,
    get_virtio_blk_device_at_index, handle_virtio_blk_interrupt_for_index,
    init_virtio_blk_for_device_at_index, init_virtio_blk_with_transport_at_index,
};
pub use blk_driver::VirtioBlkDriver;

// Re-exports for VirtIO-Blk IoScheduler Integration
pub use blk_scheduler::{
    VirtioBlkOps, VirtioBlkPollHandler, register_virtio_blk_with_io_scheduler,
};

// Re-exports for VirtIO-Console
#[cfg(test)]
pub use console::init_virtio_console_at_index;
pub use console::{
    VirtioConsoleDevice, features as console_features, get_virtio_console_device_at_index,
    handle_virtio_console_interrupt_for_index, init_virtio_console_for_device_at_index,
    init_virtio_console_with_transport_at_index,
};
pub use console_driver::VirtioConsoleDriver;

// Re-exports for VirtIO-Input
#[cfg(test)]
pub use input::init_virtio_input_at_index;
pub use input::{
    VirtioInputDevice, VirtioInputEvent, get_virtio_input_device_at_index,
    handle_virtio_input_interrupt_for_index, init_virtio_input_for_device_at_index,
    init_virtio_input_with_transport_at_index,
};
pub use input_driver::VirtioInputDriver;

// Re-exports for VirtIO-Balloon
#[cfg(test)]
pub use balloon::init_virtio_balloon_at_index;
pub use balloon::{
    VirtioBalloonDevice, features as balloon_features, get_virtio_balloon_device_at_index,
    handle_virtio_balloon_interrupt_for_index, init_virtio_balloon_for_device_at_index,
    init_virtio_balloon_with_transport_at_index,
};
pub use balloon_driver::VirtioBalloonDriver;
