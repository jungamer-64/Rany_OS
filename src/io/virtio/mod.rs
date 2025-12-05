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
//! - `net_async`: 非同期VirtIO-Netドライバ

#![allow(dead_code)]

pub mod core;
pub mod defs;
pub mod net_async;

// Re-export common types
pub use self::core::*;
pub use self::defs::*;

// Re-exports for async VirtIO-Net
pub use net_async::{
    VirtioNet,
    VirtioNetConfig,
    VirtioNetStats,
    VirtioSharedState,
    init_virtio_net,
    virtio_net_interrupt_handler,
    async_receive_packet,
    async_send_packet,
    async_send_data,
    Virtqueue as AsyncVirtqueue,
    VirtqDesc,
    VirtqAvail,
    VirtqUsed,
    VirtqUsedElem,
    features as net_features,
};
