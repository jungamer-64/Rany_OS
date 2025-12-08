// ============================================================================
// src/io/usb/mod.rs - USB Subsystem
// ============================================================================
//!
//! # USBサブシステム
//!
//! USB (Universal Serial Bus) デバイスのサポート。
//! xHCI (USB 3.x) コントローラを中心とした実装。
//!
//! ## アーキテクチャ
//! - xHCI ホストコントローラドライバ
//! - USB デバイスの列挙と管理
//! - USB クラスドライバ（HID、Mass Storage等）
//!
//! ## 型安全性
//! - Newtype パターンによるスロット/エンドポイント管理
//! - 状態機械による安全な状態遷移

#![allow(dead_code)]

// Re-exports from usb_driver
pub use usb_driver::{
    UsbSpeed, DeviceAddress, SlotId, EndpointAddress, PortNumber,
    TransferType, TransferDirection, TransferStatus,
    SetupPacket, UsbError, UsbResult, PortStatus,
    descriptor, class, device, xhci,
    UsbDevice, UsbClassDriver, UsbManager,
    usb_manager, init,
};
