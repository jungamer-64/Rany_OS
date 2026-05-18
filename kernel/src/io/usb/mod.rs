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
pub use usb_driver::driver_impl::UsbDriverWrapper;
pub use usb_driver::{
    DeviceAddress, EndpointAddress, PortNumber, PortStatus, SetupPacket, SlotId, TransferDirection,
    TransferStatus, TransferType, UsbClassDriver, UsbDevice, UsbError, UsbManager, UsbResult,
    UsbSpeed, class, descriptor, device, init, usb_manager, xhci,
};
