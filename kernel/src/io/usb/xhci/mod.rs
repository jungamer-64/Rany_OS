// ============================================================================
// src/io/usb/xhci/mod.rs - xHCI Host Controller Driver Module
// ============================================================================
//!
//! # xHCI (eXtensible Host Controller Interface) ドライバ
//!
//! USB 3.x ホストコントローラドライバ。
//!
//! ## アーキテクチャ
//! - レジスタ操作による直接制御
//! - TRB (Transfer Request Block) ベースのコマンド/転送
//! - イベントリングによる非同期完了通知
//!
//! ## メモリ構造
//! - DCBAA (Device Context Base Address Array)
//! - Transfer Ring per endpoint
//! - Command Ring
//! - Event Ring
//!
//! ## モジュール構造
//! - `trb`: TRB 定義と操作
//! - `context`: デバイスコンテキスト構造体
//! - `controller`: xHCI コントローラ
//! - `device`: USB デバイス実装
//! - `command`: コマンド発行と完了待ち (NEW)
//! - `event_handler`: イベントリング処理 (NEW)
//! - `initialization`: コントローラ初期化 (NEW)

#![allow(dead_code)]

pub mod command;
pub mod context;
pub mod controller;
pub mod device;
pub mod doorbell_manager;
pub mod event_handler;
pub mod initialization;
pub mod port_manager;
pub mod ring_manager;
pub mod trb;

use alloc::sync::Arc;

use crate::io::usb::{PortNumber, UsbResult};

// Re-exports
pub use command::{CommandApi, CommandBuilder as CmdBuilder, CommandExecutor, CommandFuture};
pub use context::{DeviceContext, EndpointContext, InputContext, InputControlContext, SlotContext};
pub use controller::XhciController;
pub use device::XhciDevice;
pub use doorbell_manager::{DoorbellBatch, DoorbellCoordinator, DoorbellTarget, StreamId, XhciDoorbellManager};
pub use event_handler::{CommandCompletionEvent, DeviceNotificationEvent, EventHandler, PortStatusChangeEvent, ProcessedEvent, TransferEvent};
pub use initialization::{XhciCapabilities, XhciInitContext};
pub use port_manager::{PortChangeEvent, PortError, PortInfo, PortLinkState, PortProtocol, PortSpeed, PortState, XhciPortManager};
pub use ring_manager::{CommandBuilder, ManagedRing, RingType, TransferBuilder, XhciRingManager};
pub use trb::{CompletionCode, ErstEntry, Trb, TrbRing, TrbType};

// ============================================================================
// xHCI Constants
// ============================================================================

/// 最大スロット数
pub const MAX_SLOTS: usize = 256;
/// 最大ポート数
pub const MAX_PORTS: usize = 256;
/// 最大エンドポイント数（スロットあたり）
pub const MAX_ENDPOINTS: usize = 31;
/// コマンドリングサイズ
pub const COMMAND_RING_SIZE: usize = 256;
/// イベントリングサイズ
pub const EVENT_RING_SIZE: usize = 256;
/// 転送リングサイズ
pub const TRANSFER_RING_SIZE: usize = 256;

// ============================================================================
// xHCI Register Offsets (Operational)
// ============================================================================

/// USB Command
pub const USBCMD: usize = 0x00;
/// USB Status
pub const USBSTS: usize = 0x04;
/// Page Size
pub const PAGESIZE: usize = 0x08;
/// Device Notification Control
pub const DNCTRL: usize = 0x14;
/// Command Ring Control
pub const CRCR: usize = 0x18;
/// Device Context Base Address Array Pointer
pub const DCBAAP: usize = 0x30;
/// Configure
pub const CONFIG: usize = 0x38;
/// Port Register Set (port 1 at offset 0x400)
pub const PORTSC_BASE: usize = 0x400;
pub const PORT_REGISTER_SIZE: usize = 0x10;

// ============================================================================
// xHCI Register Offsets (Runtime)
// ============================================================================

/// Microframe Index
pub const MFINDEX: usize = 0x00;
/// Interrupter Register Set Base
pub const IR0: usize = 0x20;
/// Interrupter Management
pub const IMAN: usize = 0x00;
/// Interrupter Moderation
pub const IMOD: usize = 0x04;
/// Event Ring Segment Table Size
pub const ERSTSZ: usize = 0x08;
/// Event Ring Segment Table Base Address
pub const ERSTBA: usize = 0x10;
/// Event Ring Dequeue Pointer
pub const ERDP: usize = 0x18;

// ============================================================================
// USBCMD Bits
// ============================================================================

pub const USBCMD_RUN: u32 = 1 << 0;
pub const USBCMD_HCRST: u32 = 1 << 1;
pub const USBCMD_INTE: u32 = 1 << 2;
pub const USBCMD_HSEE: u32 = 1 << 3;

// ============================================================================
// USBSTS Bits
// ============================================================================

pub const USBSTS_HCH: u32 = 1 << 0; // Host Controller Halted
pub const USBSTS_HSE: u32 = 1 << 2; // Host System Error
pub const USBSTS_EINT: u32 = 1 << 3; // Event Interrupt
pub const USBSTS_PCD: u32 = 1 << 4; // Port Change Detect
pub const USBSTS_CNR: u32 = 1 << 11; // Controller Not Ready

// ============================================================================
// PORTSC Bits
// ============================================================================

pub const PORTSC_CCS: u32 = 1 << 0; // Current Connect Status
pub const PORTSC_PED: u32 = 1 << 1; // Port Enabled/Disabled
pub const PORTSC_OCA: u32 = 1 << 3; // Over-current Active
pub const PORTSC_PR: u32 = 1 << 4; // Port Reset
pub const PORTSC_PP: u32 = 1 << 9; // Port Power
pub const PORTSC_CSC: u32 = 1 << 17; // Connect Status Change
pub const PORTSC_PEC: u32 = 1 << 18; // Port Enabled/Disabled Change
pub const PORTSC_WRC: u32 = 1 << 19; // Warm Port Reset Change
pub const PORTSC_PRC: u32 = 1 << 21; // Port Reset Change
pub const PORTSC_PLC: u32 = 1 << 22; // Port Link State Change
pub const PORTSC_CEC: u32 = 1 << 23; // Port Config Error Change
pub const PORTSC_CHANGE_MASK: u32 =
    PORTSC_CSC | PORTSC_PEC | PORTSC_WRC | PORTSC_PRC | PORTSC_PLC | PORTSC_CEC;

// ============================================================================
// xHCI Initialization from PCI
// ============================================================================

/// PCIデバイスからxHCIを初期化
pub fn init_from_pci(base_addr: u64) -> UsbResult<Arc<XhciController>> {
    let mut controller = XhciController::new(base_addr)?;
    controller.init()?;

    let controller = Arc::new(controller);

    // ポートをスキャン
    for port in 0..controller.port_count() {
        let status = controller.port_status(PortNumber(port));
        if status.connected {
            let _ = status.speed; // suppress unused warning
        }
    }

    Ok(controller)
}
