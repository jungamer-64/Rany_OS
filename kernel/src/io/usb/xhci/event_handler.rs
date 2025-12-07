// ============================================================================
// src/io/usb/xhci/event_handler.rs - xHCI Event Handling
// ============================================================================
//!
//! xHCI イベントリング処理。
//!
//! ## イベントタイプ
//! - コマンド完了 (Command Completion)
//! - 転送完了 (Transfer Event)  
//! - ポート状態変更 (Port Status Change)
//! - その他 (Host Controller, Device Notification, etc.)

#![allow(dead_code)]

use alloc::vec::Vec;
use core::task::Waker;

use super::trb::{CompletionCode, Trb, TrbType};
use crate::io::usb::SlotId;

// ============================================================================
// Event Types
// ============================================================================

/// コマンド完了イベント
#[derive(Debug, Clone)]
pub struct CommandCompletionEvent {
    /// 完了したTRBのアドレス
    pub trb_address: u64,
    /// 完了コード
    pub completion_code: CompletionCode,
    /// スロットID
    pub slot_id: SlotId,
    /// パラメータ
    pub command_completion_parameter: u32,
}

/// 転送完了イベント
#[derive(Debug, Clone)]
pub struct TransferEvent {
    /// TRBポインタ
    pub trb_pointer: u64,
    /// 完了コード
    pub completion_code: CompletionCode,
    /// 転送長（残りバイト数）
    pub transfer_length: u32,
    /// スロットID
    pub slot_id: SlotId,
    /// エンドポイントID
    pub endpoint_id: u8,
    /// Event Data flag
    pub event_data: bool,
}

/// ポート状態変更イベント
#[derive(Debug, Clone)]
pub struct PortStatusChangeEvent {
    /// ポート番号 (1-based)
    pub port_id: u8,
    /// 完了コード
    pub completion_code: CompletionCode,
}

/// デバイス通知イベント
#[derive(Debug, Clone)]
pub struct DeviceNotificationEvent {
    /// 通知タイプ
    pub notification_type: u8,
    /// デバイススロットID
    pub slot_id: SlotId,
    /// 通知データ
    pub notification_data: u64,
}

/// 処理されたイベント
#[derive(Debug)]
pub enum ProcessedEvent {
    CommandCompletion(CommandCompletionEvent),
    Transfer(TransferEvent),
    PortStatusChange(PortStatusChangeEvent),
    DeviceNotification(DeviceNotificationEvent),
    HostController { completion_code: CompletionCode },
    Unknown { trb_type: u8 },
}

// ============================================================================
// Event Handler
// ============================================================================

/// イベントハンドラ
pub struct EventHandler {
    /// コマンド完了待ちリスト
    pending_commands: Vec<PendingCommand>,
    /// 転送完了コールバック
    transfer_callbacks: Vec<TransferCallback>,
    /// ポート変更コールバック
    port_change_callback: Option<fn(u8)>,
}

/// 保留中のコマンド
struct PendingCommand {
    trb_address: u64,
    waker: Option<Waker>,
    result: Option<CommandCompletionEvent>,
}

/// 転送コールバック
struct TransferCallback {
    slot_id: SlotId,
    endpoint_id: u8,
    callback: fn(TransferEvent),
}

impl EventHandler {
    /// 新しいイベントハンドラを作成
    pub fn new() -> Self {
        Self {
            pending_commands: Vec::new(),
            transfer_callbacks: Vec::new(),
            port_change_callback: None,
        }
    }

    /// コマンド完了待ちを登録
    pub fn register_command(&mut self, trb_address: u64, waker: Option<Waker>) {
        self.pending_commands.push(PendingCommand {
            trb_address,
            waker,
            result: None,
        });
    }

    /// コマンド完了を確認
    pub fn check_command_completion(&mut self, trb_address: u64) -> Option<CommandCompletionEvent> {
        if let Some(pos) = self.pending_commands.iter().position(|c| c.trb_address == trb_address) {
            if self.pending_commands[pos].result.is_some() {
                let cmd = self.pending_commands.remove(pos);
                return cmd.result;
            }
        }
        None
    }

    /// 転送コールバックを登録
    pub fn register_transfer_callback(
        &mut self,
        slot_id: SlotId,
        endpoint_id: u8,
        callback: fn(TransferEvent),
    ) {
        self.transfer_callbacks.push(TransferCallback {
            slot_id,
            endpoint_id,
            callback,
        });
    }

    /// ポート変更コールバックを設定
    pub fn set_port_change_callback(&mut self, callback: fn(u8)) {
        self.port_change_callback = Some(callback);
    }

    /// TRBからイベントをパース
    pub fn parse_event(trb: &Trb) -> ProcessedEvent {
        let trb_type = trb.trb_type();
        let completion_code = CompletionCode::from_u8(((trb.status >> 24) & 0xFF) as u8);

        match TrbType::from_u8(trb_type) {
            Some(TrbType::CommandCompletion) => {
                ProcessedEvent::CommandCompletion(CommandCompletionEvent {
                    trb_address: trb.parameter & !0xF,
                    completion_code,
                    slot_id: SlotId(((trb.control >> 24) & 0xFF) as u8),
                    command_completion_parameter: (trb.status & 0xFFFFFF),
                })
            }
            Some(TrbType::Transfer) => {
                ProcessedEvent::Transfer(TransferEvent {
                    trb_pointer: trb.parameter,
                    completion_code,
                    transfer_length: trb.status & 0xFFFFFF,
                    slot_id: SlotId(((trb.control >> 24) & 0xFF) as u8),
                    endpoint_id: ((trb.control >> 16) & 0x1F) as u8,
                    event_data: (trb.control & (1 << 2)) != 0,
                })
            }
            Some(TrbType::PortStatusChange) => {
                ProcessedEvent::PortStatusChange(PortStatusChangeEvent {
                    port_id: ((trb.parameter >> 24) & 0xFF) as u8,
                    completion_code,
                })
            }
            Some(TrbType::DeviceNotification) => {
                ProcessedEvent::DeviceNotification(DeviceNotificationEvent {
                    notification_type: ((trb.parameter >> 4) & 0xF) as u8,
                    slot_id: SlotId(((trb.control >> 24) & 0xFF) as u8),
                    notification_data: trb.parameter >> 8,
                })
            }
            Some(TrbType::HostController) => {
                ProcessedEvent::HostController { completion_code }
            }
            _ => ProcessedEvent::Unknown { trb_type },
        }
    }

    /// イベントを処理
    pub fn handle_event(&mut self, event: ProcessedEvent) {
        match event {
            ProcessedEvent::CommandCompletion(evt) => {
                self.handle_command_completion(evt);
            }
            ProcessedEvent::Transfer(evt) => {
                self.handle_transfer_completion(evt);
            }
            ProcessedEvent::PortStatusChange(evt) => {
                self.handle_port_status_change(evt);
            }
            ProcessedEvent::DeviceNotification(evt) => {
                self.handle_device_notification(evt);
            }
            ProcessedEvent::HostController { completion_code } => {
                self.handle_host_controller_event(completion_code);
            }
            ProcessedEvent::Unknown { trb_type } => {
                // 未知のイベント - ログ出力のみ
                let _ = trb_type;
            }
        }
    }

    fn handle_command_completion(&mut self, event: CommandCompletionEvent) {
        for cmd in &mut self.pending_commands {
            if cmd.trb_address == event.trb_address {
                cmd.result = Some(event.clone());
                if let Some(waker) = cmd.waker.take() {
                    waker.wake();
                }
                break;
            }
        }
    }

    fn handle_transfer_completion(&mut self, event: TransferEvent) {
        for cb in &self.transfer_callbacks {
            if cb.slot_id == event.slot_id && cb.endpoint_id == event.endpoint_id {
                (cb.callback)(event.clone());
                break;
            }
        }
    }

    fn handle_port_status_change(&mut self, event: PortStatusChangeEvent) {
        if let Some(callback) = self.port_change_callback {
            callback(event.port_id);
        }
    }

    fn handle_device_notification(&mut self, _event: DeviceNotificationEvent) {
        // デバイス通知の処理
    }

    fn handle_host_controller_event(&mut self, _completion_code: CompletionCode) {
        // ホストコントローライベントの処理
    }
}

impl Default for EventHandler {
    fn default() -> Self {
        Self::new()
    }
}
