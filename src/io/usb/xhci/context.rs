// ============================================================================
// src/io/usb/xhci/context.rs - xHCI Device Context Structures
// ============================================================================
//!
//! xHCI デバイスコンテキスト関連の構造体定義。
//!
//! ## コンテキスト構造
//! - SlotContext: スロット状態（デバイス接続情報）
//! - EndpointContext: エンドポイント状態（転送設定）
//! - DeviceContext: デバイス全体のコンテキスト
//! - InputContext: コマンド用の入力コンテキスト

#![allow(dead_code)]

use crate::io::usb::UsbSpeed;

// ============================================================================
// Slot Context
// ============================================================================

/// スロットコンテキスト (32バイト)
#[repr(C, align(32))]
#[derive(Clone, Copy, Debug, Default)]
pub struct SlotContext {
    /// ルートハブポート番号、速度など
    pub route_string_and_speed: u32,
    /// 最大終了レイテンシなど
    pub latency_and_ports: u32,
    /// 親ハブスロットID、TTポート番号
    pub tt_info: u32,
    /// デバイス状態、デバイスアドレス
    pub state_and_address: u32,
    /// 予約
    pub reserved: [u32; 4],
}

impl SlotContext {
    /// スロット状態を取得
    pub fn slot_state(&self) -> u8 {
        ((self.state_and_address >> 27) & 0x1F) as u8
    }

    /// デバイスアドレスを取得
    pub fn device_address(&self) -> u8 {
        (self.state_and_address & 0xFF) as u8
    }

    /// 設定
    pub fn set_context(
        &mut self,
        speed: UsbSpeed,
        route_string: u32,
        root_port: u8,
        context_entries: u8,
    ) {
        self.route_string_and_speed = (route_string & 0xFFFFF)
            | ((speed.to_slot_speed() as u32) << 20)
            | ((context_entries as u32) << 27);

        self.latency_and_ports = (root_port as u32) << 16;
    }
}

// ============================================================================
// Endpoint Context
// ============================================================================

/// エンドポイントコンテキスト (32バイト)
#[repr(C, align(32))]
#[derive(Clone, Copy, Debug, Default)]
pub struct EndpointContext {
    /// エンドポイント状態、タイプなど
    pub ep_state_and_type: u32,
    /// 最大パケットサイズ、バーストサイズなど
    pub max_packet_and_burst: u32,
    /// TRデキューポインタ
    pub tr_dequeue_ptr: u64,
    /// 平均TRB長など
    pub average_trb_length: u32,
    /// 予約
    pub reserved: [u32; 3],
}

impl EndpointContext {
    /// 設定
    pub fn set_context(
        &mut self,
        ep_type: u8,
        max_packet_size: u16,
        max_burst_size: u8,
        tr_dequeue_ptr: u64,
        interval: u8,
        error_count: u8,
    ) {
        self.ep_state_and_type =
            ((ep_type as u32) << 3) | ((error_count as u32) << 1) | ((interval as u32) << 16);

        self.max_packet_and_burst = (max_packet_size as u32) | ((max_burst_size as u32) << 8);

        // DCS (Dequeue Cycle State) = 1
        self.tr_dequeue_ptr = tr_dequeue_ptr | 1;

        self.average_trb_length = 8; // デフォルト値
    }
}

// ============================================================================
// Device Context
// ============================================================================

/// デバイスコンテキスト
#[repr(C, align(64))]
pub struct DeviceContext {
    pub slot: SlotContext,
    pub endpoints: [EndpointContext; 31],
}

// ============================================================================
// Input Context
// ============================================================================

/// 入力コンテキスト
#[repr(C, align(64))]
pub struct InputContext {
    /// 入力コントロールコンテキスト
    pub input_control: InputControlContext,
    /// スロットコンテキスト
    pub slot: SlotContext,
    /// エンドポイントコンテキスト
    pub endpoints: [EndpointContext; 31],
}

/// 入力コントロールコンテキスト
#[repr(C, align(32))]
#[derive(Clone, Copy, Debug, Default)]
pub struct InputControlContext {
    /// ドロップコンテキストフラグ
    pub drop_flags: u32,
    /// 追加コンテキストフラグ
    pub add_flags: u32,
    /// 予約
    pub reserved: [u32; 6],
}
