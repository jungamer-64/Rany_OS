// ============================================================================
// src/io/usb/class/hub/events.rs - USB Hub Events and Enumeration State
// ============================================================================
//!
//! # USB Hub イベントと列挙ステートマシン

#![allow(dead_code)]

use super::types::DeviceSpeed;

// ============================================================================
// Hub Events
// ============================================================================

/// Hub イベント
#[derive(Debug, Clone)]
pub enum HubEvent {
    /// デバイス接続
    DeviceConnected {
        port: u8,
        speed: DeviceSpeed,
    },
    /// デバイス切断
    DeviceDisconnected {
        port: u8,
    },
    /// リセット完了
    ResetComplete {
        port: u8,
        speed: DeviceSpeed,
    },
    /// 過電流
    OverCurrent {
        port: u8,
    },
    /// サスペンド
    Suspended {
        port: u8,
    },
    /// レジューム
    Resumed {
        port: u8,
    },
}

// ============================================================================
// Hub Enumeration State Machine
// ============================================================================

/// Hub 列挙状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HubEnumerationState {
    /// 初期状態
    Idle,
    /// 電源投入待ち
    WaitingPowerOn,
    /// デバイス接続待ち
    WaitingConnection,
    /// リセット中
    Resetting,
    /// リセット完了待ち
    WaitingResetComplete,
    /// アドレス設定中
    SettingAddress,
    /// 設定中
    Configuring,
    /// 完了
    Complete,
    /// エラー
    Error,
}

/// Hub 列挙ステートマシン
pub struct HubEnumerator {
    /// 現在の状態
    state: HubEnumerationState,
    /// 対象ポート
    port: u8,
    /// リトライ回数
    retry_count: u8,
    /// 最大リトライ
    max_retries: u8,
}

impl HubEnumerator {
    /// 新しいエニュメレータを作成
    pub fn new(port: u8) -> Self {
        Self {
            state: HubEnumerationState::Idle,
            port,
            retry_count: 0,
            max_retries: 3,
        }
    }
    
    /// 現在の状態を取得
    pub fn state(&self) -> HubEnumerationState {
        self.state
    }
    
    /// 次の状態に遷移
    pub fn advance(&mut self, success: bool) {
        self.state = match (self.state, success) {
            (HubEnumerationState::Idle, true) => HubEnumerationState::WaitingPowerOn,
            (HubEnumerationState::WaitingPowerOn, true) => HubEnumerationState::WaitingConnection,
            (HubEnumerationState::WaitingConnection, true) => HubEnumerationState::Resetting,
            (HubEnumerationState::Resetting, true) => HubEnumerationState::WaitingResetComplete,
            (HubEnumerationState::WaitingResetComplete, true) => HubEnumerationState::SettingAddress,
            (HubEnumerationState::SettingAddress, true) => HubEnumerationState::Configuring,
            (HubEnumerationState::Configuring, true) => HubEnumerationState::Complete,
            (_, false) => {
                self.retry_count += 1;
                if self.retry_count >= self.max_retries {
                    HubEnumerationState::Error
                } else {
                    HubEnumerationState::Resetting // リトライ
                }
            }
            (state, _) => state,
        };
    }
    
    /// 完了したか
    pub fn is_complete(&self) -> bool {
        matches!(self.state, HubEnumerationState::Complete | HubEnumerationState::Error)
    }
    
    /// 成功したか
    pub fn is_success(&self) -> bool {
        self.state == HubEnumerationState::Complete
    }
}
