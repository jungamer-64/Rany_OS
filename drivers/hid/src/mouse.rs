// ============================================================================
// drivers/hid/src/mouse.rs - PS/2 Mouse Driver Core
// ============================================================================
//!
//! # PS/2マウスドライバコア
//!
//! PS/2マウスからの入力を処理するドライバのコア実装。
//! カーネル固有の依存を含まない純粋なデバイスロジック。
//!
//! ## 機能
//! - PS/2マウス入力 (標準3バイトパケット)
//! - マウスイベントキュー
//! - 割り込みコンテキストでの安全な処理
use alloc::collections::VecDeque;
use core::fmt;
use hal::port_io::PortU8;

// ============================================================================
// Error Types
// ============================================================================

/// マウス初期化エラー
///
/// 初期化処理中に発生しうるエラーを分類。
/// 各エラーにはリカバリーのヒントを含む。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MouseInitError {
    /// SET_DEFAULTS (0xF6) コマンドが失敗
    SetDefaultsFailed,

    /// ENABLE_DATA (0xF4) コマンドが失敗
    EnableDataFailed,

    /// IRQ12有効化が失敗
    IrqEnableFailed,

    /// タイムアウト
    Timeout,
}

impl fmt::Display for MouseInitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SetDefaultsFailed => write!(f, "mouse initialization failed"),
            Self::EnableDataFailed => write!(f, "mouse data streaming unavailable"),
            Self::IrqEnableFailed => write!(f, "mouse interrupt enable failed"),
            Self::Timeout => write!(f, "mouse not responding"),
        }
    }
}

// ============================================================================
// Constants
// ============================================================================

/// PS/2データポート
const PS2_DATA_PORT: u16 = 0x60;
/// PS/2ステータス/コマンドポート
const PS2_STATUS_PORT: u16 = 0x64;

/// コントローラコマンド
const CMD_READ_CONFIG: u8 = 0x20;
const CMD_WRITE_CONFIG: u8 = 0x60;
const CMD_ENABLE_AUX: u8 = 0xA8;
const CMD_WRITE_TO_AUX: u8 = 0xD4;

/// マウスコマンド
const MOUSE_CMD_SET_DEFAULTS: u8 = 0xF6;
const MOUSE_CMD_ENABLE_DATA: u8 = 0xF4;

/// 応答
const ACK: u8 = 0xFA;

/// イベントキューの最大サイズ
const MAX_EVENT_QUEUE_SIZE: usize = 128;

// ============================================================================
// Mouse Types (re-export from lib.rs)
// ============================================================================

pub use crate::{MouseButton, MouseEvent};

// ============================================================================
// Helper Functions
// ============================================================================

/// ステータスレジスタを読み取り、書き込み準備ができるまで待機
fn wait_for_write(status_port: &mut PortU8) {
    for _ in 0..100000 {
        let status = status_port.read();
        if status & 0x02 == 0 {
            return;
        }
        core::hint::spin_loop();
    }
}

// ============================================================================
// Mouse Driver
// ============================================================================

/// PS/2 マウスドライバ
pub struct Mouse {
    /// データポート
    data_port: PortU8,
    /// ステータスポート
    status_port: PortU8,
    /// パケットバッファ（標準PS/2マウスは3バイト）
    packet: [u8; 3],
    /// パケットインデックス
    packet_index: u8,
    /// イベントキュー
    event_queue: VecDeque<MouseEvent>,
    /// 前回のボタン状態（クリック検出用）
    prev_buttons: u8,
    /// マウスが初期化されているか
    initialized: bool,
}

impl Mouse {
    /// 新しいマウスドライバを作成
    pub const fn new() -> Self {
        Self {
            data_port: PortU8::new(PS2_DATA_PORT),
            status_port: PortU8::new(PS2_STATUS_PORT),
            packet: [0; 3],
            packet_index: 0,
            event_queue: VecDeque::new(),
            prev_buttons: 0,
            initialized: false,
        }
    }

    /// マウスの初期化
    pub fn init(&mut self) -> Result<(), MouseInitError> {
        // 1. Auxiliary Device (マウス) を有効化
        self.write_controller_command(CMD_ENABLE_AUX);

        // 2. コントローラ設定バイトを読み取り
        self.write_controller_command(CMD_READ_CONFIG);
        let mut config = self.read_data_timeout().ok_or(MouseInitError::Timeout)?;

        // IRQ12を有効化 (Bit 1)
        // マウスクロックを有効化 (Bit 5をクリア)
        config |= 0x02;
        config &= !0x20;

        // 設定を書き戻し
        self.write_controller_command(CMD_WRITE_CONFIG);
        self.write_data(config);

        // 設定が正しく書き込まれたか検証
        self.write_controller_command(CMD_READ_CONFIG);
        let actual_config = self.read_data_timeout().ok_or(MouseInitError::Timeout)?;
        if (actual_config & 0x02) == 0 {
            return Err(MouseInitError::IrqEnableFailed);
        }

        // 3. マウスをデフォルト設定にリセット
        self.write_mouse_command(MOUSE_CMD_SET_DEFAULTS)
            .map_err(|()| MouseInitError::SetDefaultsFailed)?;

        // 4. データストリーミング開始
        self.write_mouse_command(MOUSE_CMD_ENABLE_DATA)
            .map_err(|()| MouseInitError::EnableDataFailed)?;

        self.initialized = true;
        log::info!("[HID] Mouse initialized (IRQ12 enabled)\n");
        Ok(())
    }

    /// PS/2コントローラへのコマンド書き込み
    fn write_controller_command(&mut self, cmd: u8) {
        wait_for_write(&mut self.status_port);
        self.status_port.write(cmd);
    }

    /// PS/2データポートへの書き込み
    fn write_data(&mut self, data: u8) {
        wait_for_write(&mut self.status_port);
        self.data_port.write(data);
    }

    /// PS/2データポートからの読み込み（タイムアウト付き）
    fn read_data_timeout(&mut self) -> Option<u8> {
        for _ in 0..100000 {
            let status = self.status_port.read();
            if status & 0x01 != 0 {
                return Some(self.data_port.read());
            }
            core::hint::spin_loop();
        }
        None
    }

    /// マウスデバイスへのコマンド送信（0xD4経由）
    fn write_mouse_command(&mut self, cmd: u8) -> Result<u8, ()> {
        self.write_controller_command(CMD_WRITE_TO_AUX);
        self.write_data(cmd);

        if let Some(response) = self.read_data_timeout() {
            if response == ACK {
                return Ok(response);
            }
        }
        Err(())
    }

    /// マウスからのデータ（1バイト）を処理
    pub fn process_packet(&mut self, data: u8) {
        if !self.initialized {
            return;
        }

        // パケットの最初のバイトは常にBit 3が1であるべき
        if self.packet_index == 0 && (data & 0x08) == 0 {
            return;
        }

        self.packet[self.packet_index as usize] = data;
        self.packet_index += 1;

        if self.packet_index == 3 {
            self.packet_index = 0;
            self.finalize_packet();
        }
    }

    /// 受信した3バイトパケットを解析してイベント生成
    fn finalize_packet(&mut self) {
        let flags = self.packet[0];
        let x_raw = self.packet[1];
        let y_raw = self.packet[2];

        // オーバーフローチェック
        let x_overflow = (flags & 0x40) != 0;
        let y_overflow = (flags & 0x80) != 0;

        if x_overflow || y_overflow {
            return;
        }

        // 移動量の計算（9bit符号付き整数）
        let mut dx = x_raw as i16;
        let mut dy = y_raw as i16;

        // 符号拡張
        if (flags & 0x10) != 0 {
            dx |= !0xFF;
        }
        if (flags & 0x20) != 0 {
            dy |= !0xFF;
        }

        // ボタン状態
        let left = (flags & 0x01) != 0;
        let right = (flags & 0x02) != 0;
        let middle = (flags & 0x04) != 0;

        let event = MouseEvent {
            dx: dx as i32,
            dy: -(dy as i32),
            left_down: left,
            right_down: right,
            middle_down: middle,
        };

        self.prev_buttons = flags & 0x07;

        if self.event_queue.len() < MAX_EVENT_QUEUE_SIZE {
            self.event_queue.push_back(event);
        }
    }

    /// イベントを取得
    pub fn poll_event(&mut self) -> Option<MouseEvent> {
        self.event_queue.pop_front()
    }

    /// キューにイベントがあるか
    pub fn has_event(&self) -> bool {
        !self.event_queue.is_empty()
    }

    /// 初期化されているか
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }
}

impl Default for Mouse {
    fn default() -> Self {
        Self::new()
    }
}
