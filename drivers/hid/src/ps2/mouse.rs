// ============================================================================
// src/io/hid/ps2/mouse.rs - Mouse Handler
// ============================================================================

extern crate alloc;

use alloc::collections::VecDeque;

use super::mouse_types::MouseEvent;

/// マウスハンドラ
pub struct MouseHandler {
    /// イベントキュー
    events: VecDeque<MouseEvent>,
    /// パケットバッファ
    packet: [u8; 4],
    /// パケットインデックス
    packet_index: usize,
    /// パケットサイズ（3または4）
    packet_size: usize,
    /// 現在のボタン状態
    buttons: u8,
    /// 現在のX座標
    #[allow(dead_code)]
    x: i32,
    /// 現在のY座標
    #[allow(dead_code)]
    y: i32,
}

impl MouseHandler {
    /// 新しいマウスハンドラを作成
    pub fn new(has_wheel: bool) -> Self {
        Self {
            events: VecDeque::new(),
            packet: [0; 4],
            packet_index: 0,
            packet_size: if has_wheel { 4 } else { 3 },
            buttons: 0,
            x: 0,
            y: 0,
        }
    }

    /// バイトを処理
    pub fn process_byte(&mut self, byte: u8) {
        // 同期チェック（最初のバイトはビット3が常に1）
        if self.packet_index == 0 && (byte & 0x08) == 0 {
            return;
        }

        self.packet[self.packet_index] = byte;
        self.packet_index += 1;

        if self.packet_index >= self.packet_size {
            self.process_packet();
            self.packet_index = 0;
        }
    }

    /// パケットを処理
    fn process_packet(&mut self) {
        let flags = self.packet[0];
        let mut dx = self.packet[1] as i16;
        let mut dy = self.packet[2] as i16;

        // 符号拡張
        if (flags & 0x10) != 0 {
            dx -= 256;
        }
        if (flags & 0x20) != 0 {
            dy -= 256;
        }

        // Y軸を反転（PS/2マウスは上が正）
        dy = -dy;

        // ホイール（4バイトパケットの場合）
        let wheel = if self.packet_size == 4 {
            let w = self.packet[3] as i8;
            if w > 7 { 0 } else { w }
        } else {
            0
        };

        // ボタン状態
        let buttons = flags & 0x07;

        // イベントを生成
        self.events.push_back(MouseEvent {
            dx,
            dy,
            wheel,
            buttons,
        });

        // 位置を更新
        self.buttons = buttons;
    }

    /// イベントをポップ
    pub fn pop_event(&mut self) -> Option<MouseEvent> {
        self.events.pop_front()
    }

    /// 現在のボタン状態を取得
    #[allow(dead_code)]
    pub fn buttons(&self) -> u8 {
        self.buttons
    }
}
