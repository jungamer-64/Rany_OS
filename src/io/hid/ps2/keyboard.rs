// ============================================================================
// src/io/hid/ps2/keyboard.rs - Keyboard Handler
// ============================================================================

extern crate alloc;

use alloc::collections::VecDeque;

use super::keycode::{KeyCode, KeyEvent, Modifiers};

/// キーボードハンドラ
pub struct KeyboardHandler {
    /// イベントキュー
    events: VecDeque<KeyEvent>,
    /// 修飾キー状態
    modifiers: Modifiers,
    /// E0プレフィックスフラグ
    e0_prefix: bool,
    /// E1プレフィックスフラグ
    e1_prefix: bool,
}

impl KeyboardHandler {
    /// 新しいキーボードハンドラを作成
    pub fn new() -> Self {
        Self {
            events: VecDeque::new(),
            modifiers: Modifiers::default(),
            e0_prefix: false,
            e1_prefix: false,
        }
    }

    /// スキャンコードを処理
    pub fn process_scancode(&mut self, scancode: u8) {
        // プレフィックスをチェック
        if scancode == 0xE0 {
            self.e0_prefix = true;
            return;
        }
        if scancode == 0xE1 {
            self.e1_prefix = true;
            return;
        }

        // ブレークコード（キー解放）をチェック
        let pressed = (scancode & 0x80) == 0;
        let code = scancode & 0x7F;

        let extended = self.e0_prefix;
        self.e0_prefix = false;
        self.e1_prefix = false;

        let key_code = KeyCode(code);

        // 修飾キーを更新
        self.update_modifiers(key_code, pressed, extended);

        // イベントをキューに追加
        self.events.push_back(KeyEvent {
            code: key_code,
            pressed,
            extended,
        });
    }

    /// 修飾キー状態を更新
    fn update_modifiers(&mut self, code: KeyCode, pressed: bool, extended: bool) {
        match (code, extended) {
            (KeyCode::LEFT_SHIFT, false) => self.modifiers.left_shift = pressed,
            (KeyCode::RIGHT_SHIFT, false) => self.modifiers.right_shift = pressed,
            (KeyCode::LEFT_CTRL, false) => self.modifiers.left_ctrl = pressed,
            (KeyCode::LEFT_CTRL, true) => self.modifiers.right_ctrl = pressed,
            (KeyCode::LEFT_ALT, false) => self.modifiers.left_alt = pressed,
            (KeyCode::LEFT_ALT, true) => self.modifiers.right_alt = pressed,
            (KeyCode::CAPS_LOCK, false) if pressed => {
                self.modifiers.caps_lock = !self.modifiers.caps_lock;
            }
            (KeyCode::NUM_LOCK, false) if pressed => {
                self.modifiers.num_lock = !self.modifiers.num_lock;
            }
            (KeyCode::SCROLL_LOCK, false) if pressed => {
                self.modifiers.scroll_lock = !self.modifiers.scroll_lock;
            }
            _ => {}
        }
    }

    /// イベントをポップ
    pub fn pop_event(&mut self) -> Option<KeyEvent> {
        self.events.pop_front()
    }

    /// 修飾キー状態を取得
    pub fn modifiers(&self) -> Modifiers {
        self.modifiers
    }

    /// スキャンコードを文字に変換
    pub fn scancode_to_char(&self, scancode: u8, extended: bool) -> Option<char> {
        if extended {
            return None;
        }

        let shifted = self.modifiers.shift() ^ self.modifiers.caps_lock;

        // US配列のマッピング（簡易版）
        let c = match scancode {
            0x02 => if shifted { '!' } else { '1' },
            0x03 => if shifted { '@' } else { '2' },
            0x04 => if shifted { '#' } else { '3' },
            0x05 => if shifted { '$' } else { '4' },
            0x06 => if shifted { '%' } else { '5' },
            0x07 => if shifted { '^' } else { '6' },
            0x08 => if shifted { '&' } else { '7' },
            0x09 => if shifted { '*' } else { '8' },
            0x0A => if shifted { '(' } else { '9' },
            0x0B => if shifted { ')' } else { '0' },
            0x0C => if shifted { '_' } else { '-' },
            0x0D => if shifted { '+' } else { '=' },
            0x10 => if shifted { 'Q' } else { 'q' },
            0x11 => if shifted { 'W' } else { 'w' },
            0x12 => if shifted { 'E' } else { 'e' },
            0x13 => if shifted { 'R' } else { 'r' },
            0x14 => if shifted { 'T' } else { 't' },
            0x15 => if shifted { 'Y' } else { 'y' },
            0x16 => if shifted { 'U' } else { 'u' },
            0x17 => if shifted { 'I' } else { 'i' },
            0x18 => if shifted { 'O' } else { 'o' },
            0x19 => if shifted { 'P' } else { 'p' },
            0x1A => if shifted { '{' } else { '[' },
            0x1B => if shifted { '}' } else { ']' },
            0x1E => if shifted { 'A' } else { 'a' },
            0x1F => if shifted { 'S' } else { 's' },
            0x20 => if shifted { 'D' } else { 'd' },
            0x21 => if shifted { 'F' } else { 'f' },
            0x22 => if shifted { 'G' } else { 'g' },
            0x23 => if shifted { 'H' } else { 'h' },
            0x24 => if shifted { 'J' } else { 'j' },
            0x25 => if shifted { 'K' } else { 'k' },
            0x26 => if shifted { 'L' } else { 'l' },
            0x27 => if shifted { ':' } else { ';' },
            0x28 => if shifted { '"' } else { '\'' },
            0x29 => if shifted { '~' } else { '`' },
            0x2B => if shifted { '|' } else { '\\' },
            0x2C => if shifted { 'Z' } else { 'z' },
            0x2D => if shifted { 'X' } else { 'x' },
            0x2E => if shifted { 'C' } else { 'c' },
            0x2F => if shifted { 'V' } else { 'v' },
            0x30 => if shifted { 'B' } else { 'b' },
            0x31 => if shifted { 'N' } else { 'n' },
            0x32 => if shifted { 'M' } else { 'm' },
            0x33 => if shifted { '<' } else { ',' },
            0x34 => if shifted { '>' } else { '.' },
            0x35 => if shifted { '?' } else { '/' },
            0x39 => ' ',
            0x0F => '\t',
            0x1C => '\n',
            _ => return None,
        };

        Some(c)
    }
}

impl Default for KeyboardHandler {
    fn default() -> Self {
        Self::new()
    }
}
