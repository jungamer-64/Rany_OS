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
        let table = if shifted { &SHIFTED_MAP } else { &NORMAL_MAP };
        let idx = scancode as usize;
        if idx >= table.len() {
            return None;
        }
        let c = table[idx];
        if c == '\0' { None } else { Some(c) }
    }
}

/// JP106/109 keyboard scancode-to-character lookup table (unshifted).
static NORMAL_MAP: [char; 128] = {
    let mut m = ['\0'; 128];
    m[0x02] = '1'; m[0x03] = '2'; m[0x04] = '3'; m[0x05] = '4';
    m[0x06] = '5'; m[0x07] = '6'; m[0x08] = '7'; m[0x09] = '8';
    m[0x0A] = '9'; m[0x0B] = '0'; m[0x0C] = '-'; m[0x0D] = '^';
    m[0x0F] = '\t';
    m[0x10] = 'q'; m[0x11] = 'w'; m[0x12] = 'e'; m[0x13] = 'r';
    m[0x14] = 't'; m[0x15] = 'y'; m[0x16] = 'u'; m[0x17] = 'i';
    m[0x18] = 'o'; m[0x19] = 'p'; m[0x1A] = '@'; m[0x1B] = '[';
    m[0x1C] = '\n';
    m[0x1E] = 'a'; m[0x1F] = 's'; m[0x20] = 'd'; m[0x21] = 'f';
    m[0x22] = 'g'; m[0x23] = 'h'; m[0x24] = 'j'; m[0x25] = 'k';
    m[0x26] = 'l'; m[0x27] = ';'; m[0x28] = ':';
    m[0x2B] = ']';
    m[0x2C] = 'z'; m[0x2D] = 'x'; m[0x2E] = 'c'; m[0x2F] = 'v';
    m[0x30] = 'b'; m[0x31] = 'n'; m[0x32] = 'm';
    m[0x33] = ','; m[0x34] = '.'; m[0x35] = '/';
    m[0x39] = ' ';
    m[0x73] = '\\'; m[0x7D] = '\\';
    m
};

/// JP106/109 keyboard scancode-to-character lookup table (shifted).
static SHIFTED_MAP: [char; 128] = {
    let mut m = ['\0'; 128];
    m[0x02] = '!'; m[0x03] = '"'; m[0x04] = '#'; m[0x05] = '$';
    m[0x06] = '%'; m[0x07] = '&'; m[0x08] = '\''; m[0x09] = '(';
    m[0x0A] = ')'; m[0x0C] = '='; m[0x0D] = '~';
    m[0x0F] = '\t';
    m[0x10] = 'Q'; m[0x11] = 'W'; m[0x12] = 'E'; m[0x13] = 'R';
    m[0x14] = 'T'; m[0x15] = 'Y'; m[0x16] = 'U'; m[0x17] = 'I';
    m[0x18] = 'O'; m[0x19] = 'P'; m[0x1A] = '`'; m[0x1B] = '{';
    m[0x1C] = '\n';
    m[0x1E] = 'A'; m[0x1F] = 'S'; m[0x20] = 'D'; m[0x21] = 'F';
    m[0x22] = 'G'; m[0x23] = 'H'; m[0x24] = 'J'; m[0x25] = 'K';
    m[0x26] = 'L'; m[0x27] = '+'; m[0x28] = '*';
    m[0x2B] = '}';
    m[0x2C] = 'Z'; m[0x2D] = 'X'; m[0x2E] = 'C'; m[0x2F] = 'V';
    m[0x30] = 'B'; m[0x31] = 'N'; m[0x32] = 'M';
    m[0x33] = '<'; m[0x34] = '>'; m[0x35] = '?';
    m[0x39] = ' ';
    m[0x73] = '_'; m[0x7D] = '|';
    m
};

impl Default for KeyboardHandler {
    fn default() -> Self {
        Self::new()
    }
}
