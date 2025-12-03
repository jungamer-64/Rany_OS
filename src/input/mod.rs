// ============================================================================
// src/input/mod.rs - Input Device Drivers (Keyboard, Mouse)
// ============================================================================
//!
//! # 入力デバイスドライバ
//!
//! PS/2キーボード、マウスのドライバ実装。
//!
//! ## 機能
//! - PS/2キーボード入力
//! - スキャンコード変換
//! - キーイベントキュー
//! - 修飾キー状態管理

#![allow(dead_code)]

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;
use x86_64::instructions::port::Port;

// ============================================================================
// Constants
// ============================================================================

/// PS/2データポート
const PS2_DATA_PORT: u16 = 0x60;
/// PS/2ステータス/コマンドポート
const PS2_STATUS_PORT: u16 = 0x64;
const PS2_COMMAND_PORT: u16 = 0x64;

/// キーボードコマンド
const KB_CMD_SET_LEDS: u8 = 0xED;
const KB_CMD_ECHO: u8 = 0xEE;
const KB_CMD_SET_SCANCODE_SET: u8 = 0xF0;
const KB_CMD_IDENTIFY: u8 = 0xF2;
const KB_CMD_SET_TYPEMATIC: u8 = 0xF3;
const KB_CMD_ENABLE_SCANNING: u8 = 0xF4;
const KB_CMD_DISABLE_SCANNING: u8 = 0xF5;
const KB_CMD_SET_DEFAULT: u8 = 0xF6;
const KB_CMD_RESET: u8 = 0xFF;

/// キーボード応答
const KB_ACK: u8 = 0xFA;
const KB_RESEND: u8 = 0xFE;
const KB_ECHO_RESPONSE: u8 = 0xEE;

// ============================================================================
// Key Codes
// ============================================================================

/// キーコード（仮想キーコード）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum KeyCode {
    // 特殊キー
    None = 0,
    Escape = 1,
    F1 = 2,
    F2 = 3,
    F3 = 4,
    F4 = 5,
    F5 = 6,
    F6 = 7,
    F7 = 8,
    F8 = 9,
    F9 = 10,
    F10 = 11,
    F11 = 12,
    F12 = 13,

    // 数字キー
    Key1 = 20,
    Key2 = 21,
    Key3 = 22,
    Key4 = 23,
    Key5 = 24,
    Key6 = 25,
    Key7 = 26,
    Key8 = 27,
    Key9 = 28,
    Key0 = 29,

    // 文字キー
    A = 30,
    B = 31,
    C = 32,
    D = 33,
    E = 34,
    F = 35,
    G = 36,
    H = 37,
    I = 38,
    J = 39,
    K = 40,
    L = 41,
    M = 42,
    N = 43,
    O = 44,
    P = 45,
    Q = 46,
    R = 47,
    S = 48,
    T = 49,
    U = 50,
    V = 51,
    W = 52,
    X = 53,
    Y = 54,
    Z = 55,

    // 記号キー
    Minus = 60,
    Equals = 61,
    LeftBracket = 62,
    RightBracket = 63,
    Backslash = 64,
    Semicolon = 65,
    Quote = 66,
    Grave = 67,
    Comma = 68,
    Period = 69,
    Slash = 70,

    // 制御キー
    Backspace = 80,
    Tab = 81,
    Enter = 82,
    Space = 83,

    // 修飾キー
    LeftShift = 90,
    RightShift = 91,
    LeftCtrl = 92,
    RightCtrl = 93,
    LeftAlt = 94,
    RightAlt = 95,
    LeftSuper = 96,
    RightSuper = 97,
    CapsLock = 98,
    NumLock = 99,
    ScrollLock = 100,

    // ナビゲーション
    Insert = 110,
    Delete = 111,
    Home = 112,
    End = 113,
    PageUp = 114,
    PageDown = 115,
    Up = 116,
    Down = 117,
    Left = 118,
    Right = 119,

    // テンキー
    Numpad0 = 130,
    Numpad1 = 131,
    Numpad2 = 132,
    Numpad3 = 133,
    Numpad4 = 134,
    Numpad5 = 135,
    Numpad6 = 136,
    Numpad7 = 137,
    Numpad8 = 138,
    Numpad9 = 139,
    NumpadPlus = 140,
    NumpadMinus = 141,
    NumpadMultiply = 142,
    NumpadDivide = 143,
    NumpadEnter = 144,
    NumpadPeriod = 145,

    // その他
    PrintScreen = 150,
    Pause = 151,
    Menu = 152,

    Unknown = 255,
}

impl KeyCode {
    /// ASCIIコードに変換（可能な場合）
    pub fn to_ascii(&self, shift: bool, caps_lock: bool) -> Option<char> {
        let shifted = shift ^ caps_lock;

        match self {
            // アルファベット
            KeyCode::A => Some(if shifted { 'A' } else { 'a' }),
            KeyCode::B => Some(if shifted { 'B' } else { 'b' }),
            KeyCode::C => Some(if shifted { 'C' } else { 'c' }),
            KeyCode::D => Some(if shifted { 'D' } else { 'd' }),
            KeyCode::E => Some(if shifted { 'E' } else { 'e' }),
            KeyCode::F => Some(if shifted { 'F' } else { 'f' }),
            KeyCode::G => Some(if shifted { 'G' } else { 'g' }),
            KeyCode::H => Some(if shifted { 'H' } else { 'h' }),
            KeyCode::I => Some(if shifted { 'I' } else { 'i' }),
            KeyCode::J => Some(if shifted { 'J' } else { 'j' }),
            KeyCode::K => Some(if shifted { 'K' } else { 'k' }),
            KeyCode::L => Some(if shifted { 'L' } else { 'l' }),
            KeyCode::M => Some(if shifted { 'M' } else { 'm' }),
            KeyCode::N => Some(if shifted { 'N' } else { 'n' }),
            KeyCode::O => Some(if shifted { 'O' } else { 'o' }),
            KeyCode::P => Some(if shifted { 'P' } else { 'p' }),
            KeyCode::Q => Some(if shifted { 'Q' } else { 'q' }),
            KeyCode::R => Some(if shifted { 'R' } else { 'r' }),
            KeyCode::S => Some(if shifted { 'S' } else { 's' }),
            KeyCode::T => Some(if shifted { 'T' } else { 't' }),
            KeyCode::U => Some(if shifted { 'U' } else { 'u' }),
            KeyCode::V => Some(if shifted { 'V' } else { 'v' }),
            KeyCode::W => Some(if shifted { 'W' } else { 'w' }),
            KeyCode::X => Some(if shifted { 'X' } else { 'x' }),
            KeyCode::Y => Some(if shifted { 'Y' } else { 'y' }),
            KeyCode::Z => Some(if shifted { 'Z' } else { 'z' }),

            // 数字と記号（USキーボードレイアウト）
            KeyCode::Key1 => Some(if shift { '!' } else { '1' }),
            KeyCode::Key2 => Some(if shift { '@' } else { '2' }),
            KeyCode::Key3 => Some(if shift { '#' } else { '3' }),
            KeyCode::Key4 => Some(if shift { '$' } else { '4' }),
            KeyCode::Key5 => Some(if shift { '%' } else { '5' }),
            KeyCode::Key6 => Some(if shift { '^' } else { '6' }),
            KeyCode::Key7 => Some(if shift { '&' } else { '7' }),
            KeyCode::Key8 => Some(if shift { '*' } else { '8' }),
            KeyCode::Key9 => Some(if shift { '(' } else { '9' }),
            KeyCode::Key0 => Some(if shift { ')' } else { '0' }),

            // 記号
            KeyCode::Minus => Some(if shift { '_' } else { '-' }),
            KeyCode::Equals => Some(if shift { '+' } else { '=' }),
            KeyCode::LeftBracket => Some(if shift { '{' } else { '[' }),
            KeyCode::RightBracket => Some(if shift { '}' } else { ']' }),
            KeyCode::Backslash => Some(if shift { '|' } else { '\\' }),
            KeyCode::Semicolon => Some(if shift { ':' } else { ';' }),
            KeyCode::Quote => Some(if shift { '"' } else { '\'' }),
            KeyCode::Grave => Some(if shift { '~' } else { '`' }),
            KeyCode::Comma => Some(if shift { '<' } else { ',' }),
            KeyCode::Period => Some(if shift { '>' } else { '.' }),
            KeyCode::Slash => Some(if shift { '?' } else { '/' }),

            // 制御キー
            KeyCode::Space => Some(' '),
            KeyCode::Enter => Some('\n'),
            KeyCode::Tab => Some('\t'),
            KeyCode::Backspace => Some('\x08'),

            // テンキー
            KeyCode::Numpad0 => Some('0'),
            KeyCode::Numpad1 => Some('1'),
            KeyCode::Numpad2 => Some('2'),
            KeyCode::Numpad3 => Some('3'),
            KeyCode::Numpad4 => Some('4'),
            KeyCode::Numpad5 => Some('5'),
            KeyCode::Numpad6 => Some('6'),
            KeyCode::Numpad7 => Some('7'),
            KeyCode::Numpad8 => Some('8'),
            KeyCode::Numpad9 => Some('9'),
            KeyCode::NumpadPlus => Some('+'),
            KeyCode::NumpadMinus => Some('-'),
            KeyCode::NumpadMultiply => Some('*'),
            KeyCode::NumpadDivide => Some('/'),
            KeyCode::NumpadPeriod => Some('.'),
            KeyCode::NumpadEnter => Some('\n'),

            _ => None,
        }
    }
}

// ============================================================================
// Key Event
// ============================================================================

/// キーの状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyState {
    /// キーが押された
    Pressed,
    /// キーが離された
    Released,
}

/// 修飾キーの状態
#[derive(Debug, Clone, Copy, Default)]
pub struct Modifiers {
    pub shift: bool,
    pub ctrl: bool,
    pub alt: bool,
    pub super_key: bool,
    pub caps_lock: bool,
    pub num_lock: bool,
    pub scroll_lock: bool,
}

impl Modifiers {
    /// いずれかの修飾キーが押されているか
    pub fn any(&self) -> bool {
        self.shift || self.ctrl || self.alt || self.super_key
    }
}

/// キーイベント
#[derive(Debug, Clone, Copy)]
pub struct KeyEvent {
    /// キーコード
    pub key: KeyCode,
    /// キーの状態
    pub state: KeyState,
    /// 修飾キーの状態
    pub modifiers: Modifiers,
    /// ASCII文字（可能な場合）
    pub char: Option<char>,
}

impl KeyEvent {
    /// 新しいキーイベントを作成
    pub fn new(key: KeyCode, state: KeyState, modifiers: Modifiers) -> Self {
        let char = if state == KeyState::Pressed {
            key.to_ascii(modifiers.shift, modifiers.caps_lock)
        } else {
            None
        };

        Self {
            key,
            state,
            modifiers,
            char,
        }
    }
}

// ============================================================================
// Scancode Translation (Set 1)
// ============================================================================

/// スキャンコードセット1からキーコードへの変換
fn scancode_to_keycode_set1(scancode: u8) -> KeyCode {
    match scancode {
        0x01 => KeyCode::Escape,
        0x02 => KeyCode::Key1,
        0x03 => KeyCode::Key2,
        0x04 => KeyCode::Key3,
        0x05 => KeyCode::Key4,
        0x06 => KeyCode::Key5,
        0x07 => KeyCode::Key6,
        0x08 => KeyCode::Key7,
        0x09 => KeyCode::Key8,
        0x0A => KeyCode::Key9,
        0x0B => KeyCode::Key0,
        0x0C => KeyCode::Minus,
        0x0D => KeyCode::Equals,
        0x0E => KeyCode::Backspace,
        0x0F => KeyCode::Tab,
        0x10 => KeyCode::Q,
        0x11 => KeyCode::W,
        0x12 => KeyCode::E,
        0x13 => KeyCode::R,
        0x14 => KeyCode::T,
        0x15 => KeyCode::Y,
        0x16 => KeyCode::U,
        0x17 => KeyCode::I,
        0x18 => KeyCode::O,
        0x19 => KeyCode::P,
        0x1A => KeyCode::LeftBracket,
        0x1B => KeyCode::RightBracket,
        0x1C => KeyCode::Enter,
        0x1D => KeyCode::LeftCtrl,
        0x1E => KeyCode::A,
        0x1F => KeyCode::S,
        0x20 => KeyCode::D,
        0x21 => KeyCode::F,
        0x22 => KeyCode::G,
        0x23 => KeyCode::H,
        0x24 => KeyCode::J,
        0x25 => KeyCode::K,
        0x26 => KeyCode::L,
        0x27 => KeyCode::Semicolon,
        0x28 => KeyCode::Quote,
        0x29 => KeyCode::Grave,
        0x2A => KeyCode::LeftShift,
        0x2B => KeyCode::Backslash,
        0x2C => KeyCode::Z,
        0x2D => KeyCode::X,
        0x2E => KeyCode::C,
        0x2F => KeyCode::V,
        0x30 => KeyCode::B,
        0x31 => KeyCode::N,
        0x32 => KeyCode::M,
        0x33 => KeyCode::Comma,
        0x34 => KeyCode::Period,
        0x35 => KeyCode::Slash,
        0x36 => KeyCode::RightShift,
        0x37 => KeyCode::NumpadMultiply,
        0x38 => KeyCode::LeftAlt,
        0x39 => KeyCode::Space,
        0x3A => KeyCode::CapsLock,
        0x3B => KeyCode::F1,
        0x3C => KeyCode::F2,
        0x3D => KeyCode::F3,
        0x3E => KeyCode::F4,
        0x3F => KeyCode::F5,
        0x40 => KeyCode::F6,
        0x41 => KeyCode::F7,
        0x42 => KeyCode::F8,
        0x43 => KeyCode::F9,
        0x44 => KeyCode::F10,
        0x45 => KeyCode::NumLock,
        0x46 => KeyCode::ScrollLock,
        0x47 => KeyCode::Numpad7,
        0x48 => KeyCode::Numpad8,
        0x49 => KeyCode::Numpad9,
        0x4A => KeyCode::NumpadMinus,
        0x4B => KeyCode::Numpad4,
        0x4C => KeyCode::Numpad5,
        0x4D => KeyCode::Numpad6,
        0x4E => KeyCode::NumpadPlus,
        0x4F => KeyCode::Numpad1,
        0x50 => KeyCode::Numpad2,
        0x51 => KeyCode::Numpad3,
        0x52 => KeyCode::Numpad0,
        0x53 => KeyCode::NumpadPeriod,
        0x57 => KeyCode::F11,
        0x58 => KeyCode::F12,
        _ => KeyCode::Unknown,
    }
}

/// 拡張スキャンコード（E0プレフィックス後）
fn extended_scancode_to_keycode(scancode: u8) -> KeyCode {
    match scancode {
        0x1C => KeyCode::NumpadEnter,
        0x1D => KeyCode::RightCtrl,
        0x35 => KeyCode::NumpadDivide,
        0x38 => KeyCode::RightAlt,
        0x47 => KeyCode::Home,
        0x48 => KeyCode::Up,
        0x49 => KeyCode::PageUp,
        0x4B => KeyCode::Left,
        0x4D => KeyCode::Right,
        0x4F => KeyCode::End,
        0x50 => KeyCode::Down,
        0x51 => KeyCode::PageDown,
        0x52 => KeyCode::Insert,
        0x53 => KeyCode::Delete,
        0x5B => KeyCode::LeftSuper,
        0x5C => KeyCode::RightSuper,
        0x5D => KeyCode::Menu,
        _ => KeyCode::Unknown,
    }
}

// ============================================================================
// Keyboard Driver
// ============================================================================

/// キーボードドライバ
pub struct Keyboard {
    /// データポート
    data_port: Port<u8>,
    /// ステータスポート
    status_port: Port<u8>,
    /// 修飾キーの状態
    modifiers: Modifiers,
    /// イベントキュー
    event_queue: VecDeque<KeyEvent>,
    /// 拡張スキャンコードフラグ
    extended: bool,
    /// リリースフラグ
    release: bool,
}

impl Keyboard {
    /// 新しいキーボードドライバを作成
    pub const fn new() -> Self {
        Self {
            data_port: Port::new(PS2_DATA_PORT),
            status_port: Port::new(PS2_STATUS_PORT),
            modifiers: Modifiers {
                shift: false,
                ctrl: false,
                alt: false,
                super_key: false,
                caps_lock: false,
                num_lock: false,
                scroll_lock: false,
            },
            event_queue: VecDeque::new(),
            extended: false,
            release: false,
        }
    }

    /// キーボードを初期化
    pub fn init(&mut self) {
        // キーボードをリセット
        self.send_command(KB_CMD_RESET);

        // スキャンを有効化
        self.send_command(KB_CMD_ENABLE_SCANNING);

        // LEDを消灯
        self.update_leds();
    }

    /// コマンドを送信
    fn send_command(&mut self, cmd: u8) {
        // キーボードの準備を待つ
        self.wait_for_write();
        unsafe {
            self.data_port.write(cmd);
        }
    }

    /// 書き込み準備を待つ
    fn wait_for_write(&mut self) {
        for _ in 0..10000 {
            let status = unsafe { self.status_port.read() };
            if status & 0x02 == 0 {
                return;
            }
            core::hint::spin_loop();
        }
    }

    /// LEDを更新
    fn update_leds(&mut self) {
        let led_state = (self.modifiers.scroll_lock as u8)
            | ((self.modifiers.num_lock as u8) << 1)
            | ((self.modifiers.caps_lock as u8) << 2);

        self.send_command(KB_CMD_SET_LEDS);
        self.wait_for_write();
        unsafe {
            self.data_port.write(led_state);
        }
    }

    /// スキャンコードを処理
    pub fn process_scancode(&mut self, scancode: u8) {
        // 拡張スキャンコードのプレフィックス
        if scancode == 0xE0 {
            self.extended = true;
            return;
        }

        // E1プレフィックス（Pauseキー用、今回はスキップ）
        if scancode == 0xE1 {
            return;
        }

        // リリースビットをチェック
        let released = scancode & 0x80 != 0;
        let scancode = scancode & 0x7F;

        // キーコードに変換
        let keycode = if self.extended {
            self.extended = false;
            extended_scancode_to_keycode(scancode)
        } else {
            scancode_to_keycode_set1(scancode)
        };

        if keycode == KeyCode::Unknown {
            return;
        }

        let state = if released {
            KeyState::Released
        } else {
            KeyState::Pressed
        };

        // 修飾キーの状態を更新
        self.update_modifiers(keycode, state);

        // イベントを作成
        let event = KeyEvent::new(keycode, state, self.modifiers);
        self.event_queue.push_back(event);
    }

    /// 修飾キーの状態を更新
    fn update_modifiers(&mut self, key: KeyCode, state: KeyState) {
        let pressed = state == KeyState::Pressed;

        match key {
            KeyCode::LeftShift | KeyCode::RightShift => {
                self.modifiers.shift = pressed;
            }
            KeyCode::LeftCtrl | KeyCode::RightCtrl => {
                self.modifiers.ctrl = pressed;
            }
            KeyCode::LeftAlt | KeyCode::RightAlt => {
                self.modifiers.alt = pressed;
            }
            KeyCode::LeftSuper | KeyCode::RightSuper => {
                self.modifiers.super_key = pressed;
            }
            KeyCode::CapsLock if pressed => {
                self.modifiers.caps_lock = !self.modifiers.caps_lock;
                self.update_leds();
            }
            KeyCode::NumLock if pressed => {
                self.modifiers.num_lock = !self.modifiers.num_lock;
                self.update_leds();
            }
            KeyCode::ScrollLock if pressed => {
                self.modifiers.scroll_lock = !self.modifiers.scroll_lock;
                self.update_leds();
            }
            _ => {}
        }
    }

    /// イベントを取得
    pub fn poll_event(&mut self) -> Option<KeyEvent> {
        self.event_queue.pop_front()
    }

    /// 文字入力を取得
    pub fn poll_char(&mut self) -> Option<char> {
        while let Some(event) = self.poll_event() {
            if event.state == KeyState::Pressed {
                if let Some(c) = event.char {
                    return Some(c);
                }
            }
        }
        None
    }

    /// 現在の修飾キーの状態を取得
    pub fn modifiers(&self) -> Modifiers {
        self.modifiers
    }

    /// キューにイベントがあるか
    pub fn has_event(&self) -> bool {
        !self.event_queue.is_empty()
    }
}

// ============================================================================
// Global State
// ============================================================================

/// グローバルキーボード
static KEYBOARD: Mutex<Keyboard> = Mutex::new(Keyboard::new());

/// キーボードを初期化
pub fn init() {
    KEYBOARD.lock().init();
    crate::log!("[INPUT] Keyboard initialized\n");
}

/// スキャンコードを処理（割り込みハンドラから呼ばれる）
pub fn handle_scancode(scancode: u8) {
    KEYBOARD.lock().process_scancode(scancode);
}

/// イベントを取得
pub fn poll_event() -> Option<KeyEvent> {
    KEYBOARD.lock().poll_event()
}

/// 文字入力を取得
pub fn poll_char() -> Option<char> {
    KEYBOARD.lock().poll_char()
}

/// イベントがあるか
pub fn has_event() -> bool {
    KEYBOARD.lock().has_event()
}

/// 修飾キーの状態を取得
pub fn modifiers() -> Modifiers {
    KEYBOARD.lock().modifiers()
}

// ============================================================================
// Mouse (stub)
// ============================================================================

/// マウスボタン
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MouseButton {
    Left,
    Right,
    Middle,
}

/// マウスイベント
#[derive(Debug, Clone, Copy)]
pub struct MouseEvent {
    pub dx: i32,
    pub dy: i32,
    pub button: Option<MouseButton>,
    pub pressed: bool,
}

// TODO: マウスドライバの実装

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keycode_to_ascii() {
        assert_eq!(KeyCode::A.to_ascii(false, false), Some('a'));
        assert_eq!(KeyCode::A.to_ascii(true, false), Some('A'));
        assert_eq!(KeyCode::A.to_ascii(false, true), Some('A'));
        assert_eq!(KeyCode::A.to_ascii(true, true), Some('a'));
    }

    #[test]
    fn test_scancode_conversion() {
        assert_eq!(scancode_to_keycode_set1(0x1E), KeyCode::A);
        assert_eq!(scancode_to_keycode_set1(0x39), KeyCode::Space);
        assert_eq!(scancode_to_keycode_set1(0x1C), KeyCode::Enter);
    }
}
