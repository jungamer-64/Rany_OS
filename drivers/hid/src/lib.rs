// ============================================================================
// drivers/hid/src/lib.rs - Human Interface Device Driver
// ============================================================================
//!
//! # HID Driver
//!
//! Human Interface Device support (keyboard, mouse, etc.)
//!
//! ## Architecture
//! - Keyboard scan code to key event translation
//! - Mouse event handling
//! - PS/2 and USB HID support
//!
//! This crate provides the core HID implementation that is platform-independent.
//! Kernel-specific wrappers (global instances, interrupt handlers) remain in the kernel.

#![no_std]
#![allow(dead_code)]

extern crate alloc;

pub mod driver;
pub mod ffi;
pub mod keyboard;
pub mod keymap;
pub mod mouse;
pub mod ps2;
pub mod queue;
pub mod stream;

// Re-export driver for kernel use
pub use driver::KeyboardDriver;

// Re-export stream/future helpers for kernel use
pub use stream::{
    CharFuture, CharFutureArc, DriverOps, KeyEventFuture, KeyboardStream, KeyboardStreamArc,
    DEFAULT_POLL_BUDGET,
};

use alloc::string::String;

// ============================================================================
// Key Codes
// ============================================================================

/// スキャンコードセット1のキーコード
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum KeyCode {
    // ファンクションキー
    Escape = 0x01,
    F1 = 0x3B,
    F2 = 0x3C,
    F3 = 0x3D,
    F4 = 0x3E,
    F5 = 0x3F,
    F6 = 0x40,
    F7 = 0x41,
    F8 = 0x42,
    F9 = 0x43,
    F10 = 0x44,
    F11 = 0x57,
    F12 = 0x58,

    // 数字キー
    Key1 = 0x02,
    Key2 = 0x03,
    Key3 = 0x04,
    Key4 = 0x05,
    Key5 = 0x06,
    Key6 = 0x07,
    Key7 = 0x08,
    Key8 = 0x09,
    Key9 = 0x0A,
    Key0 = 0x0B,

    // 記号キー
    Minus = 0x0C,
    Equals = 0x0D,
    Backspace = 0x0E,
    Tab = 0x0F,

    // 文字キー（QWERTY配列）
    Q = 0x10,
    W = 0x11,
    E = 0x12,
    R = 0x13,
    T = 0x14,
    Y = 0x15,
    U = 0x16,
    I = 0x17,
    O = 0x18,
    P = 0x19,
    LeftBracket = 0x1A,
    RightBracket = 0x1B,
    Enter = 0x1C,
    LeftCtrl = 0x1D,
    A = 0x1E,
    S = 0x1F,
    D = 0x20,
    F = 0x21,
    G = 0x22,
    H = 0x23,
    J = 0x24,
    K = 0x25,
    L = 0x26,
    Semicolon = 0x27,
    Quote = 0x28,
    BackTick = 0x29,
    LeftShift = 0x2A,
    Backslash = 0x2B,
    Z = 0x2C,
    X = 0x2D,
    C = 0x2E,
    V = 0x2F,
    B = 0x30,
    N = 0x31,
    M = 0x32,
    Comma = 0x33,
    Period = 0x34,
    Slash = 0x35,
    RightShift = 0x36,

    // その他
    LeftAlt = 0x38,
    Space = 0x39,
    CapsLock = 0x3A,
    NumLock = 0x45,
    ScrollLock = 0x46,

    // 矢印キー（拡張スキャンコード）
    Up = 0x48,
    Down = 0x50,
    Left = 0x4B,
    Right = 0x4D,

    // ナビゲーションキー（拡張スキャンコード）
    Insert = 0x52,
    Delete = 0x53,
    Home = 0x47,
    End = 0x4F,
    PageUp = 0x49,
    PageDown = 0x51,

    // テンキー (Phase 5)
    // 注意: テンキーはナビゲーションキーと同じスキャンコードを持つため、
    // 内部的に異なる値を使用し、from_scancode()で適切に変換する
    // 0xC0-0xCF の範囲を使用（PS/2では未使用）
    NumPad0 = 0xC0,       // NumLockオンで '0', オフで Insert (実際は0x52)
    NumPad1 = 0xC1,       // NumLockオンで '1', オフで End (実際は0x4F)
    NumPad2 = 0xC2,       // NumLockオンで '2', オフで Down (実際は0x50)
    NumPad3 = 0xC3,       // NumLockオンで '3', オフで PageDown (実際は0x51)
    NumPad4 = 0xC4,       // NumLockオンで '4', オフで Left (実際は0x4B)
    NumPad5 = 0xC5,       // NumLockオンで '5', オフで (nothing) (実際は0x4C)
    NumPad6 = 0xC6,       // NumLockオンで '6', オフで Right (実際は0x4D)
    NumPad7 = 0xC7,       // NumLockオンで '7', オフで Home (実際は0x47)
    NumPad8 = 0xC8,       // NumLockオンで '8', オフで Up (実際は0x48)
    NumPad9 = 0xC9,       // NumLockオンで '9', オフで PageUp (実際は0x49)
    NumPadDecimal = 0xCA, // NumLockオンで '.', オフで Delete (実際は0x53)
    NumPadEnter = 0x9C,   // 拡張コード (E0 1C)
    NumPadPlus = 0x4E,
    NumPadMinus = 0x4A,
    NumPadMultiply = 0x37,
    NumPadDivide = 0xB5, // 拡張コード (E0 35)

    // 不明
    Unknown = 0xFF,
}

// ============================================================================
// Key Event Types
// ============================================================================

/// キーイベントの種類
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
    pub alt_gr: bool, // Right Alt (AltGr for European layouts)
    pub caps_lock: bool,
    pub num_lock: bool,
    pub scroll_lock: bool,
}

impl Modifiers {
    /// 任意の修飾キーが押されているか
    pub fn any(&self) -> bool {
        self.shift || self.ctrl || self.alt || self.alt_gr
    }

    /// Ctrlキーのみが押されているか（Ctrl+系ショートカット判定用）
    pub fn ctrl_only(&self) -> bool {
        self.ctrl && !self.shift && !self.alt && !self.alt_gr
    }

    /// AltGrキーが押されているか（欧州圏レイアウト用）
    pub fn has_altgr(&self) -> bool {
        self.alt_gr
    }
}

/// キーイベント
#[derive(Debug, Clone, Copy)]
pub struct KeyEvent {
    /// キーコード
    pub key: KeyCode,
    /// 押下/解放状態
    pub state: KeyState,
    /// 修飾キーの状態
    pub modifiers: Modifiers,
    /// 生スキャンコード（デバッグ用）
    ///
    /// bit 0-7: スキャンコード
    /// bit 8: 拡張フラグ (0xE0 prefix)
    ///
    /// `KeyCode::Unknown`の場合に特に有用。
    pub raw_scancode: u16,
}

impl KeyEvent {
    /// 修飾キーの状態を取得（後方互換性のためのアクセサ）
    pub fn modifiers(&self) -> Modifiers {
        self.modifiers
    }

    /// 後方互換性のためのアクセサ
    pub fn shift(&self) -> bool {
        self.modifiers.shift
    }
    pub fn ctrl(&self) -> bool {
        self.modifiers.ctrl
    }
    pub fn alt(&self) -> bool {
        self.modifiers.alt
    }
    pub fn caps_lock(&self) -> bool {
        self.modifiers.caps_lock
    }
}

// ============================================================================
// Mouse Types
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
    /// X方向の移動量
    pub dx: i32,
    /// Y方向の移動量
    pub dy: i32,
    /// 左ボタンが押されているか
    pub left_down: bool,
    /// 右ボタンが押されているか
    pub right_down: bool,
    /// 中ボタンが押されているか
    pub middle_down: bool,
}

impl MouseEvent {
    /// いずれかのボタンが押されているか
    pub fn any_button(&self) -> bool {
        self.left_down || self.right_down || self.middle_down
    }

    /// 移動があるか
    pub fn has_movement(&self) -> bool {
        self.dx != 0 || self.dy != 0
    }
}

// ============================================================================
// HID Error
// ============================================================================

#[derive(Debug, Clone)]
pub enum HidError {
    DeviceNotFound,
    Timeout,
    InvalidData,
    Other(String),
}

pub type HidResult<T> = Result<T, HidError>;

// ============================================================================
// Keymap Re-exports
// ============================================================================
pub use keymap::{
    ctrl_char_map, DvorakKeymap, JisKeymap, Keymap, UsQwertyKeymap, DEFAULT_KEYMAP, DVORAK_KEYMAP,
    JIS_KEYMAP,
};

// Keyboard helpers - use `hid_driver::keyboard::*` for full access
pub use keyboard::StreamAlreadyTaken;

#[cfg(feature = "qemu-test-export")]
pub mod qemu_tests {
    use crate::keymap::{DvorakKeymap, Keymap, UsQwertyKeymap};
    use crate::queue::{ScancodeQueue, DEFAULT_QUEUE_SIZE};
    use crate::{KeyCode, Modifiers};

    pub fn keymap_smoke() -> bool {
        let keymap = UsQwertyKeymap;
        let mut mods = Modifiers::default();
        if keymap.to_char(KeyCode::A, &mods) != Some('a') {
            return false;
        }
        mods.shift = true;
        keymap.to_char(KeyCode::A, &mods) == Some('A')
    }

    pub fn keymap_ctrl_smoke() -> bool {
        let keymap = UsQwertyKeymap;
        let mods = Modifiers {
            ctrl: true,
            ..Default::default()
        };
        keymap.to_char(KeyCode::C, &mods) == Some('\x03')
            && keymap.to_char(KeyCode::Z, &mods) == Some('\x1A')
    }

    pub fn dvorak_smoke() -> bool {
        let keymap = DvorakKeymap;
        let mods = Modifiers::default();
        keymap.to_char(KeyCode::S, &mods) == Some('o')
            && keymap.to_char(KeyCode::Q, &mods) == Some('\'')
    }

    pub fn queue_basic_smoke() -> bool {
        let queue = ScancodeQueue::new();
        if !queue.is_empty() {
            return false;
        }
        if !queue.push(0x1E) {
            return false;
        }
        if queue.is_empty() {
            return false;
        }
        queue.pop() == Some(0x1E) && queue.is_empty()
    }

    pub fn queue_full_smoke() -> bool {
        let queue = ScancodeQueue::new();
        for i in 0..(DEFAULT_QUEUE_SIZE - 1) {
            if !queue.push(i as u16) {
                return false;
            }
        }
        if queue.push(0xFFFF) {
            return false;
        }
        for i in 0..(DEFAULT_QUEUE_SIZE - 1) {
            if queue.pop() != Some(i as u16) {
                return false;
            }
        }
        queue.is_empty() && queue.pop().is_none()
    }

    pub fn queue_wraparound_smoke() -> bool {
        let queue = ScancodeQueue::new();

        for i in 0..10u16 {
            if !queue.push(i) || queue.pop() != Some(i) {
                return false;
            }
        }

        for i in 0..(DEFAULT_QUEUE_SIZE - 1) {
            if !queue.push(i as u16) {
                return false;
            }
        }

        for i in 0..(DEFAULT_QUEUE_SIZE - 1) {
            if queue.pop() != Some(i as u16) {
                return false;
            }
        }

        true
    }

    pub fn stream_char_future_smoke() -> bool {
        crate::stream::qemu_tests::char_future_ready_smoke()
    }

    // =========================================================================
    // driver.rs smoke tests
    // =========================================================================

    pub fn driver_new_smoke() -> bool {
        let driver = crate::driver::KeyboardDriver::new();
        !driver.has_event() && driver.dropped_events() == 0
    }

    pub fn driver_handle_scancode_smoke() -> bool {
        use crate::stream::DriverOps;
        let driver = crate::driver::KeyboardDriver::new();
        driver.handle_scancode(0x1E);
        if !driver.has_event() {
            return false;
        }
        match driver.poll_key_event_internal() {
            Some(event) => {
                event.key == crate::KeyCode::A && event.state == crate::KeyState::Pressed
            }
            None => false,
        }
    }

    pub fn driver_extended_scancode_smoke() -> bool {
        use crate::stream::DriverOps;
        let driver = crate::driver::KeyboardDriver::new();
        driver.handle_scancode(0xE0);
        driver.handle_scancode(0x48);
        if !driver.has_event() {
            return false;
        }
        match driver.poll_key_event_internal() {
            Some(event) => event.key == crate::KeyCode::Up,
            None => false,
        }
    }

    pub fn driver_key_release_smoke() -> bool {
        use crate::stream::DriverOps;
        let driver = crate::driver::KeyboardDriver::new();
        driver.handle_scancode(0x9E);
        match driver.poll_key_event_internal() {
            Some(event) => {
                event.key == crate::KeyCode::A && event.state == crate::KeyState::Released
            }
            None => false,
        }
    }

    // =========================================================================
    // keyboard.rs smoke tests
    // =========================================================================

    pub fn from_scancode_basic_smoke() -> bool {
        use crate::keyboard::KeyCodeExt;
        crate::KeyCode::from_scancode(0x10, false) == crate::KeyCode::Q
            && crate::KeyCode::from_scancode(0x48, true) == crate::KeyCode::Up
    }

    // =========================================================================
    // keymap.rs extended smoke tests
    // =========================================================================

    fn mods(shift: bool, caps_lock: bool) -> Modifiers {
        Modifiers {
            shift,
            caps_lock,
            ..Default::default()
        }
    }

    fn mods_ctrl() -> Modifiers {
        Modifiers {
            ctrl: true,
            ..Default::default()
        }
    }

    pub fn us_qwerty_letters_smoke() -> bool {
        let keymap = UsQwertyKeymap;
        keymap.to_char(KeyCode::A, &mods(false, false)) == Some('a')
            && keymap.to_char(KeyCode::Z, &mods(false, false)) == Some('z')
            && keymap.to_char(KeyCode::A, &mods(true, false)) == Some('A')
            && keymap.to_char(KeyCode::A, &mods(false, true)) == Some('A')
            && keymap.to_char(KeyCode::A, &mods(true, true)) == Some('a')
    }

    pub fn us_qwerty_numbers_smoke() -> bool {
        let keymap = UsQwertyKeymap;
        keymap.to_char(KeyCode::Key1, &mods(false, false)) == Some('1')
            && keymap.to_char(KeyCode::Key1, &mods(true, false)) == Some('!')
            && keymap.to_char(KeyCode::Key2, &mods(true, false)) == Some('@')
    }

    pub fn us_qwerty_special_smoke() -> bool {
        let keymap = UsQwertyKeymap;
        keymap.to_char(KeyCode::Space, &mods(false, false)) == Some(' ')
            && keymap.to_char(KeyCode::Enter, &mods(false, false)) == Some('\n')
            && keymap.to_char(KeyCode::Tab, &mods(false, false)) == Some('\t')
    }

    pub fn non_printable_keys_smoke() -> bool {
        let keymap = UsQwertyKeymap;
        keymap.to_char(KeyCode::F1, &mods(false, false)).is_none()
            && keymap
                .to_char(KeyCode::Escape, &mods(false, false))
                .is_none()
            && keymap.to_char(KeyCode::Up, &mods(false, false)).is_none()
    }

    pub fn ctrl_characters_smoke() -> bool {
        let keymap = UsQwertyKeymap;
        keymap.to_char(KeyCode::C, &mods_ctrl()) == Some('\x03')
            && keymap.to_char(KeyCode::D, &mods_ctrl()) == Some('\x04')
            && keymap.to_char(KeyCode::Z, &mods_ctrl()) == Some('\x1A')
    }

    pub fn jis_symbols_smoke() -> bool {
        let keymap = crate::keymap::JisKeymap;
        keymap.to_char(KeyCode::Key2, &mods(true, false)) == Some('"')
            && keymap.to_char(KeyCode::Key6, &mods(true, false)) == Some('&')
            && keymap.to_char(KeyCode::Key7, &mods(true, false)) == Some('\'')
            && keymap.to_char(KeyCode::LeftBracket, &mods(false, false)) == Some('@')
            && keymap.to_char(KeyCode::LeftBracket, &mods(true, false)) == Some('{')
    }

    pub fn jis_letters_smoke() -> bool {
        let keymap = crate::keymap::JisKeymap;
        keymap.to_char(KeyCode::A, &mods(false, false)) == Some('a')
            && keymap.to_char(KeyCode::A, &mods(true, false)) == Some('A')
            && keymap.to_char(KeyCode::Z, &mods(false, false)) == Some('z')
    }

    pub fn jis_ctrl_smoke() -> bool {
        let keymap = crate::keymap::JisKeymap;
        keymap.to_char(KeyCode::C, &mods_ctrl()) == Some('\x03')
            && keymap.to_char(KeyCode::D, &mods_ctrl()) == Some('\x04')
    }

    pub fn dvorak_home_row_smoke() -> bool {
        let keymap = DvorakKeymap;
        keymap.to_char(KeyCode::A, &mods(false, false)) == Some('a')
            && keymap.to_char(KeyCode::S, &mods(false, false)) == Some('o')
            && keymap.to_char(KeyCode::D, &mods(false, false)) == Some('e')
            && keymap.to_char(KeyCode::F, &mods(false, false)) == Some('u')
            && keymap.to_char(KeyCode::G, &mods(false, false)) == Some('i')
            && keymap.to_char(KeyCode::H, &mods(false, false)) == Some('d')
            && keymap.to_char(KeyCode::J, &mods(false, false)) == Some('h')
            && keymap.to_char(KeyCode::K, &mods(false, false)) == Some('t')
            && keymap.to_char(KeyCode::L, &mods(false, false)) == Some('n')
            && keymap.to_char(KeyCode::Semicolon, &mods(false, false)) == Some('s')
    }

    pub fn dvorak_top_row_smoke() -> bool {
        let keymap = DvorakKeymap;
        keymap.to_char(KeyCode::Q, &mods(false, false)) == Some('\'')
            && keymap.to_char(KeyCode::W, &mods(false, false)) == Some(',')
            && keymap.to_char(KeyCode::E, &mods(false, false)) == Some('.')
            && keymap.to_char(KeyCode::R, &mods(false, false)) == Some('p')
            && keymap.to_char(KeyCode::T, &mods(false, false)) == Some('y')
            && keymap.to_char(KeyCode::Y, &mods(false, false)) == Some('f')
    }

    pub fn dvorak_bottom_row_smoke() -> bool {
        let keymap = DvorakKeymap;
        keymap.to_char(KeyCode::Z, &mods(false, false)) == Some(';')
            && keymap.to_char(KeyCode::X, &mods(false, false)) == Some('q')
            && keymap.to_char(KeyCode::C, &mods(false, false)) == Some('j')
            && keymap.to_char(KeyCode::Slash, &mods(false, false)) == Some('z')
    }

    pub fn dvorak_caps_lock_smoke() -> bool {
        let keymap = DvorakKeymap;
        keymap.to_char(KeyCode::S, &mods(false, true)) == Some('O')
            && keymap.to_char(KeyCode::S, &mods(true, true)) == Some('o')
    }

    pub fn global_keymap_instances_smoke() -> bool {
        crate::keymap::DEFAULT_KEYMAP.name() == "US QWERTY"
            && crate::keymap::JIS_KEYMAP.name() == "JIS (Japanese)"
            && crate::keymap::DVORAK_KEYMAP.name() == "Dvorak"
    }

    pub fn numpad_us_qwerty_smoke() -> bool {
        let keymap = UsQwertyKeymap;
        keymap.to_char(KeyCode::NumPad0, &mods(false, false)) == Some('0')
            && keymap.to_char(KeyCode::NumPad5, &mods(false, false)) == Some('5')
            && keymap.to_char(KeyCode::NumPad9, &mods(false, false)) == Some('9')
            && keymap.to_char(KeyCode::NumPadPlus, &mods(false, false)) == Some('+')
            && keymap.to_char(KeyCode::NumPadMinus, &mods(false, false)) == Some('-')
            && keymap.to_char(KeyCode::NumPadMultiply, &mods(false, false)) == Some('*')
            && keymap.to_char(KeyCode::NumPadDivide, &mods(false, false)) == Some('/')
            && keymap.to_char(KeyCode::NumPadDecimal, &mods(false, false)) == Some('.')
            && keymap.to_char(KeyCode::NumPadEnter, &mods(false, false)) == Some('\n')
    }

    pub fn numpad_jis_smoke() -> bool {
        let keymap = crate::keymap::JisKeymap;
        keymap.to_char(KeyCode::NumPad0, &mods(false, false)) == Some('0')
            && keymap.to_char(KeyCode::NumPad5, &mods(false, false)) == Some('5')
            && keymap.to_char(KeyCode::NumPadPlus, &mods(false, false)) == Some('+')
            && keymap.to_char(KeyCode::NumPadEnter, &mods(false, false)) == Some('\n')
    }

    pub fn numpad_dvorak_smoke() -> bool {
        let keymap = DvorakKeymap;
        keymap.to_char(KeyCode::NumPad0, &mods(false, false)) == Some('0')
            && keymap.to_char(KeyCode::NumPad5, &mods(false, false)) == Some('5')
            && keymap.to_char(KeyCode::NumPadMultiply, &mods(false, false)) == Some('*')
            && keymap.to_char(KeyCode::NumPadDivide, &mods(false, false)) == Some('/')
    }

    pub fn numpad_shift_ignored_smoke() -> bool {
        let keymap = UsQwertyKeymap;
        keymap.to_char(KeyCode::NumPad0, &mods(true, false)) == Some('0')
            && keymap.to_char(KeyCode::NumPadPlus, &mods(true, false)) == Some('+')
    }
}
