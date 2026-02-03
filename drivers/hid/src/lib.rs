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
    CharFuture, CharFutureArc, DEFAULT_POLL_BUDGET, DriverOps, KeyEventFuture, KeyboardStream,
    KeyboardStreamArc,
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
    DEFAULT_KEYMAP, DVORAK_KEYMAP, DvorakKeymap, JIS_KEYMAP, JisKeymap, Keymap, UsQwertyKeymap,
    ctrl_char_map,
};

// Keyboard helpers - use `hid_driver::keyboard::*` for full access
pub use keyboard::StreamAlreadyTaken;
