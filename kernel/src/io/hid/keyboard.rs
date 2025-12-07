// ============================================================================
// src/io/hid/keyboard.rs - Async PS/2 Keyboard Driver
// フェーズ3: インスタンス化、SPSC強制、Keymap分離
// ============================================================================
//!
//! # 非同期キーボードドライバ
//!
//! PS/2キーボードからの入力を非同期Futureとして提供。
//! Interrupt-Wakerブリッジと連携して、割り込み駆動の入力処理を実現。
//!
//! ## アーキテクチャ
//!
//! ```text
//! ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
//! │   PS/2 IRQ 1    │────▶│   SPSC Queue    │────▶│  KeyboardStream │
//! │  (Producer)     │     │  (Lock-Free)    │     │   (Consumer)    │
//! └─────────────────┘     └─────────────────┘     └─────────────────┘
//!         │                                               │
//!         └───────── IsrSafeWaker ◀───────────────────────┘
//! ```
//!
//! ## 設計原則
//! - **厳密なSPSC**: Single Producer (ISR) - Single Consumer (KeyboardStream holder)
//! - **所有権ベースの保証**: KeyboardStreamの所有権でConsumer単一性を型レベルで強制
//! - **IRQ安全**: IrqMutexによるデッドロック防止
//! - **インスタンス化**: 複数キーボードデバイスのサポート基盤
//! - **Keymap分離**: 多言語対応のための抽象化
//!
//! ## SPSC契約
//!
//! このドライバは**厳密なSPSC (Single Producer Single Consumer)** を採用:
//! - Producer: ISR（割り込みハンドラ）のみ
//! - Consumer: `KeyboardStream`の所有者のみ
//!
//! `KeyboardStream`は`Clone`不可で、所有権の移動によってのみ受け渡し可能。
//! これにより、コンパイル時にConsumerの単一性が保証される。

#![allow(dead_code)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::fmt;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicUsize, AtomicU64, Ordering};
use core::task::{Context, Poll, Waker};

// Keymapモジュールからインポート
pub use super::keymap::{DvorakKeymap, JisKeymap, Keymap, UsQwertyKeymap, DEFAULT_KEYMAP};

// ============================================================================
// エラー型
// ============================================================================

/// ストリーム取得エラー
///
/// `take_stream()`が失敗した場合に返される。
/// 既に別のコンシューマがストリームを保持している場合に発生。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamAlreadyTaken;

impl fmt::Display for StreamAlreadyTaken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Keyboard stream already taken by another consumer")
    }
}

// ============================================================================
// スキャンコード定数
// ============================================================================

/// PS/2 スキャンコード: 拡張プレフィックス (0xE0)
const SCANCODE_EXTENDED_PREFIX: u8 = 0xE0;

/// キューデータ: 拡張フラグビット (bit 8)
const QUEUE_EXTENDED_FLAG: u16 = 0x0100;

/// スキャンコード: キーリリースビット (bit 7)
const SCANCODE_RELEASE_BIT: u8 = 0x80;

/// スキャンコードのキーコード部分マスク (bit 0-6)
const SCANCODE_KEYCODE_MASK: u8 = 0x7F;

/// スキャンコードキューのサイズ（2のべき乗であること）
const SCANCODE_QUEUE_SIZE: usize = 128;

/// キューサイズのマスク（モジュロ演算の高速化）
const SCANCODE_QUEUE_MASK: usize = SCANCODE_QUEUE_SIZE - 1;

// サイズが2のべき乗であることを静的に検証
const _: () = assert!(
    SCANCODE_QUEUE_SIZE.is_power_of_two(),
    "SCANCODE_QUEUE_SIZE must be a power of two"
);

// ============================================================================
// キーコード
// ============================================================================

/// スキャンコードセット1のキーコード
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    NumPad0 = 0xC0,      // NumLockオンで '0', オフで Insert (実際は0x52)
    NumPad1 = 0xC1,      // NumLockオンで '1', オフで End (実際は0x4F)
    NumPad2 = 0xC2,      // NumLockオンで '2', オフで Down (実際は0x50)
    NumPad3 = 0xC3,      // NumLockオンで '3', オフで PageDown (実際は0x51)
    NumPad4 = 0xC4,      // NumLockオンで '4', オフで Left (実際は0x4B)
    NumPad5 = 0xC5,      // NumLockオンで '5', オフで (nothing) (実際は0x4C)
    NumPad6 = 0xC6,      // NumLockオンで '6', オフで Right (実際は0x4D)
    NumPad7 = 0xC7,      // NumLockオンで '7', オフで Home (実際は0x47)
    NumPad8 = 0xC8,      // NumLockオンで '8', オフで Up (実際は0x48)
    NumPad9 = 0xC9,      // NumLockオンで '9', オフで PageUp (実際は0x49)
    NumPadDecimal = 0xCA, // NumLockオンで '.', オフで Delete (実際は0x53)
    NumPadEnter = 0x9C,  // 拡張コード (E0 1C)
    NumPadPlus = 0x4E,
    NumPadMinus = 0x4A,
    NumPadMultiply = 0x37,
    NumPadDivide = 0xB5, // 拡張コード (E0 35)

    // 不明
    Unknown = 0xFF,
}

impl KeyCode {
    /// スキャンコードからキーコードに変換
    ///
    /// # PS/2スキャンコードセット1の規則
    ///
    /// テンキーとナビゲーションキーは同じスキャンコード値を共有しますが、
    /// 拡張プレフィックス（E0）の有無で区別されます：
    ///
    /// - **拡張コード（E0プレフィックスあり）**: ナビゲーションキー（矢印、Home、End等）
    /// - **非拡張コード**: テンキー（NumPad0-9、演算子）
    ///
    /// ## スキャンコードマッピング表
    ///
    /// | スキャンコード | 拡張時 | 非拡張時 |
    /// |-------------|--------|---------|
    /// | 0x47        | Home   | NumPad7 |
    /// | 0x48        | Up     | NumPad8 |
    /// | 0x49        | PageUp | NumPad9 |
    /// | 0x4A        | -      | NumPadMinus |
    /// | 0x4B        | Left   | NumPad4 |
    /// | 0x4C        | -      | NumPad5 |
    /// | 0x4D        | Right  | NumPad6 |
    /// | 0x4E        | -      | NumPadPlus |
    /// | 0x4F        | End    | NumPad1 |
    /// | 0x50        | Down   | NumPad2 |
    /// | 0x51        | PageDown | NumPad3 |
    /// | 0x52        | Insert | NumPad0 |
    /// | 0x53        | Delete | NumPadDecimal |
    /// | 0x1C        | NumPadEnter | Enter |
    /// | 0x35        | NumPadDivide | Slash |
    /// | 0x37        | -      | NumPadMultiply |
    pub fn from_scancode(scancode: u8, extended: bool) -> Self {
        if extended {
            // 拡張スキャンコード（E0プレフィックス付き）
            // - ナビゲーションキー（矢印、Home、End等）
            // - NumPadEnter、NumPadDivide
            match scancode {
                // 矢印キー
                0x48 => KeyCode::Up,
                0x50 => KeyCode::Down,
                0x4B => KeyCode::Left,
                0x4D => KeyCode::Right,
                // ナビゲーションキー
                0x52 => KeyCode::Insert,
                0x53 => KeyCode::Delete,
                0x47 => KeyCode::Home,
                0x4F => KeyCode::End,
                0x49 => KeyCode::PageUp,
                0x51 => KeyCode::PageDown,
                // 拡張テンキー
                0x1C => KeyCode::NumPadEnter, // E0 1C
                0x35 => KeyCode::NumPadDivide, // E0 35
                _ => KeyCode::Unknown,
            }
        } else {
            // 非拡張スキャンコード
            // - メインキーボード
            // - テンキー（NumPad0-9、演算子）
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
                0x29 => KeyCode::BackTick,
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
                // テンキー乗算キー
                0x37 => KeyCode::NumPadMultiply,
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
                // テンキー数字キー（非拡張時）
                0x47 => KeyCode::NumPad7,
                0x48 => KeyCode::NumPad8,
                0x49 => KeyCode::NumPad9,
                0x4A => KeyCode::NumPadMinus,
                0x4B => KeyCode::NumPad4,
                0x4C => KeyCode::NumPad5,
                0x4D => KeyCode::NumPad6,
                0x4E => KeyCode::NumPadPlus,
                0x4F => KeyCode::NumPad1,
                0x50 => KeyCode::NumPad2,
                0x51 => KeyCode::NumPad3,
                0x52 => KeyCode::NumPad0,
                0x53 => KeyCode::NumPadDecimal,
                0x57 => KeyCode::F11,
                0x58 => KeyCode::F12,
                _ => KeyCode::Unknown,
            }
        }
    }

    /// キーコードを文字に変換（デフォルトキーマップを使用）
    ///
    /// # Note
    /// 新しいコードでは`keymap.to_char(key, &modifiers)`を直接使用してください。
    pub fn to_char(&self, shift: bool, caps_lock: bool) -> Option<char> {
        let modifiers = Modifiers {
            shift,
            caps_lock,
            ..Default::default()
        };
        DEFAULT_KEYMAP.to_char(*self, &modifiers)
    }
}

// ============================================================================
// キーイベント
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
    pub alt_gr: bool,  // Right Alt (AltGr for European layouts)
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
    /// このイベントを文字に変換（デフォルトキーマップ使用）
    pub fn to_char(&self) -> Option<char> {
        if self.state == KeyState::Released {
            return None;
        }
        DEFAULT_KEYMAP.to_char(self.key, &self.modifiers)
    }

    /// 指定されたキーマップで文字に変換
    pub fn to_char_with_keymap<K: Keymap>(&self, keymap: &K) -> Option<char> {
        if self.state == KeyState::Released {
            return None;
        }
        keymap.to_char(self.key, &self.modifiers)
    }

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
// 修飾キー状態（インスタンス内部状態）
// ============================================================================

/// 修飾キー状態（アトミック・ビットマスク）
///
/// 全ての修飾キー状態を単一のAtomicU32で管理し、
/// 一貫したスナップショットを保証する。
///
/// # ビットレイアウト
/// ```text
/// bit 0:  left_shift
/// bit 1:  right_shift
/// bit 2:  left_ctrl
/// bit 3:  right_ctrl
/// bit 4:  left_alt
/// bit 5:  right_alt (AltGr)
/// bit 6:  caps_lock
/// bit 7:  num_lock
/// bit 8:  scroll_lock
/// bit 9-31: reserved
/// ```
struct ModifierState {
    bits: core::sync::atomic::AtomicU32,
}

impl ModifierState {
    // ビット位置定数（衝突防止のため明示的に定義）
    const BIT_LEFT_SHIFT: u32 = 0;
    const BIT_RIGHT_SHIFT: u32 = 1;
    const BIT_LEFT_CTRL: u32 = 2;
    const BIT_RIGHT_CTRL: u32 = 3;
    const BIT_LEFT_ALT: u32 = 4;
    const BIT_RIGHT_ALT: u32 = 5;
    const BIT_CAPS_LOCK: u32 = 6;
    const BIT_NUM_LOCK: u32 = 7;
    const BIT_SCROLL_LOCK: u32 = 8;

    // ビットマスク定数
    const LEFT_SHIFT: u32 = 1 << Self::BIT_LEFT_SHIFT;
    const RIGHT_SHIFT: u32 = 1 << Self::BIT_RIGHT_SHIFT;
    const LEFT_CTRL: u32 = 1 << Self::BIT_LEFT_CTRL;
    const RIGHT_CTRL: u32 = 1 << Self::BIT_RIGHT_CTRL;
    const LEFT_ALT: u32 = 1 << Self::BIT_LEFT_ALT;
    const RIGHT_ALT: u32 = 1 << Self::BIT_RIGHT_ALT;  // AltGr
    const CAPS_LOCK: u32 = 1 << Self::BIT_CAPS_LOCK;
    const NUM_LOCK: u32 = 1 << Self::BIT_NUM_LOCK;
    const SCROLL_LOCK: u32 = 1 << Self::BIT_SCROLL_LOCK;

    const SHIFT_MASK: u32 = Self::LEFT_SHIFT | Self::RIGHT_SHIFT;
    const CTRL_MASK: u32 = Self::LEFT_CTRL | Self::RIGHT_CTRL;
    const ALT_MASK: u32 = Self::LEFT_ALT;  // Left Alt only for normal Alt

    // コンパイル時ビット位置検証
    const _BIT_VALIDATION: () = {
        // 全ビット位置が32未満であることを確認
        assert!(Self::BIT_SCROLL_LOCK < 32, "Bit position exceeds u32 range");

        // ビット位置の一意性検証（網羅的）
        assert!(Self::BIT_LEFT_SHIFT != Self::BIT_RIGHT_SHIFT);
        assert!(Self::BIT_LEFT_SHIFT != Self::BIT_LEFT_CTRL);
        assert!(Self::BIT_LEFT_SHIFT != Self::BIT_RIGHT_CTRL);
        assert!(Self::BIT_LEFT_SHIFT != Self::BIT_LEFT_ALT);
        assert!(Self::BIT_LEFT_SHIFT != Self::BIT_RIGHT_ALT);
        assert!(Self::BIT_LEFT_SHIFT != Self::BIT_CAPS_LOCK);
        assert!(Self::BIT_LEFT_SHIFT != Self::BIT_NUM_LOCK);
        assert!(Self::BIT_LEFT_SHIFT != Self::BIT_SCROLL_LOCK);
        assert!(Self::BIT_RIGHT_SHIFT != Self::BIT_LEFT_CTRL);
        assert!(Self::BIT_RIGHT_SHIFT != Self::BIT_RIGHT_CTRL);
        assert!(Self::BIT_RIGHT_SHIFT != Self::BIT_LEFT_ALT);
        assert!(Self::BIT_RIGHT_SHIFT != Self::BIT_RIGHT_ALT);
        assert!(Self::BIT_RIGHT_SHIFT != Self::BIT_CAPS_LOCK);
        assert!(Self::BIT_RIGHT_SHIFT != Self::BIT_NUM_LOCK);
        assert!(Self::BIT_RIGHT_SHIFT != Self::BIT_SCROLL_LOCK);
        assert!(Self::BIT_LEFT_CTRL != Self::BIT_RIGHT_CTRL);
        assert!(Self::BIT_LEFT_CTRL != Self::BIT_LEFT_ALT);
        assert!(Self::BIT_LEFT_CTRL != Self::BIT_RIGHT_ALT);
        assert!(Self::BIT_LEFT_CTRL != Self::BIT_CAPS_LOCK);
        assert!(Self::BIT_LEFT_CTRL != Self::BIT_NUM_LOCK);
        assert!(Self::BIT_LEFT_CTRL != Self::BIT_SCROLL_LOCK);
        assert!(Self::BIT_RIGHT_CTRL != Self::BIT_LEFT_ALT);
        assert!(Self::BIT_RIGHT_CTRL != Self::BIT_RIGHT_ALT);
        assert!(Self::BIT_RIGHT_CTRL != Self::BIT_CAPS_LOCK);
        assert!(Self::BIT_RIGHT_CTRL != Self::BIT_NUM_LOCK);
        assert!(Self::BIT_RIGHT_CTRL != Self::BIT_SCROLL_LOCK);
        assert!(Self::BIT_LEFT_ALT != Self::BIT_RIGHT_ALT);
        assert!(Self::BIT_LEFT_ALT != Self::BIT_CAPS_LOCK);
        assert!(Self::BIT_LEFT_ALT != Self::BIT_NUM_LOCK);
        assert!(Self::BIT_LEFT_ALT != Self::BIT_SCROLL_LOCK);
        assert!(Self::BIT_RIGHT_ALT != Self::BIT_CAPS_LOCK);
        assert!(Self::BIT_RIGHT_ALT != Self::BIT_NUM_LOCK);
        assert!(Self::BIT_RIGHT_ALT != Self::BIT_SCROLL_LOCK);
        assert!(Self::BIT_CAPS_LOCK != Self::BIT_NUM_LOCK);
        assert!(Self::BIT_CAPS_LOCK != Self::BIT_SCROLL_LOCK);
        assert!(Self::BIT_NUM_LOCK != Self::BIT_SCROLL_LOCK);
    };

    const fn new() -> Self {
        Self {
            bits: core::sync::atomic::AtomicU32::new(0),
        }
    }

    /// 一貫したスナップショットを取得
    ///
    /// 単一のアトミックロードで全ての修飾キー状態を取得するため、
    /// 割り込み中の状態変更に対しても一貫性が保証される。
    fn snapshot(&self) -> Modifiers {
        let bits = self.bits.load(Ordering::Acquire);
        Modifiers {
            shift: (bits & Self::SHIFT_MASK) != 0,
            ctrl: (bits & Self::CTRL_MASK) != 0,
            alt: (bits & Self::ALT_MASK) != 0,
            alt_gr: (bits & Self::RIGHT_ALT) != 0,
            caps_lock: (bits & Self::CAPS_LOCK) != 0,
            num_lock: (bits & Self::NUM_LOCK) != 0,
            scroll_lock: (bits & Self::SCROLL_LOCK) != 0,
        }
    }

    /// ビットをセット
    #[inline]
    fn set_bit(&self, mask: u32) {
        self.bits.fetch_or(mask, Ordering::Release);
    }

    /// ビットをクリア
    #[inline]
    fn clear_bit(&self, mask: u32) {
        self.bits.fetch_and(!mask, Ordering::Release);
    }

    /// ビットをトグル
    #[inline]
    fn toggle_bit(&self, mask: u32) {
        self.bits.fetch_xor(mask, Ordering::Release);
    }

    /// ビットを設定/クリア
    #[inline]
    fn update_bit(&self, mask: u32, pressed: bool) {
        if pressed {
            self.set_bit(mask);
        } else {
            self.clear_bit(mask);
        }
    }
}

// ============================================================================
// IsrSafeWaker - 割り込み安全なWaker通知機構
// ============================================================================

/// ISR安全なWaker通知機構（ダブルバッファ方式）
///
/// ISR（割り込みハンドラ）から安全にWakerを起床させるための機構。
///
/// # 設計
///
/// - ISRは`notify()`でpendingフラグを立てるのみ（アロケーションなし）
/// - Consumerは`check_and_wake()`で実際の起床処理
/// - 2スロットバッファで、ISRアクセス中の更新を安全化
///
/// # ⚠️ 注意: これは真のEpoch-based Reclamationではありません
///
/// このダブルバッファ方式は、ISRが`notify()`でpendingフラグのみを操作し、
/// Wakerを直接操作しないことを前提としています。そのため、完全なEBRは不要です。
///
/// ## 動作フロー
///
/// ```text
/// ISR (Producer):
///   handle_scancode() -> notify() -> pending.store(true)
///   [Wakerは触らない]
///
/// Consumer (poll):
///   poll() -> register(waker) -> 次スロットにWaker書き込み
///                              -> epoch更新
///
/// Executor/Consumer:
///   check_and_wake() -> pending確認
///                    -> current_epochスロットから wake_by_ref()
/// ```
///
/// ## 安全性の保証
///
/// | 操作 | 呼び出し元 | アクセス対象 | 安全性 |
/// |------|-----------|-------------|--------|
/// | notify() | ISR | pendingフラグのみ | ✅ AtomicBoolのみ |
/// | register() | Consumer | 次スロット書き込み | ✅ 排他アクセス |
/// | check_and_wake() | Consumer | 現スロット読み取り | ✅ Release-Acquire |
///
/// # Safety Contract
///
/// この`unsafe impl Send/Sync`は以下の契約に基づきます：
///
/// 1. **`register()`はConsumerスレッドからのみ呼び出す**
///    - 次スロットへの書き込みは単一スレッドからのみ
///    - ISRは現スロットのみ参照するため競合なし
///
/// 2. **`notify()`はISRから呼ばれても安全**
///    - `pending: AtomicBool`のみ操作
///    - Wakerスロットは一切触らない
///
/// 3. **`check_and_wake()`はConsumer/Executorからのみ呼び出す**
///    - `pending.swap(false)`でISRとの同期
///    - epoch読み取り後のスロット参照はRelease-Acquireで保護
///
/// 4. **Waker::clone()とwake_by_ref()はSend/Sync安全**
///    - Wakerの契約による保証
///
/// # 検証状況
///
/// - [x] シングルコア環境: 割り込み禁止なしでも安全（ISRがWaker触らない）
/// - [ ] マルチコア環境: 形式検証未実施（Miri/Loomでのテスト推奨）
/// - [ ] 弱メモリモデル（ARM/RISC-V）: Release-Acquireで理論上安全だが実機未検証
struct IsrSafeWaker {
    /// 起床が保留されているか（ISRがセット、Consumer/Executorがクリア）
    pending: AtomicBool,

    /// 現在有効なエポック（偶数/奇数でスロット0/1を選択）
    ///
    /// # Invariant
    /// - epoch % 2 == 0: waker_slots[0] が有効
    /// - epoch % 2 == 1: waker_slots[1] が有効
    current_epoch: AtomicU64,

    /// 2世代のWakerスロット（epoch-based reclamation）
    ///
    /// # Safety
    /// - 書き込み: Consumerスレッドからのみ（register）
    /// - 読み取り: ISR/Consumer両方から可能
    /// - 古いスロットは次のregister()まで有効を保証
    waker_slots: [core::cell::UnsafeCell<Option<Waker>>; 2],

    /// Wakerが登録されているか（読み取り専用フラグ）
    has_waker: AtomicBool,
}

// Safety: ダブルバッファ方式により以下を保証
//
// 1. ISRは`notify()`でpendingフラグのみ操作（Wakerスロット触らない）
// 2. register()は次スロットに書き込み → epoch更新（現スロットは安全）
// 3. check_and_wake()は現スロットを参照（Release-Acquire同期）
//
// 前提条件:
// - register()はConsumerスレッドからのみ呼ばれる
// - ISRはnotify()のみ呼び出す（Waker操作なし）
//
// ⚠️ アーキテクチャ制限: x86_64でのみ検証済み
//    ARM/RISC-Vでの使用は形式検証（Loom等）完了後に有効化してください
#[cfg(not(target_arch = "x86_64"))]
compile_error!(
    "IsrSafeWaker is only verified on x86_64 (TSO memory model). \
     ARM/RISC-V require formal verification with Loom/Miri before use. \
     To enable on other architectures, add feature 'experimental-weak-memory'."
);

unsafe impl Send for IsrSafeWaker {}
unsafe impl Sync for IsrSafeWaker {}

impl IsrSafeWaker {
    const fn new() -> Self {
        Self {
            pending: AtomicBool::new(false),
            current_epoch: AtomicU64::new(0),
            waker_slots: [
                core::cell::UnsafeCell::new(None),
                core::cell::UnsafeCell::new(None),
            ],
            has_waker: AtomicBool::new(false),
        }
    }

    /// Wakerを登録（Consumerスレッドから呼び出し）
    ///
    /// # Epoch-based Reclamation
    ///
    /// 1. 次のepochのスロットに新しいWakerを書き込み
    /// 2. current_epochをインクリメントして新スロットを有効化
    /// 3. 古いスロットは次回のregister()まで保持（ISRがまだ参照中の可能性）
    ///
    /// # Memory Ordering
    ///
    /// - Release: epoch更新前にWaker書き込みが完了していることを保証
    /// - ISR側のAcquireと対になる
    fn register(&self, waker: &Waker) {
        let old_epoch = self.current_epoch.load(Ordering::Acquire);
        let next_epoch = old_epoch.wrapping_add(1);
        let next_slot = (next_epoch % 2) as usize;

        // 次のスロットに新しいWakerを書き込み
        // Safety: Consumerスレッドからのみ呼ばれ、このスロットはISRから参照されない
        // （ISRは current_epoch のスロットのみ参照）
        unsafe {
            let slot = &mut *self.waker_slots[next_slot].get();

            // 既存のWakerと同じなら更新不要
            if let Some(existing) = slot {
                if existing.will_wake(waker) {
                    return;
                }
            }

            *slot = Some(waker.clone());
        }

        // エポックを進めて新スロットを有効化
        // Release: スロット書き込みが完了してからepoch更新
        self.current_epoch.store(next_epoch, Ordering::Release);
        self.has_waker.store(true, Ordering::Release);
    }

    /// ISRから呼び出し: 起床を通知（フラグを立てるだけ）
    ///
    /// # Safety
    /// - ロックなし、アロケーションなし
    /// - ISRから安全に呼び出せる
    /// - マルチコア環境でも安全
    #[inline]
    fn notify(&self) {
        // フラグを立てるだけ - ISRからでも安全
        self.pending.store(true, Ordering::Release);
    }

    /// Executor/Consumerから呼び出し: 保留中の起床があればWakerを起床
    ///
    /// # 戻り値
    /// `true`: 起床を実行した、`false`: 保留なしまたはWaker未登録
    ///
    /// # Note
    /// この関数はExecutorのポーリングループまたはConsumerの
    /// poll()開始時に呼ばれる。
    /// Waker::wake_by_ref()はここで呼ばれるため、
    /// アロケータがロックを取っても問題ない。
    fn check_and_wake(&self) -> bool {
        // pending フラグをチェック＆クリア
        if !self.pending.swap(false, Ordering::AcqRel) {
            return false;
        }

        // Wakerが登録されていれば起床
        if self.has_waker.load(Ordering::Acquire) {
            let epoch = self.current_epoch.load(Ordering::Acquire);
            let slot_idx = (epoch % 2) as usize;

            // Safety: Acquire orderingによりepoch更新後のスロット状態を参照
            let waker_slot = unsafe { &*self.waker_slots[slot_idx].get() };
            if let Some(waker) = waker_slot {
                waker.wake_by_ref();
                return true;
            }
        }

        false
    }

    /// 即座に起床（Consumer側から、キューにデータがある場合など）
    ///
    /// ISRを経由せず直接起床させたい場合に使用。
    #[allow(dead_code)]
    fn wake_now(&self) {
        if self.has_waker.load(Ordering::Acquire) {
            let epoch = self.current_epoch.load(Ordering::Acquire);
            let slot_idx = (epoch % 2) as usize;

            let waker_slot = unsafe { &*self.waker_slots[slot_idx].get() };
            if let Some(waker) = waker_slot {
                waker.wake_by_ref();
            }
        }
    }

    /// 保留中の起床があるか
    #[inline]
    fn is_pending(&self) -> bool {
        self.pending.load(Ordering::Acquire)
    }

    /// Wakerが登録されているか
    #[allow(dead_code)]
    fn is_registered(&self) -> bool {
        self.has_waker.load(Ordering::Acquire)
    }
}

// ============================================================================
// スキャンコードキュー（インスタンス内部状態）
// ============================================================================

/// ロックフリーSPSCスキャンコードキュー
///
/// # データフォーマット (u16)
/// ```text
/// ┌─────────────────────────────────────────┐
/// │ bit 15-9: Reserved (0)                 │
/// │ bit 8:    Extended Flag (0xE0 prefix)  │
/// │ bit 7-0:  Raw Scancode                 │
/// └─────────────────────────────────────────┘
/// ```
///
/// # Memory Ordering契約
///
/// ## Producer (ISR) → Consumer (poll) の同期
///
/// ```text
/// Producer (push):                    Consumer (pop):
/// ─────────────────                   ─────────────────
/// 1. buffer[tail].store(Release)      1. tail.load(Acquire)  ←── 同期点
/// 2. tail.store(Release) ───────────►
///                                     2. buffer[head].load(Acquire)
///                                     3. head.store(Release)
/// ```
///
/// ## 保証
///
/// - Release-Acquire同期により、Consumerが新しいtailを見たとき
///   buffer[old_tail]のデータが確実に見える（C++11メモリモデル準拠）
///
/// ## ⚠️ プラットフォーム考慮事項
///
/// - **x86-64 (TSO)**: Release-Acquireは自動的に保証される
/// - **ARM64 (弱メモリモデル)**: 理論上安全だが、実機検証推奨
/// - **RISC-V**: fence命令が必要な場合あり（コンパイラが挿入）
///
/// # 検証推奨
///
/// 商用利用前にLoomでのテストを推奨:
/// ```ignore
/// #[test]
/// fn loom_test_queue() {
///     loom::model(|| {
///         // Producer/Consumer並行テスト
///     });
/// }
/// ```
struct ScancodeQueue {
    buffer: [core::sync::atomic::AtomicU16; SCANCODE_QUEUE_SIZE],
    tail: AtomicUsize,
    head: AtomicUsize,
}

impl ScancodeQueue {
    const fn new() -> Self {
        const ZERO: core::sync::atomic::AtomicU16 = core::sync::atomic::AtomicU16::new(0);
        Self {
            buffer: [ZERO; SCANCODE_QUEUE_SIZE],
            tail: AtomicUsize::new(0),
            head: AtomicUsize::new(0),
        }
    }

    /// キューにデータを追加（Producer側：ISRから呼び出し）
    ///
    /// # Memory Ordering
    /// - `buffer[tail].store(Release)`: データ書き込みがtail更新前に完了することを保証
    /// - `tail.store(Release)`: Consumer側がtailを見たとき、データが確実に見える
    ///
    /// この順序が崩れると、Consumerが古いデータを読む可能性がある（特にARM等の弱メモリモデル）
    #[inline]
    fn push(&self, data: u16) -> bool {
        let tail = self.tail.load(Ordering::Relaxed);
        let head = self.head.load(Ordering::Acquire);

        let next_tail = (tail + 1) & SCANCODE_QUEUE_MASK;
        if next_tail == head {
            return false;
        }

        // ✅ Release: Consumer が tail を読んだ時にデータが見えることを保証
        self.buffer[tail].store(data, Ordering::Release);
        // tail の更新 - Consumer への公開
        self.tail.store(next_tail, Ordering::Release);
        true
    }

    /// キューからデータを取得（Consumer側：pollから呼び出し）
    ///
    /// # Memory Ordering
    /// - `head.load(Acquire)`: 前回のhead更新以降の書き込みが見えることを保証
    /// - `tail.load(Acquire)`: Producerのbuffer書き込みが見えることを保証
    /// - `buffer[head].load(Acquire)`: データ読み取りがhead更新前に完了することを保証
    ///
    /// # Note on ABA Problem Mitigation
    /// headのロードにAcquireを使用することで、マルチコア環境での
    /// ABA問題変種のリスクを軽減します。ただし、このキューはSPSC設計の
    /// ため、単一Consumerが保証されていれば完全に安全です。
    #[inline]
    fn pop(&self) -> Option<u16> {
        // ✅ Acquire: 前回のhead更新以降の全ての操作が見えることを保証
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);

        if head == tail {
            return None;
        }

        // ✅ Acquire: Producer の書き込みが確実に見える
        let data = self.buffer[head].load(Ordering::Acquire);
        // head の更新 - スロットを解放
        self.head
            .store((head + 1) & SCANCODE_QUEUE_MASK, Ordering::Release);
        Some(data)
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.head.load(Ordering::Acquire) == self.tail.load(Ordering::Acquire)
    }
}

// ============================================================================
// キーボードドライバ（インスタンス化）
// ============================================================================

/// キーボードドライバの内部状態
///
/// 全てのステートがインスタンス内に含まれるため、
/// 複数のキーボードデバイスを独立して管理可能。
pub struct KeyboardDriver {
    /// 初期化済みフラグ
    initialized: AtomicBool,
    /// スキャンコードキュー
    queue: ScancodeQueue,
    /// 修飾キー状態
    modifiers: ModifierState,
    /// ISRの拡張スキャンコード状態
    extended_pending: AtomicBool,
    /// Waker通知機構（ISR安全）
    waker: IsrSafeWaker,
    /// ストリーム発行済みフラグ
    stream_taken: AtomicBool,
    /// キュー満杯によるドロップカウンタ（診断用）
    dropped_events: AtomicU64,
}

impl KeyboardDriver {
    /// 新しいドライバを作成
    pub const fn new() -> Self {
        Self {
            initialized: AtomicBool::new(false),
            queue: ScancodeQueue::new(),
            modifiers: ModifierState::new(),
            extended_pending: AtomicBool::new(false),
            waker: IsrSafeWaker::new(),
            stream_taken: AtomicBool::new(false),
            dropped_events: AtomicU64::new(0),
        }
    }

    /// ドライバを初期化
    ///
    /// # Note
    /// この関数は冪等（idempotent）ですが、2回目以降の呼び出しは警告ログを出力します。
    /// 複数回呼ばれている場合は、初期化ロジックの見直しを検討してください。
    pub fn init(&self) {
        if self.initialized.swap(true, Ordering::SeqCst) {
            // 2回目以降の呼び出し - 警告を出力
            crate::log!("[KEYBOARD] WARNING: init() called multiple times (ignored)\n");
            return;
        }
        crate::log!("[KEYBOARD] Keyboard driver initialized (Instance-based, Single-core only)\n");
    }

    /// スキャンコードを処理（ISRから呼ばれる）
    ///
    /// # Safety Contract
    /// この関数はISRコンテキストからのみ呼び出されること。
    /// ロックフリー実装のため、デッドロックの危険はない。
    pub fn handle_scancode(&self, scancode: u8) {
        if scancode == SCANCODE_EXTENDED_PREFIX {
            self.extended_pending.store(true, Ordering::Relaxed);
            return;
        }

        let extended = self.extended_pending.swap(false, Ordering::Relaxed);
        let data: u16 = (scancode as u16) | if extended { QUEUE_EXTENDED_FLAG } else { 0 };

        if self.queue.push(data) {
            // ISR内では notify() のみ（フラグを立てるだけ）
            // 実際の wake() は Consumer の poll() で行われる
            self.waker.notify();
        } else {
            // キュー満杯: イベントドロップを記録
            // ISR内なのでログ出力は避け、カウンタのみインクリメント
            // 飽和加算: オーバーフロー時は u64::MAX で固定
            let _ = self.dropped_events.fetch_update(
                Ordering::Relaxed,
                Ordering::Relaxed,
                |v| v.checked_add(1).or(Some(u64::MAX)),
            );
            // ✅ キュー満杯でもConsumerに通知
            // キューにデータがあることを知らせ、Consumerが処理を進められるようにする
            self.waker.notify();
        }
    }

    /// ドロップされたイベント数を取得（診断用）
    ///
    /// # Returns
    /// キュー満杯によりドロップされたイベントの総数。
    ///
    /// # 飽和動作
    /// カウンタは飽和加算を使用しており、`u64::MAX`に達すると
    /// それ以上増加しません。`u64::MAX`は約1845京イベントに相当し、
    /// 毎秒1000イベントでも約585億年かかるため、実用上は問題になりません。
    ///
    /// # 使用例
    /// ```ignore
    /// let dropped = driver.dropped_events();
    /// if dropped > 0 {
    ///     log!("Warning: {} events dropped due to full queue", dropped);
    ///     driver.reset_dropped_events();  // 必要に応じてリセット
    /// }
    /// ```
    pub fn dropped_events(&self) -> u64 {
        self.dropped_events.load(Ordering::Relaxed)
    }

    /// ドロップカウンタをリセット（診断用）
    ///
    /// # Returns
    /// リセット前の値を返す。これにより、アトミックに「読み取りとリセット」を行える。
    pub fn reset_dropped_events(&self) -> u64 {
        self.dropped_events.swap(0, Ordering::Relaxed)
    }

    /// 次のキーイベントを取得（ノンブロッキング）
    fn poll_key_event_internal(&self) -> Option<KeyEvent> {
        let data = self.queue.pop()?;

        let extended = (data & QUEUE_EXTENDED_FLAG) != 0;
        let scancode = (data & 0xFF) as u8;
        let released = (scancode & SCANCODE_RELEASE_BIT) != 0;
        let code = scancode & SCANCODE_KEYCODE_MASK;

        let key = KeyCode::from_scancode(code, extended);
        let state = if released {
            KeyState::Released
        } else {
            KeyState::Pressed
        };

        self.update_modifiers(key, extended, released);

        // 生スキャンコードを保持（デバッグ用）
        // bit 0-6: キーコード部分、bit 7: リリースビット、bit 8: 拡張フラグ
        let raw_scancode = data;

        Some(KeyEvent {
            key,
            state,
            modifiers: self.modifiers.snapshot(),
            raw_scancode,
        })
    }

    /// 修飾キーの状態を更新
    fn update_modifiers(&self, key: KeyCode, extended: bool, released: bool) {
        let pressed = !released;
        match key {
            KeyCode::LeftShift => {
                self.modifiers.update_bit(ModifierState::LEFT_SHIFT, pressed);
            }
            KeyCode::RightShift => {
                self.modifiers.update_bit(ModifierState::RIGHT_SHIFT, pressed);
            }
            KeyCode::LeftCtrl => {
                let mask = if extended {
                    ModifierState::RIGHT_CTRL
                } else {
                    ModifierState::LEFT_CTRL
                };
                self.modifiers.update_bit(mask, pressed);
            }
            KeyCode::LeftAlt => {
                let mask = if extended {
                    ModifierState::RIGHT_ALT  // AltGr
                } else {
                    ModifierState::LEFT_ALT
                };
                self.modifiers.update_bit(mask, pressed);
            }
            KeyCode::CapsLock if pressed => {
                self.modifiers.toggle_bit(ModifierState::CAPS_LOCK);
            }
            KeyCode::NumLock if pressed => {
                self.modifiers.toggle_bit(ModifierState::NUM_LOCK);
            }
            KeyCode::ScrollLock if pressed => {
                self.modifiers.toggle_bit(ModifierState::SCROLL_LOCK);
            }
            _ => {}
        }
    }

    /// キーボードストリームを取得（所有権ベースのSPSC強制）
    ///
    /// デフォルトのUSキーマップを使用。他のキーマップが必要な場合は
    /// `take_stream_with_keymap()`を使用。
    ///
    /// # Errors
    /// 既にストリームが発行されている場合は`Err(StreamAlreadyTaken)`を返す。
    /// これにより、呼び出し元でフォールバック処理（シリアルコンソールへの切り替えなど）が可能。
    ///
    /// # Returns
    /// キーイベントを受信するためのストリーム
    ///
    /// # Example
    /// ```ignore
    /// match keyboard.take_stream() {
    ///     Ok(stream) => { /* キーボード入力を使用 */ }
    ///     Err(StreamAlreadyTaken) => {
    ///         log!("Keyboard stream already taken, falling back to serial");
    ///     }
    /// }
    /// ```
    pub fn take_stream(&'static self) -> Result<KeyboardStream, StreamAlreadyTaken> {
        self.take_stream_with_keymap(&DEFAULT_KEYMAP)
    }

    /// 指定されたキーマップでキーボードストリームを取得
    ///
    /// # Arguments
    /// * `keymap` - 使用するキーマップ（'staticライフタイム必須）
    ///
    /// # Errors
    /// 既にストリームが発行されている場合は`Err(StreamAlreadyTaken)`を返す。
    ///
    /// # Example
    /// ```ignore
    /// static JIS_KEYMAP: JisKeymap = JisKeymap::new();
    /// let stream = keyboard.take_stream_with_keymap(&JIS_KEYMAP)?;
    /// ```
    pub fn take_stream_with_keymap(
        &'static self,
        keymap: &'static dyn Keymap,
    ) -> Result<KeyboardStream, StreamAlreadyTaken> {
        if self.stream_taken.swap(true, Ordering::SeqCst) {
            return Err(StreamAlreadyTaken);
        }
        Ok(KeyboardStream {
            driver: self,
            keymap,
        })
    }

    /// Arc<dyn Keymap>を使用するキーボードストリームを取得 (Phase 5)
    ///
    /// 動的なキーマップ切り替えや、'staticでないキーマップが必要な場合に使用。
    ///
    /// # Arguments
    /// * `keymap` - 使用するキーマップ（Arc<dyn Keymap>）
    ///
    /// # Errors
    /// 既にストリームが発行されている場合は`Err(StreamAlreadyTaken)`を返す。
    ///
    /// # Example
    /// ```ignore
    /// let custom_keymap = Arc::new(MyCustomKeymap::new());
    /// let stream = keyboard.take_stream_with_arc_keymap(custom_keymap)?;
    ///
    /// // キーマップをランタイムで切り替え
    /// stream.set_keymap(Arc::new(AnotherKeymap::new()));
    /// ```
    ///
    /// # Performance Consideration
    /// 静的なキーマップで十分な場合は`take_stream_with_keymap()`を使用してください。
    /// `KeyboardStreamArc`は`Arc`のオーバーヘッド（参照カウント）があります。
    pub fn take_stream_with_arc_keymap(
        &'static self,
        keymap: Arc<dyn Keymap>,
    ) -> Result<KeyboardStreamArc, StreamAlreadyTaken> {
        if self.stream_taken.swap(true, Ordering::SeqCst) {
            return Err(StreamAlreadyTaken);
        }
        Ok(KeyboardStreamArc {
            driver: self,
            keymap,
        })
    }

    /// キーボードストリームを取得（パニック版・テスト/初期化用）
    ///
    /// # Panics
    /// 既にストリームが発行されている場合
    ///
    /// # Note
    /// 本番コードでは`take_stream()`を使用し、エラーハンドリングを行うこと。
    pub fn take_stream_or_panic(&'static self) -> KeyboardStream {
        self.take_stream().expect("SPSC violation: Stream already taken")
    }

    /// ストリームを返却（テスト用）
    fn return_stream(&self) {
        self.stream_taken.store(false, Ordering::SeqCst);
    }

    /// Wakerを登録（内部用）
    fn register_waker(&self, waker: &Waker) {
        self.waker.register(waker);
    }

    /// 保留中のISR通知があれば起床処理を実行
    ///
    /// # 使用場面
    /// 1. Executorのポーリングループで定期的に呼び出す
    /// 2. Futureのpoll()開始時に呼び出す
    ///
    /// ISRは`notify()`でフラグを立てるだけなので、
    /// 実際の`wake()`はこのメソッドで行う。
    ///
    /// # Returns
    /// `true`: 起床を実行した（Waker::wake_by_ref()を呼んだ）
    /// `false`: 保留なしまたはWaker未登録
    pub fn process_pending_wake(&self) -> bool {
        self.waker.check_and_wake()
    }

    /// 保留中の起床があるか（Executorがポーリング判断用）
    pub fn has_pending_wake(&self) -> bool {
        self.waker.is_pending()
    }

    /// イベントがあるかチェック
    pub fn has_event(&self) -> bool {
        !self.queue.is_empty()
    }

    /// 現在の修飾キー状態を取得
    pub fn get_modifiers(&self) -> Modifiers {
        self.modifiers.snapshot()
    }

    // =========================================================================
    // 内部API（モジュール内のみ使用）
    // =========================================================================

    /// 次のキーイベントを取得（非ブロッキング）
    ///
    /// # ⚠️ Deprecated
    /// この関数は後方互換性のためにのみ存在します。
    /// SPSC契約を破る可能性があるため、新しいコードでは使用しないでください。
    ///
    /// # Note
    /// この関数は `KeyboardStream` 経由でのみ使用すべきです。
    /// 直接呼び出すとSPSC契約が保証されません。
    #[deprecated(
        since = "0.3.0",
        note = "SPSC contract violation risk. Use KeyboardStream::poll() instead. \
                This function will be removed in Phase 4."
    )]
    #[doc(hidden)]
    pub(crate) fn poll_key_event(&self) -> Option<KeyEvent> {
        self.poll_key_event_internal()
    }
}

// ============================================================================
// KeyboardStream - 所有権ベースのSPSC Consumer
// ============================================================================

/// キーボード入力ストリーム
///
/// このストリームの所有者だけがキーイベントを受信できる。
/// `Clone`不可なので、所有権の移動によってのみ受け渡し可能。
/// これにより、コンパイル時にConsumerの単一性が保証される。
///
/// # Dynamic Keymap
/// ストリーム作成時にキーマップを指定可能。指定しない場合はUS配列がデフォルト。
/// キーマップは `'static` ライフタイムが必要（グローバル定義を推奨）。
pub struct KeyboardStream {
    driver: &'static KeyboardDriver,
    keymap: &'static dyn Keymap,
}

impl KeyboardStream {
    /// 次のキーイベントを非同期で待機
    pub fn read_key(&mut self) -> KeyEventFuture {
        KeyEventFuture {
            driver: self.driver,
        }
    }

    /// 次の文字を非同期で待機
    ///
    /// ストリーム作成時に指定されたキーマップを使用して
    /// キーコードを文字に変換します。
    ///
    /// # 動作詳細
    /// キューに複数のイベントがある場合、文字に変換できるイベントが見つかるまで
    /// すべてのイベントを処理します。Releasedイベントや変換できないキー（修飾キーなど）は
    /// スキップされます。
    ///
    /// # Performance
    /// - **Average case**: O(1) - ほとんどの場合、最初のイベントが文字
    /// - **Worst case**: O(QUEUE_SIZE) - 128回のループ（修飾キーのみのイベント列など）
    ///
    /// 最悪の場合でも128回のループは許容範囲内として設計されています。
    pub fn read_char(&mut self) -> CharFuture {
        CharFuture {
            driver: self.driver,
            keymap: self.keymap,
            budget: DEFAULT_POLL_BUDGET,
        }
    }

    /// 次の文字を非同期で待機（カスタムバジェット）
    ///
    /// 高負荷環境やリアルタイム要件が厳しい場合に、
    /// バジェットを調整できます。
    ///
    /// # Arguments
    /// * `budget` - 1回pollで処理するイベントの最大数
    ///
    /// # Example
    /// ```ignore
    /// // 高頻度入力が予想される場合はバジェットを大きく
    /// let ch = stream.read_char_with_budget(32).await;
    /// // リアルタイム性が重要な場合は小さく
    /// let ch = stream.read_char_with_budget(4).await;
    /// ```
    pub fn read_char_with_budget(&mut self, budget: usize) -> CharFuture {
        CharFuture {
            driver: self.driver,
            keymap: self.keymap,
            budget,
        }
    }

    /// 次のキーイベントをポーリング（ノンブロッキング）
    pub fn poll(&mut self) -> Option<KeyEvent> {
        self.driver.poll_key_event_internal()
    }

    /// イベントがあるかチェック
    pub fn has_event(&self) -> bool {
        self.driver.has_event()
    }

    /// 現在の修飾キー状態を取得
    pub fn modifiers(&self) -> Modifiers {
        self.driver.get_modifiers()
    }

    /// 現在のキーマップを取得
    pub fn keymap(&self) -> &'static dyn Keymap {
        self.keymap
    }
}

/// # Panic Handling
///
/// パニック時もストリームは自動返却されます。これにより、
/// パニック後の部分的なリカバリーが可能になりますが、
/// ドライバの内部状態（修飾キー、Wakerなど）は不整合の可能性があります。
///
/// 確実な動作のためには、パニック後はシステム全体を再起動してください。
///
/// # 設計判断
/// - **Option A（現在の実装）**: 常に返却 → パニック後のリカバリー可能
/// - Option B: パニック時は返却しない → 明示的なrelease()が必要
///
/// 組み込みシステムの実用性を考慮し、Option Aを採用しています。
impl Drop for KeyboardStream {
    fn drop(&mut self) {
        self.driver.return_stream();
    }
}

// Clone不可（SPSC強制）
// impl !Clone for KeyboardStream {}  // negative impl は nightly のみ

// ============================================================================
// KeyboardStreamArc - Arc<dyn Keymap>を使用する動的キーマップストリーム (Phase 5)
// ============================================================================

/// 動的キーマップを使用するキーボード入力ストリーム (Phase 5)
///
/// `KeyboardStream`と異なり、`Arc<dyn Keymap>`を所有することで
/// ランタイムでのキーマップ切り替えや、'staticでないキーマップの使用が可能。
///
/// # Use Cases
/// - ユーザー設定に基づくキーマップの動的ロード
/// - カスタムキーマップの実装（ゲーム固有のキーバインドなど）
/// - テストでのモックキーマップ使用
///
/// # Memory Overhead
/// - `KeyboardStream`: キーマップへの参照（ポインタサイズ）
/// - `KeyboardStreamArc`: `Arc`のオーバーヘッド（参照カウント + ポインタ）
///
/// 静的なキーマップで十分な場合は`KeyboardStream`を使用してください。
pub struct KeyboardStreamArc {
    driver: &'static KeyboardDriver,
    keymap: Arc<dyn Keymap>,
}

impl KeyboardStreamArc {
    /// 次のキーイベントを非同期で待機
    pub fn read_key(&mut self) -> KeyEventFuture {
        KeyEventFuture {
            driver: self.driver,
        }
    }

    /// 次の文字を非同期で待機
    ///
    /// ストリーム作成時に指定されたキーマップを使用して
    /// キーコードを文字に変換します。
    pub fn read_char(&mut self) -> CharFutureArc<'_> {
        CharFutureArc {
            driver: self.driver,
            keymap: &self.keymap,
        }
    }

    /// 次のキーイベントをポーリング（ノンブロッキング）
    pub fn poll(&mut self) -> Option<KeyEvent> {
        self.driver.poll_key_event_internal()
    }

    /// イベントがあるかチェック
    pub fn has_event(&self) -> bool {
        self.driver.has_event()
    }

    /// 現在の修飾キー状態を取得
    pub fn modifiers(&self) -> Modifiers {
        self.driver.get_modifiers()
    }

    /// 現在のキーマップを取得（Arcクローン）
    pub fn keymap(&self) -> Arc<dyn Keymap> {
        Arc::clone(&self.keymap)
    }

    /// 現在のキーマップへの参照を取得
    pub fn keymap_ref(&self) -> &dyn Keymap {
        &*self.keymap
    }

    /// キーマップを変更（ランタイム切り替え）
    pub fn set_keymap(&mut self, keymap: Arc<dyn Keymap>) {
        self.keymap = keymap;
    }
}

impl Drop for KeyboardStreamArc {
    fn drop(&mut self) {
        self.driver.return_stream();
    }
}

/// 文字入力待ちFuture（Arc<dyn Keymap>版）
///
/// # Note
/// `CharFuture`と同様のバジェット制限（MAX_EVENTS_PER_POLL）を適用。
/// 詳細は`CharFuture`のドキュメントを参照。
pub struct CharFutureArc<'a> {
    driver: &'static KeyboardDriver,
    keymap: &'a Arc<dyn Keymap>,
}

impl Future for CharFutureArc<'_> {
    type Output = char;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // poll開始時に保留中のISR通知を処理
        self.driver.process_pending_wake();

        // イベント処理回数のバジェット制限
        // 最悪ケースでも DEFAULT_POLL_BUDGET 回で処理を打ち切り、
        // 他のタスクに実行機会を与える
        let mut events_processed = 0;

        // 文字が得られるまでループ（バジェット制限付き）
        loop {
            if events_processed >= DEFAULT_POLL_BUDGET {
                // バジェット超過: 次回pollに持ち越し
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }

            if let Some(event) = self.driver.poll_key_event_internal() {
                events_processed += 1;
                // Pressedイベントのみ処理
                if event.state == KeyState::Pressed {
                    if let Some(ch) = self.keymap.to_char(event.key, &event.modifiers) {
                        return Poll::Ready(ch);
                    }
                }
                // Released や変換できないキーは次へ
            } else {
                // キューが空
                self.driver.register_waker(cx.waker());
                // ダブルチェック
                if let Some(event) = self.driver.poll_key_event_internal() {
                    if event.state == KeyState::Pressed {
                        if let Some(ch) = self.keymap.to_char(event.key, &event.modifiers) {
                            return Poll::Ready(ch);
                        }
                    }
                    // 次のループへ
                } else {
                    return Poll::Pending;
                }
            }
        }
    }
}

// ============================================================================
// Async Futures
// ============================================================================

/// キーイベント待ちFuture
pub struct KeyEventFuture {
    driver: &'static KeyboardDriver,
}

impl Future for KeyEventFuture {
    type Output = KeyEvent;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // ✅ poll開始時に保留中のISR通知を処理
        // ISRは notify() でフラグを立てるだけなので、
        // 実際の wake() はここで行う
        self.driver.process_pending_wake();

        if let Some(event) = self.driver.poll_key_event_internal() {
            Poll::Ready(event)
        } else {
            self.driver.register_waker(cx.waker());
            // ダブルチェック: register後にデータが来ていないか
            if let Some(event) = self.driver.poll_key_event_internal() {
                Poll::Ready(event)
            } else {
                Poll::Pending
            }
        }
    }
}

/// 文字入力待ちFuture
///
/// # バジェット制限
/// 1回のpoll()で処理するイベント数は`budget`で制限される。
/// デフォルトは`DEFAULT_POLL_BUDGET`（16）だが、
/// `KeyboardStream::read_char_with_budget()`で変更可能。
pub struct CharFuture {
    driver: &'static KeyboardDriver,
    keymap: &'static dyn Keymap,
    /// 1回のpoll()で処理するイベントの最大数
    budget: usize,
}

/// デフォルトのpoll()バジェット
///
/// リアルタイム性を保つため、修飾キーだけが大量に来ても
/// poll()が長時間ブロックしないようにする。
pub const DEFAULT_POLL_BUDGET: usize = 16;

impl Future for CharFuture {
    type Output = char;

    /// # Performance
    ///
    /// - **Best case**: O(1) - 最初のイベントが文字に変換可能
    /// - **Typical case**: O(数個) - 修飾キーを数個スキップ
    /// - **Worst case**: O(MAX_EVENTS_PER_POLL) - バジェット制限で中断
    ///
    /// バジェット(MAX_EVENTS_PER_POLL=16)を超えた場合は`wake_by_ref()`で
    /// 次回pollに持ち越し。これによりExecutorの公平性を維持。
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // poll開始時に保留中のISR通知を処理
        self.driver.process_pending_wake();

        let mut events_checked: usize = 0;
        let budget = self.budget;

        loop {
            // バジェット制限: リアルタイム性のため
            if events_checked >= budget {
                // タイムスライス使い果たし - 次回に持ち越し
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }

            if let Some(event) = self.driver.poll_key_event_internal() {
                events_checked += 1;

                // Releasedイベントはスキップ
                if event.state == KeyState::Released {
                    continue;
                }
                // 文字に変換可能か
                if let Some(c) = self.keymap.to_char(event.key, &event.modifiers) {
                    return Poll::Ready(c);
                }
                // 変換できないキー（修飾キー等）はスキップ
                continue;
            } else {
                // キューが空 - Wakerを登録して待機
                self.driver.register_waker(cx.waker());

                // ダブルチェック: register後にデータが来ていないか
                if let Some(event) = self.driver.poll_key_event_internal() {
                    events_checked += 1;

                    if event.state == KeyState::Released {
                        continue;
                    }
                    if let Some(c) = self.keymap.to_char(event.key, &event.modifiers) {
                        return Poll::Ready(c);
                    }
                    // 変換できなければ次のループへ
                    continue;
                }
                return Poll::Pending;
            }
        }
    }
}

// ============================================================================
// グローバルインスタンス（PS/2キーボード用）
// ============================================================================

/// グローバルPS/2キーボードドライバ
///
/// 単一のPS/2キーボードをサポートする場合はこれを使用。
/// 複数デバイスが必要な場合は、別のインスタンスを作成してください。
static PS2_KEYBOARD: KeyboardDriver = KeyboardDriver::new();

/// PS/2キーボードドライバにアクセス
pub fn keyboard() -> &'static KeyboardDriver {
    &PS2_KEYBOARD
}

/// PS/2キーボードを初期化
pub fn init() {
    PS2_KEYBOARD.init();
}

/// 割り込みハンドラから呼ばれる（PS/2キーボード用）
pub fn handle_keyboard_interrupt(scancode: u8) {
    PS2_KEYBOARD.handle_scancode(scancode);
}

/// 保留中のISR通知を処理（Executorから呼び出し）
///
/// Executorのメインループで定期的に呼び出すことで、
/// ISRからの通知を確実にWaker起床に変換する。
///
/// # Example
/// ```ignore
/// loop {
///     // ISR通知の処理
///     keyboard::process_pending_wakes();
///
///     // タスクの実行
///     executor.poll_tasks();
/// }
/// ```
pub fn process_pending_wakes() -> bool {
    PS2_KEYBOARD.process_pending_wake()
}

// ============================================================================
// 内部API（crate内部使用・後方互換性）
// ============================================================================

/// 次のキーイベントをポーリング（非ブロッキング）
///
/// # Note
/// この関数はSPSC契約を強制しません。
/// 新しいコードでは`keyboard().take_stream()`を使用してください。
#[doc(hidden)]
pub(crate) fn poll_key_event() -> Option<KeyEvent> {
    PS2_KEYBOARD.poll_key_event()
}

/// 次の文字をポーリング（非ブロッキング）
///
/// # Note
/// 内部使用向け。新しいコードでは`KeyboardStream`を使用してください。
#[doc(hidden)]
pub(crate) fn poll_char() -> Option<char> {
    while let Some(event) = PS2_KEYBOARD.poll_key_event() {
        if let Some(c) = event.to_char() {
            return Some(c);
        }
    }
    None
}

/// イベントがあるかチェック
pub fn has_event() -> bool {
    PS2_KEYBOARD.has_event()
}

// ============================================================================
// テスト
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keycode_to_char() {
        assert_eq!(KeyCode::A.to_char(false, false), Some('a'));
        assert_eq!(KeyCode::A.to_char(true, false), Some('A'));
        assert_eq!(KeyCode::A.to_char(false, true), Some('A'));
        assert_eq!(KeyCode::A.to_char(true, true), Some('a'));
    }

    #[test]
    fn test_scancode_queue() {
        let queue = ScancodeQueue::new();

        assert!(queue.is_empty());
        assert!(queue.push(0x1E));
        assert!(!queue.is_empty());
        assert_eq!(queue.pop(), Some(0x1E));
        assert!(queue.is_empty());
    }

    #[test]
    fn test_scancode_queue_full() {
        let queue = ScancodeQueue::new();

        // Fill the queue
        for i in 0..SCANCODE_QUEUE_SIZE {
            assert!(queue.push(i as u16), "Push should succeed at index {}", i);
        }

        // Queue should be full now
        assert!(!queue.push(0xFFFF), "Push should fail when queue is full");

        // Verify all items can be popped in order
        for i in 0..SCANCODE_QUEUE_SIZE {
            assert_eq!(queue.pop(), Some(i as u16), "Pop should return correct value at index {}", i);
        }

        // Queue should be empty
        assert!(queue.is_empty());
        assert_eq!(queue.pop(), None);
    }

    #[test]
    fn test_scancode_queue_wraparound() {
        let queue = ScancodeQueue::new();

        // Push and pop some items to advance head/tail
        for i in 0..10u16 {
            assert!(queue.push(i));
            assert_eq!(queue.pop(), Some(i));
        }

        // Now fill the queue
        for i in 0..SCANCODE_QUEUE_SIZE {
            assert!(queue.push(i as u16));
        }

        // Pop all and verify
        for i in 0..SCANCODE_QUEUE_SIZE {
            assert_eq!(queue.pop(), Some(i as u16));
        }
    }

    #[test]
    fn test_modifier_snapshot() {
        let state = ModifierState::new();
        let snap = state.snapshot();
        assert!(!snap.shift);
        assert!(!snap.ctrl);
        assert!(!snap.alt);
    }

    #[test]
    fn test_modifier_state_bit_operations() {
        let state = ModifierState::new();

        // Set left shift
        state.set_bit(ModifierState::LEFT_SHIFT);
        let snap = state.snapshot();
        assert!(snap.shift);

        // Set right shift too
        state.set_bit(ModifierState::RIGHT_SHIFT);
        let snap = state.snapshot();
        assert!(snap.shift);

        // Clear left shift
        state.clear_bit(ModifierState::LEFT_SHIFT);
        let snap = state.snapshot();
        assert!(snap.shift); // Still true because right is pressed

        // Clear right shift
        state.clear_bit(ModifierState::RIGHT_SHIFT);
        let snap = state.snapshot();
        assert!(!snap.shift);
    }

    #[test]
    fn test_modifier_state_toggle() {
        let state = ModifierState::new();

        // Toggle caps lock on
        state.toggle_bit(ModifierState::CAPS_LOCK);
        assert!(state.snapshot().caps_lock);

        // Toggle caps lock off
        state.toggle_bit(ModifierState::CAPS_LOCK);
        assert!(!state.snapshot().caps_lock);
    }

    #[test]
    fn test_key_event_raw_scancode() {
        let event = KeyEvent {
            key: KeyCode::A,
            state: KeyState::Pressed,
            modifiers: Modifiers::default(),
            raw_scancode: 0x1E,
        };
        assert_eq!(event.raw_scancode, 0x1E);
    }

    #[test]
    fn test_key_event_to_char_with_modifiers() {
        // Normal press
        let event = KeyEvent {
            key: KeyCode::A,
            state: KeyState::Pressed,
            modifiers: Modifiers::default(),
            raw_scancode: 0x1E,
        };
        assert_eq!(event.to_char(), Some('a'));

        // Released key should not produce character
        let released = KeyEvent {
            key: KeyCode::A,
            state: KeyState::Released,
            modifiers: Modifiers::default(),
            raw_scancode: 0x9E,
        };
        assert_eq!(released.to_char(), None);

        // With shift
        let shifted = KeyEvent {
            key: KeyCode::A,
            state: KeyState::Pressed,
            modifiers: Modifiers { shift: true, ..Modifiers::default() },
            raw_scancode: 0x1E,
        };
        assert_eq!(shifted.to_char(), Some('A'));
    }

    #[test]
    fn test_control_characters() {
        let mods = Modifiers { ctrl: true, ..Modifiers::default() };

        // Ctrl+A through Ctrl+Z
        assert_eq!(DEFAULT_KEYMAP.to_char(KeyCode::A, &mods), Some('\x01'));
        assert_eq!(DEFAULT_KEYMAP.to_char(KeyCode::Z, &mods), Some('\x1A'));

        // Ctrl+[ = Escape
        assert_eq!(DEFAULT_KEYMAP.to_char(KeyCode::LeftBracket, &mods), Some('\x1B'));

        // Ctrl+\ = FS
        assert_eq!(DEFAULT_KEYMAP.to_char(KeyCode::Backslash, &mods), Some('\x1C'));

        // Ctrl+] = GS
        assert_eq!(DEFAULT_KEYMAP.to_char(KeyCode::RightBracket, &mods), Some('\x1D'));

        // Ctrl+^ = RS
        assert_eq!(DEFAULT_KEYMAP.to_char(KeyCode::Key6, &mods), Some('\x1E'));

        // Ctrl+- = US
        assert_eq!(DEFAULT_KEYMAP.to_char(KeyCode::Minus, &mods), Some('\x1F'));

        // Ctrl+/ = DEL
        assert_eq!(DEFAULT_KEYMAP.to_char(KeyCode::Slash, &mods), Some('\x7F'));
    }

    #[test]
    fn test_keymap_trait_default() {
        let mods = Modifiers::default();
        assert_eq!(DEFAULT_KEYMAP.to_char(KeyCode::Space, &mods), Some(' '));
        assert_eq!(DEFAULT_KEYMAP.to_char(KeyCode::Enter, &mods), Some('\n'));
        assert_eq!(DEFAULT_KEYMAP.to_char(KeyCode::Tab, &mods), Some('\t'));
        assert_eq!(DEFAULT_KEYMAP.to_char(KeyCode::Backspace, &mods), Some('\x08'));
    }

    #[test]
    fn test_dropped_events_saturating() {
        let driver = KeyboardDriver::new();

        // Access dropped_events counter directly for testing
        // Note: This tests the atomic fetch_update pattern
        let initial = driver.dropped_events.load(Ordering::Relaxed);
        assert_eq!(initial, 0);
    }

    // =========================================================================
    // Phase 5 テスト: テンキーサポート
    // =========================================================================

    #[test]
    fn test_numpad_scancode_mapping() {
        // 非拡張コード: テンキー
        assert_eq!(KeyCode::from_scancode(0x47, false), KeyCode::NumPad7);
        assert_eq!(KeyCode::from_scancode(0x48, false), KeyCode::NumPad8);
        assert_eq!(KeyCode::from_scancode(0x49, false), KeyCode::NumPad9);
        assert_eq!(KeyCode::from_scancode(0x4A, false), KeyCode::NumPadMinus);
        assert_eq!(KeyCode::from_scancode(0x4B, false), KeyCode::NumPad4);
        assert_eq!(KeyCode::from_scancode(0x4C, false), KeyCode::NumPad5);
        assert_eq!(KeyCode::from_scancode(0x4D, false), KeyCode::NumPad6);
        assert_eq!(KeyCode::from_scancode(0x4E, false), KeyCode::NumPadPlus);
        assert_eq!(KeyCode::from_scancode(0x4F, false), KeyCode::NumPad1);
        assert_eq!(KeyCode::from_scancode(0x50, false), KeyCode::NumPad2);
        assert_eq!(KeyCode::from_scancode(0x51, false), KeyCode::NumPad3);
        assert_eq!(KeyCode::from_scancode(0x52, false), KeyCode::NumPad0);
        assert_eq!(KeyCode::from_scancode(0x53, false), KeyCode::NumPadDecimal);
        assert_eq!(KeyCode::from_scancode(0x37, false), KeyCode::NumPadMultiply);

        // 拡張コード: ナビゲーションキー
        assert_eq!(KeyCode::from_scancode(0x47, true), KeyCode::Home);
        assert_eq!(KeyCode::from_scancode(0x48, true), KeyCode::Up);
        assert_eq!(KeyCode::from_scancode(0x49, true), KeyCode::PageUp);
        assert_eq!(KeyCode::from_scancode(0x4B, true), KeyCode::Left);
        assert_eq!(KeyCode::from_scancode(0x4D, true), KeyCode::Right);
        assert_eq!(KeyCode::from_scancode(0x4F, true), KeyCode::End);
        assert_eq!(KeyCode::from_scancode(0x50, true), KeyCode::Down);
        assert_eq!(KeyCode::from_scancode(0x51, true), KeyCode::PageDown);
        assert_eq!(KeyCode::from_scancode(0x52, true), KeyCode::Insert);
        assert_eq!(KeyCode::from_scancode(0x53, true), KeyCode::Delete);

        // 拡張テンキー
        assert_eq!(KeyCode::from_scancode(0x1C, true), KeyCode::NumPadEnter);
        assert_eq!(KeyCode::from_scancode(0x35, true), KeyCode::NumPadDivide);
    }

    #[test]
    fn test_numpad_to_char() {
        let mods = Modifiers::default();

        // テンキー数字
        assert_eq!(DEFAULT_KEYMAP.to_char(KeyCode::NumPad0, &mods), Some('0'));
        assert_eq!(DEFAULT_KEYMAP.to_char(KeyCode::NumPad1, &mods), Some('1'));
        assert_eq!(DEFAULT_KEYMAP.to_char(KeyCode::NumPad5, &mods), Some('5'));
        assert_eq!(DEFAULT_KEYMAP.to_char(KeyCode::NumPad9, &mods), Some('9'));

        // テンキー演算子
        assert_eq!(DEFAULT_KEYMAP.to_char(KeyCode::NumPadPlus, &mods), Some('+'));
        assert_eq!(DEFAULT_KEYMAP.to_char(KeyCode::NumPadMinus, &mods), Some('-'));
        assert_eq!(DEFAULT_KEYMAP.to_char(KeyCode::NumPadMultiply, &mods), Some('*'));
        assert_eq!(DEFAULT_KEYMAP.to_char(KeyCode::NumPadDivide, &mods), Some('/'));

        // テンキー特殊
        assert_eq!(DEFAULT_KEYMAP.to_char(KeyCode::NumPadDecimal, &mods), Some('.'));
        assert_eq!(DEFAULT_KEYMAP.to_char(KeyCode::NumPadEnter, &mods), Some('\n'));
    }

    // =========================================================================
    // Phase 5 テスト: マルチコアIsrSafeWaker
    // =========================================================================

    #[test]
    fn test_isr_safe_waker_epoch_based() {
        // IsrSafeWakerの基本動作テスト
        let waker = IsrSafeWaker::new();

        // 初期状態
        assert!(!waker.is_pending());
        assert!(!waker.is_registered());

        // notify()でpendingフラグが立つ
        waker.notify();
        assert!(waker.is_pending());

        // check_and_wake()でpendingフラグがクリアされる（Wakerなし）
        assert!(!waker.check_and_wake()); // Wakerなしなのでfalse
        assert!(!waker.is_pending());
    }

    #[test]
    fn test_isr_safe_waker_double_notify() {
        let waker = IsrSafeWaker::new();

        // 複数回notify()しても問題なし
        waker.notify();
        waker.notify();
        waker.notify();
        assert!(waker.is_pending());

        // 1回のcheck_and_wakeでクリア
        waker.check_and_wake();
        assert!(!waker.is_pending());
    }
}
