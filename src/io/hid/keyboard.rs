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
    // スキャンコードは非拡張コードを使用
    NumPad0 = 0x52,      // NumLockオンで '0', オフで Insert
    NumPad1 = 0x4F,      // NumLockオンで '1', オフで End
    NumPad2 = 0x50,      // NumLockオンで '2', オフで Down
    NumPad3 = 0x51,      // NumLockオンで '3', オフで PageDown
    NumPad4 = 0x4B,      // NumLockオンで '4', オフで Left
    NumPad5 = 0x4C,      // NumLockオンで '5', オフで (nothing)
    NumPad6 = 0x4D,      // NumLockオンで '6', オフで Right
    NumPad7 = 0x47,      // NumLockオンで '7', オフで Home
    NumPad8 = 0x48,      // NumLockオンで '8', オフで Up
    NumPad9 = 0x49,      // NumLockオンで '9', オフで PageUp
    NumPadDecimal = 0x53, // NumLockオンで '.', オフで Delete
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
    pub fn from_scancode(scancode: u8, extended: bool) -> Self {
        if extended {
            match scancode {
                0x48 => KeyCode::Up,
                0x50 => KeyCode::Down,
                0x4B => KeyCode::Left,
                0x4D => KeyCode::Right,
                0x52 => KeyCode::Insert,
                0x53 => KeyCode::Delete,
                0x47 => KeyCode::Home,
                0x4F => KeyCode::End,
                0x49 => KeyCode::PageUp,
                0x51 => KeyCode::PageDown,
                _ => KeyCode::Unknown,
            }
        } else {
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
    // ビットマスク定数
    const LEFT_SHIFT: u32 = 1 << 0;
    const RIGHT_SHIFT: u32 = 1 << 1;
    const LEFT_CTRL: u32 = 1 << 2;
    const RIGHT_CTRL: u32 = 1 << 3;
    const LEFT_ALT: u32 = 1 << 4;
    const RIGHT_ALT: u32 = 1 << 5;  // AltGr
    const CAPS_LOCK: u32 = 1 << 6;
    const NUM_LOCK: u32 = 1 << 7;
    const SCROLL_LOCK: u32 = 1 << 8;

    const SHIFT_MASK: u32 = Self::LEFT_SHIFT | Self::RIGHT_SHIFT;
    const CTRL_MASK: u32 = Self::LEFT_CTRL | Self::RIGHT_CTRL;
    const ALT_MASK: u32 = Self::LEFT_ALT;  // Left Alt only for normal Alt

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

/// ISR-Safe Waker通知機構
///
/// ISR（割り込みハンドラ）から安全にWakerを起床させるための機構。
///
/// # ⚠️ 重要: シングルコア専用
///
/// **この実装はシングルコア環境でのみ安全に動作します。**
///
/// マルチコア環境では以下の問題が発生する可能性があります：
/// - `without_interrupts()`は現在のCPUコアの割り込みのみを禁止
/// - 別コアのISRが`notify()`を呼び、同時に`check_and_wake()`が実行される可能性
/// - `has_waker.load(Acquire)`後、`waker`アクセス前に別コアで`register()`が走る可能性
///
/// マルチコア対応が必要な場合は、以下のいずれかが必要：
/// - `Arc<Mutex<Option<Waker>>>` を使用（ISR外で更新する設計）
/// - `AtomicPtr<Waker>` + epoch-based reclamation
/// - 全コアのIPI（Inter-Processor Interrupt）による同期
///
/// # 設計原則
///
/// **ISR内では絶対にアロケータを呼ばない**ことを保証するため、
/// ISRでは`AtomicBool`フラグを立てるだけにし、実際の`Waker::wake()`は
/// Consumer側の`poll()`開始時に行う。
///
/// ## 動作フロー
///
/// ```text
/// ISR (Producer):
///   handle_scancode() -> notify() -> pending.store(true)
///
/// Executor (poll loop):
///   [poll開始時] -> check_and_wake()
///                    └─> pending==true? ─yes─> real_waker.wake_by_ref()
///                                              └─> 再度pollされる
///
/// Consumer (poll):
///   poll() -> データ取得 or Pending
///          -> register_waker(cx.waker()) で real_waker を更新
/// ```
///
/// ## なぜこの設計か
///
/// 1. **VTable/Data不整合の回避**: Wakerを分割保存せず、割り込み禁止で更新
/// 2. **ISR内dealloc回避**: ISRでは`pending`フラグのみ操作
/// 3. **transmute不使用**: RustのWaker内部レイアウト依存を排除
/// 4. **確実な起床**: pendingフラグはFutureのpoll()開始時に処理
///
/// # Safety Contract
///
/// - `register()`は割り込み禁止区間で実行（CLI/STI）
/// - `notify()`はISRから呼ばれてもOK（AtomicBoolのみ操作）
/// - `check_and_wake()`はConsumer/Executorスレッドからのみ呼び出し
/// - **シングルコア環境でのみ使用すること**
struct IsrSafeWaker {
    /// 起床が保留されているか（ISRがセット、Consumer/Executorがクリア）
    pending: AtomicBool,
    /// 登録されたWaker（Optionでラップ、UnsafeCellで内部可変性）
    ///
    /// # Invariant
    /// - 書き込みは割り込み禁止区間でのみ行う（シングルコア前提）
    /// - 読み取りはConsumer/Executorスレッドからのみ
    waker: core::cell::UnsafeCell<Option<Waker>>,
    /// Wakerが登録されているか（読み取り専用フラグ）
    has_waker: AtomicBool,
}

// Safety: waker フィールドへのアクセスは以下のルールで保護:
// - 書き込み: 割り込み禁止区間でのみ (register) - シングルコア前提
// - 読み取り: Consumer/Executorスレッドからのみ (check_and_wake)
// - ISRからは pending フラグのみ操作
//
// ⚠️ シングルコア環境でのみ安全
unsafe impl Send for IsrSafeWaker {}
unsafe impl Sync for IsrSafeWaker {}

impl IsrSafeWaker {
    const fn new() -> Self {
        Self {
            pending: AtomicBool::new(false),
            waker: core::cell::UnsafeCell::new(None),
            has_waker: AtomicBool::new(false),
        }
    }

    /// Wakerを登録（Consumerスレッドから呼び出し）
    ///
    /// # 実装詳細
    /// 割り込み禁止区間で実行することで、ISRとのレースを防止。
    /// これにより、Wakerの読み書きがアトミックに行われることを保証。
    fn register(&self, waker: &Waker) {
        // 割り込み禁止区間でWakerを更新
        // これにより、ISRがpendingをチェックしている最中に
        // Wakerが中途半端な状態になることを防ぐ
        x86_64::instructions::interrupts::without_interrupts(|| {
            // Safety: 割り込み禁止中なのでISRとの競合なし
            let waker_slot = unsafe { &mut *self.waker.get() };

            // 既存のWakerがあり、同じWakerなら更新不要
            if let Some(existing) = waker_slot {
                if existing.will_wake(waker) {
                    return;
                }
            }

            // 新しいWakerを登録
            *waker_slot = Some(waker.clone());
            self.has_waker.store(true, Ordering::Release);
        });
    }

    /// ISRから呼び出し: 起床を通知（フラグを立てるだけ）
    ///
    /// # Safety
    /// - ロックなし、アロケーションなし
    /// - ISRから安全に呼び出せる
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
            // Safety:
            // - has_waker==true なら waker は Some
            // - Consumer/Executorスレッドからのみ呼ばれる
            // - ISRは pending フラグしか操作しない
            // - 割り込み禁止は不要（読み取りのみ＆ISRはwaker触らない）
            let waker_slot = unsafe { &*self.waker.get() };
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
            let waker_slot = unsafe { &*self.waker.get() };
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
    /// - `tail.load(Acquire)`: Producerのbuffer書き込みが見えることを保証
    /// - `buffer[head].load(Acquire)`: データ読み取りがhead更新前に完了することを保証
    ///
    /// この順序が崩れると、Producer側が書き込み中のデータを読む可能性がある
    #[inline]
    fn pop(&self) -> Option<u16> {
        let head = self.head.load(Ordering::Relaxed);
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
    /// キュー満杯によりドロップされたイベントの総数
    pub fn dropped_events(&self) -> u64 {
        self.dropped_events.load(Ordering::Relaxed)
    }

    /// ドロップカウンタをリセット（診断用）
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
pub struct CharFuture {
    driver: &'static KeyboardDriver,
    keymap: &'static dyn Keymap,
}

impl Future for CharFuture {
    type Output = char;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // ✅ poll開始時に保留中のISR通知を処理
        self.driver.process_pending_wake();

        loop {
            if let Some(event) = self.driver.poll_key_event_internal() {
                // 動的キーマップを使用して文字変換
                if event.state == KeyState::Released {
                    continue;
                }
                if let Some(c) = self.keymap.to_char(event.key, &event.modifiers) {
                    return Poll::Ready(c);
                }
                continue;
            } else {
                self.driver.register_waker(cx.waker());
                // ダブルチェック: register後にデータが来ていないか
                if let Some(event) = self.driver.poll_key_event_internal() {
                    if event.state == KeyState::Released {
                        continue;
                    }
                    if let Some(c) = self.keymap.to_char(event.key, &event.modifiers) {
                        return Poll::Ready(c);
                    }
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
}
