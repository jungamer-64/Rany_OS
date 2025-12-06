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
//!         └───────── AtomicWaker (Single) ◀───────────────┘
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
// AtomicWaker - ロックフリーWaker管理
// ============================================================================

/// ロックフリーAtomicWaker（ISR安全版）
///
/// ISR（割り込みハンドラ）から安全に呼び出せるよう、
/// **一切のロック（Mutex/SpinLock）を使用せず、
/// ISR内でのメモリ解放も行わない**実装。
///
/// # 設計
/// `Waker`の内部構造（data + vtable）を直接アトミック変数に保持。
/// これにより、ヒープアロケーションを完全に排除。
///
/// # 状態遷移
/// ```text
/// IDLE (0, 0) ─── register() ──▶ REGISTERED (data, vtable)
///      ▲                              │
///      └────── wake() ────────────────┘
/// ```
///
/// # Safety
/// - `register()`はConsumerスレッドからのみ呼び出される（SPSC契約）
/// - `wake()`はISRから呼び出される可能性がある
/// - **ISR内でのメモリ解放なし**（アロケータデッドロック回避）
struct AtomicWaker {
    /// Waker内部のdataポインタ（AtomicU64として保持）
    /// 0 = 未登録
    waker_data: core::sync::atomic::AtomicU64,
    /// Waker内部のvtableポインタ（AtomicU64として保持）
    waker_vtable: core::sync::atomic::AtomicU64,
}

impl AtomicWaker {
    const fn new() -> Self {
        Self {
            waker_data: core::sync::atomic::AtomicU64::new(0),
            waker_vtable: core::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Wakerを登録（Consumerスレッドから呼び出し）
    ///
    /// # Note
    /// Wakerの内部構造（RawWaker）を直接保持することで、
    /// ヒープアロケーションを回避。
    fn register(&self, waker: &Waker) {
        // Wakerをcloneして所有権を取得
        let waker_clone = waker.clone();

        // Wakerの内部構造を取り出す
        // Safety: Waker は RawWaker(data, vtable) のラッパー
        let raw: core::task::RawWaker = unsafe {
            // Waker -> RawWaker への変換
            // Waker::as_raw() は nightly なので、transmute で対応
            core::mem::transmute(waker_clone)
        };

        // RawWaker から data と vtable を取り出す
        // RawWaker の内部構造: (data: *const (), vtable: &'static RawWakerVTable)
        let (data, vtable): (*const (), *const core::task::RawWakerVTable) = unsafe {
            core::mem::transmute(raw)
        };

        // アトミックに保存
        // Note: 順序が重要 - vtableを先に書いてからdataを書く
        // wake()側はdataを先に読むので、data!=0ならvtableも有効
        self.waker_vtable.store(vtable as u64, Ordering::Release);
        self.waker_data.store(data as u64, Ordering::Release);
    }

    /// Wakerを起床させてクリア（ISRから呼び出し可能）
    ///
    /// # Safety
    /// - ロックフリーなのでISRから安全に呼び出せる
    /// - **メモリ解放なし**: wake()はWakerの参照を消費するが、
    ///   RawWakerVTable::wake は内部でclone+dropを適切に処理する
    /// - CASにより、複数回のwake()呼び出しでも二重起床しない
    fn wake(&self) {
        // dataをアトミックに取得してクリア
        let data = self.waker_data.swap(0, Ordering::AcqRel);

        if data != 0 {
            // vtableを取得（dataが有効だったのでvtableも有効）
            let vtable = self.waker_vtable.load(Ordering::Acquire);

            // RawWakerを再構築
            let raw_waker: core::task::RawWaker = unsafe {
                core::mem::transmute((data as *const (), vtable as *const core::task::RawWakerVTable))
            };

            // Wakerを再構築して起床
            // Safety: register()で保存した有効なRawWaker
            let waker = unsafe { Waker::from_raw(raw_waker) };
            waker.wake();
            // Note: wake()は自身を消費し、RawWakerVTable::wake経由で
            // 適切にリソースを解放する。これはアロケータを呼ばない
            // （Wakerの実装依存だが、通常は参照カウントのデクリメントのみ）
        }
    }

    /// Wakerを起床させるが、Wakerは保持したまま（wake_by_ref相当）
    ///
    /// 複数回起床させる必要がある場合に使用。
    #[allow(dead_code)]
    fn wake_by_ref(&self) {
        let data = self.waker_data.load(Ordering::Acquire);

        if data != 0 {
            let vtable = self.waker_vtable.load(Ordering::Acquire);

            // RawWakerを再構築
            let raw_waker: core::task::RawWaker = unsafe {
                core::mem::transmute((data as *const (), vtable as *const core::task::RawWakerVTable))
            };

            // Wakerを再構築
            let waker = unsafe { Waker::from_raw(raw_waker) };

            // wake_by_ref相当: cloneしてwake
            waker.wake_by_ref();

            // wakerをリークして二重解放を防ぐ
            // （register時にcloneしたWakerの所有権を維持）
            core::mem::forget(waker);
        }
    }

    /// Wakerが登録されているか
    #[allow(dead_code)]
    fn is_registered(&self) -> bool {
        self.waker_data.load(Ordering::Acquire) != 0
    }
}

// Note: Dropは不要
// register()で保存したWakerは、wake()で消費されるか、
// KeyboardDriverがstaticなので実質リークしても問題ない

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

    #[inline]
    fn push(&self, data: u16) -> bool {
        let tail = self.tail.load(Ordering::Relaxed);
        let head = self.head.load(Ordering::Acquire);

        let next_tail = (tail + 1) & SCANCODE_QUEUE_MASK;
        if next_tail == head {
            return false;
        }

        self.buffer[tail].store(data, Ordering::Relaxed);
        self.tail.store(next_tail, Ordering::Release);
        true
    }

    #[inline]
    fn pop(&self) -> Option<u16> {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Acquire);

        if head == tail {
            return None;
        }

        let data = self.buffer[head].load(Ordering::Relaxed);
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
    /// Waker（単一Consumer用・ロックフリー）
    waker: AtomicWaker,
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
            waker: AtomicWaker::new(),
            stream_taken: AtomicBool::new(false),
            dropped_events: AtomicU64::new(0),
        }
    }

    /// ドライバを初期化
    pub fn init(&self) {
        if self.initialized.swap(true, Ordering::SeqCst) {
            return;
        }
        crate::log!("[KEYBOARD] Keyboard driver initialized (Instance-based)\n");
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
            self.waker.wake();
        } else {
            // キュー満杯: イベントドロップを記録
            // ISR内なのでログ出力は避け、カウンタのみインクリメント
            self.dropped_events.fetch_add(1, Ordering::Relaxed);
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

        Some(KeyEvent {
            key,
            state,
            modifiers: self.modifiers.snapshot(),
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
        if self.stream_taken.swap(true, Ordering::SeqCst) {
            return Err(StreamAlreadyTaken);
        }
        Ok(KeyboardStream { driver: self })
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

    /// イベントがあるかチェック
    pub fn has_event(&self) -> bool {
        !self.queue.is_empty()
    }

    /// 現在の修飾キー状態を取得
    pub fn get_modifiers(&self) -> Modifiers {
        self.modifiers.snapshot()
    }

    // =========================================================================
    // 後方互換性API（Deprecated）
    // =========================================================================

    /// 次のキーイベントを取得（非ブロッキング）
    ///
    /// # Warning
    /// この関数はSPSC契約を型レベルで強制しません。
    /// 新しいコードでは`take_stream()`を使用してください。
    pub fn poll_key_event(&self) -> Option<KeyEvent> {
        self.poll_key_event_internal()
    }

    /// 次のキーイベントを非同期で待機
    ///
    /// # Deprecated
    /// 代わりに`take_stream()`を使用してください。
    #[deprecated(
        since = "0.3.0",
        note = "Use take_stream() for ownership-based SPSC guarantee"
    )]
    pub fn read_key(&'static self) -> KeyEventFuture {
        KeyEventFuture { driver: self }
    }

    /// 次の文字を非同期で待機
    ///
    /// # Deprecated
    /// 代わりに`take_stream()`を使用してください。
    #[deprecated(
        since = "0.3.0",
        note = "Use take_stream() and KeyboardStream::read_char()"
    )]
    pub fn read_char(&'static self) -> CharFuture {
        CharFuture { driver: self }
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
pub struct KeyboardStream {
    driver: &'static KeyboardDriver,
}

impl KeyboardStream {
    /// 次のキーイベントを非同期で待機
    pub fn read_key(&mut self) -> KeyEventFuture {
        KeyEventFuture {
            driver: self.driver,
        }
    }

    /// 次の文字を非同期で待機
    pub fn read_char(&mut self) -> CharFuture {
        CharFuture {
            driver: self.driver,
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
}

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
        if let Some(event) = self.driver.poll_key_event_internal() {
            Poll::Ready(event)
        } else {
            self.driver.register_waker(cx.waker());
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
}

impl Future for CharFuture {
    type Output = char;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            if let Some(event) = self.driver.poll_key_event_internal() {
                if let Some(c) = event.to_char() {
                    return Poll::Ready(c);
                }
                continue;
            } else {
                self.driver.register_waker(cx.waker());
                if let Some(event) = self.driver.poll_key_event_internal() {
                    if let Some(c) = event.to_char() {
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

// ============================================================================
// 後方互換性API
// ============================================================================

/// 次のキーイベントをポーリング（非ブロッキング）
///
/// # Warning
/// この関数はSPSC契約を強制しません。
/// 新しいコードでは`keyboard().take_stream()`を使用してください。
pub fn poll_key_event() -> Option<KeyEvent> {
    PS2_KEYBOARD.poll_key_event()
}

/// 次の文字をポーリング（非ブロッキング）
pub fn poll_char() -> Option<char> {
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
    fn test_modifier_snapshot() {
        let state = ModifierState::new();
        let snap = state.snapshot();
        assert!(!snap.shift);
        assert!(!snap.ctrl);
        assert!(!snap.alt);
    }
}
