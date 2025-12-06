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

use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use core::task::{Context, Poll, Waker};

use crate::sync::IrqMutex;

// Keymapモジュールからインポート
pub use super::keymap::{DvorakKeymap, JisKeymap, Keymap, UsQwertyKeymap, DEFAULT_KEYMAP};

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
    /// 新しいコードでは`keymap.to_char(key, shift, caps_lock)`を直接使用してください。
    pub fn to_char(&self, shift: bool, caps_lock: bool) -> Option<char> {
        DEFAULT_KEYMAP.to_char(*self, shift, caps_lock)
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
    pub caps_lock: bool,
    pub num_lock: bool,
    pub scroll_lock: bool,
}

impl Modifiers {
    /// 任意の修飾キーが押されているか
    pub fn any(&self) -> bool {
        self.shift || self.ctrl || self.alt
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
        self.key
            .to_char(self.modifiers.shift, self.modifiers.caps_lock)
    }

    /// 指定されたキーマップで文字に変換
    pub fn to_char_with_keymap<K: Keymap>(&self, keymap: &K) -> Option<char> {
        if self.state == KeyState::Released {
            return None;
        }
        keymap.to_char(self.key, self.modifiers.shift, self.modifiers.caps_lock)
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

/// 修飾キーの内部状態
struct ModifierState {
    left_shift: AtomicBool,
    right_shift: AtomicBool,
    left_ctrl: AtomicBool,
    right_ctrl: AtomicBool,
    left_alt: AtomicBool,
    right_alt: AtomicBool,
    caps_lock: AtomicBool,
    num_lock: AtomicBool,
    scroll_lock: AtomicBool,
}

impl ModifierState {
    const fn new() -> Self {
        Self {
            left_shift: AtomicBool::new(false),
            right_shift: AtomicBool::new(false),
            left_ctrl: AtomicBool::new(false),
            right_ctrl: AtomicBool::new(false),
            left_alt: AtomicBool::new(false),
            right_alt: AtomicBool::new(false),
            caps_lock: AtomicBool::new(false),
            num_lock: AtomicBool::new(false),
            scroll_lock: AtomicBool::new(false),
        }
    }

    fn snapshot(&self) -> Modifiers {
        Modifiers {
            shift: self.left_shift.load(Ordering::Relaxed)
                || self.right_shift.load(Ordering::Relaxed),
            ctrl: self.left_ctrl.load(Ordering::Relaxed)
                || self.right_ctrl.load(Ordering::Relaxed),
            alt: self.left_alt.load(Ordering::Relaxed)
                || self.right_alt.load(Ordering::Relaxed),
            caps_lock: self.caps_lock.load(Ordering::Relaxed),
            num_lock: self.num_lock.load(Ordering::Relaxed),
            scroll_lock: self.scroll_lock.load(Ordering::Relaxed),
        }
    }
}

// ============================================================================
// AtomicWaker - 厳密なSPSCのためのWaker管理
// ============================================================================

/// Atomic Waker（単一Waker専用）
///
/// SPSCの契約を強制するため、2つ目のWaker登録は許可しない。
/// `futures`クレートの`AtomicWaker`と同様の機能だが、SPSC違反検出機能付き。
struct AtomicWaker {
    waker: IrqMutex<Option<Waker>>,
    /// Consumer登録済みフラグ
    registered: AtomicBool,
}

impl AtomicWaker {
    const fn new() -> Self {
        Self {
            waker: IrqMutex::new(None),
            registered: AtomicBool::new(false),
        }
    }

    /// Wakerを登録
    ///
    /// # Panics
    /// 既に異なるWakerが登録されている場合（SPSC違反）
    fn register(&self, waker: &Waker) {
        let mut guard = self.waker.lock();

        if let Some(existing) = guard.as_ref() {
            if existing.will_wake(waker) {
                // 同じWakerなら何もしない
                return;
            }
            // 異なるWakerが既に登録されている
            // これはSPSC違反の可能性が高い
            #[cfg(debug_assertions)]
            {
                crate::log!(
                    "[KEYBOARD] Warning: Different waker registered. Possible SPSC violation.\n"
                );
            }
        }

        *guard = Some(waker.clone());
        self.registered.store(true, Ordering::Release);
    }

    /// Wakerを起床させてクリア
    fn wake(&self) {
        if let Some(waker) = self.waker.lock().take() {
            self.registered.store(false, Ordering::Release);
            waker.wake();
        }
    }

    /// Wakerが登録されているか
    #[allow(dead_code)]
    fn is_registered(&self) -> bool {
        self.registered.load(Ordering::Acquire)
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
    /// Waker（単一Consumer用）
    waker: AtomicWaker,
    /// ストリーム発行済みフラグ
    stream_taken: AtomicBool,
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
    pub fn handle_scancode(&self, scancode: u8) {
        if scancode == SCANCODE_EXTENDED_PREFIX {
            self.extended_pending.store(true, Ordering::Relaxed);
            return;
        }

        let extended = self.extended_pending.swap(false, Ordering::Relaxed);
        let data: u16 = (scancode as u16) | if extended { QUEUE_EXTENDED_FLAG } else { 0 };

        if self.queue.push(data) {
            self.waker.wake();
        }
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
        match key {
            KeyCode::LeftShift => self
                .modifiers
                .left_shift
                .store(!released, Ordering::Relaxed),
            KeyCode::RightShift => self
                .modifiers
                .right_shift
                .store(!released, Ordering::Relaxed),
            KeyCode::LeftCtrl => {
                if extended {
                    self.modifiers
                        .right_ctrl
                        .store(!released, Ordering::Relaxed);
                } else {
                    self.modifiers
                        .left_ctrl
                        .store(!released, Ordering::Relaxed);
                }
            }
            KeyCode::LeftAlt => {
                if extended {
                    self.modifiers
                        .right_alt
                        .store(!released, Ordering::Relaxed);
                } else {
                    self.modifiers.left_alt.store(!released, Ordering::Relaxed);
                }
            }
            KeyCode::CapsLock if !released => {
                let current = self.modifiers.caps_lock.load(Ordering::Relaxed);
                self.modifiers.caps_lock.store(!current, Ordering::Relaxed);
            }
            KeyCode::NumLock if !released => {
                let current = self.modifiers.num_lock.load(Ordering::Relaxed);
                self.modifiers.num_lock.store(!current, Ordering::Relaxed);
            }
            KeyCode::ScrollLock if !released => {
                let current = self.modifiers.scroll_lock.load(Ordering::Relaxed);
                self.modifiers
                    .scroll_lock
                    .store(!current, Ordering::Relaxed);
            }
            _ => {}
        }
    }

    /// キーボードストリームを取得（所有権ベースのSPSC強制）
    ///
    /// # Panics
    /// 既にストリームが発行されている場合（SPSC違反）
    ///
    /// # Returns
    /// キーイベントを受信するためのストリーム
    pub fn take_stream(&'static self) -> KeyboardStream {
        if self.stream_taken.swap(true, Ordering::SeqCst) {
            panic!("[KEYBOARD] SPSC violation: Stream already taken. Only one consumer allowed.");
        }
        KeyboardStream { driver: self }
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
