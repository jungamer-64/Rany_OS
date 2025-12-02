// ============================================================================
// src/io/keyboard.rs - Async Keyboard Driver
// 設計書 フェーズ2: キーボード入力の非同期処理化
// ============================================================================
//!
//! # 非同期キーボードドライバ
//!
//! PS/2キーボードからの入力を非同期Futureとして提供。
//! Interrupt-Wakerブリッジと連携して、割り込み駆動の入力処理を実現。
//!
//! ## 設計原則
//! - ロックフリーなキューによるスキャンコード管理
//! - async/awaitによるブロッキングなしの入力待ち
//! - 標準的なUS配列のキーマップ

#![allow(dead_code)]

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use alloc::collections::VecDeque;
use spin::Mutex;

// ============================================================================
// スキャンコードとキーコード
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
    
    // 不明
    Unknown = 0xFF,
}

impl KeyCode {
    /// スキャンコードからキーコードに変換
    pub fn from_scancode(scancode: u8, extended: bool) -> Self {
        if extended {
            // 拡張スキャンコード（0xE0プレフィックス）
            match scancode {
                0x48 => KeyCode::Up,
                0x50 => KeyCode::Down,
                0x4B => KeyCode::Left,
                0x4D => KeyCode::Right,
                _ => KeyCode::Unknown,
            }
        } else {
            // 通常のスキャンコード
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
    
    /// キーコードをASCII文字に変換（シフトなし）
    pub fn to_char(&self, shift: bool, caps_lock: bool) -> Option<char> {
        let base = match self {
            KeyCode::Key1 => if shift { '!' } else { '1' },
            KeyCode::Key2 => if shift { '@' } else { '2' },
            KeyCode::Key3 => if shift { '#' } else { '3' },
            KeyCode::Key4 => if shift { '$' } else { '4' },
            KeyCode::Key5 => if shift { '%' } else { '5' },
            KeyCode::Key6 => if shift { '^' } else { '6' },
            KeyCode::Key7 => if shift { '&' } else { '7' },
            KeyCode::Key8 => if shift { '*' } else { '8' },
            KeyCode::Key9 => if shift { '(' } else { '9' },
            KeyCode::Key0 => if shift { ')' } else { '0' },
            KeyCode::Minus => if shift { '_' } else { '-' },
            KeyCode::Equals => if shift { '+' } else { '=' },
            KeyCode::LeftBracket => if shift { '{' } else { '[' },
            KeyCode::RightBracket => if shift { '}' } else { ']' },
            KeyCode::Semicolon => if shift { ':' } else { ';' },
            KeyCode::Quote => if shift { '"' } else { '\'' },
            KeyCode::BackTick => if shift { '~' } else { '`' },
            KeyCode::Backslash => if shift { '|' } else { '\\' },
            KeyCode::Comma => if shift { '<' } else { ',' },
            KeyCode::Period => if shift { '>' } else { '.' },
            KeyCode::Slash => if shift { '?' } else { '/' },
            KeyCode::Space => ' ',
            KeyCode::Enter => '\n',
            KeyCode::Tab => '\t',
            KeyCode::Backspace => '\x08',
            
            // 文字キー
            KeyCode::Q => if shift ^ caps_lock { 'Q' } else { 'q' },
            KeyCode::W => if shift ^ caps_lock { 'W' } else { 'w' },
            KeyCode::E => if shift ^ caps_lock { 'E' } else { 'e' },
            KeyCode::R => if shift ^ caps_lock { 'R' } else { 'r' },
            KeyCode::T => if shift ^ caps_lock { 'T' } else { 't' },
            KeyCode::Y => if shift ^ caps_lock { 'Y' } else { 'y' },
            KeyCode::U => if shift ^ caps_lock { 'U' } else { 'u' },
            KeyCode::I => if shift ^ caps_lock { 'I' } else { 'i' },
            KeyCode::O => if shift ^ caps_lock { 'O' } else { 'o' },
            KeyCode::P => if shift ^ caps_lock { 'P' } else { 'p' },
            KeyCode::A => if shift ^ caps_lock { 'A' } else { 'a' },
            KeyCode::S => if shift ^ caps_lock { 'S' } else { 's' },
            KeyCode::D => if shift ^ caps_lock { 'D' } else { 'd' },
            KeyCode::F => if shift ^ caps_lock { 'F' } else { 'f' },
            KeyCode::G => if shift ^ caps_lock { 'G' } else { 'g' },
            KeyCode::H => if shift ^ caps_lock { 'H' } else { 'h' },
            KeyCode::J => if shift ^ caps_lock { 'J' } else { 'j' },
            KeyCode::K => if shift ^ caps_lock { 'K' } else { 'k' },
            KeyCode::L => if shift ^ caps_lock { 'L' } else { 'l' },
            KeyCode::Z => if shift ^ caps_lock { 'Z' } else { 'z' },
            KeyCode::X => if shift ^ caps_lock { 'X' } else { 'x' },
            KeyCode::C => if shift ^ caps_lock { 'C' } else { 'c' },
            KeyCode::V => if shift ^ caps_lock { 'V' } else { 'v' },
            KeyCode::B => if shift ^ caps_lock { 'B' } else { 'b' },
            KeyCode::N => if shift ^ caps_lock { 'N' } else { 'n' },
            KeyCode::M => if shift ^ caps_lock { 'M' } else { 'm' },
            
            _ => return None,
        };
        
        Some(base)
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

/// キーイベント
#[derive(Debug, Clone, Copy)]
pub struct KeyEvent {
    /// キーコード
    pub key: KeyCode,
    /// 押下/解放状態
    pub state: KeyState,
    /// シフトキーが押されているか
    pub shift: bool,
    /// Ctrlキーが押されているか
    pub ctrl: bool,
    /// Altキーが押されているか
    pub alt: bool,
    /// CapsLockが有効か
    pub caps_lock: bool,
}

impl KeyEvent {
    /// このイベントを文字に変換
    pub fn to_char(&self) -> Option<char> {
        if self.state == KeyState::Released {
            return None;
        }
        self.key.to_char(self.shift, self.caps_lock)
    }
}

// ============================================================================
// キーボード状態管理
// ============================================================================

/// キーボードの修飾キー状態
struct ModifierState {
    /// 左シフト押下中
    left_shift: AtomicBool,
    /// 右シフト押下中
    right_shift: AtomicBool,
    /// 左Ctrl押下中
    left_ctrl: AtomicBool,
    /// 左Alt押下中
    left_alt: AtomicBool,
    /// CapsLock有効
    caps_lock: AtomicBool,
    /// NumLock有効
    num_lock: AtomicBool,
    /// 拡張スキャンコードモード
    extended_mode: AtomicBool,
}

impl ModifierState {
    const fn new() -> Self {
        Self {
            left_shift: AtomicBool::new(false),
            right_shift: AtomicBool::new(false),
            left_ctrl: AtomicBool::new(false),
            left_alt: AtomicBool::new(false),
            caps_lock: AtomicBool::new(false),
            num_lock: AtomicBool::new(false),
            extended_mode: AtomicBool::new(false),
        }
    }
    
    fn is_shift(&self) -> bool {
        self.left_shift.load(Ordering::Relaxed) || self.right_shift.load(Ordering::Relaxed)
    }
    
    fn is_ctrl(&self) -> bool {
        self.left_ctrl.load(Ordering::Relaxed)
    }
    
    fn is_alt(&self) -> bool {
        self.left_alt.load(Ordering::Relaxed)
    }
    
    fn is_caps_lock(&self) -> bool {
        self.caps_lock.load(Ordering::Relaxed)
    }
}

/// グローバル修飾キー状態
static MODIFIER_STATE: ModifierState = ModifierState::new();

// ============================================================================
// スキャンコードキュー（ロックフリー）
// ============================================================================

const SCANCODE_QUEUE_SIZE: usize = 128;

/// ロックフリーなスキャンコードキュー
struct ScancodeQueue {
    buffer: [AtomicU8; SCANCODE_QUEUE_SIZE],
    head: AtomicUsize,
    tail: AtomicUsize,
}

impl ScancodeQueue {
    const fn new() -> Self {
        const ZERO: AtomicU8 = AtomicU8::new(0);
        Self {
            buffer: [ZERO; SCANCODE_QUEUE_SIZE],
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
        }
    }
    
    /// スキャンコードをプッシュ（ISRから呼ばれる）
    fn push(&self, scancode: u8) -> bool {
        let tail = self.tail.load(Ordering::Relaxed);
        let head = self.head.load(Ordering::Acquire);
        
        let next_tail = (tail + 1) % SCANCODE_QUEUE_SIZE;
        if next_tail == head {
            // キューが満杯
            return false;
        }
        
        self.buffer[tail].store(scancode, Ordering::Relaxed);
        self.tail.store(next_tail, Ordering::Release);
        true
    }
    
    /// スキャンコードをポップ
    fn pop(&self) -> Option<u8> {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Acquire);
        
        if head == tail {
            return None;
        }
        
        let scancode = self.buffer[head].load(Ordering::Relaxed);
        self.head.store((head + 1) % SCANCODE_QUEUE_SIZE, Ordering::Release);
        Some(scancode)
    }
    
    /// キューが空かどうか
    fn is_empty(&self) -> bool {
        self.head.load(Ordering::Acquire) == self.tail.load(Ordering::Acquire)
    }
}

/// グローバルスキャンコードキュー
static SCANCODE_QUEUE: ScancodeQueue = ScancodeQueue::new();

// ============================================================================
// Waker管理
// ============================================================================

/// キーボード入力待ちWaker
static KEYBOARD_WAKER: Mutex<Option<Waker>> = Mutex::new(None);

/// Wakerを登録
fn register_waker(waker: &Waker) {
    let mut guard = KEYBOARD_WAKER.lock();
    match &*guard {
        Some(existing) if existing.will_wake(waker) => {}
        _ => *guard = Some(waker.clone()),
    }
}

/// Wakerを起床
fn wake_waiting() {
    if let Some(waker) = KEYBOARD_WAKER.lock().take() {
        waker.wake();
    }
}

// ============================================================================
// キーボードドライバ
// ============================================================================

/// キーボードドライバ
pub struct KeyboardDriver {
    /// 初期化済みフラグ
    initialized: AtomicBool,
}

impl KeyboardDriver {
    /// 新しいドライバを作成
    pub const fn new() -> Self {
        Self {
            initialized: AtomicBool::new(false),
        }
    }
    
    /// ドライバを初期化
    pub fn init(&self) {
        if self.initialized.swap(true, Ordering::SeqCst) {
            return; // 既に初期化済み
        }
        
        // PS/2キーボードコントローラの初期化
        // （基本的な初期化はBIOSが行っているので、ここでは追加設定のみ）
        
        crate::log!("[KEYBOARD] Keyboard driver initialized\n");
    }
    
    /// スキャンコードを処理（ISRから呼ばれる）
    pub fn handle_scancode(&self, scancode: u8) {
        // 拡張スキャンコードプレフィックスのチェック
        if scancode == 0xE0 {
            MODIFIER_STATE.extended_mode.store(true, Ordering::Relaxed);
            return;
        }
        
        // キューにプッシュ
        if SCANCODE_QUEUE.push(scancode) {
            // 待機中のタスクを起床
            wake_waiting();
        }
    }
    
    /// 次のキーイベントを取得（ノンブロッキング）
    pub fn poll_key_event(&self) -> Option<KeyEvent> {
        let scancode = SCANCODE_QUEUE.pop()?;
        
        let extended = MODIFIER_STATE.extended_mode.swap(false, Ordering::Relaxed);
        let released = (scancode & 0x80) != 0;
        let code = scancode & 0x7F;
        
        let key = KeyCode::from_scancode(code, extended);
        let state = if released { KeyState::Released } else { KeyState::Pressed };
        
        // 修飾キーの状態を更新
        match key {
            KeyCode::LeftShift => MODIFIER_STATE.left_shift.store(!released, Ordering::Relaxed),
            KeyCode::RightShift => MODIFIER_STATE.right_shift.store(!released, Ordering::Relaxed),
            KeyCode::LeftCtrl => MODIFIER_STATE.left_ctrl.store(!released, Ordering::Relaxed),
            KeyCode::LeftAlt => MODIFIER_STATE.left_alt.store(!released, Ordering::Relaxed),
            KeyCode::CapsLock if !released => {
                let current = MODIFIER_STATE.caps_lock.load(Ordering::Relaxed);
                MODIFIER_STATE.caps_lock.store(!current, Ordering::Relaxed);
            }
            KeyCode::NumLock if !released => {
                let current = MODIFIER_STATE.num_lock.load(Ordering::Relaxed);
                MODIFIER_STATE.num_lock.store(!current, Ordering::Relaxed);
            }
            _ => {}
        }
        
        Some(KeyEvent {
            key,
            state,
            shift: MODIFIER_STATE.is_shift(),
            ctrl: MODIFIER_STATE.is_ctrl(),
            alt: MODIFIER_STATE.is_alt(),
            caps_lock: MODIFIER_STATE.is_caps_lock(),
        })
    }
    
    /// 次のキーイベントを非同期で待機
    pub fn read_key(&self) -> KeyEventFuture {
        KeyEventFuture { _driver: self }
    }
    
    /// 次の文字を非同期で待機
    pub fn read_char(&self) -> CharFuture {
        CharFuture { _driver: self }
    }
    
    /// 行を非同期で読み取り
    pub fn read_line(&self) -> LineFuture {
        LineFuture {
            _driver: self,
            buffer: alloc::string::String::new(),
        }
    }
}

/// グローバルキーボードドライバ
static KEYBOARD_DRIVER: KeyboardDriver = KeyboardDriver::new();

/// キーボードドライバにアクセス
pub fn keyboard() -> &'static KeyboardDriver {
    &KEYBOARD_DRIVER
}

/// キーボードを初期化
pub fn init() {
    KEYBOARD_DRIVER.init();
}

/// 割り込みハンドラから呼ばれる
pub fn handle_keyboard_interrupt(scancode: u8) {
    KEYBOARD_DRIVER.handle_scancode(scancode);
}

// ============================================================================
// Async Futures
// ============================================================================

/// キーイベント待ちFuture
pub struct KeyEventFuture<'a> {
    _driver: &'a KeyboardDriver,
}

impl<'a> Future for KeyEventFuture<'a> {
    type Output = KeyEvent;
    
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if let Some(event) = KEYBOARD_DRIVER.poll_key_event() {
            Poll::Ready(event)
        } else {
            register_waker(cx.waker());
            
            // 再度チェック（Wakerを登録した後にイベントが来た可能性）
            if let Some(event) = KEYBOARD_DRIVER.poll_key_event() {
                Poll::Ready(event)
            } else {
                Poll::Pending
            }
        }
    }
}

/// 文字入力待ちFuture
pub struct CharFuture<'a> {
    _driver: &'a KeyboardDriver,
}

impl<'a> Future for CharFuture<'a> {
    type Output = char;
    
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            if let Some(event) = KEYBOARD_DRIVER.poll_key_event() {
                if let Some(c) = event.to_char() {
                    return Poll::Ready(c);
                }
                // 文字に変換できないキーは無視して続行
                continue;
            } else {
                register_waker(cx.waker());
                
                // 再度チェック
                if let Some(event) = KEYBOARD_DRIVER.poll_key_event() {
                    if let Some(c) = event.to_char() {
                        return Poll::Ready(c);
                    }
                }
                
                return Poll::Pending;
            }
        }
    }
}

/// 行入力待ちFuture
pub struct LineFuture<'a> {
    _driver: &'a KeyboardDriver,
    buffer: alloc::string::String,
}

impl<'a> Future for LineFuture<'a> {
    type Output = alloc::string::String;
    
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            if let Some(event) = KEYBOARD_DRIVER.poll_key_event() {
                if event.state == KeyState::Released {
                    continue;
                }
                
                match event.key {
                    KeyCode::Enter => {
                        let result = core::mem::take(&mut self.buffer);
                        return Poll::Ready(result);
                    }
                    KeyCode::Backspace => {
                        self.buffer.pop();
                    }
                    _ => {
                        if let Some(c) = event.to_char() {
                            if c != '\n' && c != '\x08' {
                                self.buffer.push(c);
                            }
                        }
                    }
                }
            } else {
                register_waker(cx.waker());
                return Poll::Pending;
            }
        }
    }
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
        assert!(queue.push(0x1E)); // 'A'
        assert!(!queue.is_empty());
        assert_eq!(queue.pop(), Some(0x1E));
        assert!(queue.is_empty());
    }
}
