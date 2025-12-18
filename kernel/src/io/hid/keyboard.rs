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
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use core::task::{Context, Poll, Waker};

// Keymapモジュールからインポート
pub use super::keymap::{DEFAULT_KEYMAP, DvorakKeymap, JisKeymap, Keymap, UsQwertyKeymap};

// ============================================================================
// エラー型
// ============================================================================

// StreamAlreadyTaken is provided by the `hid_driver` crate.
pub use hid_driver::StreamAlreadyTaken;

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

// Imports from hid_driver
pub use hid_driver::{KeyCode, KeyEvent, KeyState, Modifiers};

// ============================================================================
// Extension Traits
// ============================================================================

// KeyCode helper trait is provided by the `hid_driver` crate.
#[deprecated(note = "KeyCodeExt re-export is deprecated; prefer `hid_driver::KeyCodeExt` directly.")]
pub use hid_driver::KeyCodeExt;

// KeyCodeExt implementation is provided by the `hid_driver` crate and
// re-exported above (`pub use hid_driver::KeyCodeExt`). Kernel should not
// implement the trait for `hid_driver::KeyCode` to avoid orphan-rule violations.

// ============================================================================
// キーイベント
// ============================================================================

// KeyEventExt helper trait is provided by the `hid_driver` crate.
#[deprecated(note = "KeyEventExt re-export is deprecated; prefer `hid_driver::KeyEventExt` directly.")]
pub use hid_driver::KeyEventExt;

// ModifierState implementation moved to `hid_driver` crate. Re-export it here for
// backward-compatibility with kernel code that expects this type.
#[deprecated(note = "Compatibility re-export `ModifierState` is deprecated; prefer `hid_driver::ModifierState` directly.")]
pub use hid_driver::ModifierState;

// IsrSafeWaker implementation moved to `hid_driver` crate. Re-export it here for
// backward compatibility.
#[deprecated(note = "Compatibility re-export `IsrSafeWaker` is deprecated; prefer `hid_driver::IsrSafeWaker` directly.")]
pub use hid_driver::IsrSafeWaker;

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
            log::info!("[KEYBOARD] WARNING: init() called multiple times (ignored)\n");
            return;
        }
        log::info!("[KEYBOARD] Keyboard driver initialized (Instance-based, Single-core only)\n");
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
            let _ = self
                .dropped_events
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                    v.checked_add(1).or(Some(u64::MAX))
                });
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

        // self.update_modifiers(key, extended, released);

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
    /*
    /// 修飾キーの状態を更新
    fn update_modifiers(&self, key: KeyCode, extended: bool, released: bool) {
         // ... implementation commented out ...
    }
    */

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
    pub fn take_stream(&'static self) -> Result<hid_driver::KeyboardStream, StreamAlreadyTaken> {
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
    ) -> Result<hid_driver::KeyboardStream, StreamAlreadyTaken> {
        if self.stream_taken.swap(true, Ordering::SeqCst) {
            return Err(StreamAlreadyTaken);
        }
        Ok(hid_driver::KeyboardStream::new(self, keymap))
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
    ) -> Result<hid_driver::KeyboardStreamArc, StreamAlreadyTaken> {
        if self.stream_taken.swap(true, Ordering::SeqCst) {
            return Err(StreamAlreadyTaken);
        }
        Ok(hid_driver::KeyboardStreamArc::new(self, keymap))
    }

    /// キーボードストリームを取得（パニック版・テスト/初期化用）
    ///
    /// # Panics
    /// 既にストリームが発行されている場合
    ///
    /// # Note
    /// 本番コードでは`take_stream()`を使用し、エラーハンドリングを行うこと。
    #[deprecated(note = "`take_stream_or_panic` is deprecated; prefer `take_stream()` and handle `StreamAlreadyTaken` explicitly instead of panicking.")]
    pub fn take_stream_or_panic(&'static self) -> hid_driver::KeyboardStream {
        self.take_stream()
            .expect("SPSC violation: Stream already taken")
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

// Stream/future helpers are implemented in the `hid_driver` crate
// to allow reuse by other implementations. Re-export them here for
// backward-compatibility with existing kernel code.

pub use hid_driver::{
    CharFuture, CharFutureArc, DEFAULT_POLL_BUDGET, KeyEventFuture, KeyboardStream,
    KeyboardStreamArc,
};

// Implement DriverOps at module scope so the driver-side stream helpers
// can call back into this kernel implementation.
impl hid_driver::stream::DriverOps for KeyboardDriver {
    fn poll_key_event_internal(&self) -> Option<hid_driver::KeyEvent> {
        self.poll_key_event_internal()
    }
    fn register_waker(&self, waker: &Waker) {
        self.register_waker(waker);
    }
    fn process_pending_wake(&self) -> bool {
        self.process_pending_wake()
    }
    fn has_event(&self) -> bool {
        self.has_event()
    }
    fn get_modifiers(&self) -> hid_driver::Modifiers {
        self.get_modifiers()
    }
    fn return_stream(&self) {
        self.return_stream()
    }
}

// ============================================================================
// Async Futures
// ============================================================================

// ============================================================================
// グローバルインスタンス（PS/2キーボード用）
// ============================================================================

/// グローバルPS/2キーボードドライバ
///
/// 単一のPS/2キーボードをサポートする場合はこれを使用。
/// 複数デバイスが必要な場合は、別のインスタンスを作成してください。
static PS2_KEYBOARD: KeyboardDriver = KeyboardDriver::new();

/// PS/2キーボードドライバにアクセス
#[deprecated(note = "`keyboard()` accessor is deprecated; prefer acquiring a `KeyboardStream` via `take_stream()` or initialize the keyboard via `crate::io::hid::keyboard_init()`.")]
pub fn keyboard() -> &'static KeyboardDriver {
    &PS2_KEYBOARD
}

/// PS/2キーボードを初期化
#[deprecated(note = "`keyboard::init()` is deprecated; prefer `crate::io::hid::keyboard_init()` or initialize the PS/2 controller directly.")]
pub fn init() {
    PS2_KEYBOARD.init();
}

/// 割り込みハンドラから呼ばれる（PS/2キーボード用）
#[deprecated(note = "`handle_keyboard_interrupt` is deprecated; prefer the PS/2 controller's `keyboard_interrupt_handler` re-export or register the handler via the PS/2 driver.")]
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
    PS2_KEYBOARD.poll_key_event_internal()
}

/// 次の文字をポーリング（非ブロッキング）
///
/// # Note
/// 内部使用向け。新しいコードでは`KeyboardStream`を使用してください。
#[doc(hidden)]
pub(crate) fn poll_char() -> Option<char> {
    while let Some(event) = PS2_KEYBOARD.poll_key_event_internal() {
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
            assert_eq!(
                queue.pop(),
                Some(i as u16),
                "Pop should return correct value at index {}",
                i
            );
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
            modifiers: Modifiers {
                shift: true,
                ..Modifiers::default()
            },
            raw_scancode: 0x1E,
        };
        assert_eq!(shifted.to_char(), Some('A'));
    }

    #[test]
    fn test_control_characters() {
        let mods = Modifiers {
            ctrl: true,
            ..Modifiers::default()
        };

        // Ctrl+A through Ctrl+Z
        assert_eq!(DEFAULT_KEYMAP.to_char(KeyCode::A, &mods), Some('\x01'));
        assert_eq!(DEFAULT_KEYMAP.to_char(KeyCode::Z, &mods), Some('\x1A'));

        // Ctrl+[ = Escape
        assert_eq!(
            DEFAULT_KEYMAP.to_char(KeyCode::LeftBracket, &mods),
            Some('\x1B')
        );

        // Ctrl+\ = FS
        assert_eq!(
            DEFAULT_KEYMAP.to_char(KeyCode::Backslash, &mods),
            Some('\x1C')
        );

        // Ctrl+] = GS
        assert_eq!(
            DEFAULT_KEYMAP.to_char(KeyCode::RightBracket, &mods),
            Some('\x1D')
        );

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
        assert_eq!(
            DEFAULT_KEYMAP.to_char(KeyCode::Backspace, &mods),
            Some('\x08')
        );
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
        assert_eq!(
            DEFAULT_KEYMAP.to_char(KeyCode::NumPadPlus, &mods),
            Some('+')
        );
        assert_eq!(
            DEFAULT_KEYMAP.to_char(KeyCode::NumPadMinus, &mods),
            Some('-')
        );
        assert_eq!(
            DEFAULT_KEYMAP.to_char(KeyCode::NumPadMultiply, &mods),
            Some('*')
        );
        assert_eq!(
            DEFAULT_KEYMAP.to_char(KeyCode::NumPadDivide, &mods),
            Some('/')
        );

        // テンキー特殊
        assert_eq!(
            DEFAULT_KEYMAP.to_char(KeyCode::NumPadDecimal, &mods),
            Some('.')
        );
        assert_eq!(
            DEFAULT_KEYMAP.to_char(KeyCode::NumPadEnter, &mods),
            Some('\n')
        );
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
