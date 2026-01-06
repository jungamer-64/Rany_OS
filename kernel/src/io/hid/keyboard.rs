// ============================================================================
// kernel/src/io/hid/keyboard.rs - Async PS/2 Keyboard Driver (Kernel Wrapper)
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
//! ## 実装
//!
//! コアロジックは `hid_driver` クレートに実装されています。
//! このモジュールは以下のカーネル固有の機能を提供します:
//! - グローバルPS/2キーボードインスタンス
//! - 割り込みハンドラのエントリポイント
//! - カーネルレベルのAPIラッパー

#![allow(dead_code)]

// ============================================================================
// Re-exports from hid_driver crate
// ============================================================================

// Core types
pub use hid_driver::{KeyCode, KeyEvent, KeyState, Modifiers};

// Driver
pub use hid_driver::KeyboardDriver;

// Stream and futures
pub use hid_driver::{
    CharFuture, CharFutureArc, DEFAULT_POLL_BUDGET, KeyEventFuture, KeyboardStream,
    KeyboardStreamArc,
};

// Extension traits
pub use hid_driver::{KeyCodeExt, KeyEventExt};

// to_char() method on KeyEvent
// use hid_driver::KeyEventExt as _KeyEventExt;

// Error types
pub use hid_driver::StreamAlreadyTaken;



// Keymap re-exports
pub use super::keymap::{DEFAULT_KEYMAP, DvorakKeymap, JisKeymap, Keymap, UsQwertyKeymap};

// ============================================================================
// グローバルインスタンス（PS/2キーボード用）
// ============================================================================

/// グローバルPS/2キーボードドライバ
///
/// 単一のPS/2キーボードをサポートする場合はこれを使用。
/// 複数デバイスが必要な場合は、別のインスタンスを作成してください。
pub(crate) static PS2_KEYBOARD: KeyboardDriver = KeyboardDriver::new();

// ============================================================================
// Public API
// ============================================================================

// init() function removed - use Ps2KeyboardDriver via DriverRegistry instead

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

/// イベントがあるかチェック
pub fn has_event() -> bool {
    PS2_KEYBOARD.has_event()
}

/// キーボードストリームを取得
///
/// デフォルトのUSキーマップを使用します。
///
/// # Errors
/// 既にストリームが発行されている場合は`Err(StreamAlreadyTaken)`を返す。
pub fn take_stream() -> Result<KeyboardStream, StreamAlreadyTaken> {
    PS2_KEYBOARD.take_stream()
}

/// 指定されたキーマップでキーボードストリームを取得
///
/// # Arguments
/// * `keymap` - 使用するキーマップ（'staticライフタイム必須）
pub fn take_stream_with_keymap(
    keymap: &'static dyn Keymap,
) -> Result<KeyboardStream, StreamAlreadyTaken> {
    PS2_KEYBOARD.take_stream_with_keymap(keymap)
}

/// Arc<dyn Keymap>を使用するキーボードストリームを取得
///
/// 動的なキーマップ切り替えが必要な場合に使用。
pub fn take_stream_with_arc_keymap(
    keymap: alloc::sync::Arc<dyn Keymap>,
) -> Result<KeyboardStreamArc, StreamAlreadyTaken> {
    PS2_KEYBOARD.take_stream_with_arc_keymap(keymap)
}

// ============================================================================
// 内部API（crate内部使用・後方互換性）
// ============================================================================



/// 次の文字をポーリング（非ブロッキング）
///
/// # Note
/// 内部使用向け。新しいコードでは`KeyboardStream`を使用してください。
#[doc(hidden)]
pub(crate) fn poll_char() -> Option<char> {
    use hid_driver::DriverOps;
    while let Some(event) = PS2_KEYBOARD.poll_key_event_internal() {
        if let Some(c) = event.to_char() {
            return Some(c);
        }
    }
    None
}

/// 次のキーイベントをポーリング（非ブロッキング）- 内部API
///
/// service_impl.rs の poll_input_event から使用される。
#[doc(hidden)]
pub(crate) fn poll_input_event() -> Option<KeyEvent> {
    use hid_driver::DriverOps;
    PS2_KEYBOARD.poll_key_event_internal()
}

// ============================================================================
// Extern crate declarations
// ============================================================================

extern crate alloc;
