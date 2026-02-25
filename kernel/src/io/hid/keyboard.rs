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
pub use hid_driver::keyboard::{KeyCodeExt, KeyEventExt};

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

/// IRQ1 handler entry for the async keyboard stream path.
///
/// Reads one byte from the PS/2 data port and pushes it to `PS2_KEYBOARD`.
/// This keeps the IRQ producer aligned with the `KeyboardStream` consumer used by ExoShell.
pub fn keyboard_interrupt_handler() {
    let status_val: u8;
    let data: u8;

    unsafe {
        core::arch::asm!(
            "in al, dx",
            out("al") status_val,
            in("dx") crate::io::hid::ps2::ports::STATUS,
            options(nomem, nostack)
        );
        if (status_val & crate::io::hid::ps2::status::OUTPUT_FULL) == 0 {
            return;
        }
        core::arch::asm!(
            "in al, dx",
            out("al") data,
            in("dx") crate::io::hid::ps2::ports::DATA,
            options(nomem, nostack)
        );
    }

    PS2_KEYBOARD.handle_scancode(data);
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

/// Register or clear an IRQ-side keyboard event tap.
///
/// The callback executes in interrupt context and must be non-blocking.
pub fn set_event_tap(tap: Option<fn(KeyEvent)>) {
    PS2_KEYBOARD.set_event_tap(tap);
}

// ============================================================================
// 内部API（crate内部使用・後方互換性）
// ============================================================================



// Internal polling shims removed: Use `KeyboardStream` via `crate::io::hid::keyboard::take_stream()`
// and async stream APIs instead of `poll_char()`/`poll_input_event()`.
// ============================================================================
// Extern crate declarations
// ============================================================================

extern crate alloc;
