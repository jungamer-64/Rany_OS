// ============================================================================
// src/io/hid/mouse.rs - PS/2 Mouse Driver (Kernel Wrapper)
// ============================================================================
//!
//! # PS/2マウスドライバ
//!
//! カーネル固有のグローバル状態とAPI。
//! コア実装は `hid_driver::mouse` に移動済み。

#![allow(dead_code)]

use spin::Mutex;

// Re-export everything from hid_driver::mouse
pub use hid_driver::mouse::{Mouse, MouseInitError};
pub use hid_driver::{MouseButton, MouseEvent};

// ============================================================================
// Global State
// ============================================================================

/// グローバルマウス
static MOUSE: Mutex<Mouse> = Mutex::new(Mouse::new());

// ============================================================================
// Public API - Initialization
// ============================================================================

/// マウスを初期化
///
/// # Returns
/// - `Ok(())` - 初期化成功
/// - `Err(MouseInitError)` - 初期化失敗
pub fn init() -> Result<(), MouseInitError> {
    MOUSE.lock().init()
}

// ============================================================================
// Public API - Mouse (割り込みハンドラ用)
// ============================================================================

/// マウスパケットバイトを処理（IRQ12割り込みハンドラから呼ばれる）
/// try_lockを使用してデッドロックを防止
pub fn handle_mouse_packet(data: u8) {
    if let Some(mut guard) = MOUSE.try_lock() {
        guard.process_packet(data);
    }
}

// ============================================================================
// Public API - Mouse (ユーザーコード用)
// ============================================================================

/// マウスイベントを取得（割り込みを無効にして実行）
pub fn poll_mouse_event() -> Option<MouseEvent> {
    x86_64::instructions::interrupts::without_interrupts(|| MOUSE.lock().poll_event())
}

/// マウスイベントがあるか（割り込みを無効にして実行）
pub fn has_mouse_event() -> bool {
    x86_64::instructions::interrupts::without_interrupts(|| MOUSE.lock().has_event())
}

/// マウスが初期化されているか
pub fn is_mouse_initialized() -> bool {
    x86_64::instructions::interrupts::without_interrupts(|| MOUSE.lock().is_initialized())
}
