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
pub(crate) static MOUSE: Mutex<Mouse> = Mutex::new(Mouse::new());

// ============================================================================
// Public API - Initialization
// ============================================================================

// init() function removed - use Ps2MouseDriver via DriverRegistry instead

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

// Compatibility polling helpers removed.
// Use event-driven `MouseEvent` streams (preferred) or query the global `MOUSE` under
// an interrupts-disabled section when necessary, e.g.:
//
// x86_64::instructions::interrupts::without_interrupts(|| crate::io::hid::mouse::MOUSE.lock().poll_event())
//
// This preserves deterministic behavior without relying on deprecated wrappers.

/// マウスが初期化されているか
pub fn is_mouse_initialized() -> bool {
    x86_64::instructions::interrupts::without_interrupts(|| MOUSE.lock().is_initialized())
} 
